# RMM Rules
Remote Management and Monitoring (RMM) tools are software like TeamViewer. We have implemented detection for the following software:
- AnyDesk v9.6.7
- AnyViewer v5.5.0
- Ammyy Admin v3.10
- Atera Splashtop v3.8.0.4
- TeamViewer v15.73.5
- RemotePC v7.6.95
- RustDesk v1.4.5
- UltraVNC v1.6.4.0

Most of the rules should be self-documenting, but here is a quick rundown the rule categories.

## DNS/mDNS/Custom Broadcast
Our DNS rules inspect responses rather than queries. We opted for replies as they are more difficult for an adversary to alter assuming they do not control the upstream DNS infrastructure, just in case there are ways to obfuscate DNS queries. Possible improvements could be adding rules for the queries as well.

For mDNS, the queries are abalyzed as any responses are sent to the multicast IP address. Assuming an adversary wanting to find other hosts on the network, or connect from the outside, the most interesting entity is the requester.

Some software like AnyDesk sends proprietary mutlicast messages to discover other devices with the tool installed. The very specific address and port are good indicators of AnyDesk presence. 
```
alert udp any any -> 239.255.102.18 50001 (msg:"AnyDesk Network Discovery Traffic"; sid:1000043; rev:1;)
alert udp any any -> 239.255.102.18 50002 (msg:"AnyDesk Network Discovery Traffic"; sid:1000044; rev:1;)
alert udp any any -> 239.255.102.18 50003 (msg:"AnyDesk Network Discovery Traffic"; sid:1000045; rev:1;)
```

*Note: While we have not observed these specific packets in our testing, combining these network indicators with payload signatures would increase detection precision, though it risks evasion if the payload structure changes.*

## HTTP
The rules detect specific HTTP requests by verifying that the connection originates from the RMM client to the vendor infrastructure and that the session is established.

- **Ammy Admin:** The rules trigger when the requested hostname contains `ammyy`.
- **AnyDesk:** The rules detect a `POST` request containing a specific `User-Agent` string identifying `anydesk.

## TLS and QUIC
The rules detect various TLS attributes that are indicative of an RMM tool in the network. They match on identifying elements when the tools connect to the developer servers for authentication, relay and updates:

- **TLS SNI:** Matches specific Server Name Indications (SNIs) (e.g., teamviewer)
- **TLS Server certificates:**
  - Checks if TLSv1.2 is used (as TLSv1.3 encrypts the certificate)
  - Checks if the message type is a `Server Hello` (`0x02`)
  - Scans the remainder of the payload for vendor-specific strings
- **TLS JA4 Hashes:** Extracts and matches hashes from the Client Hello`

Similarly, QUIC handshakes are parsed to isolate the inner TLS packets and extract the corresponding JA4 hash.

## Port Rules
The purely port-based rules are generic and likely to produce a high volume of false positives. They are mostly there as a possible network artifact but require testing in a live environment. Perhaps they are better suited from a forensic POV or combined with other indicators. A highly specific example was observed in our testing as SYN packets sent by AnyDesk to port 7070, which is tracked under `sid:1000041`.

## Magic Bytes
Virtual Network Computing (VNC) does not utilize TLS. Instead, it relies on the Remote Frame Buffer (RFB) protocol. During session negotiation, the client sends its supported RFB version to the server in plaintext (e.g., `RFB 003.008). This string is highly distinct and reliably fingerprinted by Suricata.

## Other Correlations
The `t12d2108h1_76e208dd3e22_2dae41c691ec` JA4 hash actually matches both TeamViewer and AnyViewer. To tell them apart, rule `1000036` looks for a connection to `ip138[.]com` via the TLS SNI, when AnyViewer connects to this geolocation lookup service (likely to comply with Chinese laws).
When Suricata sees this SNI, it sets a flag using the `xbits` keyword and tracks the source IP for 60 seconds. If that same IP then produces the shared JA4 hash while the flag is active, rule `1000035` triggers. This correlation gives us a much more precise alert for AnyViewer on the network.
