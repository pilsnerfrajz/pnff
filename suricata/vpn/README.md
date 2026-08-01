# VPN Rules
Our VPN rules contain both VPN software application and VPN protocol fingerprints. The rules that target the VPN applications are similar to the rules in [suricata/rmm/rmm.rules](suricata/rmm/rmm.rules).

---

**Apps/programs:**
- ExpressVPN v12.104.0 (128) (VPN)
- Mullvad v2025.14 (VPN)
- NordVPN v7.56.2.0 (VPN)
- ProtonVPN v4.3.11 (VPN)
- VyprVPN v6.0.4 (VPN)
- Windscribe v2.19.7 (VPN)
- WARP v2025.10.186.0 (VPN)
- rsocx v0.1.3 (SOCKS5 Reverse Proxy)
- rpivot (SOCKS4 Reverse Proxy)

---

**Protocols:**
- WireGuard
  - Vanilla
  - TCP mode
  - LWO Obfuscation (Mullvad)
  - Shadowsocks Obfuscation (Mullvad)
  - QUIC Obfuscation (Mullvad)
- Nordlynx (NordVPN), detected as vanilla WireGuard
- OpenVPN (UDP/TCP) 
- IPsec (Based on IKE exchange)
- SOCKS5

---

**TLS/QUIC-Based**
- Lightway UDP (ExpressVPN)
- Lightway TCP (ExpressVPN)
- Wstunnel (Windscribe)
- Stealth (Windscribe)
- Stealth (ProtonVPN)
- NordWhisper (NordVPN)
- Cloudflare MASQUE Protocol (WARP)

## Application/Program Fingerprints and TLS/QUIC-Based Protocols
These fingerprints target standard protocols such as DNS, HTTP and TLS handshakes. These are already described in [suricata/rmm/README.md](suricata/rmm/README.md) and are not repeated here. Application-specific rules are grouped together with their respective TLS-based protocols (e.g., Wstunnel) in the rule file. TLS/QUIC-based rules are identified via TLS Client Hello fingerprints.

## WireGuard
Here we explain WireGuard and obfuscation modes. All rules use the `flowbits` keyword to track the flow of the communication to generate an alert once a complete handshake is seen. 

### Vanilla (UDP and TCP)
WireGuard has fixed handshake packet lengths. Together with reserved and uninitialized bytes, it is easily detectable. WireGuard over TCP adds two additional bytes to the packets for the length field in the TCP header, but is otherwise equally detectable. Because there is no WireGuard protocol keyword in Suricata, we use the `dsize` keyword to match packet sizes, and the `content` keyword to target the fixed bytes in the packets. The rules are also separated by the `tcp` and `udp` protocol keywords.

### LWO
Lightweight WireGuard Obfuscation (LWO) is a proprietary obfuscation method used by Mullvad. The packet size is the same as vanilla WireGuard and runs over UDP. The LWO detection rules look for the same packet sizes, but also if the most significant bit of the second byte is set to 1. This is the "magic byte" of LWO. Since LWO is used to obfuscate the otherwise easily detectable WireGuard patterns, we can't rely on header fields. Instead, we look for packet entropies within a certain interval which we derived from our recorded traffic. This is explained further in the thesis.

### Shadowsocks
WireGuard over Shadowsocks is similar to LWO, and contains no fixed bytes. The Mullvad implementation of Shadowsocks is the 2017 version which adds predictable overhead. Our testing showed a 55 byte overhead which we use for the `dsize` keyword. The second check is that the entropy is within the established interval. The entropy check is necessary because the Shadowsocks implementation does not have any fixed bytes to match on.

We also made an effort to detect Shadowsocks 2022, but due to no available traffic, it is untested.

### WireGuard over QUIC
This obfuscation layer transforms it into a QUIC-based protocol and is fingerprinted with JA4. 

## OpenVPN
OpenVPN in TCP and UDP modes follow the same pattern as WireGuard with a two byte difference. OpenVPN is detectable by looking at the minimum and maximum size of the initiation and response packets. The calculation for the overhead is placed in the rule file, and the rules only match when the packet is within the interval. It then extracts the five most significant bits of the first byte of the OpenVPN header with the `byte_test` keyword. If these bits match `0x07`, it is a client initiation message. If it is `0x08`, it comes from the server and completes the handshake. We use the `flow` keyword to reduce false positives, for example to not match if `0x08` is sent from the client. `flowbits` are also used to keep track of the communication flow and only alert on a complete handshake. 

## IPSec
IPSec is difficult to detect as it contains no obvious patterns. We instead rely on detecting IKE handshakes. The `ike` protocol keyword exists in Suricata, but does not support all fields that we target in our rules. IKE operates with several messages that contain fingerprintable sequences. In this case, we also add specific ports to the rules, as they will be used with the specific messages if the implementation is RFC compliant. The specific byte sequences are detailed further in the thesis. 

We support both IKEv1 and IKEv2. IKEv1 was not present in any of the VPN vendors' implementations, but we tested the rules against PCAPs found online. 

## SOCKS
We implemented rules for both forward and reverse SOCKS5 proxies. The rules verify that the initiation packet has a size larger than two bytes and less than 258 bytes. It checks if the first byte is `0x05` (denoting the SOCKS version) and that the second byte has a value larger than `0x00`. The second byte specifies the number of supported authentication methods (up to 255). We then extract the value of the second byte and add 2 to calculate the expected total length of the packet. Finally, we verify that the packet contains no additional trailing data beyond this calculated length. For example, a packet of size 10 means there are exactly 8 authentication methods. Enforcing this exact length match adds protection against false positives that a generic `dsize` range cannot prevent.

## Lightway UDP
ExpressVPN's Lightway UDP protocol has very distinct header fields that are fingerprintable. The rule checks that the packet starts with the magic bytes `He` (in ASCII). It then looks for two reserved bytes at offset 6, immediately followed by eight bytes of an uninitialized session ID. This is followed by `0x16` denoting that there is a DTLS handshake message, and `fe` specifies DTLSv1.X. 

## Bonus Rules
A low number of suggested cipher suites in TLS and QUIC handshakes is unusual. We added two general rules to detect Client Hellos that only offers one cipher suite. These rules are easy to modify to change the threshold to another number depending on what is deemed unusual. These are found under ANOMALY RULES in the `vpn.rules` file.

We have included a fingerprint for rpivot, which is a SOCKS4 reverse proxy. It has the most amount of stars on GitHub when searching for SOCKS4 reverse proxies. It is unfortunately not SOCKS4 compliant, but its traffic contains a highly specific string that was easy to implement as a bonus rule.
