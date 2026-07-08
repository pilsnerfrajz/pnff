# pnff -- Passive Network Fingerprinting Framework
This repository contains the code, scripts, and rules associated with the master's thesis ***Detecting Post-Compromise Activity in OT Networks: A Multilayered Network Fingerprinting Approach***. The research was conducted as a collaboration between Truesec and KTH Royal Institute of Technology by William Hedenskog, supervised by Nicklas Keijser (Truesec), Marco Casagrande (KTH), and examined by Panos Papadimitratos (KTH).

PNFF is designed for Operational Technology (OT) environments, relying strictly on passive network fingerprinting to avoid disrupting sensitive industrial assets. The framework targets three specific traffic profiles — **Plaintext Network Protocols**, **Virtual Private Network (VPN) Tunnels** and **OPC Unified Architecture (OPC UA)** — to identify:

1. **Desktop Applications**
2. **VPN Protocols**
3. **OPC UA library/vendor implementations**

## Requirements

- `tshark`
- `awk`
- Python3 (`scipy` and `scapy` modules)
- Unix shell (e.g., `bash` or `zsh`, via WSL on Windows)
- Common CLI utilities (`sed`, `sort`, etc.)
- `JA4X` binary (See Licensing)

## Plaintext Traffic
We leverage unencrypted and partially encrypted protocols to identify applications on the network using DNS, HTTP, TLS Client Hello handshakes, TLS Server Name Indication (SNI), TLS certificates, and broadcast messages (mDNS). By fusing these artifacts with port numbers and magic bytes, we successfully identify the following applications (though the framework is extensible to any software):

- **RMM Tools:** Ammyy Admin, AnyDesk, AnyViewer, Splashtop, RemotePC, RustDesk, TeamViewer, and UltraVNC
- **VPN Clients:** VyprVPN, Windscribe, ExpressVPN, ProtonVPN, NordVPN, Cloudflare WARP, and Mullvad VPN

## VPN Protocols
We analyze the structural characteristics of the unencrypted, mandatory handshake messages sent during VPN tunnel initialization to passively identify the underlying protocol. Additionally, packet entropy is used to differentiate between WireGuard implementations. We successfully identify the following VPN protocols:

- **Commercial:** WireGuard (UDP/TCP), IPSec (via IKE), OpenVPN (UDP/TCP)
- **Proprietary:** Lightway UDP, Lightway TCP, NordVPN Nordlynx, NordVPN Stealth, NordVPN Nordwhisper, ProtonVPN Stealth, Windscribe Stealth, Windscribe Wstunnel, Cloudflare WARP
- **Obfuscated:** Lightweight WireGuard Obfuscation (LWO), WireGuard over Shadowsocks, WireGuard over QUIC
- **Proxy:** SOCKS5

## OPC UA
OPC UA vendor and library implementations do not send any data that identifies the vendor inside OPC UA messages. PNFF produces fingerprints named `UA-FP`, inspired by JA4, that are directly comparable and human-readable, based on OPC UA `HEL` and `ACK` messages, that uniquely identify the application vendor. 

UA-FP has the format `uatv_recv_send_mms_mcc`.
- `t` is either `a` or `h` for `ACK`/`HEL` messages
- `v` is the OPC UA version (e.g., 0)
- `recv` is the receive buffer size
- `send` is the send buffer size
- `mms` is the max message size
- `mcc` is the max chunk count

Using these fingerprints, we identify 10 OPC UA implementations from 7 vendors/libraries. 

- **Vendors:** Prosys OPC, Integration Objects, Kepware, Softing, and Matrikon
- **Libraries:** opcua-asyncio and python-opcua

Additionally, we use JA4X fingerprinting to detect spoofed certificates, which we test with our rogue server. Another promising use case in OT is identifying default vendor certificates that may compromise security. 

## Scripts
Our automated traffic analysis scripts are located in the `/scripts` directory. Their targets and required arguments are displayed in the table. Python scripts are located inside `/scripts/python`. The scripts are used for entropy calculation of handshake messages, UA-FP fingerprint-to-Suricata conversion, and for our OPC UA rogue server attack.

| Script | Target | Usage |
| :--- | :--- | :--- |
| `scripts/extract-app.sh` | Applications | `./extract-app.sh pcap_file` |
| `scripts/extract-vpn.sh` | VPN Protocols | `./extract-vpn.sh pcap_file` |
| `scripts/extract-opcua.sh` | OPC UA Implementations | `./extract-opcua.sh pcap_file server_port [ja4x_path]` |
| `scripts/python/entropy.py` | Entropy of handshakes | `python3 entropy.py folder_path isize rsize` |
| `scripts/python/uafp-to-suricata.py` | UA-FP to Suricata conversion | `python3 uafp-to-suricata.py output_file sid ua_fp` |
| `scripts/python/rogue.py` | Rogue server main file | `python3 rogue.py -p port -t target` |
| `scripts/python/framework.py` | Rogue server functions | N/A |

**`extract-opcua.sh`:** This script requires the TCP port number where the OPC UA server is listening (e.g., `4840`). If you wish to also extract JA4X certificate fingerprints, you must provide the local path to the compiled JA4X binary as the third argument. The binary can be downloaded from the [JA4+ Releases page](https://github.com/FoxIO-LLC/ja4/releases) or built from source.

**`entropy.py`:** This script requires the path to the folder containing the PCAP files, as well as the expected sizes of the initial (`isize`) and response (`rsize`) handshake packets (e.g., 148 and 92 bytes, respectively).

**`uafp-to-suricata.py`:** This script converts `UA-FP` fingerprints (`ua_fp` argument) into Suricata format. The rule is appended to the output file, using `sid` as the signature ID.

**Rogue server:** Because it is not the main goal of this research, nor a core component of the fingerprinting framework, instructions on how to set up the rogue server are explained in Section 5.3.3 of the thesis.

## Suricata Detection Rules
Our Suricata rules are located inside the `/suricata` folder. Application fingerprints are placed inside `application.rules`, VPN signatures in `vpn.rules`, and OPC UA fingerprints within `opcua.rules`. The rules can easily be tested against a PCAP with the example command:
```
suricata -r vpn.pcap -S vpn.rules -k none -l .
```
- `-r`: read pcap file
- `-S`: custom rules file
- `-k none`: disable checksum validation
- `-l .`: log to current directory

Inspect the `fast.log` file generated in the current directory to verify if the rules matched any traffic.

## Acknowledgements

- **Rogue Server Attack:** We adapted and modified existing code created by [Alessandro Erba, Anne Müller and Nils Ole Tippenhauer](https://github.com/scy-phy/OPC-UA-attacks-POC).
- **JA4+:** We leverage JA4 for TLS analysis, and JA4X for detecting spoofed OPC UA certificates. JA4+ is developed and maintained by [FoxIO](https://github.com/FoxIO-LLC/ja4).

## Licensing

The original code, framework, and Suricata rules in this repository are licensed under the [MIT License](LICENSE).

**Disclaimer Regarding JA4+ (JA4X)**
This framework relies on the JA4+ suite (specifically JA4X) for certificate fingerprinting in OPC UA. JA4X is **not** distributed within this repository and must be acquired separately. 

Please note that JA4X is licensed under the **FoxIO License 1.1**, which permits academic research and internal non-commercial use, but strictly prohibits commercial use and monetization. Any user intending to utilize JA4X commercially must obtain explicit permission from FoxIO, LLC. 

For full details, see the [JA4+ Licensing Information](https://github.com/FoxIO-LLC/ja4#licensing).
