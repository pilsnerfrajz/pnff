# Passive Network Fingerprinting Framework
This code repository contains the files associated with the master thesis by William Hedenskog on the topic ***Detecting Post-Compromise Activity in OT Networks: A Multilayered Network Fingerprinting Approach***. It was conducted as a collaboration between Truesec and KTH Royal Institute of Technology, together with Nicklas Keijser (Truesec), Marco Casagrande (KTH) and Panos Papadimitratos (KTH). 

In our work we present a passive network fingerprinting framework that specifically targets **Remote Management and Monitoring (RMM) software**, **Virtual Private Network (VPN) applications and protocols**, and the industrial interoperability standard **OPC Unified Architecutre (OPC UA)**. We describe the framework in [The Framework](#the-framework), followed by an explanation of our script for automated packet analysis and calculations in [Network Packet Extraction Scripts](#network-packet-extraction-scripts). We describe how Suricata detection rules work in more detail (compared to the thesis) in [Suricata Detection Rules](#suricata-detection-rules) and end with crediting tools that contriuted to the thesis, and an important note

## Requirements
- `tshark`
- `awk`
- python
  - `scipy` and `scapy` pip modules
- unix shell eg., `zsh` or `bash` (via WSL on Windows)
- common CLI utilities like `sed` and `sort`
- `JA4X` binary

## The Framework
Because this research primarily focuses on Operational Technology (OT) environments, we rely on passive fingerprinting to not disrupt operations of sensitive OT devices. We target three types of network traffic profiles: plaintext network protocols, VPN tunnels, and OPC UA.

### Plaintext Traffic
We leverage plaintext protocols to identify applications on the network via, DNS, HTTP, Transport Layer Security (TLS) handshakes, TLS Server Name Indication (SNI), TLS certificates, and broadcast messages such as mDNS. Other fingerprintable attributes include *magic bytes*, port numbers and proprietary broadcast addresses. Each artifact contributes to the total fingerprint of an application, with some being more distinct than others.

By leveraging this methodology, we successfully identify the following applications, but the framework is extensible to any software.
- **RMM Tools:** Ammyy Admin, AnyDesk, AnyViewer, Splashtop, RemotePC, RustDesk, TeamViewer, and UltraVNC
- **VPN Software Clients:** VyprVPN, Windscribe, ExpressVPN, ProtonVPN, NordVPN, Cloudflare WARP, and Mullvad VPN

### VPN Protocols
The purpose of VPN protocols is to hide traffic inside encrypted packets. The use of VPNs render fingerprinting of plaintext protocols useless, but every VPN connection send mandatory handshake messages in plaintext that can be used to identify the protocol. 

## Network Packet Extraction Scripts


## Suricata Detection Rules


## Acknowledgements

- **Rogue Server Attack:** In this work, we adapted and modified existing code created by [Alessandro Erba, Anne Müller and Nils Ole Tippenhauer](https://github.com/scy-phy/OPC-UA-attacks-POC)
- **JA4+:** 

## Licensing

The original code, framework, and Suricata rules in this repository are licensed under the [MIT License](LICENSE).

**Disclaimer Regarding JA4+ (JA4X)**
This framework relies on the JA4+ suite (specifically JA4X) for certificate fingerprinting in OPC UA. JA4X is **not** distributed within this repository and must be acquired separately. 

Please note that JA4X is licensed under the **FoxIO License 1.1**, which permits academic research and internal non-commercial use, but strictly prohibits commercial use and monetization. Any user intending to utilize JA4X commercially must obtain explicit permission from FoxIO, LLC. 

For full details, see the [JA4+ Licensing Information](https://github.com/FoxIO-LLC/ja4#licensing).
