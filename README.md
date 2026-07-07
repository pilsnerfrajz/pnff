# Passive Network Fingerprinting Framework
This code repository contains the files associated with the master thesis by William Hedenskog on the topic ***Detecting Post-Compromise Activity in OT Networks: A Multilayered Network Fingerprinting Approach***. It was conducted as a collaboration between KTH Royal Institute of Technology and Truesec, together with Nicklas Keijser (Truesec), Marco Casagrande (KTH) and Panos Papadimitratos (KTH). 

In our work we present a passive network fingerprinting framework that specifically targets **Remote Management and Monitoring (RMM) software**, **Virtual Private Network (VPN) applications and protocols**, and the industrial interoperability standard **OPC Unified Architecutre (OPC UA)**. We describe the framework in [The Framework](#the-framework), followed by an explanation of our script for automated packet analysis and calculations in [Network Packet Extraction Scripts](network-packet-extraction-scripts). We describe how Suricata detection rules work in more details (compared to the thesis) in [Suricata Detection Rules](suricata-detection-rules) and end with 

# Requirements
- `tshark`
- `awk`
- common utilities like `sed` and `sort`
- python
  - `scipy` and `scapy` pip modules
- unix shell eg., `zsh` or `bash` (via WSL on Windows)
- `JA4X` binary

# The Framework
Because this research primarily focuses on Operational Technology (OT) environments, we rely on passive fingerprinting to not disrupt operations of sensitive OT devices. We target three types of network traffic profiles: plaintext network protocols, VPN tunnels, and OPC UA.

## Plaintext Traffic
We leverage plaintext protocols to identify applications on the network via, DNS, HTTP, Transport Layer Security (TLS) handshakes, TLS Server Name Indication (SNI), TLS certificates, and broadcast messages such as mDNS. Other fingerprintable attributes include *magic bytes*, port numbers and proprietary broadcast addresses. For 

# Network Packet Extraction Scripts


# Suricata Detection Rules


# Acknowledgements

- **Rogue Server Attack:** In this work, we adapted and modified existing code created by [Alessandro Erba, Anne Müller and Nils Ole Tippenhauer](https://github.com/scy-phy/OPC-UA-attacks-POC)
- **JA4+**

# LICENSING
ONLY JA4 OF THE JA4+ FINGERPRINTING SUITE IS PERMITTED FOR COMMERCIAL USE. IT IS NOT PERMISSIVE FOR MONETIZATION, BUT ALLOWS ACADEMIC RESEARCH. ANY USER LOOKING TO USE A TECHNIQUE SUCH AS JA4X MUST RECEIVE PERMISSION FROM FOXIO LLC. SEE [JA4+ LICENSING](https://github.com/FoxIO-LLC/ja4#licensing) FOR MORE INFORMATION.
