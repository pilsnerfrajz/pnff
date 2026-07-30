#!/bin/bash
if [ $# -ne 1 ]; then
    echo "Usage: $0 pcap_file"
    exit 1
fi

echo -e "\n--- mDNS ---\n"
tshark -r "$1" -Y "mdns" -Tfields -e dns.qry.name -e dns.resp.name |
    tr -s '[:blank:]' '\n' |
    tr ',' '\n' |
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
    grep -v '^$' |
    sort -u

echo -e "\n--- Multicast (non-mDNS) + Port ---\n"
tshark -r "$1" -Y "udp && !icmp && ip.dst == 224.0.0.0/4 && !mdns" -Tfields -e ip.src -e ip.dst -e udp.dstport |
    sort -u

echo -e "\n--- DNS ---\n"
tshark -r "$1" -Y "dns && !mdns" -Tfields -e dns.qry.name -e dns.resp.name |
    tr -s '[:blank:]' '\n' |
    tr ',' '\n' |
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
    grep -v '^$' |
    sort -u

echo -e "\n--- HTTP ---\n"
tshark -r "$1" -Y "http.request && http.host" -Tfields -e http.host -e http.request.uri -e http.user_agent |
    sort -u

echo -e "\n--- TLS JA4 SNI ---\n"
tshark -r "$1" -Y "tls.handshake.ja4" -Tfields -e tls.handshake.ja4 -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str |
    sort -u

echo -e "\n--- TLS Certificate Domains ---\n"
tshark -r "$1" -Y "tls.handshake.certificate" -Tfields -e x509ce.dNSName |
    tr ',' '\n' |
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
    grep -v '^$' |
    sort -u
