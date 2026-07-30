#!/bin/bash
if [ $# -ne 1 ]; then
    echo "Usage: $0 pcap_file"
    exit 1
fi

# Define AWK functions in-file as bash variables and pass them to the AWK environment
ENTROPY='
function entropy(payload,   counts, byte, ent, bytes, p, i, b)
{
    delete counts
    ent = 0
    bytes = length(payload) / 2
    for(i = 1; i <= length(payload); i += 2)
    {
        byte = substr(payload, i, 2)
        counts[byte]++
    }
    for (b in counts)
    {
        p = counts[b] / bytes
        ent -= p * (log(p) / log(2))
    }
    return ent
}
'

OPENVPN='
function openvpn_logic(frame, type, src, dst, payload_len, proto,     p,
    flow_forward, flow_reverse)
{
    if (proto == "6") p = "TCP"
    else if (proto == "17") p = "UDP"
    else p = "OTHER"

    if (type == "38") type_str = "Initiation"
    else if (type == "40") type_str = "Response"
    else type_str = "Unknown"

    # Create flow keys
    flow_forward = src "-" dst
    flow_reverse = dst "-" src

    # Memorize if type starts with 3
    if (type ~ /^3[0-9a-fA-F]$/) {
        valid_flows[flow_forward] = 1
        valid_flows[flow_reverse] = 1
    }

    if (valid_flows[flow_forward] == 1) {
        printf "Frame: %-8s | Type: 0x%-2s | Payload Length: %-4s | Transport: %-3s | %s\n", frame, type, payload_len-8, p, type_str
    }

    # Reset flow state
    if (type ~ /^4[0-9a-fA-F]$/) {
        valid_flows[flow_forward] = 0
        valid_flows[flow_reverse] = 0
    }
}
'

# https://hexcalculator.org/hex-to-decimal-in-awk/
HEX2DEC='
function hex2dec(h,   i, d, n, c) {
    n = 0
    for (i = 1; i <= length(h); i++) {
        c = substr(h, i, 1)
        if (c ~ /[0-9]/) d = c
        else d = index("ABCDEF", toupper(c)) + 9
        n = n * 16 + d
    }
    return n
}
'

echo -e "\n--- WireGuard (UDP) Handshakes ---\n"
tshark -r "$1" -Y "wg.type == 1 || wg.type == 2" -Tfields -e frame.number -e wg.type -e wg.reserved -e wg.mac2 -e udp.length -e udp.payload |
     awk "$ENTROPY"'{
        if ($2 == 1) type_str = "Initiation"
        else if ($2 == 2) type_str = "Response"
        else type_str = "Unknown"
        printf "Frame: %-8s| Type: 0x%02x | Reserved: %-6s | MAC2: %-16s | Length: %-4s | Entropy: %-7.4f | %s\n", $1, $2, $3, $4, $5-8, entropy($6), type_str
    }'

echo -e "\n--- WireGuard (TCP) Handshakes ---\n"
tshark -r "$1" -Y "tcp.len == 150 || tcp.len == 94" -Tfields -e frame.number -e tcp.payload -e tcp.len |
    awk "$ENTROPY"'{
        tcp_bytes = substr($2, 0, 2)
        rsvrd = substr($2, 7, 6)
        type = substr($2, 5, 2)

        if (type == "01") {
            mac2 = substr($2, 269, 32)
            type_str = "Initiation"
        } else if (type == "02") {
            mac2 = substr($2, 157, 32)
            type_str = "Response"
        } else {
            mac2 = "N/A"
            type_str = "Unknown"
        }

        printf "Frame: %-8s| Type: 0x%02x | Reserved: %-6s | MAC2: %-16s | Length: %-4s | Entropy: %-7.4f | %s\n", $1, type, rsvrd, mac2, $3, entropy(substr($2, 5)), type_str
    }'

echo -e "\n--- WireGuard LWO Obuscation ---\n"
tshark -r "$1" -Y "!(quic || openvpn) &&  (udp.length == 156 || udp.length == 100) && udp.payload[1] & 0x80 == 0x80" -Tfields -e frame.number -e udp.length -e udp.payload |
    awk "$ENTROPY"'{
        printf "Frame: %-8s | Length: %-5s | Entropy: %-7.4f | %s\n", $1, $2-8, entropy($3), "LWO Bit Set"
    }'

echo -e "\n--- WireGuard Shadowsocks 2017 Obfuscation ---\n"
tshark -r "$1" -Y "!(quic || openvpn) && (udp.length == 211 || udp.length == 155)" -Tfields -e frame.number -e udp.length -e udp.payload |
    awk "$ENTROPY"'{
        printf "Frame: %-8s | Length: %-5s | Entropy: %-7.4f | %s\n", $1, $2-8, entropy($3), "chacha20-ietf-poly1305 or aes-256-gcm"
    }'
tshark -r "$1" -Y "!(quic || openvpn) &&  (udp.length == 195 || udp.length == 139)" -Tfields -e frame.number -e udp.length -e udp.payload |
    awk "$ENTROPY"'{
        printf "Frame: %-8s | Length: %-5s | Entropy: %-7.4f | %s\n", $1, $2-8, entropy($3), "aes-128-gcm"
    }'

echo -e "\n--- OpenVPN Handshakes ---\n"
tshark -r "$1" -Y "(!(ip.dst == 224.0.0.0/4) &&(udp.length < 128 && udp.payload[0] & 0xf8 == 0x38) || (udp.payload[0] & 0xf8 == 0x40) || openvpn.opcode == 7 || openvpn.opcode == 8)" -Tfields -e frame.number -e udp.payload[0] -e ip.src -e ip.dst -e udp.length -e ip.proto |
    awk "$OPENVPN"'{openvpn_logic($1, $2, $3, $4, $5, $6)}'
tshark -r "$1" -Y "((tcp.len < 130 && tcp.payload[2] & 0xf8 == 0x38) || (tcp.payload[2] & 0xf8 == 0x40) || openvpn.opcode == 7 || openvpn.opcode == 8)" -Tfields -e frame.number -e tcp.payload[2] -e ip.src -e ip.dst -e tcp.len -e ip.proto |
    awk "$OPENVPN"'{openvpn_logic($1, $2, $3, $4, $5, $6)}'

echo -e "\n--- SOCKS Handshakes ---\n"
tshark -r "$1" -Y "(tcp.len > 2 && tcp.len <= 257 && tcp.payload[0] == 0x05 && tcp.payload[1] > 0) || (tcp.len == 2 && tcp.payload[0] == 0x05)" -Tfields -e frame.number -e tcp.len -e tcp.payload[0:2] -e tcp.payload[2:] |
    awk "$HEX2DEC"'{
        gsub(/:/, "", $3)
        ver = substr($3, 1, 2)

        if ($2 == 2) {
            choice = substr($3, 3, 2)
            printf "Frame: %-8s | Version: %-2s | Choice: %-2s | Length: %-3s | %s\n", $1, ver, choice, $2, "Server Choice"
        }
        else if ($2 > 2) {
            nauth = hex2dec(substr($3, 3, 2))
            gsub(/:/, "", $4)
            if (length($4)/2 == nauth)
                printf "Frame: %-8s | Version: %-2s | NAuth: %-3s | Length: %-3s | %s\n", $1, ver, nauth, $2, "Client Greeting"
        }
    }'

echo -e "\n--- IKE Initiation ---\n"
tshark -r "$1" -Y "isakmp" -Tfields -e frame.number -e isakmp.rspi -e isakmp.nextpayload -e isakmp.mjver -e isakmp.mnver -e isakmp.exchangetype -e isakmp.length -e udp.dstport |
    awk '{
        split($3, nxt_arr, ",")
        next_payload = nxt_arr[1]
        major_version = $4
        exchange_type = $6

        if (major_version == "0x02") {
            if (next_payload == 33 && exchange_type == 34) type_str = "IKEv2 SA Establishment"
            else if (next_payload == 53 && exchange_type == 35) type_str = "IKEv2 Fragmentation (Likely Certificate Exchange)"
            else if (next_payload == 46 && exchange_type == 35) type_str = "IKEv2 Authentication"
            else type_str = "IKEv2 Other"
        }
        else if (major_version == "0x01") {
            if (next_payload == 1 && exchange_type == 2) type_str = "IKEv1 Phase 1 Main Mode"
            else if (next_payload == 1 && exchange_type == 4) type_str = "IKEv1 Phase 1 Aggressive Mode"
            else if (next_payload == 8 && exchange_type == 32) type_str = "IKEv1 Phase 2 Quick Mode"
            else if (next_payload == 8 && exchange_type == 4) type_str = "IKEv1 Phase 2 Aggressive Mode"
            else type_str = "IKEv1 Other"
        }
        else type_str = "Unknown Version"

        printf "Frame: %-8s | RSPI: %-16s | Next Payload: 0x%02x | Ver: %x.%x | Exchange Type: 0x%02x | Length: %-4s | UDP Dest Port: %-5s | %s\n", $1, $2, $3, $4, $5, $6, $7, $8, type_str
    }'

echo -e "\n--- ExpressVPN Ligthway UDP ---\n"
tshark -r "$1" -Y "udp.payload[0:2] == 48:65 && udp.payload[6:2] == 00:00 && udp.payload[16:1] == 0x16 && udp.payload[29:1] == 0x01" -Tfields -e frame.number -e udp.payload -e ip.src -e ip.dst -e udp.length |
    awk "$HEX2DEC"'{
        H = sprintf("%c", hex2dec(substr($2, 1, 2)))
        e = sprintf("%c", hex2dec(substr($2, 3, 2)))
        mjver = substr($2, 5, 2)
        mnver = substr($2, 7, 2)
        rsrvd = substr($2, 13, 2)
        session_id = substr($2, 17, 16)
        dtls_type = substr($2, 33, 2)
        dtls_mjver = substr($2, 35, 2)
        dtls_mnver = substr($2, 37, 2)

        if (H == "H" && e == "e" && match(session_id, /^(0+)$/)) {
            dtls_hex = substr($2, 33)

            cmd = "echo -n " dtls_hex " | xxd -r -p | od -Ax -tx1 -v | text2pcap -q -u 1234,1234 - - 2>/dev/null | tshark -r - -Tfields -e dtls.handshake.ja4"

            # Run command and save output to ja4 variable
            cmd | getline ja4
            close(cmd)

            if (ja4 != "") {
                printf "Frame: %-8s | Magic: %c%c | Lightway ver: %s.%s | Reserved: %s | Session ID: %s | DTLS Type: %s | DTLS ver: %s%s | Length: %-4s | JA4: %s | %s\n", $1, H, e, hex2dec(mjver), hex2dec(mnver), rsrvd, session_id, dtls_type, dtls_mjver, dtls_mnver, $5, ja4, "ExpressVPN Lightway"
            }
        }
    }'

echo -e "\n--- Web-based VPNs (TLS/QUIC JA4, SNI, ALPN) ---\n"
tshark -r "$1" -Y "tls.handshake.ja4" -Tfields -e tls.handshake.ja4 -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str |
    sort -u

echo -e "\n--- Web-based VPNs (TLS Certificate Domains) ---\n"
tshark -r "$1" -Y "tls.handshake.certificate" -Tfields -e x509ce.dNSName |
    tr ',' '\n' |
    sed 's/^[[:space:]]*//;s/[[:space:]]*$//' |
    grep -v '^$' |
    sort -u
