#!/bin/bash

function file_exist () {
    ls "$1" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        return 1
    fi
    return 0
}

if [ $# -ne 2 ] && [ $# -ne 3 ]; then
    echo "Usage: $0 pcap_file server_port [ja4x_path]"
    echo "Options:"
    echo "  pcap_file  : path to the input pcap file"
    echo "  server_port: TCP port number where the OPC UA server is listening (e.g., 4840)"
    echo "  ja4x_path  : local path to Rust binary available here: https://github.com/FoxIO-LLC/ja4/releases/tag/v0.14.0"
    exit 1
fi

pcap_file=$1
server_port=$2

file_exist $pcap_file || { echo "No such file or directory: $1"; exit 1; }

if [ $# = 2 ]; then
    file_exist "$(dirname "$0")/ja4x" || { echo "ja4x binary not found in $(cd "$(dirname "$0")" && pwd)"; exit 1; }
    ja4x_path="$(pwd)/$(dirname "$0")/ja4x"
else
    file_exist "$3" || { echo "No such ja4x file or directory: $3"; exit 1; }
    ja4x_path="$3"
fi

echo -e "--- OPC UA Hello Message (Client Fingerprint) ---\n"
tshark -r "$pcap_file" -d tcp.port==$server_port,opcua -Y "tcp.port == $server_port && opcua.transport.type == HEL" -Tfields -e opcua.transport.ver -e opcua.transport.rbs -e opcua.transport.sbs -e opcua.transport.mms -e opcua.transport.mcc |
    sort -u |
    sed -E 's/[[:space:]]+/_/g; s/^/uah/'

echo -e "\n--- OPC UA Acknowledge Message (Server Fingerprint) ---\n"
tshark -r "$pcap_file" -d tcp.port==$server_port,opcua -Y "tcp.port == $server_port && opcua.transport.type == ACK" -Tfields -e opcua.transport.ver -e opcua.transport.rbs -e opcua.transport.sbs -e opcua.transport.mms -e opcua.transport.mcc |
    sort -u |
    sed -E 's/[[:space:]]+/_/g; s/^/uaa/'

echo -e "\n--- OPC UA OpenSecureChannel (JA4X Certificate Fingerprints) ---\n"
tshark -r "$pcap_file" -d tcp.port==$server_port,opcua -Y "tcp.port == $server_port && opcua.security.scert" -Tfields -e tcp.srcport -e opcua.security.scert |
    awk -v server_port="$server_port" -v ja4x_bin="$ja4x_path" '{
        if ($1 == server_port) src = "Server"
        else src = "Client"
        cert = $2
        ja4x_output = ""

        # keep track of dupes
        if (seen[src, cert]++) next

        # call bash commands
        cmd = "echo \"" cert "\" | tr ',' '\n' | " \
              "sort -u | " \
              "while read -r cert; do " \
              "    if [ -z \"$cert\" ] || [ \"$cert\" = \"<MISSING>\" ]; then " \
              "        continue; " \
              "    fi; " \
              "    echo \"$cert\" | xxd -r -p | openssl x509 -inform der -outform pem -out /tmp/ja4xcert.x509 2>/dev/null; " \
              "   " ja4x_bin " /tmp/ja4xcert.x509 | grep -i \"ja4x:\"; " \
              "    rm -f /tmp/ja4xcert.x509; " \
              "done"
        cmd | getline ja4x_output
        close(cmd)

        if (ja4x_output != "") {
            printf "%s %s\n", src, ja4x_output
        }
    }'
