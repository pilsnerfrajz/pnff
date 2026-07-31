import collections
import sys
from pathlib import Path

from scapy.all import IP, UDP, rdpcap
from scipy.stats import entropy

usage = f"""Usage: python3 {Path(sys.argv[0]).name} folder_path isize rsize

Arguments:
  folder_path : The folder containing the pcap files to analyze
  isize       : The size of the initial handshake packet (e.g., 148 or 203 bytes)
  rsize       : The size of the response handshake packet (e.g., 92 or 147 bytes)
  mode/output : The censorship mode. Output file will be <mode>_init.log and <mode>_resp.log"""

# Source: https://onestopdataanalysis.com/shannon-entropy/
def shannon_entropy(dna_sequence):
    bases = collections.Counter(list(dna_sequence))
    # define distribution
    dist = [x / sum(bases.values()) for x in bases.values()]

    # use scipy to calculate entropy
    return entropy(dist, base=2)


def calc_handshake_entropy(file_path, init_size, resp_size):
    try:
        packets = rdpcap(file_path)
    except Exception as e:
        print(f"Error: {e}")
        return None, None

    # Dictionary to track the last seen packet per flow (Source -> Dest)
    pending_handshakes = {}

    frame = 0
    init_entropy = None

    for pkt in packets:
        frame += 1
        if pkt.haslayer(UDP) and pkt.haslayer(IP):
            ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
            payload = bytes(pkt[UDP].payload)
            size = len(payload)

            # Flow identifier (tracking bidirectional flow)
            flow_key = (ip_src, ip_dst, sport, dport)
            reverse_flow = (ip_dst, ip_src, dport, sport)

            # STEP 1: Look for Initiation (init_size bytes)
            if size == init_size:
                init_entropy = shannon_entropy(payload)
                pending_handshakes[flow_key] = {"entropy": init_entropy}

            # STEP 2: Look for Response (resp_size bytes)
            elif size == resp_size:
                # Check if we saw a handshake packet in the reverse direction recently
                if reverse_flow in pending_handshakes:
                    resp_entropy = shannon_entropy(payload)
                    return (init_entropy, resp_entropy)

    print("NO HANDSHAKE FOUND\n")
    return (None, None)

def analyze_file(file_name, init_size, resp_size, target_folder):
    clean_name = file_name.relative_to(target_folder)
    print(f"Analyzing file: {clean_name}")
    return calc_handshake_entropy(str(file_name.absolute()), int(init_size), int(resp_size))

def output_results(init_list, resp_list, output_file):
    with open(output_file + "_init.log", "a") as f:
        for val in sorted(init_list):
            if val is not None:
                f.write(f"{val:.4f}\n")
    with open(output_file + "_resp.log", "a") as f:
        for val in sorted(resp_list):
            if val is not None:
                f.write(f"{val:.4f}\n")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print(usage)
        sys.exit(1)

    path_arg = sys.argv[1].lstrip("/")
    path = Path(path_arg).resolve()
    init_list = []
    resp_list = []

    if path.is_file():
        target_folder = path.parent
        init_entropy, resp_entropy = analyze_file(path, int(sys.argv[2]), int(sys.argv[3]), target_folder)
        output_results(init_entropy, resp_entropy, sys.argv[4])
    elif path.is_dir():
        target_folder = path
        print(f"Scanning absolute path: {target_folder}")

        if not target_folder.exists():
            print(f"ERROR: The folder {target_folder} does not exist!")
            sys.exit(1)

        for file_path in target_folder.rglob("*"):
            if file_path.is_file():
                init_entropy, resp_entropy = analyze_file(
                    file_path, int(sys.argv[2]), int(sys.argv[3]), target_folder
                )
                if init_entropy is not None and resp_entropy is not None:
                    init_list.append(init_entropy)
                    resp_list.append(resp_entropy)
        output_results(init_list, resp_list, sys.argv[4])
