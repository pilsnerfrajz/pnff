import collections
import sys
from pathlib import Path

from scapy.all import IP, UDP, rdpcap
from scipy.stats import entropy

usage = f"""Usage: python3 {Path(sys.argv[0]).name} folder_path isize rsize

Arguments:
  folder_path : The folder containing the pcap files to analyze
  isize       : The size of the initial handshake packet (e.g., 148 or 203 bytes)
  rsize       : The size of the response handshake packet (e.g., 92 or 147 bytes)"""


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
        return

    print(
        f"{'Frame':<8} | {'Source':<15} -> {'Dest':<15} | {'Size':<5} | {'Entropy':<8} | {'Status'}"
    )
    print("-" * 80)

    # Variables for average calculations
    stats = {
        "handshakes": 0,
        "init_ent_sum": 0.0,
        "resp_ent_sum": 0.0,
        "min_init_ent": float("inf"),
        "max_init_ent": float("-inf"),
        "min_resp_ent": float("inf"),
        "max_resp_ent": float("-inf"),
    }

    # Dictionary to track the last seen packet per flow (Source -> Dest)
    pending_handshakes = {}

    frame = 0
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
                print(
                    f"{frame:<8} | {ip_src:<15} -> {ip_dst:<15} | {size:<5} | {init_entropy:<8.4f} | [1/2] Initiation"
                )

            # STEP 2: Look for Response (resp_size bytes)
            elif size == resp_size:
                # Check if we saw a handshake packet in the reverse direction recently
                if reverse_flow in pending_handshakes:
                    resp_entropy = shannon_entropy(payload)
                    print(
                        f"{frame:<8} | {ip_src:<15} -> {ip_dst:<15} | {size:<5} | {resp_entropy:<8.4f} | [2/2] HANDSHAKE COMPLETE\n"
                    )

                    stats["handshakes"] += 1
                    stats["init_ent_sum"] += pending_handshakes[reverse_flow]["entropy"]
                    stats["resp_ent_sum"] += resp_entropy
                    if (
                        pending_handshakes[reverse_flow]["entropy"]
                        < stats["min_init_ent"]
                    ):
                        stats["min_init_ent"] = pending_handshakes[reverse_flow][
                            "entropy"
                        ]
                    if (
                        pending_handshakes[reverse_flow]["entropy"]
                        > stats["max_init_ent"]
                    ):
                        stats["max_init_ent"] = pending_handshakes[reverse_flow][
                            "entropy"
                        ]
                    if resp_entropy < stats["min_resp_ent"]:
                        stats["min_resp_ent"] = resp_entropy
                    if resp_entropy > stats["max_resp_ent"]:
                        stats["max_resp_ent"] = resp_entropy

                    # Clear the state so we don't double-count
                    del pending_handshakes[reverse_flow]

    if stats["handshakes"] > 0:
        init_avg = stats["init_ent_sum"] / stats["handshakes"]
        resp_avg = stats["resp_ent_sum"] / stats["handshakes"]
        print(
            f"\nInitiation    Min/Max/Avg Entropy: {stats['min_init_ent']:.4f}/{stats['max_init_ent']:.4f}/{init_avg:.4f}"
        )
        print(
            f"Response      Min/Max/Avg Entropy: {stats['min_resp_ent']:.4f}/{stats['max_resp_ent']:.4f}/{resp_avg:.4f}"
        )
        print("-" * 60)


def analyze_file(file_name, init_size, resp_size, target_folder):
    clean_name = file_name.relative_to(target_folder)
    print(f"\nAnalyzing file: {clean_name}")
    calc_handshake_entropy(str(file_name.absolute()), int(init_size), int(resp_size))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(usage)
        sys.exit(1)

    path_arg = sys.argv[1].lstrip("/")
    path = Path(path_arg).resolve()

    if path.is_file():
        target_folder = path.parent
        analyze_file(path, int(sys.argv[2]), int(sys.argv[3]), target_folder)
    elif path.is_dir():
        target_folder = path
        print(f"Scanning absolute path: {target_folder}")

        if not target_folder.exists():
            print(f"ERROR: The folder {target_folder} does not exist!")
            sys.exit(1)

        for file_path in target_folder.rglob("*"):
            if file_path.is_file():
                analyze_file(
                    file_path, int(sys.argv[2]), int(sys.argv[3]), target_folder
                )
