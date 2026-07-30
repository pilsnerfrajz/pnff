import sys


def parse_fp(fp):
    if not fp.startswith("ua"):
        return []

    segments = fp.split("_")
    result = []

    # Append message type
    result.append(fp[2])

    for segment in segments:
        try:
            num = int(segment)
        except ValueError:
            continue
        bytes_val = num.to_bytes(4, byteorder="little")
        hex_str = " ".join(f"{byte:02x}" for byte in bytes_val)
        result.append(f"{hex_str}")
    return result


def to_rule(byte_strs, next_sid):
    if len(byte_strs) != 5:
        return "Invalid byte strings. Expected 5 elements."

    rule_name = input("Enter rule name: ")
    alert = f'alert tcp any any -> any any (msg:"{rule_name}"; '
    type = (
        f"content: {'"HEL"' if byte_strs[0] == 'h' else '"ACK"'}; offset: 0; depth: 3; "
    )

    sid = f"sid: {next_sid}; rev:1;)"
    combined_hex = " ".join(byte_strs[1:5])
    match = f'content: "|{combined_hex}|"; offset: 12; depth: 16; '
    return alert + type + match + sid


if __name__ == "__main__":
    if len(sys.argv) == 4:
        out = sys.argv[1]
        sid = sys.argv[2]
        fp = sys.argv[3]
    else:
        print(f"Usage: python3 {sys.argv[0]} output_file sid ua_fp")
        sys.exit(1)

    s = parse_fp(fp)
    with open(out, "a") as f:
        f.write(to_rule(s, sid))
        f.write("\n")