#!/usr/bin/env python3
"""Generate a private Rama ECH key file and print its public DNS ech value.

Requires OpenSSL 3 with X25519 support. Never overwrites an existing generation.
The private JSON belongs in a secret store, not in the repository or DNS.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import struct
import subprocess


def generate(openssl, public_name):
    name = public_name.encode("ascii")
    if not name or len(name) > 253 or any(
        not label or len(label) > 63 or label.startswith(b"-") or label.endswith(b"-")
        or any(byte not in b"abcdefghijklmnopqrstuvwxyz0123456789-" for byte in label)
        for label in name.split(b".")
    ):
        raise ValueError("public name must be a lowercase DNS hostname")
    private = subprocess.run(
        [openssl, "genpkey", "-algorithm", "X25519", "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    public = subprocess.run(
        [openssl, "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
        input=private, check=True, capture_output=True,
    ).stdout
    private_prefix = bytes.fromhex("302e020100300506032b656e04220420")
    public_prefix = bytes.fromhex("302a300506032b656e032100")
    if len(private) != len(private_prefix) + 32 or not private.startswith(private_prefix):
        raise ValueError("unexpected X25519 private key encoding")
    if len(public) != len(public_prefix) + 32 or not public.startswith(public_prefix):
        raise ValueError("unexpected X25519 public key encoding")
    contents = (
        struct.pack("!BHH", secrets.randbelow(256), 0x0020, 32) + public[-32:]
        + struct.pack("!HHHHH", 8, 1, 1, 1, 3)
        + bytes([64, len(name)]) + name + b"\x00\x00"
    )
    config = struct.pack("!HH", 0xfe0d, len(contents)) + contents
    encoded = lambda value: base64.b64encode(value).decode("ascii")
    keys = [{"config": encoded(config), "private_key": encoded(private[-32:]), "retry": True}]
    return keys, encoded(struct.pack("!H", len(config)) + config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--public-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    keys, public = generate(args.openssl, args.public_name)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(keys, stream)
        stream.write("\n")
    print(public)


if __name__ == "__main__":
    main()
