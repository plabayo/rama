"""Recompute reviewable reports from the checked-in decoded relay captures."""

import json
from pathlib import Path

from comparison import compare_legs


def main():
    fixtures = Path(__file__).parent / "tests/fixtures"
    captures = json.loads((fixtures / "http-contract-captures.json").read_text())
    for label, capture in captures.items():
        report = compare_legs(
            (fixtures / f"{label}-ingress.pdml").read_bytes(),
            (fixtures / f"{label}-egress.pdml").read_bytes(),
            capture["protocol"],
            capture["ports"]["ingress"],
            capture["ports"]["egress"],
            b"external-relay-body",
            quic_version=capture["quic_version"],
        )
        destination = fixtures / f"{label}-expected.json"
        encoded = json.dumps(report, indent=2) + "\n"
        if not destination.exists() or json.loads(destination.read_text()) != json.loads(encoded):
            destination.write_text(encoded)
        print(label)


if __name__ == "__main__":
    main()
