"""Numeric, uploadable packet-decoder diagnostics; never serialize traffic values."""

import json

from pdml import pdml_packets, values

ISSUES = {
    "quic.decryption_failed": "decryption_failed",
    "quic.connection.unknown": "unknown_connection",
}


def decoding_health(data):
    packets = pdml_packets(data)
    counts = dict.fromkeys(ISSUES.values(), 0)
    samples = []
    quic_packets = http3_frames = 0
    for packet in packets:
        names = {node.get("name") for node in packet.iter("field")}
        quic_packets += any(node.get("name") == "quic" for node in packet.findall("proto"))
        http3_frames += sum(node.get("name") == "http3.frame" for node in packet.iter("field"))
        issues = [label for name, label in ISSUES.items() if name in names]
        for issue in issues:
            counts[issue] += 1
        if issues and len(samples) < 16:
            # Whitelist field names and coerce numeric values. Never include
            # expert messages, addresses, keys, headers or decrypted bytes.
            sample = {"issues": issues}
            for name, label in (("frame.number", "packet"), ("udp.length", "udp_lengths")):
                numeric = [int(value) for value in values(packet, name)
                           if value.isascii() and value.isdecimal() and len(value) <= 10]
                sample[label] = numeric[:4]
            samples.append(sample)
    return dict(packets=len(packets), quic_packets=quic_packets,
                http3_frames=http3_frames, issues=counts, samples=samples,
                no_reported_quic_errors=not any(counts.values()))


def require_quic_decoding(data, report_path):
    report = decoding_health(data)
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    if not report["no_reported_quic_errors"]:
        counts = ", ".join(f"{name}={count}" for name, count in report["issues"].items() if count)
        raise ValueError(
            f"undecodable QUIC packet evidence ({counts}); check UDP segmentation "
            "offload and TLS key logging before interpreting missing headers or "
            f"QPACK gaps; numeric diagnostics: {report_path.name}"
        )
