"""Independent evidence for the pinned runner's preferred-address limitations.

Raw upstream failures remain failures in its JSON. This checker distinguishes a
verified migration rejected by its first-packet rule from a peer that never tried
the advertised address. Neither is an upstream test success.
"""
import hashlib
import ipaddress
from pathlib import Path
import re
import subprocess

from check_results import InvalidResults

FIELDS = [
    "frame.number", "ip.src", "ipv6.src", "udp.srcport", "ip.dst", "ipv6.dst", "udp.dstport",
    "quic.dcid", "quic.path_challenge.data", "quic.path_response.data", "quic.frame_type",
    "tls.quic.parameter.preferred_address.ipv4address",
    "tls.quic.parameter.preferred_address.ipv4port",
    "tls.quic.parameter.preferred_address.ipv6address",
    "tls.quic.parameter.preferred_address.ipv6port",
    "tls.quic.parameter.preferred_address.connectionid",
]
PREFERRED = {("193.167.100.100", 4433), ("fd00:cafe:cafe:100::100", 4433)}


def require(condition, message):
    if not condition:
        raise InvalidResults(f"preferred-address evidence: {message}")


def values(value):
    return tuple(part for part in value.split(",") if part)


def read_packets(capture, keys):
    command = ["tshark", "-r", str(capture), "-o", f"tls.keylog_file:{keys}",
               "-Y", "quic", "-T", "fields", "-E", "occurrence=a"]
    for field in FIELDS:
        command += ["-e", field]
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    packets = []
    for line in result.stdout.splitlines():
        row = line.split("\t")
        require(len(row) == len(FIELDS), "unexpected tshark field count")
        def address(v4, v6, port):
            return str(ipaddress.ip_address(row[v4] or row[v6])), int(row[port])
        packets.append({
            "number": int(row[0]), "src": address(1, 2, 3), "dst": address(4, 5, 6),
            "dcids": values(row[7]), "challenges": values(row[8]), "responses": values(row[9]),
            "frames": tuple(int(value, 0) for value in values(row[10])),
            "preferred": tuple((str(ipaddress.ip_address(row[ip])), int(row[port]))
                               for ip, port in ((11, 12), (13, 14)) if row[ip] and row[port]),
            "preferred_cids": values(row[15]),
        })
    require(bool(packets), "empty or undecodable capture")
    return packets


def has_stream(packet):
    return any(0x08 <= frame <= 0x0f for frame in packet["frames"])


def verify_packets(client_trace, server_trace, *, peer_did_not_exercise=False):
    """Use both capture points; never infer peer behavior from a console message."""
    advertised = set()
    preferred_cids = set()
    for packet in client_trace:
        if packet["src"][1] == 443:
            advertised.update(packet["preferred"])
            preferred_cids.update(packet["preferred_cids"])
    require(advertised == PREFERRED, "both expected preferred endpoints must be advertised")
    require(len(preferred_cids) == 1 and bool(next(iter(preferred_cids))), "missing/ambiguous preferred CID")
    preferred_cid = next(iter(preferred_cids))
    new_client = [p for p in client_trace if p["dst"] in advertised]
    new_server = [p for p in server_trace if p["src"] in advertised]
    if peer_did_not_exercise:
        require(not new_client and not new_server, "peer did try the preferred path")
        require(not any(p["dst"] in advertised or p["src"] in advertised for p in client_trace + server_trace),
                "unexpected preferred-path packet")
        return {"classification": "peer-did-not-exercise", "advertised": sorted(advertised),
                "preferred_cid": preferred_cid, "preferred_path_packets": 0}

    require(bool(new_client) and bool(new_server), "migration did not use the preferred path")
    first = new_client[0]
    original = [p for p in client_trace if p["number"] < first["number"] and p["dst"][1] == 443]
    require(bool(original), "missing original client path")
    require(first["dcids"] == (preferred_cid,), "first probe did not use the advertised preferred CID")
    require(preferred_cid not in original[-1]["dcids"], "migration reused the original DCID")
    require(bool(first["challenges"]) and not has_stream(first), "first client packet must validate the preferred path")
    require(not new_server[0]["challenges"] and bool(new_server[0]["responses"]),
            "first server packet does not match the known checker ordering limitation")
    matching = [p for p in client_trace if p["src"] == first["dst"] and p["dst"] == first["src"]
                and set(p["responses"]) & set(first["challenges"])]
    require(bool(matching), "server did not answer the client's preferred-address probe")
    validated_at = matching[0]["number"]
    require(validated_at > first["number"], "invalid response ordering")
    require(not any(has_stream(p) and p["number"] < validated_at for p in new_client),
            "client sent streams on the preferred path before validation")
    require(any(p["number"] > validated_at for p in new_client), "client did not migrate after validation")
    require(any(p["src"] == first["dst"] and p["number"] > validated_at and has_stream(p)
                for p in client_trace), "no server stream traffic after validation")

    challenges = [(p["src"], p["dst"], token) for p in server_trace if p["src"][1] in (443, 4433)
                  for token in p["challenges"]]
    require(any(src == first["dst"] for src, _, _ in challenges), "server did not validate the new path")
    answered = {(p["dst"], p["src"], token) for p in client_trace for token in p["responses"]}
    require(set(challenges) <= answered, "server PATH_CHALLENGE without a matching path-specific response")
    return {"classification": "checker-incompatible", "advertised": sorted(advertised),
            "preferred_cid": preferred_cid, "server_challenges_answered": len(set(challenges)),
            "client_preferred_packets": len(new_client), "server_preferred_packets": len(new_server)}


def verify_files(directory):
    source = directory / "server_www"
    downloaded = directory / "client_downloads"
    originals = sorted(path for path in source.iterdir() if path.is_file())
    copies = sorted(path for path in downloaded.iterdir() if path.is_file())
    require(len(originals) == len(copies) == 1, "expected one transferred file")
    require(originals[0].name == copies[0].name, "downloaded filename differs")
    require(originals[0].stat().st_size == 2 * 1024 * 1024, "incorrect migration workload size")
    digests = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (originals[0], copies[0])]
    require(digests[0] == digests[1], "downloaded bytes differ")
    return {"file": originals[0].name, "sha256": digests[0], "bytes": originals[0].stat().st_size}


def verify_migration(artifacts, role, peer, exits):
    require((role, peer) in {("client", "ngtcp2"), ("server", "ngtcp2"), ("server", "quic-go")},
            "pair has no declared runner limitation")
    require(exits.get("client_exit") == 0 and exits.get("server_exit") in (0, 137, 143),
            "client failed or server exited unexpectedly")
    pair = f"{peer}_rama" if role == "client" else f"rama_{peer}"
    directory = Path(artifacts) / f"logs-rama-{role}" / pair / "connectionmigration"
    console = (directory / "output.txt").read_text()
    peer_did_not_exercise = (role, peer) == ("server", "quic-go")
    expected = ("Server saw only a single path in use; test broken?" if peer_did_not_exercise
                else "did not contain a PATH_CHALLENGE frame")
    require(expected in console, "upstream did not report the expected limitation")
    keys = directory / role / "keys.log"
    require(bool(keys.read_text().strip()), "missing TLS keys")
    result = verify_packets(read_packets(directory / "sim/trace_node_left.pcap", keys),
                            read_packets(directory / "sim/trace_node_right.pcap", keys),
                            peer_did_not_exercise=peer_did_not_exercise)
    result.update(verify_files(directory))
    result.update(role=role, peer=peer, case="connectionmigration", upstream_result="failed")
    return result
