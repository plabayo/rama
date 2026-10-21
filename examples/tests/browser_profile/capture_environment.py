"""Admit Linux loopback packet evidence before starting expensive fixtures.

Linux UDP GSO can appear in AF_PACKET captures as one oversized datagram before
segmentation. QUIC short headers have no packet length: tshark cannot recover
those boundaries and reports decryption failures, missing streams or headers.
The application can still work perfectly. Never repair this by weakening an
oracle or disabling GSO in Rama's production transport.
"""

import argparse
import json
import platform
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys

from fixture_process import running, wait_ready

FEATURE = "tx-udp-segmentation"
REPORT = "capture-environment.json"
UDP_SEGMENT = 103  # Linux uapi linux/udp.h.


def udp_segmentation(text):
    matches = re.findall(r"^tx-udp-segmentation: (on|off)(?: \[fixed\])?$", text, re.M)
    if len(matches) != 1:
        raise RuntimeError("cannot establish tx-udp-segmentation state from ethtool")
    return matches[0]


def offload_state(interface):
    return udp_segmentation(subprocess.check_output(
        ["ethtool", "-k", interface], text=True, timeout=10,
        stderr=subprocess.PIPE,
    ))


class PacketBoundaryError(RuntimeError):
    def __init__(self, lengths):
        self.lengths = lengths[:16]
        self.count = len(lengths)
        super().__init__(
            "segmented UDP capture probe did not preserve three datagrams; "
            f"observed UDP lengths={self.lengths} (count={self.count})"
        )


def check_lengths(lengths):
    # Three original datagrams, not one GSO super-packet or a partial capture.
    if lengths != [1208, 1208, 1208]:
        raise PacketBoundaryError(lengths)


def segmented_probe(interface, root):
    """Compare real received datagrams with the capture of one UDP_SEGMENT send.

    Constants are Linux uapi SOL_UDP / UDP_SEGMENT. Payload is synthetic, carries
    no credentials, and is never sent outside loopback. Delete the probe pcap on
    every exit; only lengths and counts belong in the persistent report.
    """
    capture = root / "capture-probe.pcapng"
    log = root / "capture-probe.log"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(3)
            sender.bind(("127.0.0.1", 0))
            source, destination = sender.getsockname()[1], receiver.getsockname()[1]
            command = ["dumpcap", "-i", interface, "-a", "duration:2",
                       "-f", f"udp src port {source} and dst port {destination}",
                       "-w", str(capture)]
            with running(command, log) as process:
                wait_ready(process, log, lambda text: "File:" in text, timeout=5)
                payload = b"R" * 1200  # Synthetic payload; no application traffic.
                sender.sendmsg([payload * 3], [(socket.IPPROTO_UDP, UDP_SEGMENT, struct.pack("=H", 1200))],
                               0, receiver.getsockname())
                for _ in range(3):
                    data, peer = receiver.recvfrom(4096)
                    if data != payload or peer != sender.getsockname():
                        raise RuntimeError("segmented UDP receiver mismatch")
                if process.wait(timeout=6) != 0:
                    raise RuntimeError("segmented UDP probe capture failed")
            rows = subprocess.check_output(
                ["tshark", "-r", str(capture), "-Y",
                 f"udp.srcport == {source} && udp.dstport == {destination}",
                 "-T", "fields", "-e", "udp.length"],
                text=True, stderr=subprocess.PIPE, timeout=10,
            )
            lengths = [int(row) for row in rows.splitlines()]
            check_lengths(lengths)
            return dict(received_datagrams=3, captured_udp_lengths=lengths)
    finally:
        capture.unlink(missing_ok=True)


def require_capture_environment(interface, root):
    """Read-only preflight: never silently change the user's interface settings."""
    report = dict(platform=sys.platform, kernel=platform.release(),
                  interface=interface, status="checking", stage="offload")
    try:
        if sys.platform != "linux":
            report.update(status="not_applicable", reason="Linux UDP GSO probe")
            return
        # These fixtures bind to 127.0.0.1; probing a different interface cannot
        # establish evidence for their connections.
        if interface != "lo":
            raise RuntimeError("Linux loopback fixtures require --interface lo")
        state = offload_state(interface)
        report[FEATURE] = state
        if state != "off":
            raise RuntimeError(
                "Linux loopback capture requires tx-udp-segmentation off; "
                "UDP GSO hides QUIC datagram boundaries from tshark. "
                "On an isolated test interface run: sudo ethtool -K lo "
                "tx-udp-segmentation off; restore the original state afterward."
            )
        report["stage"] = "segmented_udp_probe"
        report["probe"] = segmented_probe(interface, root)
        report.update(status="passed", stage="complete")
    except Exception as error:
        # Keep subprocess output and packet/header values out of uploadable JSON.
        report.update(status="failed", error_type=type(error).__name__)
        if isinstance(error, PacketBoundaryError):
            report["probe"] = dict(captured_udp_lengths=error.lengths,
                                   captured_datagrams=error.count)
        if isinstance(error, (FileNotFoundError, subprocess.SubprocessError)):
            raise RuntimeError(
                "capture preflight could not run ethtool/dumpcap/tshark; "
                "install packet tools and check capture permissions"
            ) from error
        raise
    finally:
        (root / REPORT).write_text(json.dumps(report, indent=2) + "\n")


def configure_ci(mode, state_path):
    """Explicit CI-only mutation, with saved original state and verified restore.

    The regular runners never call this. Hosted jobs own their loopback device;
    their always() cleanup calls restore even if preparation or capture failed.
    """
    if mode == "prepare-ci":
        original = offload_state("lo")
        # Never overwrite the state needed to undo an earlier preparation.
        with state_path.open("x") as output:
            output.write(original + "\n")
        target = "off"
    else:
        if not state_path.exists():
            return
        target = state_path.read_text().strip()
        if target not in ("on", "off"):
            raise RuntimeError("invalid saved UDP offload state")
    if offload_state("lo") != target:
        subprocess.run(["sudo", "ethtool", "-K", "lo", FEATURE, target],
                       check=True, timeout=10)
    if offload_state("lo") != target:
        raise RuntimeError("UDP offload setting did not take effect")
    if mode == "restore-ci":
        state_path.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare-ci", "restore-ci", "check"))
    parser.add_argument("state", type=Path)
    args = parser.parse_args()
    if args.mode == "check":
        args.state.mkdir(mode=0o700)
        require_capture_environment("lo", args.state)
    else:
        configure_ci(args.mode, args.state)
