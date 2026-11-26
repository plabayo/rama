"""Select the daily matrix entries requested by workflow_dispatch."""

import itertools
import json
import os

# Scarce runners queue on repository-wide slots; rows that share one run in turn.
BASE_SUITES = {
    # OS: ((suite, slot, timeout minutes), ...)
    "macos-15": (
        ("all-features", "rama-macos-slot-2", 300),
        ("minimal", "rama-macos-slot-1", 180),
        ("crypto", "rama-macos-slot-6", 150),
    ),
    # The slowest host runs only the all-features suite; macos-15 covers the rest.
    "macos-15-intel": (("all-features", "rama-macos-slot-3", 360),),
    "windows-11-arm": (
        ("all-features", "rama-windows-slot-1", 300),
        ("minimal", "rama-windows-slot-3", 180),
        ("crypto", "rama-windows-slot-1", 150),
    ),
    "windows-latest": (
        ("all-features", "rama-windows-slot-5", 300),
        ("minimal", "rama-windows-slot-6", 180),
        ("crypto", "rama-windows-slot-7", 150),
    ),
    "ubuntu-24.04-arm": (("all-features", "", 240), ("minimal", "", 120), ("crypto", "", 90)),
    "ubuntu-latest": (("all-features", "", 240), ("minimal", "", 120), ("crypto", "", 90)),
}
QUIC_SLOTS = {
    # (runner, toolchain, backend): slot
    ("macos-15", "stable", "boring"): "rama-macos-slot-4",
    ("macos-15", "stable", "rustls-ring"): "rama-macos-slot-0",
    ("macos-15", "stable", "rustls-aws-lc"): "rama-macos-slot-0",
    ("macos-15", "1.96.0", "boring"): "rama-macos-slot-5",
    ("macos-15", "1.96.0", "rustls-ring"): "rama-macos-slot-11",
    ("macos-15", "1.96.0", "rustls-aws-lc"): "rama-macos-slot-11",
    ("windows-latest", "stable", "boring"): "rama-windows-slot-6",
    ("windows-latest", "stable", "rustls-ring"): "rama-windows-slot-7",
    ("windows-latest", "stable", "rustls-aws-lc"): "rama-windows-slot-3",
    ("windows-latest", "1.96.0", "boring"): "rama-windows-slot-2",
    ("windows-latest", "1.96.0", "rustls-ring"): "rama-windows-slot-3",
    ("windows-latest", "1.96.0", "rustls-aws-lc"): "rama-windows-slot-7",
}


def matrices():
    browsers = []
    for browser, protocol, mode in itertools.product(
        ("chrome", "firefox"), ("h1", "h2", "h3"), ("debug", "release")
    ):
        for transport in (("tls", "plaintext") if protocol == "h1" else ("tls",)):
            browsers.append({
                "name": f"browser-{browser}-{protocol}-{transport}-{mode}",
                "browser": browser,
                "protocol": protocol,
                "transport": transport,
                "mode": mode,
            })
    safari = [
        {"name": f"browser-safari-macos-{mode}", "mode": mode}
        for mode in ("debug", "release")
    ]
    base = [
        {
            "name": f"test-rust-base-{suite}-stable-{runner}",
            "os": runner,
            "toolchain": "stable",
            "suite": suite,
            "slim": runner == "macos-15-intel",
            "slot": slot,
            "timeout": timeout,
        }
        for runner, suites in BASE_SUITES.items()
        for suite, slot, timeout in suites
    ]
    # One backend per job: each is an isolated build, so a rerun repeats only its own.
    quic = [
        {
            "name": f"test-quic-interop-qa-{backend}-{toolchain}-{runner}",
            "os": runner,
            "toolchain": toolchain,
            "backends": backend,
            "slot": slot,
            "timeout": 180 if backend == "boring" else 120,
        }
        for (runner, toolchain, backend), slot in QUIC_SLOTS.items()
    ]
    relay = [
        {
            "name": f"native-relay-{label}-{mode}",
            "scenario": {"label": label, "protocol": protocol, "quic_version": quic_version},
            "mode": mode,
        }
        for label, protocol, quic_version in (
            ("h1", "h1", 1), ("h2", "h2", 1), ("h3-v1", "h3", 1), ("h3-v2", "h3", 2)
        )
        for mode in ("debug", "release")
    ]
    # 23: the last release without PKIXRevocationChecker; 34: a current one.
    android = [{"name": f"android-on-device-api-{api}", "api": api} for api in (23, 34)]
    return {
        "test-browser-profiles": browsers,
        "test-safari-desktop": safari,
        "test-rust-base": base,
        "test-quic-interop-qa": quic,
        "test-native-relay-contract": relay,
        "test-android-on-device": android,
    }


def select(only):
    requested = set(only.lower().split())
    if only and not requested:
        raise ValueError("expected a daily job name")
    owners = {}
    outputs = {}
    for job, rows in matrices().items():
        for row in rows:
            owners[row["name"]] = job
        selected = [
            row for row in rows
            if not requested or job in requested or row["name"] in requested
        ]
        outputs[job] = json.dumps(selected, separators=(",", ":"))
    # The result gate checks logical job IDs; each matrix job aggregates its selected entries.
    outputs["only"] = " ".join(sorted({owners.get(name, name) for name in requested}))
    return outputs


if __name__ == "__main__":
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as target:
        for key, value in select(os.environ["ONLY"]).items():
            print(f"{key}={value}", file=target)
