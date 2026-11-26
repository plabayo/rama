"""Select the daily browser and QUIC matrix entries requested by workflow_dispatch."""

import itertools
import json
import os


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
    quic = [
        {
            "name": f"test-quic-interop-qa-all-{toolchain}-{runner}",
            "os": runner,
            "toolchain": toolchain,
            "backends": "all",
        }
        for runner, toolchain in itertools.product(("macos-15", "windows-latest"), ("stable", "1.96.0"))
    ]
    return {
        "test-browser-profiles": browsers,
        "test-safari-desktop": safari,
        "test-quic-interop-qa": quic,
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
