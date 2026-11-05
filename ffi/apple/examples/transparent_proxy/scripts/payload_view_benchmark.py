#!/usr/bin/env python3
"""Compare payload views in fresh Release XCTest processes on loopback.

The client NE flow is synthetic. This does not install a signed provider or
change system settings. The output directory must not already exist.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import subprocess
import time

ROOT = Path(__file__).resolve().parents[5]
TEST = "RamaAppleNetworkExtensionTests.PayloadViewBenchmarkTests/testPayloadViewTransferMatrix"
SCENARIOS = [
    "upload", "download", "concurrent_upload", "concurrent_download",
    "slow_upload", "slow_download",
]
SEED = 11052026


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--library-dir", type=Path)
    parser.add_argument("--skip-build", action="store_true",
                        help="use the already-built Release test bundle")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--pilot", action="store_true", help="four short smoke cases")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    root = args.root.resolve()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    library = (args.library_dir or root / (
        "ffi/apple/examples/transparent_proxy/tproxy_rs/target/debug")).resolve()
    if not args.skip_build:
        build = [
            "swift", "test", "--traits", "PrivateNetworkProxyControl", "-c", "release",
            "-Xswiftc", "-DRAMA_TESTING", "-Xlinker", "-L" + str(library),
            "-Xlinker", "-lrama_tproxy_example", "-Xlinker", "-lz",
            "-Xlinker", "-framework", "-Xlinker", "NetworkExtension",
            "-Xlinker", "-framework", "-Xlinker", "SystemConfiguration",
            "--filter", "WriterMemoryBudgetTests",
        ]
        with (output / "build.log").open("w") as log:
            subprocess.run(build, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    bundle = root / (
        ".build/arm64-apple-macosx/release/RamaAppleNetworkExtensionPackageTests.xctest")
    executable = bundle / "Contents/MacOS/RamaAppleNetworkExtensionPackageTests"
    source_paths = [
        "ffi/apple/RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension/Provider/NativeTcpConnection.swift",
        "ffi/apple/RamaAppleNetworkExtension/Sources/RamaAppleNetworkExtension/Provider/Pump/WriterMemoryBudget.swift",
        "ffi/apple/RamaAppleNetworkExtension/Tests/RamaAppleNetworkExtensionTests/PayloadViewBenchmarkTests.swift",
        "ffi/apple/RamaAppleNetworkExtension/Tests/RamaAppleNetworkExtensionTests/PromotedNativeUploadIntegrityTests.swift",
    ]
    metadata = {
        "platform": platform.platform(), "seed": SEED, "repeats": args.repeats,
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip(),
        "swift": subprocess.check_output(["swift", "--version"], text=True).strip(),
        "hardware": subprocess.check_output(
            ["sysctl", "-n", "machdep.cpu.brand_string", "hw.memsize", "hw.logicalcpu"],
            text=True).strip().splitlines(),
        "library_dir": str(library), "skip_build": args.skip_build,
        "binary_sha256": sha256(executable),
        "source_sha256": {path: sha256(root / path) for path in source_paths},
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rng = random.Random(SEED)
    failures = []
    with (output / "results.jsonl").open("w") as results:
        for repeat in range(args.repeats):
            cases = [(scenario, kib) for scenario in SCENARIOS for kib in [64, 128, 256]]
            rng.shuffle(cases)
            if args.pilot:
                cases = [("upload", 64), ("download", 256), ("slow_download", 128),
                         ("concurrent_upload", 256)]
            for scenario, kib in cases:
                name = f"{repeat}-{scenario}-{kib}"
                mib = 32 if "slow" in scenario else (512 if "concurrent" in scenario else 1024)
                env = os.environ | {
                    "RAMA_PVMB_BENCH": "1", "RAMA_PVMB_KIB": str(kib),
                    "RAMA_PVMB_BUDGET_MIB": "64",
                    "RAMA_PVMB_SCENARIO": scenario, "RAMA_PVMB_MIB": "4" if args.pilot else str(mib),
                }
                started = time.monotonic()
                try:
                    run = subprocess.run(
                        ["xcrun", "xctest", "-XCTest", TEST, str(bundle)], env=env,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
                except subprocess.TimeoutExpired as error:
                    captured = error.stdout or b""
                    if isinstance(captured, bytes):
                        captured = captured.decode(errors="replace")
                    (output / f"{name}.log").write_text(captured)
                    raise
                (output / f"{name}.log").write_text(run.stdout)
                rows = [json.loads(line.removeprefix("PVMB_RESULT "))
                        for line in run.stdout.splitlines() if line.startswith("PVMB_RESULT ")]
                if run.returncode or len(rows) != 1 or not rows[0]["verified"]:
                    print(run.stdout[-6000:], flush=True)
                    failure = {"case": name, "returncode": run.returncode,
                               "result_rows": len(rows)}
                    details = [json.loads(line.removeprefix("PVMB_FAILURE "))
                               for line in run.stdout.splitlines() if line.startswith("PVMB_FAILURE ")]
                    failure["details"] = details
                    failures.append(failure)
                    (output / "failures.json").write_text(json.dumps(failures, indent=2) + "\n")
                    print(f"FAILED {name}; preserving log and continuing the matrix", flush=True)
                    continue
                row = rows[0] | {"repeat": repeat, "process_wall_seconds": time.monotonic() - started}
                results.write(json.dumps(row, sort_keys=True) + "\n")
                results.flush()
                print(f'{name}: {row["mib_per_second"]:.1f} MiB/s, '
                      f'CPU {row["cpu_percent"]:.1f}%, '
                      f'RSS {row["rss_peak_bytes"]/1048576:.1f} MiB', flush=True)
            if args.pilot:
                break
    if failures:
        raise SystemExit(f"{len(failures)} benchmark cases failed; see failures.json")


if __name__ == "__main__":
    main()
