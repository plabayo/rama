"""Run one Apple preview check, then discard its completed build products."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = Path("ffi/apple/examples/transparent_proxy")
OUTPUTS = {
    "example": [EXAMPLE / "tproxy_rs/target", EXAMPLE / ".xcode-derived"],
    "ffi": [EXAMPLE / "tproxy_ffi_e2e/target", Path(".build")],
    "crates": [Path("target")],
    "release": [Path(".build")],
    "egress": [EXAMPLE / "tproxy_rs/target"],
    "xpc": [Path("target")],
}


def execute(phase, command):
    if os.environ.get("GITHUB_ACTIONS") != "true" or Path(os.environ.get("GITHUB_WORKSPACE", "")).resolve() != ROOT:
        raise RuntimeError("Build cleanup is restricted to the GitHub Actions checkout")
    outputs = [ROOT / path for path in OUTPUTS[phase]]
    if phase == "egress":
        temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
        outputs += [temporary / ("egress-policy-build-" + mode) for mode in ("asan", "tsan")]
    print(f"{phase}: {shutil.disk_usage(ROOT).free / 2**30:.1f} GiB free before check", flush=True)
    try:
        return subprocess.run(command, cwd=ROOT).returncode
    finally:
        for path in outputs:
            # Never traverse a generated-output symlink into unrelated files.
            if path.resolve() != path:
                raise RuntimeError(f"Refusing cleanup through symlink: {path}")
            if path.exists():
                print(f"Removing completed build products: {path}", flush=True)
                shutil.rmtree(path)
        print(f"{phase}: {shutil.disk_usage(ROOT).free / 2**30:.1f} GiB free after cleanup", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=OUTPUTS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command:
        parser.error("a check command is required")
    return execute(args.phase, args.command)


if __name__ == "__main__":
    raise SystemExit(main())
