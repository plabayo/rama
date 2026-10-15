#!/usr/bin/env python3
"""Compile both trait settings and inspect production objects for private API references."""
import argparse
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[5]
SYMBOL = b"nw_parameters_set_no_proxy"


def production_objects(scratch):
    objects = []
    for path in scratch.rglob("*.o"):
        parts = path.relative_to(scratch).parts
        targets = [part for part in parts[:-1] if part.endswith(".build")]
        if (targets and targets[-1] == "RamaAppleNetworkExtension.build"
                and any(part.lower() == "release" for part in parts[:-1])):
            objects.append(path)
    return objects


def check(output):
    for enabled in (False, True):
        scratch = output / ("private" if enabled else "public")
        command = ["swift", "build", "--package-path", str(ROOT), "--scratch-path", str(scratch),
                   "--configuration", "release", "--target", "RamaAppleNetworkExtension"]
        if enabled:
            command += ["--traits", "PrivateNetworkProxyControl"]
        subprocess.run(command, check=True)
        objects = production_objects(scratch)
        if not objects:
            raise RuntimeError("No production objects found")
        found = any(SYMBOL in path.read_bytes() for path in objects)
        if found != enabled:
            raise RuntimeError(f"Private symbol presence={found}, trait enabled={enabled}")
        print(f"PrivateNetworkProxyControl={enabled}: production objects verified", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.output:
        check(args.output)
    else:
        with tempfile.TemporaryDirectory(prefix="rama-private-api-trait-") as directory:
            check(Path(directory))


if __name__ == "__main__":
    main()
