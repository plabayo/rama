#!/usr/bin/env python3
"""Run docs.rs-style documentation builds for publishable workspace crates.

The docs.rs-recommended ``cargo docs-rs`` command owns the build invocation.
It applies each package's ``package.metadata.docs.rs`` configuration, sets
``DOCS_RS``, configures rustc flags for both host and target dependencies, and
uses the same rustdoc mapping options as the docs.rs builder.

Modes:
  default        Override metadata targets with the current host target.
  --all-targets  Build every target declared in each package's docs.rs
                 metadata. Run this mode on the Linux docs.rs build host.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

TOOLCHAIN = os.environ.get("RUST_TOOLCHAIN_NIGHTLY", "nightly")


def cargo_metadata():
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def docsrs_meta(package):
    return ((package.get("metadata") or {}).get("docs") or {}).get("rs") or {}


def has_lib_target(package):
    return any(
        kind in ("lib", "proc-macro", "rlib", "dylib")
        for target in package["targets"]
        for kind in target["kind"]
    )


def host_triple():
    result = subprocess.run(
        ["rustc", f"+{TOOLCHAIN}", "-vV"],
        capture_output=True,
        text=True,
        check=True,
    )
    return next(
        line.split(" ", 1)[1]
        for line in result.stdout.splitlines()
        if line.startswith("host: ")
    )


def metadata_targets(package):
    metadata = docsrs_meta(package)
    targets = metadata.get("targets")
    default = metadata.get("default-target")

    if targets is None:
        targets = []
    if default and default not in targets:
        targets = [default, *targets]

    return [*targets, *(metadata.get("additional-targets") or [])]


def ensure_targets(packages, host):
    targets = {
        target
        for package in packages
        for target in metadata_targets(package)
        if target != host
    }
    if not targets:
        return
    subprocess.run(
        ["rustup", "target", "add", "--toolchain", TOOLCHAIN, *sorted(targets)],
        check=True,
    )


def docsrs_command(package, target_dir, native_target):
    command = [
        "cargo",
        f"+{TOOLCHAIN}",
        "docs-rs",
        "--package",
        package["name"],
        "--target-dir",
        target_dir,
        "--color",
        "always",
    ]
    if native_target:
        command.extend(["--target", native_target])
    return command


def run_package(package, target_dir, native_target):
    command = docsrs_command(package, target_dir, native_target)
    target_label = native_target or "metadata targets"
    print(f"==> {package['name']} [{target_label}]", flush=True)
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"PASS: {package['name']}", flush=True)
        return True

    output = "\n".join((result.stdout + result.stderr).splitlines()[-100:])
    print(f"FAIL: {package['name']}\n{output}\n", flush=True)
    return False


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--all-targets",
        action="store_true",
        help="build every target from each package's docs.rs metadata",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if shutil.which("cargo-docs-rs") is None:
        print("cargo-docs-rs is required; install version 1.0.4", file=sys.stderr)
        return 2

    metadata = cargo_metadata()
    target_dir = os.environ.get(
        "CARGO_TARGET_DIR",
        os.path.join(metadata["workspace_root"], "target", "docsrs-check"),
    )
    packages = sorted(
        (
            package
            for package in metadata["packages"]
            if package.get("publish") is None and has_lib_target(package)
        ),
        key=lambda package: package["name"],
    )

    host = host_triple()
    native_target = None if args.all_targets else host
    if args.all_targets:
        ensure_targets(packages, host)

    print(
        f"publishable library crates ({len(packages)}): "
        + " ".join(package["name"] for package in packages)
        + "\n",
        flush=True,
    )

    failures = [
        package["name"]
        for package in packages
        if not run_package(package, target_dir, native_target)
    ]

    print("\n================ SUMMARY ================", flush=True)
    if failures:
        print(f"FAILED ({len(failures)}): {' '.join(failures)}")
        return 1

    mode = "docs.rs metadata targets" if args.all_targets else f"native target {host}"
    print(f"all {len(packages)} crates pass for {mode}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
