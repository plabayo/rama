#!/usr/bin/env python3
"""Emulate docs.rs builds for every publishable workspace crate.

docs.rs builds each crate standalone from its published package: nightly
rustdoc, the crate's own [package.metadata.docs.rs] (rustc-args -> RUSTFLAGS,
rustdoc-args -> RUSTDOCFLAGS, its feature selection), and NO workspace
.cargo/config.toml rustflags. Regular CI lanes all export
`--cfg tokio_unstable` globally, so they can never catch a crate whose
docs.rs metadata is missing a required cfg — 0.3.0-rc.1 failed on docs.rs
exactly that way (dial9 -> dial9-tokio-telemetry needs tokio_unstable).

Setting RUSTFLAGS/RUSTDOCFLAGS explicitly per crate (even empty) overrides
the workspace config, so the local crutch cannot mask anything here.

Not emulated: the packaged .crate file set (covered by
`cargo publish --workspace --dry-run` at release time) and docs.rs'
non-host default target when run locally (the CI job runs on linux,
matching docs.rs' x86_64-unknown-linux-gnu).
"""

import json
import os
import subprocess
import sys

TOOLCHAIN = os.environ.get("RUST_TOOLCHAIN_NIGHTLY", "nightly")


def cargo_metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def docsrs_meta(pkg):
    # [package.metadata.docs.rs] nests as metadata -> "docs" -> "rs"
    return ((pkg.get("metadata") or {}).get("docs") or {}).get("rs") or {}


def docsrs_cmd(pkg, target_dir, override_rustflags=None):
    meta = docsrs_meta(pkg)
    cmd = ["cargo", f"+{TOOLCHAIN}", "doc", "--no-deps", "-p", pkg["name"]]
    if meta.get("all-features"):
        cmd.append("--all-features")
    else:
        if meta.get("no-default-features"):
            cmd.append("--no-default-features")
        feats = meta.get("features") or []
        if feats:
            cmd += ["--features", ",".join(feats)]
    if meta.get("cargo-args"):
        print(f"  WARNING: {pkg['name']} has cargo-args (not emulated): {meta['cargo-args']}")

    rustflags = " ".join(meta.get("rustc-args") or [])
    if override_rustflags is not None:
        rustflags = override_rustflags
    rustdocflags = " ".join(meta.get("rustdoc-args") or [])
    if "--cfg docsrs" not in rustdocflags:
        rustdocflags = ("--cfg docsrs " + rustdocflags).strip()

    env = dict(os.environ)
    env["RUSTFLAGS"] = rustflags
    env["RUSTDOCFLAGS"] = rustdocflags
    env["CARGO_TARGET_DIR"] = target_dir
    return cmd, env, rustflags, rustdocflags


def run_pkg(pkg, target_dir, override_rustflags=None, tag=""):
    cmd, env, rf, rdf = docsrs_cmd(pkg, target_dir, override_rustflags)
    print(f"==> {pkg['name']}{tag}  [RUSTFLAGS='{rf}'] [RUSTDOCFLAGS='{rdf}']", flush=True)
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        tail = "\n".join(r.stderr.splitlines()[-60:])
        print(f"❌ FAIL: {pkg['name']}{tag}\n{tail}\n", flush=True)
        return False
    print(f"✅ PASS: {pkg['name']}{tag}", flush=True)
    return True


def main():
    md = cargo_metadata()
    target_dir = os.environ.get(
        "CARGO_TARGET_DIR", os.path.join(md["workspace_root"], "target", "docsrs-check")
    )
    # publish == null means "may publish anywhere"; [] means publish = false
    pkgs = [p for p in md["packages"] if p.get("publish") is None]
    # group by RUSTFLAGS value so dependency artifacts rebuild only once
    pkgs.sort(key=lambda p: (bool(docsrs_meta(p).get("rustc-args")), p["name"]))
    print(f"publishable crates ({len(pkgs)}): {' '.join(p['name'] for p in pkgs)}\n", flush=True)

    # Positive control: a dial9-feature crate without its rustc-args MUST fail
    # (the 0.3.0-rc.1 docs.rs failure). If it passes, this harness no longer
    # models docs.rs (or the dial9/tokio_unstable assumption changed) — do not
    # trust a green sweep, investigate.
    control = next(p for p in pkgs if p["name"] == "rama-dns")
    print("--- positive control: rama-dns with empty RUSTFLAGS (pre-#1058 conditions) ---", flush=True)
    control_failed = not run_pkg(control, target_dir, override_rustflags="", tag=" [control]")
    print(
        "--- control "
        + ("reproduced the rc.1 failure (harness models docs.rs)" if control_failed
           else "DID NOT FAIL: harness untrustworthy, investigate")
        + " ---\n",
        flush=True,
    )

    failures = [pkg["name"] for pkg in pkgs if not run_pkg(pkg, target_dir)]

    print("\n================ SUMMARY ================", flush=True)
    print(f"control (expected FAIL): {'failed as expected' if control_failed else '❌ UNEXPECTEDLY PASSED'}")
    if failures:
        print(f"❌ FAILED ({len(failures)}): {' '.join(failures)}")
    else:
        print(f"✅ all {len(pkgs)} crates pass under docs.rs-equivalent flags")
    sys.exit(0 if (control_failed and not failures) else 1)


if __name__ == "__main__":
    main()
