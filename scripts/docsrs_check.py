#!/usr/bin/env python3
"""Emulate docs.rs builds for every publishable workspace crate.

docs.rs builds each crate standalone from its published package: nightly
rustdoc via `cargo rustdoc --lib -Zrustdoc-map`, the crate's own
[package.metadata.docs.rs] (rustc-args -> RUSTFLAGS, rustdoc-args ->
RUSTDOCFLAGS, its feature selection), one build per metadata target, and NO
workspace .cargo/config.toml rustflags. Regular CI lanes all export
`--cfg tokio_unstable` globally, so they can never catch a crate whose
docs.rs metadata is missing a required cfg — 0.3.0-rc.1 failed on docs.rs
exactly that way (dial9 -> dial9-tokio-telemetry needs tokio_unstable).

Setting RUSTFLAGS/RUSTDOCFLAGS explicitly per crate (even empty) overrides
the workspace config, so the local crutch cannot mask anything here.

Modes:
  default        host-target build per crate (fast local check)
  --all-targets  additionally build every [package.metadata.docs.rs] target
                 per crate, like docs.rs does. Run this on linux — the same
                 host docs.rs builds on — for authoritative results (CI job
                 `docsrs-emulation`). The 0.3.0 non-linux target builds
                 failed there because native C deps (aws-lc-sys, ring,
                 libz-sys, ...) cannot cross-compile in the docs.rs
                 container; such crates must declare linux-only `targets`.

Not emulated: the packaged .crate file set (covered by
`cargo publish --workspace --dry-run` at release time) and the rustwide
sandbox (resource limits, no network during build). For the literal
production pipeline, see the docs.rs build subcommand:
https://github.com/rust-lang/docs.rs/blob/main/README.md#build-subcommand
"""

import json
import os
import subprocess
import sys

TOOLCHAIN = os.environ.get("RUST_TOOLCHAIN_NIGHTLY", "nightly")
DOCSRS_DEFAULT_TARGET = "x86_64-unknown-linux-gnu"


def cargo_metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def docsrs_meta(pkg):
    # [package.metadata.docs.rs] nests as metadata -> "docs" -> "rs"
    return ((pkg.get("metadata") or {}).get("docs") or {}).get("rs") or {}


def docsrs_targets(pkg):
    """The target list docs.rs would build for this crate."""
    meta = docsrs_meta(pkg)
    targets = list(meta.get("targets") or [])
    default = meta.get("default-target") or (targets[0] if targets else DOCSRS_DEFAULT_TARGET)
    return [default] + [t for t in targets if t != default]


def has_lib_target(pkg):
    return any(
        k in ("lib", "proc-macro", "rlib", "dylib") for t in pkg["targets"] for k in t["kind"]
    )


def docsrs_cmd(pkg, target_dir, override_rustflags=None, target=None):
    meta = docsrs_meta(pkg)
    # same shape as the production builder's invocation (see module docs)
    cmd = ["cargo", f"+{TOOLCHAIN}", "rustdoc", "-Zrustdoc-map", "-p", pkg["name"]]
    if has_lib_target(pkg):
        cmd.append("--lib")
    if target:
        cmd += ["--target", target]
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


def run_pkg(pkg, target_dir, override_rustflags=None, tag="", target=None):
    cmd, env, rf, rdf = docsrs_cmd(pkg, target_dir, override_rustflags, target)
    tgt = f" --target {target}" if target else ""
    print(f"==> {pkg['name']}{tag}{tgt}  [RUSTFLAGS='{rf}'] [RUSTDOCFLAGS='{rdf}']", flush=True)
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        tail = "\n".join(r.stderr.splitlines()[-60:])
        print(f"❌ FAIL: {pkg['name']}{tag}{tgt}\n{tail}\n", flush=True)
        return False
    print(f"✅ PASS: {pkg['name']}{tag}{tgt}", flush=True)
    return True


def ensure_targets(targets):
    subprocess.run(
        ["rustup", "target", "add", "--toolchain", TOOLCHAIN, *sorted(targets)],
        check=True, capture_output=True, text=True,
    )


def host_triple():
    out = subprocess.run(
        ["rustc", f"+{TOOLCHAIN}", "-vV"], capture_output=True, text=True, check=True
    ).stdout
    return next(l.split(" ", 1)[1] for l in out.splitlines() if l.startswith("host: "))


def main():
    all_targets = "--all-targets" in sys.argv[1:]
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

    host = host_triple()
    if all_targets:
        ensure_targets({t for p in pkgs for t in docsrs_targets(p)} - {host})

    failures = []
    for pkg in pkgs:
        # host-target build first: the fast signal, and the only sound one on
        # a non-linux host (cross C compilation differs from the docs.rs box)
        if not run_pkg(pkg, target_dir):
            failures.append(pkg["name"])
        if all_targets:
            # host triple already covered by the host build above
            for t in (t for t in docsrs_targets(pkg) if t != host):
                if not run_pkg(pkg, target_dir, target=t):
                    failures.append(f"{pkg['name']}@{t}")

    print("\n================ SUMMARY ================", flush=True)
    print(f"control (expected FAIL): {'failed as expected' if control_failed else '❌ UNEXPECTEDLY PASSED'}")
    if failures:
        print(f"❌ FAILED ({len(failures)}): {' '.join(failures)}")
    else:
        mode = "docs.rs-equivalent flags and targets" if all_targets else "docs.rs-equivalent flags"
        print(f"✅ all {len(pkgs)} crates pass under {mode}")
    sys.exit(0 if (control_failed and not failures) else 1)


if __name__ == "__main__":
    main()
