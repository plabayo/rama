#!/usr/bin/env python3
"""Build curl with its experimental CONNECT-UDP client into PREFIX.

curl's HTTP/3 proxy support needs OpenSSL with its QUIC API (3.5 or later), which distributions
lag behind, so OpenSSL, nghttp3 and ngtcp2 are built alongside. Every source is a pinned release
tarball, verified against its SHA-256 before it is unpacked.
"""

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

SOURCES = (
    (
        "openssl",
        "https://github.com/openssl/openssl/releases/download/openssl-3.6.2/openssl-3.6.2.tar.gz",
        "aaf51a1fe064384f811daeaeb4ec4dce7340ec8bd893027eee676af31e83a04f",
        ["--libdir=lib", "no-docs", "no-tests"],
    ),
    (
        "nghttp3",
        "https://github.com/ngtcp2/nghttp3/releases/download/v1.18.0/nghttp3-1.18.0.tar.xz",
        "aad782c23d3f01bd4bb52c8bac7a553b631ef8115fd1612703df6183449fef19",
        ["--enable-lib-only"],
    ),
    (
        "ngtcp2",
        "https://github.com/ngtcp2/ngtcp2/releases/download/v1.25.0/ngtcp2-1.25.0.tar.xz",
        "2a34d2484ba17847a5d11965704e9dd0fac4c6d8efc75ffe1ec7de66d8c6b6fb",
        ["--enable-lib-only", "--with-openssl"],
    ),
    (
        "curl",
        "https://github.com/curl/curl/releases/download/curl-8_23_0/curl-8.23.0.tar.xz",
        "8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5",
        [
            "--with-openssl",
            "--with-ngtcp2",
            "--with-nghttp3",
            "--with-nghttp2",
            "--enable-proxy-http3",
            "--without-libpsl",
            "--disable-ldap",
            "--disable-docs",
        ],
    ),
)


def fetch(url, sha256, into):
    """Download `url` into `into`, unless a verified copy is already there."""
    path = into / url.rsplit("/", 1)[1]
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != sha256:
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read()
        digest = hashlib.sha256(data).hexdigest()
        if digest != sha256:
            raise SystemExit(f"{url}: sha256 {digest}, expected {sha256}")
        path.write_bytes(data)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    args = parser.parse_args(argv)
    prefix = args.prefix.resolve()
    sources = prefix / "src"
    sources.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["PKG_CONFIG_PATH"] = os.pathsep.join(
        filter(None, [str(prefix / "lib" / "pkgconfig"), env.get("PKG_CONFIG_PATH")])
    )
    # The installed curl finds the libraries built next to it.
    env["LDFLAGS"] = " ".join(filter(None, [f"-Wl,-rpath,{prefix / 'lib'}", env.get("LDFLAGS")]))
    for name, url, sha256, flags in SOURCES:
        tarball = fetch(url, sha256, sources)
        with tarfile.open(tarball) as archive:
            archive.extractall(sources, filter="data")
        tree = sources / tarball.name.removesuffix(".tar.xz").removesuffix(".tar.gz")
        print(f"building {name} in {tree}", flush=True)
        if name == "openssl":
            commands = (
                ["./Configure", f"--prefix={prefix}", *flags],
                ["make", f"-j{args.jobs}"],
                ["make", "install_sw"],
            )
        else:
            commands = (
                ["./configure", f"--prefix={prefix}", "--disable-static", *flags],
                ["make", f"-j{args.jobs}"],
                ["make", "install"],
            )
        for command in commands:
            subprocess.run(command, cwd=tree, env=env, check=True)
    curl = prefix / "bin" / "curl"
    features = subprocess.run([str(curl), "--version"], capture_output=True, text=True, check=True).stdout
    print(features, end="")
    if "proxy-HTTP3" not in features:
        raise SystemExit(f"{curl} lacks proxy-HTTP3")


if __name__ == "__main__":
    main()
