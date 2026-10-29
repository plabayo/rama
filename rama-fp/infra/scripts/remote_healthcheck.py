#!/usr/bin/env python3
"""Bounded DNS and protocol checks for Rama's public demo services.

All checks use one Rama binary, or one temporary container from the selected
image. HTTP checks verify the reported response version and consume the body.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
import ipaddress
import json
import os
import re
from pathlib import Path
import shlex
import signal
import subprocess
import time


@dataclass(frozen=True)
class Site:
    host: str
    path: str = "/"
    plain: tuple = ("1.1", "2")
    secure: tuple = ("1.1", "2", "3")
    address: str = "A"
    alpn: tuple = ("http/1.1", "h2", "h3")
    exclusive_alpn: bool = False


SITES = (
    Site("echo"),
    Site("fp", "/consent"),
    # No HTTPS record: an HTTP/1.1-only origin gains nothing from one, and it makes
    # browsers upgrade the plain-HTTP cell to HTTPS.
    Site("h1.fp", "/consent", ("1.1",), ("1.1",), alpn=()),
    Site("h2.fp", "/consent", ("2",), ("2",), alpn=("h2",), exclusive_alpn=True),
    Site("h3.fp", "/consent", (), ("3",), alpn=("h3", "http/1.1"), exclusive_alpn=True),
    Site("ipv4"),
    Site("http-test"),
    # DNS is checked even when the runner has no IPv6 route.
    Site("ipv6", address="AAAA", secure=("1.1", "2"), alpn=()),
)


@dataclass(frozen=True)
class Probe:
    site: Site
    kind: str
    value: str
    secure: bool = False

    @property
    def domain(self):
        return self.site.host + ".ramaproxy.org"

    @property
    def label(self):
        if self.kind == "dns":
            return f"DNS {self.domain} {self.value}"
        scheme = "https" if self.secure else "http"
        return f"HTTP/{self.value} {scheme}://{self.domain}{self.site.path}"


@dataclass
class Result:
    label: str
    ok: bool
    detail: str
    attempts: int
    seconds: float
    skipped: bool = False


def command(args, timeout):
    """Keep process failure distinct from malformed or unhealthy responses."""
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"process exceeded {timeout:g}s"


def checked(args, timeout):
    code, stdout, stderr = command(args, timeout)
    if code:
        raise RuntimeError(f"{shlex.join(args)}: {stderr.strip() or stdout.strip()}")
    return stdout.strip()


class Rama(AbstractContextManager):
    """One image pull and container, shared by every probe."""

    def __init__(self, binary, image, lease, platform="linux/amd64"):
        self.binary = binary
        self.image = image
        self.lease = lease
        self.platform = platform
        self.container = None
        self.identity = binary

    def __enter__(self):
        if self.binary:
            checked([self.binary, "--version"], 10)
        else:
            checked(
                ["docker", "pull", "--quiet", "--platform", self.platform, self.image],
                180,
            )
            self.identity = checked(
                ["docker", "image", "inspect", self.image, "--format", "{{.Id}}"], 10
            )
            # The lease also bounds lifetime if the host is killed before cleanup.
            self.container = checked(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--rm",
                    "--platform",
                    self.platform,
                    "--entrypoint",
                    "/bin/sleep",
                    self.identity,
                    str(self.lease),
                ],
                20,
            )
        return self

    def args(self, *args):
        if self.binary:
            return [self.binary, *args]
        return ["docker", "exec", self.container, "/app/rama", *args]

    def __exit__(self, *_):
        if self.container:
            checked(["docker", "rm", "--force", self.container], 15)


def dns_answer(probe, stdout):
    """Read Rama's record lines, not success-shaped resolver headings."""
    records = [line[2:] for line in stdout.splitlines() if line.startswith("* ")]
    if probe.value in ("A", "AAAA"):
        version = 4 if probe.value == "A" else 6
        for record in records:
            try:
                if ipaddress.ip_address(record).version == version:
                    return True, ", ".join(records)
            except ValueError:
                continue
        return False, "no address of the required family"

    for record in records:
        try:
            parts = shlex.split(record)
            if len(parts) < 2 or not 0 < int(parts[0]) <= 65535:
                continue
        except ValueError:
            continue
        parameters = [part.partition("=") for part in parts[2:]]
        params = {key: value for key, _separator, value in parameters}
        if len(params) != len(parameters):
            continue
        # RFC9460: a mandatory key must be present and understood. This monitor
        # interprets ALPN and port; it cannot attest ECH or other required policies.
        if "mandatory" in params:
            mandatory = params["mandatory"].split(",")
            understood = {"alpn", "no-default-alpn", "port"}
            if not set(mandatory).issubset(understood & params.keys()) or len(
                set(mandatory)
            ) != len(mandatory):
                continue
        # Each usable service record must supply the whole required ALPN set.
        if params.get("port", "443") != "443":
            continue
        advertised = set(params.get("alpn", "").split(","))
        # RFC9460 HTTPS adds HTTP/1.1 unless the record suppresses defaults.
        if "no-default-alpn" not in parts[2:]:
            advertised.add("http/1.1")
        expected = set(probe.site.alpn)
        if advertised == expected or (
            not probe.site.exclusive_alpn and expected.issubset(advertised)
        ):
            return True, record
    return (
        False,
        f"need HTTPS service record with alpn={','.join(probe.site.alpn)}; got {records}",
    )


def attempt(probe, rama, args):
    """Return health, diagnostic and whether another GET/query may recover."""
    if probe.kind == "dns":
        query = rama.args(
            "resolve",
            probe.domain,
            probe.value,
            "--hickory",
            "--tcp",
            "--nameserver",
            args.resolver,
            "--time",
            str(args.dns_timeout),
            "--tries",
            "1",
            "--trace",
            "/dev/null",
        )
        code, stdout, stderr = command(query, args.dns_timeout + 3)
        if code:
            return (
                False,
                f"resolver {args.resolver}: {stderr.strip() or stdout.strip()}",
                True,
            )
        ok, detail = dns_answer(probe, stdout)
        return ok, detail, False

    scheme = "https" if probe.secure else "http"
    url = f"{scheme}://{probe.domain}{probe.site.path}"
    # Fly has no public UDP/IPv6. Mixed origins retain IPv6 TCP service.
    query = rama.args(
        f"--http{probe.value}",
        "-6" if probe.site.address == "AAAA" else "-4",
        "--fail",
        "--connect-timeout",
        str(min(5, args.timeout)),
        "--max-time",
        str(args.timeout),
        "--show-headers",
        "-o",
        "/dev/null",
        "--trace",
        "/dev/null",
        url,
    )
    code, stdout, stderr = command(query, args.timeout + 3)
    # --show-headers reports the actual response on stderr; the body is discarded.
    matches = re.findall(
        r"^\* HTTP/(1\.1|2(?:\.0)?|3(?:\.0)?) ([0-9]{3})(?: |$)", stderr, re.MULTILINE
    )
    if matches:
        version, status = matches[-1]
        version = {"2.0": "2", "3.0": "3"}.get(version, version)
        status = int(status)
        detail = (
            f"status={status}, negotiated HTTP/{version}, expected HTTP/{probe.value}"
        )
        if not code:
            return (
                200 <= status < 400 and version == probe.value,
                detail,
                status in (502, 503, 504),
            )
        if 400 <= status < 500:
            return False, detail, False
    else:
        detail = "no HTTP response status reported"
    # Avoid retaining response cookies or other server header values in reports.
    diagnostic = "\n".join(
        line for line in stderr.splitlines() if not line.startswith(("< ", "* ["))
    )
    return (
        False,
        f"{detail}; Rama exit {code}: {(diagnostic or stdout).strip()[:4000]}",
        code != 0,
    )


def run_probe(probe, rama, args):
    start = time.monotonic()
    for number in range(1, args.attempts + 1):
        ok, detail, retryable = attempt(probe, rama, args)
        if ok or not retryable or number == args.attempts:
            return Result(
                probe.label, ok, detail, number, round(time.monotonic() - start, 3)
            )
        time.sleep(0.5)


def run_phase(probes, rama, args):
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda probe: run_probe(probe, rama, args), probes))
    for result in results:
        state = "OK" if result.ok else "FAIL"
        print(
            f"{state} {result.label} ({result.seconds:g}s, attempts={result.attempts}): {result.detail}",
            flush=True,
        )
    return results


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rama",
        default=os.environ.get("RAMA_BIN"),
        help="local Rama executable instead of Docker",
    )
    parser.add_argument(
        "--image", default=os.environ.get("RAMA_IMAGE", "glendc/rama:edge")
    )
    parser.add_argument(
        "--platform",
        default="linux/amd64",
        help="published edge image platform; Docker Desktop can emulate it on ARM",
    )
    parser.add_argument(
        "--resolver",
        default="1.1.1.1",
        help="explicit DNS resolver; bypasses synthetic local HTTPS answers",
    )
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument(
        "--timeout", type=int, default=10, help="seconds per HTTP attempt"
    )
    parser.add_argument("--dns-timeout", type=int, default=3)
    parser.add_argument(
        "--dns-only", action="store_true", help="only check DNS records"
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=2,
        help="maximum attempts for transient failures",
    )
    parser.add_argument(
        "--ipv6",
        action="store_true",
        help="also probe IPv6 HTTP; AAAA is always checked",
    )
    parser.add_argument("--output", type=Path, help="directory for report.json")
    args = parser.parse_args(argv)
    for name in ("jobs", "timeout", "dns_timeout", "attempts"):
        if getattr(args, name) < 1:
            parser.error(f"--{name.replace('_', '-')} must be positive")
    return args


def main(argv=None):
    args = parse_args(argv)
    dns = [
        Probe(site, "dns", record)
        for site in SITES
        for record in ((site.address, "HTTPS") if site.alpn else (site.address,))
    ]
    http = [
        Probe(site, "http", version, secure)
        for site in SITES
        if site.address != "AAAA" or args.ipv6
        for secure, versions in ((False, site.plain), (True, site.secure))
        for version in versions
    ]
    if args.dns_only:
        http = []
    lease = (len(dns) + len(http)) * args.attempts * (
        max(args.timeout, args.dns_timeout) + 4
    ) + 60
    start = time.monotonic()
    with Rama(args.rama, args.image, lease, args.platform) as rama:
        print(
            f"Rama: {rama.identity}; DNS resolver: {args.resolver}; concurrency: {args.jobs}",
            flush=True,
        )
        results = run_phase(dns, rama, args)
        broken_addresses = {
            probe.domain
            for probe, result in zip(dns, results)
            if probe.value in ("A", "AAAA") and not result.ok
        }
        available = []
        for probe in http:
            if probe.domain in broken_addresses:
                results.append(
                    Result(
                        probe.label,
                        False,
                        "skipped: required address failed DNS preflight",
                        0,
                        0,
                        True,
                    )
                )
            else:
                available.append(probe)
        results.extend(run_phase(available, rama, args))
        report = {
            "rama": rama.identity,
            "resolver": args.resolver,
            "seconds": round(time.monotonic() - start, 3),
            "results": [asdict(result) for result in results],
        }
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    failures = sum(not result.ok and not result.skipped for result in results)
    print(
        f"{len(results)} checks in {report['seconds']:g}s; {failures} failed, "
        f"{sum(result.skipped for result in results)} skipped",
        flush=True,
    )
    return int(failures != 0)


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, KeyboardInterrupt) as error:
        raise SystemExit(f"healthcheck failed: {error}") from error
