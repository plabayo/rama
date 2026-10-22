#!/usr/bin/env python3
"""Real desktop Safari against private CLI fixtures; no packet/emulation oracle."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import sys
import tempfile

from fixture_process import running, wait_ready
from fixture_tls import fixture_certificate

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "rama-fp"))
from browser_automation.drivers import local_session
from browser_automation.workflow import PROTOCOLS, run_capture_flow
from selenium.webdriver.support.ui import WebDriverWait


def fixture_environment(parent, key, certificate):
    """Never inherit a database, storage credential, proxy or keylog destination."""
    environment = {key: value for key, value in parent.items()
                   if not key.startswith("PG") and "DATABASE" not in key
                   and not key.lower().endswith("_proxy")
                   and key not in ("RAMA_FP_STORAGE_COOKIE", "SSLKEYLOGFILE")}
    environment.update(
        RUST_LOG="info", NO_COLOR="1", NO_PROXY="127.0.0.1,localhost",
        no_proxy="127.0.0.1,localhost",
        RAMA_TLS_KEY=base64.b64encode(key.read_bytes()).decode(),
        RAMA_TLS_CRT=base64.b64encode(certificate.read_bytes()).decode(),
    )
    return environment


def verify_responses(driver, origin, protocol):
    driver.set_page_load_timeout(30)
    driver.set_script_timeout(30)
    driver.get(origin + "/consent")
    # The CLI's TCP bootstrap closes the connection and reloads into H3.
    # Fallback or a stuck bootstrap must fail, never skip this regression.
    WebDriverWait(driver, 30).until(lambda browser: PROTOCOLS.get(
        browser.execute_script(
            'return performance.getEntriesByType("navigation")[0]?.nextHopProtocol'
        )) == protocol)
    rows = driver.execute_async_script("""
        const done = arguments[0];
        (async () => {
            const results = [];
            for (let i = 0; i < 12; i++) {
                performance.clearResourceTimings();
                const kind = ['consent', 'xhr', 'form'][i % 3];
                const path = kind === 'consent' ? '/consent' : kind === 'xhr' ? '/api/xml/number/7' : '/form';
                const options = {cache: 'no-store'};
                if (kind !== 'consent') {
                    options.method = 'POST';
                    options.body = kind === 'xhr' ? '{"number":7}' : 'source=web&rating=3';
                    options.headers = {'Content-Type': kind === 'xhr' ? 'application/json' : 'application/x-www-form-urlencoded'};
                }
                const response = await fetch(path, options);
                const text = await response.text();
                const entries = performance.getEntriesByType('resource');
                const complete = kind === 'xhr'
                    ? JSON.parse(text).number === 7
                    : text.trimEnd().endsWith('</html>') && text.includes(kind === 'consent' ? 'Fingerprint Consent' : '<form');
                results.push({kind, status: response.status,
                    encoding: response.headers.get('content-encoding'),
                    complete,
                    bytes: new TextEncoder().encode(text).length,
                    protocol: entries.find(e => e.name.endsWith(path))?.nextHopProtocol});
            }
            done({results});
        })().catch(error => done({error: String(error)}));
    """)
    return rows


def validate_responses(rows, protocol):
    if not isinstance(rows, dict) or "error" in rows:
        raise ValueError("Safari response probe failed")
    results = rows.get("results", [])
    if ([row.get("kind") for row in results] != ["consent", "xhr", "form"] * 4
            or not all(
        row.get("status") == 200 and row.get("complete") and row.get("bytes", 0) > 0
        and row.get("encoding") in ("zstd", "br", "gzip", "deflate")
        and PROTOCOLS.get(row.get("protocol")) == protocol
        for row in results
    )):
        raise ValueError("Safari must receive twelve complete compressed responses over " + protocol)


def run(args):
    args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    # All identities and Automation profiles are private and removed on failure too.
    with tempfile.TemporaryDirectory(prefix="rama-safari-") as temporary:
        root = Path(temporary)
        key, certificate, _, _ = fixture_certificate(root)
        environment = fixture_environment(os.environ, key, certificate)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        address = f"127.0.0.1:{port}"
        origin = f"https://localhost:{port}"
        command = [str(args.rama), "serve", "fp", "--bind", address,
                   "--http-version", args.protocol, "--secure", "--graceful", "1"]
        if args.protocol == "h3":
            command += ["--h3-bootstrap-bind", address]
        with running(command, args.output / "server.log", environment) as server:
            wait_ready(server, args.output / "server.log",
                       lambda text: bool(re.search(r"(listening|service ready)", text)))
            with local_session("safari", profile=root / "profile",
                               safari_accept_insecure_certs=True) as driver:
                responses = verify_responses(driver, origin, args.protocol)
                report = dict(browser=driver.capabilities.get("browserName"),
                              version=driver.capabilities.get("browserVersion"),
                              protocol=args.protocol, success=False, response_probe=responses)
                report_path = args.output / "report.json"
                report_path.write_text(json.dumps(report, indent=2) + "\n")
                validate_responses(responses, args.protocol)
                if args.protocol == "h3":
                    report.update(success=True, coverage="compressed GET and POST responses",
                                  websocket="not covered: Safari sent H1 Upgrade to the H3-only TCP bootstrap")
                    report_path.write_text(json.dumps(report, indent=2) + "\n")
                    print(f"Safari {report['version']}: h3, twelve compressed GET/POST responses passed")
                    return
                try:
                    result = run_capture_flow(driver, origin, expected_protocol=args.protocol)
                except Exception:
                    report["failure_page"] = driver.execute_script(
                        'return {url: location.href, title: document.title, '
                        'bodyBytes: document.body?.textContent?.length, '
                        'protocol: performance.getEntriesByType("navigation")[0]?.nextHopProtocol}')
                    report_path.write_text(json.dumps(report, indent=2) + "\n")
                    raise
                report.update(success=True, coverage="six browser operations and compressed GET/POST responses",
                              user_agent=result.user_agent, protocols=result.protocols,
                              page_results=result.page_results)
                report_path.write_text(json.dumps(report, indent=2) + "\n")
                print(f"Safari {result.browser_version}: {args.protocol}, all six flows and twelve compressed responses passed")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rama", required=True, type=Path)
    parser.add_argument("--protocol", required=True, choices=("h1", "h2", "h3"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--accept-fixture-certificate", action="store_true",
                        help="Accept the private localhost certificate only in this Automation session")
    args = parser.parse_args(argv)
    if sys.platform != "darwin":
        parser.error("desktop Safari requires macOS")
    if not args.accept_fixture_certificate:
        parser.error("--accept-fixture-certificate is required (no system trust changes)")
    for program in ("openssl", "safaridriver"):
        if shutil.which(program) is None:
            parser.error("required executable not found: " + program)
    args.rama = args.rama.resolve(strict=True)
    args.output = args.output.resolve()
    def interrupted(number, _frame):
        raise InterruptedError(number)
    previous = {number: signal.signal(number, interrupted)
                for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        run(args)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
