#!/usr/bin/env python3
"""Test settings restoration and evidence validation without changing settings."""
import http.client
import io
import sys
from contextlib import redirect_stderr
import json
import re
import socket
import subprocess
import threading
from types import SimpleNamespace
import tempfile
import unittest
import zipfile
from urllib.parse import urlsplit
from pathlib import Path
from unittest.mock import patch

from egress_proxy_policy import check_test_log, main, run, run_suite, servers, settings_transaction, execute, LOCAL_TESTS, ROOT


class SettingsTransactionTests(unittest.TestCase):
    def test_restore_on_success(self):
        with patch("egress_proxy_policy.run") as run:
            with settings_transaction(["helper"], "snapshot"):
                pass
        self.assertEqual([c.args[0] for c in run.call_args_list],
                         [["helper", "apply", "snapshot"], ["helper", "restore", "snapshot"]])

    def test_restore_on_test_failure_and_interrupt(self):
        for error in (RuntimeError("test failed"), KeyboardInterrupt(), SystemExit(15)):
            with self.subTest(error=error), patch("egress_proxy_policy.run") as run:
                with self.assertRaises(type(error)):
                    with settings_transaction(["helper"], "snapshot"):
                        raise error
                self.assertEqual(run.call_args.args[0], ["helper", "restore", "snapshot"])

    def test_restore_even_if_apply_committed_then_failed(self):
        with patch("egress_proxy_policy.run", side_effect=[RuntimeError("apply notification failed"), None]) as run:
            with self.assertRaises(RuntimeError):
                with settings_transaction(["helper"], "snapshot"):
                    self.fail("must not run tests")
            self.assertEqual(run.call_args.args[0], ["helper", "restore", "snapshot"])

    def test_restoration_failure_is_not_hidden(self):
        with patch("egress_proxy_policy.run", side_effect=[None, RuntimeError("restore failed")]):
            with self.assertRaisesRegex(RuntimeError, "restore failed"):
                with settings_transaction(["helper"], "snapshot"):
                    pass


class TestEvidenceTests(unittest.TestCase):
    def check(self, content):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.log"
            path.write_text(content)
            return check_test_log(path, {"testRequired"})

    def case(self, name="testRequired", status="passed"):
        prefix = f"Test Case '-[RamaAppleNetworkExtensionTests.NativeTcpConnectionTests {name}]' "
        return prefix + "started.\n" + prefix + status + " (0.001 seconds).\n"

    def test_accepts_completed_required_test(self):
        self.assertEqual(self.check(self.case()), 1)

    def test_rejects_skipped_and_failed_tests(self):
        for result in ("skipped", "failed"):
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                self.check(self.case(status=result))

    def test_rejects_empty_missing_unexpected_and_duplicate_tests(self):
        for names in ([], ["testOther"], ["testRequired", "testOther"],
                      ["testRequired", "testRequired"]):
            with self.subTest(names=names), self.assertRaises(RuntimeError):
                self.check(''.join(self.case(name) for name in names))

    def test_rejects_truncated_output_and_changed_format(self):
        for content in (self.case().splitlines()[0], self.case().splitlines()[1],
                        self.case().replace("Test Case", "Changed format")):
            with self.subTest(content=content), self.assertRaises(RuntimeError):
                self.check(content)


class FixtureTests(unittest.TestCase):
    def test_pac_fetch_and_connect_echo_after_half_close(self):
        with servers() as (proxy, url):
            address = urlsplit(url)
            client = http.client.HTTPConnection(address.hostname, address.port, timeout=5)
            try:
                client.request("GET", address.path)
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("Cache-Control"), "no-store")
                self.assertIn(b'host === "rama-egress-test.invalid"', response.read())
            finally:
                client.close()
            with socket.create_connection(proxy.server_address, timeout=5) as connection:
                connection.sendall(b"CONNECT rama-egress-test.invalid:443 HTTP/1.1\r\n\r\n")
                header = b""
                while b"\r\n\r\n" not in header:
                    chunk = connection.recv(4096)
                    self.assertTrue(chunk, "proxy closed before the CONNECT response")
                    header += chunk
                self.assertEqual(header, b"HTTP/1.1 200 Connection Established\r\n\r\n")
                payload = bytes(range(256)) * 2048
                connection.sendall(payload)
                connection.shutdown(socket.SHUT_WR)
                echoed = bytearray()
                while chunk := connection.recv(65536):
                    echoed.extend(chunk)
                self.assertEqual(echoed, payload)
            with socket.create_connection(proxy.server_address, timeout=5) as connection:
                connection.sendall(b"CONNECT unrelated.invalid:443 HTTP/1.1\r\n\r\n")
                self.assertTrue(connection.recv(4096).startswith(b"HTTP/1.1 403 Forbidden"))
            with proxy.count_lock:
                self.assertEqual(proxy.contacts, 2)
                self.assertEqual(proxy.pac_fetches, 1)


class ReportTests(unittest.TestCase):
    def test_failed_pac_test_preserves_server_counters(self):
        proxy = SimpleNamespace(count_lock=threading.Lock(), contacts=2, pac_fetches=7)
        report = {"checks": []}

        def failed_test(*args, **kwargs):
            proxy.contacts += 1
            proxy.pac_fetches += 1
            raise subprocess.CalledProcessError(1, ["swift", "test"])

        with tempfile.TemporaryDirectory() as directory, \
                patch("egress_proxy_policy.run", side_effect=failed_test), \
                self.assertRaises(subprocess.CalledProcessError):
            run_suite(Path(directory), report, "system-pac-allowed", ["swift", "test"],
                      {"testDeveloperSystemProxyScenario"}, proxy=proxy)
        self.assertEqual(report["checks"], [{"name": "system-pac-allowed", "status": "failed",
                                           "proxy_contacts": 1, "pac_fetches": 1}])

    def test_failure_produces_shareable_report_without_settings_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            def fail_after_snapshot(args, destination, report):
                (destination / "original.plist").write_text("private settings")
                raise RuntimeError("required check failed")

            with patch("sys.argv", ["egress_proxy_policy.py"]), \
                    patch("egress_proxy_policy.tempfile.mkdtemp", return_value=directory), \
                    patch("egress_proxy_policy.subprocess.check_output", side_effect=["abc\n", b""]), \
                    patch("egress_proxy_policy.execute", side_effect=fail_after_snapshot), \
                    patch("builtins.print"), self.assertRaisesRegex(RuntimeError, "required check failed"):
                main()
            with zipfile.ZipFile(Path(directory) / "report.zip") as report:
                self.assertEqual(set(report.namelist()), {"report.json", "run.log"})
                evidence = json.loads(report.read("report.json"))
                self.assertEqual(evidence["status"], "failed")
                self.assertEqual(evidence["error"], "required check failed")


class HarnessSelectionTests(unittest.TestCase):
    def test_inventory_matches_native_tcp_test_suite(self):
        source = ROOT / "ffi/apple/RamaAppleNetworkExtension/Tests/RamaAppleNetworkExtensionTests/NativeTcpConnectionTests.swift"
        names = re.findall(r"^    func (test\w+)\(", source.read_text(), re.MULTILINE)
        self.assertEqual(len(names), len(set(names)), "duplicate native TCP test names")
        self.assertEqual(set(names), LOCAL_TESTS | {"testDeveloperSystemProxyScenario"},
                         "update LOCAL_TESTS when native TCP tests change")

    def test_only_requested_configuration_runs_and_old_os_coverage_is_explicit(self):
        for version in ("13.7", "26.5"):
            args = SimpleNamespace(system_pac_service=None, scratch_path=Path("/tmp/build"),
                                   skip_build=False, deep=False, configuration=["asan"])
            report = {}
            with tempfile.TemporaryDirectory() as directory, patch("egress_proxy_policy.run"), patch("egress_proxy_policy.platform.mac_ver", return_value=(version, (), "")), patch("egress_proxy_policy.run_suite") as suite:
                execute(args, Path(directory), report)
            self.assertEqual(suite.call_count, 1)
            call = suite.call_args
            self.assertEqual(call.args[2], "local-asan")
            self.assertIn("address", call.args[3])
            self.assertIn("PrivateNetworkProxyControl", call.args[3])
            self.assertEqual(call.args[3][call.args[3].index("--filter") + 1], "NativeTcpConnectionTests/")
            self.assertIn("testDeveloperSystemProxyScenario", call.args[3][-1])
            if version.startswith("13"):
                self.assertEqual(len(report["unsupported_tests"]), 3)
                self.assertEqual(call.args[4], LOCAL_TESTS - set(report["unsupported_tests"]))
            else:
                self.assertEqual(call.args[4], LOCAL_TESTS)

    def test_system_pac_prefetch_during_apply_counts_for_its_case(self):
        args = SimpleNamespace(system_pac_service="Wi-Fi", scratch_path=Path("/tmp/build"),
                               skip_build=False, deep=False, configuration=None)
        proxy = SimpleNamespace(count_lock=threading.Lock(), contacts=0, pac_fetches=0)
        report = {"checks": []}
        def command(cmd, log_path=None, **kwargs):
            if "apply" in cmd and "denied" not in cmd[-1]:
                proxy.pac_fetches += 1  # Settings notification fetches before Swift starts.
            if log_path:
                system = log_path.name.startswith("system-pac-")
                names = {"testDeveloperSystemProxyScenario"} if system else LOCAL_TESTS
                log_path.write_text("".join(
                    f"Test Case '-[RamaAppleNetworkExtensionTests.NativeTcpConnectionTests {name}]' " + suffix
                    for name in names for suffix in ("started.\n", "passed (0.001 seconds).\n")))
                if system and kwargs["env"]["RAMA_EGRESS_TEST_USED_PROXY"] == "1":
                    proxy.contacts += 1
        with tempfile.TemporaryDirectory() as directory, patch("egress_proxy_policy.servers") as fixture, \
                patch("egress_proxy_policy.run", side_effect=command), \
                patch("egress_proxy_policy.time.sleep"), patch("egress_proxy_policy.signal.signal"), \
                patch("egress_proxy_policy.platform.mac_ver", return_value=("26.5", (), "")):
            fixture.return_value.__enter__.return_value = (proxy, "http://127.0.0.1/example.pac")
            execute(args, Path(directory), report)
        self.assertEqual([check["pac_fetches"] for check in report["checks"][1:]], [1, 0, 1])
        self.assertTrue(report["settings_restored"])

    def test_failed_command_prints_log_path_and_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / "failure.log"
            stderr = io.StringIO()
            with (Path(directory) / "run.log").open("w") as log, patch("egress_proxy_policy.LOG", log), redirect_stderr(stderr):
                with self.assertRaises(subprocess.CalledProcessError):
                    run([sys.executable, "-c", "print('meaningful failure'); raise SystemExit(1)"], log_path)
            self.assertIn(str(log_path), stderr.getvalue())
            self.assertIn("meaningful failure", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
