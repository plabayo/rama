#!/usr/bin/env python3
"""Test settings restoration and evidence validation without changing settings."""
import http.client
import json
import socket
import tempfile
import unittest
import zipfile
from urllib.parse import urlsplit
from pathlib import Path
from unittest.mock import patch

from egress_proxy_policy import check_test_log, main, servers, settings_transaction


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


if __name__ == "__main__":
    unittest.main()
