"""Small regressions for false health reports; live runs cover Docker and services."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import remote_healthcheck as health


class HealthcheckTests(unittest.TestCase):
    def test_dns_checks_address_family_and_effective_alpn(self):
        site = next(site for site in health.SITES if site.host == "h3.fp")
        cases = [
            ("A", "* 198.51.100.1", True),
            ("A", "* 2001:db8::1", False),
            ("AAAA", "* 2001:db8::1", True),
            ("AAAA", "* 198.51.100.1", False),
            ("A", "Resolving A", False),
            ("HTTPS", '* 1 . alpn="h3" no-default-alpn', False),
            ("HTTPS", '* 1 . alpn="h3"', True),
            ("HTTPS", '* 1 . alpn="h3","http/1.1"', True),
            ("HTTPS", '* 1 . alpn="http/1.1"', False),
            ("HTTPS", '* 1 . alpn="h3","h2" no-default-alpn', False),
            ("HTTPS", '* 1 . alpn="h3" no-default-alpn port=8443', False),
            ("HTTPS", '* 0 other.example. alpn="h3" no-default-alpn', False),
            ("HTTPS", '* 1 . alpn="unterminated', False),
            ("HTTPS", '* 1 . alpn="h3" no-default-alpn mandatory=port', False),
            (
                "HTTPS",
                '* 1 . alpn="h3" no-default-alpn mandatory=key65400 key65400=x',
                False,
            ),
            ("HTTPS", '* 1 . alpn="h3" no-default-alpn mandatory=', False),
            ("HTTPS", '* 1 . alpn="h3" no-default-alpn mandatory=mandatory', False),
            ("HTTPS", '* 1 . alpn="h3" no-default-alpn mandatory=alpn,alpn', False),
            (
                "HTTPS",
                '* 1 . alpn="h3","http/1.1" no-default-alpn port=443 mandatory=port,alpn',
                True,
            ),
        ]
        for kind, answer, expected in cases:
            with self.subTest(kind=kind, answer=answer):
                probe = health.Probe(site, "dns", kind)
                self.assertEqual(health.dns_answer(probe, answer)[0], expected)

    def test_mixed_origin_keeps_http1_and_does_not_union_separate_records(self):
        probe = health.Probe(health.Site("fp"), "dns", "HTTPS")
        self.assertTrue(health.dns_answer(probe, '* 1 . alpn="h3","h2"')[0])
        for answer in (
            '* 1 . alpn="h3","h2" no-default-alpn',
            '* 1 . alpn="h3"\n* 2 . alpn="h2"',
        ):
            self.assertFalse(health.dns_answer(probe, answer)[0])

    def test_http_requires_exact_protocol_success_and_complete_body(self):
        args = health.parse_args(["--rama", "/fake/rama"])
        rama = health.Rama(args.rama, "unused", 60)
        cases = [
            ("1.1", 0, "* HTTP/1.1 200 OK", True),
            ("2", 0, "* HTTP/2.0 200 OK", True),
            ("3", 0, "* HTTP/3.0 200 OK", True),
            ("1.1", 0, "* HTTP/2.0 200 OK", False),
            ("2", 0, "* HTTP/1.1 200 OK", False),
            ("3", 124, "* HTTP/3.0 200 OK\nbody timed out", False),
            ("2", 22, "* HTTP/2.0 503 Unavailable", False),
            ("2", 0, "* HTTP/2.0 404 Not Found", False),
            ("2", 0, "no response", False),
        ]
        for version, code, output, expected in cases:
            with self.subTest(version=version, code=code, output=output):
                probe = health.Probe(health.Site("fp"), "http", version, True)
                with patch.object(health, "command", return_value=(code, "", output)):
                    self.assertEqual(health.attempt(probe, rama, args)[0], expected)

    def test_deadline_terminates_a_stalled_client(self):
        code, _stdout, stderr = health.command(
            [sys.executable, "-c", "import time; time.sleep(1)"], 0.03
        )
        self.assertEqual(code, 124)
        self.assertIn("exceeded", stderr)


if __name__ == "__main__":
    unittest.main()
