import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import embedded

PLANNED = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0"


def echoed(*, user_agent=PLANNED, ja4=True, ja4h=True, version="HTTP/2.0"):
    return json.dumps({
        "ua": {"user_agent": user_agent},
        "http": {"version": version,
                 "ja4h": {"hash": "h", "profile": {"hash": "h", "matched": ja4h}}},
        "tls": {"ja4": {"hash": "t", "profile": {"hash": "t", "matched": ja4}}},
    }).encode()


class VerdictTests(unittest.TestCase):
    def verdict(self, stdout, *, resumed_only=False, returncode=0, version="HTTP/2.0"):
        flow = {"initiator": "navigate", "request_fields": ["cookie", "te"],
                "trust_anchors": False, "resumed_only": resumed_only}
        result = SimpleNamespace(stdout=stdout, stderr=b"", returncode=returncode)
        with tempfile.TemporaryDirectory() as root, patch.object(
            embedded.subprocess, "run", return_value=result
        ) as run:
            verdict = embedded.emulate(
                SimpleNamespace(rama=Path("rama")), {"user_agent": PLANNED},
                version, flow, 443, Path(root),
            )
        command = run.call_args.args[0]
        self.command = command
        self.assertIn("user-agent: " + PLANNED, command)
        self.assertIn("cookie: c0=1", command)
        self.assertIn("te: trailers", command)
        return verdict

    def test_matching_fingerprints_of_the_planned_profile_pass(self):
        self.assertTrue(self.verdict(echoed())["passed"])

    def test_another_profile_judged_by_echo_never_passes(self):
        other = PLANNED.replace("157.0", "156.0")
        self.assertFalse(self.verdict(echoed(user_agent=other))["passed"])

    def test_each_fingerprint_and_the_exit_status_must_hold(self):
        self.assertFalse(self.verdict(echoed(ja4=False))["passed"])
        self.assertFalse(self.verdict(echoed(ja4h=False))["passed"])
        self.assertFalse(self.verdict(echoed(), returncode=1)["passed"])
        self.assertFalse(self.verdict(b"not json")["passed"])

    def test_the_echoed_http_version_must_be_the_planned_one(self):
        self.assertFalse(self.verdict(echoed(version="HTTP/1.1"))["passed"])

    def test_http1_is_negotiated_with_the_browser_alpn_offer(self):
        verdict = self.verdict(echoed(version="HTTP/1.1"), version="HTTP/1.1")
        self.assertTrue(verdict["passed"])
        self.assertNotIn("--http1.1", self.command)
        self.assertFalse(self.verdict(echoed(), version="HTTP/1.1")["passed"])

    def test_resumption_only_references_are_judged_by_ja4h(self):
        verdict = self.verdict(echoed(ja4=False), resumed_only=True)
        self.assertTrue(verdict["passed"])
        self.assertEqual(verdict["tls"], "resumption-only reference")
        self.assertFalse(self.verdict(echoed(ja4h=False), resumed_only=True)["passed"])


if __name__ == "__main__":
    unittest.main()
