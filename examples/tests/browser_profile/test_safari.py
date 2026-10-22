"""Safari coverage must reject fallback and the original empty-body failure."""

from pathlib import Path
import tempfile
import unittest

from safari import fixture_environment, validate_responses


class SafariTests(unittest.TestCase):
    def test_success_requires_every_compressed_response_on_requested_protocol(self):
        for protocol, wire in (("h1", "http/1.1"), ("h2", "h2"), ("h3", "h3")):
            good = dict(status=200, complete=True, bytes=4745, encoding="zstd", protocol=wire)
            kinds = ["consent", "xhr", "form"] * 4
            validate_responses({"results": [dict(good, kind=kind) for kind in kinds]}, protocol)
            for change in (dict(bytes=0), dict(complete=False), dict(status=503),
                           dict(encoding=None), dict(protocol="unknown")):
                rows = [dict(good, kind=kind) for kind in kinds]
                rows[0].update(change)
                with self.subTest(protocol=protocol, change=change), self.assertRaises(ValueError):
                    validate_responses({"results": rows}, protocol)
        with self.assertRaises(ValueError):
            validate_responses({"results": [dict(good, protocol="h2", kind=kind) for kind in kinds]}, "h3")
        with self.assertRaises(ValueError):
            validate_responses({"results": [good] * 11}, "h3")
        with self.assertRaises(ValueError):
            validate_responses({"error": "fetch failed"}, "h3")

    def test_fixture_cannot_inherit_storage_proxy_or_keylog(self):
        parent = dict(DATABASE_URL="production", RAMA_FP_DATABASE_URL="production",
                      PGHOST="production", RAMA_FP_STORAGE_COOKIE="secret",
                      HTTPS_PROXY="external", https_proxy="external", SSLKEYLOGFILE="foreign",
                      PATH="/bin")
        with tempfile.TemporaryDirectory() as temporary:
            key, certificate = Path(temporary) / "key", Path(temporary) / "cert"
            key.write_bytes(b"key")
            certificate.write_bytes(b"cert")
            result = fixture_environment(parent, key, certificate)
        self.assertEqual(result["PATH"], "/bin")
        for name in set(parent) - {"PATH"}:
            self.assertNotIn(name, result)
        self.assertEqual(result["NO_PROXY"], "127.0.0.1,localhost")
        self.assertEqual(parent["DATABASE_URL"], "production")
