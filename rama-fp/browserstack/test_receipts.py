"""Public receipts contain only bounded identity, flow and lifecycle facts."""

import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import quote

from receipts import identity, write_receipt


class ReceiptTests(unittest.TestCase):
    def test_identity_is_bounded_allowlisted_and_does_not_infer_missing_values(self):
        secret = "private/value&token"
        actual = identity(
            {
                "browserName": "chrome",
                "browserVersion": "155.0",
                "deviceName": secret,
                "os": quote(secret, safe=""),
                "osVersion": "x" * 129,
                "platformName": "bad\nvalue",
                "sessionId": "must-not-retain",
                "provider": {"accessKey": secret},
            },
            secrets=(secret,),
        )
        self.assertEqual(
            actual,
            {
                "browserName": "chrome",
                "browserVersion": "155.0",
                "deviceName": None,
                "os": None,
                "osVersion": None,
                "platformName": None,
            },
        )
        absent = identity({}, secrets=())
        self.assertTrue(all(value is None for value in absent.values()))

    def test_writer_rejects_incomplete_unknown_and_private_values_before_writing(self):
        flows = dict.fromkeys(
            ("navigate", "fetch", "xhr", "ws", "form", "form_get"), "h3"
        )
        for name, changes, secrets in (
            ("missing_flow", {"protocols": {"navigate": "h3"}}, ()),
            ("unknown_transport", {"protocols": {**flows, "ws": "unavailable"}}, ()),
            ("unknown_flow", {"protocols": {**flows, "other": "h3"}}, ()),
            (
                "incomplete_visit",
                {"visits": [{"status": "passed", "protocols": {"navigate": "h3"}}]},
                (),
            ),
            (
                "private_string",
                {"unexpected": "private-access-token"},
                ("private-access-token",),
            ),
            (
                "quoted_credential",
                {"unexpected": 'private"access-token'},
                ('private"access-token',),
            ),
            (
                "backslash_credential",
                {"unexpected": "private\\access-token"},
                ("private\\access-token",),
            ),
            (
                "unicode_credential",
                {"unexpected": "private-🐢-token"},
                ("private-🐢-token",),
            ),
        ):
            with self.subTest(case=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "receipt.json"
                with self.assertRaises(ValueError):
                    write_receipt(
                        path, {"protocols": flows, **changes}, secrets=secrets
                    )
                self.assertFalse(path.exists())

    def test_write_is_exclusive_and_preserves_mixed_protocols(self):
        receipt = {
            "protocols": {
                **dict.fromkeys(("navigate", "fetch", "xhr", "form", "form_get"), "h3"),
                "ws": "h1",
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            write_receipt(path, receipt, secrets=())
            original = path.read_bytes()
            self.assertEqual(json.loads(original), receipt)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_receipt(path, {"protocols": None}, secrets=())
            self.assertEqual(path.read_bytes(), original)
