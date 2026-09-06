import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
import unittest
from unittest.mock import MagicMock, mock_open, patch

import main


class ProfileGeneratorTests(unittest.TestCase):
    def test_export_retains_partial_captures_and_reports_completeness(self):
        now = datetime(2026, 9, 6, tzinfo=timezone.utc)
        complete = dict.fromkeys(main.REQUIRED_PROFILE_FIELDS, {})
        complete.update(uastr="complete", updated_at=now, h1_headers_fetch=None)
        partial = dict(complete, uastr="partial", h2_settings=None,
                       h2_headers_navigate=None, tls_client_hello=None)
        stale = dict(complete, uastr="stale", updated_at=now - timedelta(days=15))
        undated = dict(complete, uastr="undated", updated_at=None)
        columns = list(complete)
        driver = MagicMock()
        cursor = driver.connect.return_value.__enter__.return_value.cursor.return_value.__enter__.return_value
        cursor.description = [(name,) for name in columns]
        cursor.fetchall.return_value = [tuple(row[name] for name in columns)
                                       for row in [complete, partial, stale, undated]]
        output = io.StringIO()
        with (patch.dict("sys.modules", {"psycopg": driver}),
              patch.dict(main.os.environ, {"RAMA_FP_DATABASE_URL": "mock://offline"}),
              patch.object(main.time, "time", return_value=now.timestamp()),
              patch("builtins.open", mock_open()) as opened,
              contextlib.redirect_stdout(output)):
            main.main()
        rows = json.loads("".join(call.args[0] for call in opened().write.call_args_list))
        self.assertEqual([row["uastr"] for row in rows], ["complete", "partial"])
        for field in ["h2_settings", "h2_headers_navigate", "tls_client_hello"]:
            self.assertIsNone(rows[1][field])
            self.assertIn(field, output.getvalue())
        self.assertIn("Incomplete profile 'partial'", output.getvalue())
        self.assertIn("2 (1 complete, 1 incomplete)", output.getvalue())
        self.assertNotIn("Incomplete profile 'complete'", output.getvalue())

    def test_missing_columns_and_nulls_are_both_reported(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main.report_profile_completeness([{"uastr": "partial", "h1_settings": None}])
        for field in main.REQUIRED_PROFILE_FIELDS:
            self.assertIn(field, output.getvalue())
        self.assertIn("1 (0 complete, 1 incomplete)", output.getvalue())

    def test_empty_export_has_unambiguous_counts(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main.report_profile_completeness([])
        self.assertEqual(output.getvalue().strip(), "Total profiles: 0 (0 complete, 0 incomplete)")


if __name__ == "__main__":
    unittest.main()
