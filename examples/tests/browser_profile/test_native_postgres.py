"""Native fixtures must isolate credentials and clean up failed runs."""

import unittest
from unittest.mock import patch

import native_postgres
from disposable_postgres import isolated_environment


class NativeDatabaseTests(unittest.TestCase):
    def test_credentials_stay_in_environment(self):
        env = {"RAMA_BROWSER_CAPTURE_DATABASE_URL":
               "host=127.0.0.1 port=54321 user=postgres password=private dbname=rama_fp_capture"}
        with patch("native_postgres.subprocess.run") as command:
            native_postgres.create_database(env, "rama_fp_replay")
        self.assertNotIn("private", " ".join(command.call_args.args[0]))
        self.assertEqual(command.call_args.kwargs["env"]["PGDATABASE"], "rama_fp_capture")
        self.assertEqual(command.call_args.kwargs["env"]["PGPORT"], "54321")
        with self.assertRaises(ValueError):
            native_postgres.create_database(env, "production")

    def test_backend_markers_are_not_inherited(self):
        child = isolated_environment({"RAMA_BROWSER_TEST_PG_NATIVE": "/foreign",
                                      "RAMA_BROWSER_TEST_PG_CONTAINER": "foreign",
                                      "PGHOST": "production"}, "owned", None)
        for name in ("RAMA_BROWSER_TEST_PG_NATIVE", "RAMA_BROWSER_TEST_PG_CONTAINER", "PGHOST"):
            self.assertNotIn(name, child)

