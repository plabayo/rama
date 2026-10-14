#!/usr/bin/env python3
"""Unit tests for the optional settings transaction; never modify settings."""
import unittest
from unittest.mock import patch

from egress_proxy_policy import settings_transaction


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


if __name__ == "__main__":
    unittest.main()
