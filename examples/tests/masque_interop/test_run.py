"""Unit tests for the interop harness's own verdicts."""

import unittest

from run import child_env, client_runs

TEN_OK = "".join(f'run {run} ok: "h3 origin"\n' for run in range(1, 11))


class ClientRunsTest(unittest.TestCase):
    def test_every_reported_run_passes_when_the_client_exits_cleanly(self):
        runs = client_runs(TEN_OK, 0, 10)
        self.assertTrue(all(run["ok"] for run in runs))

    def test_a_client_failing_on_exit_fails_every_run(self):
        runs = client_runs(TEN_OK, 1, 10)
        self.assertFalse(any(run["ok"] for run in runs))
        self.assertEqual({run["exit_code"] for run in runs}, {1})

    def test_unreported_runs_fail(self):
        runs = client_runs('run 1 ok: "h3 origin"\n', 0, 3)
        self.assertEqual([run["ok"] for run in runs], [True, False, False])

    def test_duplicate_and_out_of_range_reports_fail(self):
        for extra in ('run 1 ok: "duplicate"\n', 'run 11 ok: "unexpected"\n'):
            self.assertFalse(any(run["ok"] for run in client_runs(TEN_OK + extra, 0, 10)))


class ChildEnvTest(unittest.TestCase):
    def test_caller_proxy_settings_cannot_bypass_the_tunnel(self):
        env = child_env({"HTTPS_PROXY": "http://wrong:1", "https_proxy": "http://wrong:2", "NO_PROXY": "*"})
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertNotIn("https_proxy", env)
        self.assertEqual(env["NO_PROXY"], "")
    def test_rama_logs_its_shutdown_whatever_the_caller_set(self):
        for caller in ({}, {"RUST_LOG": ""}, {"RUST_LOG": "error"}):
            env = child_env({"PATH": "/bin", **caller})
            self.assertEqual(env["RUST_LOG"], "info")
            self.assertEqual(env["PATH"], "/bin")


if __name__ == "__main__":
    unittest.main()
