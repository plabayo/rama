"""Unit tests for the interop harness's own verdicts."""

import unittest

from run import answered_over_http3, child_env, client_runs, curl_proxy_protocols, tunnels_opened

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


class CurlVerdictTest(unittest.TestCase):
    def test_only_a_200_over_http3_counts(self):
        self.assertTrue(answered_over_http3("* using HTTP/3\n< HTTP/3 200\n< content-length: 4\n"))
        for other in ("< HTTP/2 200\n", "< HTTP/3 502\n", "> HTTP/3 200\n", ""):
            self.assertFalse(answered_over_http3(other))

    def test_only_opened_tunnels_to_the_target_count(self):
        log = "\n".join([
            'INFO audit: opened event="tunnel_opened" tunnel.id=1 tunnel.target=127.0.0.1:443 tunnel.address=x',
            'INFO audit: opened event="tunnel_opened" tunnel.id=2 tunnel.target=127.0.0.1:4430 tunnel.address=x',
            'INFO audit: closed event="tunnel_closed" tunnel.id=1 tunnel.target=127.0.0.1:443',
        ])
        self.assertEqual(tunnels_opened(log, "127.0.0.1:443"), 1)
        self.assertEqual(tunnels_opened(log, "127.0.0.1:4430"), 1)
        self.assertEqual(tunnels_opened(log, "127.0.0.1:44"), 0)

    def test_the_proxy_protocol_is_the_one_curl_completed_its_phase_over(self):
        h2 = "* CONNECT-UDP: 'h2' negotiated\n* CONNECT-UDP phase completed for HTTP/2 proxy\n< HTTP/3 200\n"
        h1 = "* CONNECT-UDP: 'http/1.1' negotiated\n* CONNECT-UDP phase completed for HTTP proxy\n"
        h3 = "* CONNECT-UDP phase completed for HTTP/3 proxy\n"
        self.assertEqual(curl_proxy_protocols(h2), {"h2"})
        self.assertEqual(curl_proxy_protocols(h1), {"h1"})
        self.assertEqual(curl_proxy_protocols(h3), {"h3"})
        # An HTTP/2 row that fell back to HTTP/1.1 does not pass as HTTP/2.
        self.assertNotEqual(curl_proxy_protocols(h1), {"h2"})
        self.assertEqual(curl_proxy_protocols("* using HTTP/3\n< HTTP/3 200\n"), set())
