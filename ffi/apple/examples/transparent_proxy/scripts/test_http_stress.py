"""Exercise the load tool against a local HTTP origin."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest

from stress_traffic import Results, transfer


class Origin(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = b"complete response"
        self.send_response(503 if self.path == "/error" else 200)
        self.send_header("Content-Length", str(len(body) + (10 if self.path == "/truncated" else 0)))
        self.end_headers()
        self.wfile.write(body)


class HttpStressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(timeout=5)

    def test_complete_response_counts_exact_download(self):
        elapsed, downloaded, error = transfer(
            "curl", f"http://127.0.0.1:{self.server.server_port}/ok", [], 2)
        self.assertIsNone(error)
        self.assertEqual(downloaded, len(b"complete response"))
        self.assertGreater(elapsed, 0)

    def test_truncated_success_and_error_status_are_failures(self):
        for path in ("truncated", "error"):
            with self.subTest(path=path):
                _, _, error = transfer(
                    "curl", f"http://127.0.0.1:{self.server.server_port}/{path}", [], 2)
                self.assertIsNotNone(error)

    def test_summary_does_not_hide_failures_or_unbound_latency_storage(self):
        results = Results()
        for _ in range(100):
            results.record("get", 0.003, 10, None)
        results.record("get", 0.020, 0, "failed")
        summary = results.summary(2)["get"]
        self.assertEqual(summary["requests"], 101)
        self.assertEqual(summary["failures"], 1)
        self.assertEqual(summary["downloaded_bytes"], 1000)
        self.assertEqual(summary["p95_latency_upper_bound_ms"], 4)
        self.assertEqual(len(results.classes["get"]["latency_buckets_ms"]), 2)


if __name__ == "__main__":
    unittest.main()
