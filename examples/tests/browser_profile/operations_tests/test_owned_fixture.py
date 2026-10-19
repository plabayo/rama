"""Current replay destination, fixture identity and TLS controls."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import tempfile
import ssl
import unittest
from unittest.mock import patch

from flows import ReplayTarget, replay_args
from fixture_tls import fixture_certificate
from replay import check_tls_hostname
from operations_tests.admission_fixtures import ORIGIN


class OwnedFixtureTests(unittest.TestCase):
    def test_certificate_has_exact_hostname_and_default_localhost_san(self):
        for hostname, san in (
            ("localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1"),
            ("h3.fp.ramaproxy.org", "subjectAltName=DNS:h3.fp.ramaproxy.org"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)

                def generate(command, **kwargs):
                    (root / "key.pem").write_bytes(b"private")
                    (root / "cert.pem").write_bytes(b"cert")
                    self.assertEqual(
                        command[command.index("-subj") + 1], "/CN=" + hostname
                    )
                    self.assertEqual(command[command.index("-addext") + 1], san)

                with patch("fixture_tls.subprocess.run", side_effect=generate), patch(
                    "fixture_tls.subprocess.check_output", return_value=b"public"
                ):
                    key, _, _ = fixture_certificate(root, hostname=hostname)
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        for hostname in (
            "bad/name",
            "bad\nname",
            "-bad.example",
            "a..b",
            "a" * 64 + ".example",
        ):
            with patch("fixture_tls.subprocess.run") as start, self.assertRaises(
                ValueError
            ):
                fixture_certificate(Path("unused"), hostname=hostname)
            start.assert_not_called()

    def test_named_fixture_certificate_verifies_only_its_host(self):
        with tempfile.TemporaryDirectory() as directory:
            key, certificate, _spki = fixture_certificate(
                Path(directory), hostname="h3.fp.ramaproxy.org"
            )
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(certificate, key)
            client_context = ssl.create_default_context(cafile=str(certificate))

            def handshake(hostname):
                client_in, client_out, server_in, server_out = (
                    ssl.MemoryBIO() for _ in range(4)
                )
                client = client_context.wrap_bio(
                    client_in, client_out, server_hostname=hostname
                )
                server = server_context.wrap_bio(
                    server_in, server_out, server_side=True
                )
                finished = [False, False]
                for _ in range(12):
                    for index, peer in enumerate((client, server)):
                        if not finished[index]:
                            try:
                                peer.do_handshake()
                                finished[index] = True
                            except ssl.SSLWantReadError:
                                pass
                    server_in.write(client_out.read())
                    client_in.write(server_out.read())
                    if all(finished):
                        return
                self.fail("owned in-memory handshake did not finish")

            handshake("h3.fp.ramaproxy.org")
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake("x3.fp.ramaproxy.org")

    def test_replay_resolution_is_current_owned_authority_only(self):
        request = SimpleNamespace(
            method="GET", uri="/report", headers=(), bindings={}, body=b""
        )
        target = ReplayTarget(
            "h2",
            ORIGIN,
            Path("fixture.pem"),
            resolve=("h3.fp.ramaproxy.org:32543:127.0.0.1",),
        )
        arguments = replay_args("rama", "archive", "out", target, "navigate", request)
        self.assertEqual(arguments[arguments.index("--resolve") + 1], target.resolve[0])
        self.assertEqual(arguments[-1], ORIGIN + "/report")
        plain = replay_args(
            "rama", "archive", "out", replace(target, resolve=()), "navigate", request
        )
        self.assertNotIn("--resolve", plain)
        for mapping in (
            "other.example:32543:127.0.0.1",
            "h3.fp.ramaproxy.org:32543:198.51.100.7",
            "h3.fp.ramaproxy.org:443:127.0.0.1",
        ):
            with self.subTest(mapping=mapping), self.assertRaises(ValueError):
                replay_args(
                    "rama",
                    "archive",
                    "out",
                    replace(target, resolve=(mapping,)),
                    "navigate",
                    request,
                )

    def test_equal_length_wrong_sni_keeps_trust_and_current_route(self):
        command = [
            "rama",
            "send",
            "--http3",
            "--cacert",
            "fixture.pem",
            "--resolve",
            "h3.fp.ramaproxy.org:32543:127.0.0.1",
            ORIGIN + "/report",
        ]
        with tempfile.TemporaryDirectory() as directory:

            def execute(arguments, **kwargs):
                self.assertEqual(arguments.count("--resolve"), 1)
                self.assertNotIn("h3.fp.ramaproxy.org:32543:127.0.0.1", arguments)
                self.assertEqual(
                    arguments[-1], "https://x3.fp.ramaproxy.org:32543/report"
                )
                self.assertEqual(arguments[-2], "x3.fp.ramaproxy.org:32543:127.0.0.1")
                self.assertEqual(
                    arguments[arguments.index("--cacert") + 1], "fixture.pem"
                )
                self.assertEqual(len(arguments[-1]), len(command[-1]))
                kwargs["stdout"].write("CERTIFICATE_VERIFY_FAILED")
                return SimpleNamespace(returncode=1)

            with patch("replay.subprocess.run", side_effect=execute):
                check_tls_hostname(command, {}, Path(directory))


if __name__ == "__main__":
    unittest.main()
