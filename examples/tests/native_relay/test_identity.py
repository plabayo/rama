"""Check the real chain used by independent native relay clients and origins."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from identity import local_identities


class FixtureIdentityTests(unittest.TestCase):
    def test_origin_leaf_has_a_valid_local_ca_chain_and_server_purpose(self):
        with tempfile.TemporaryDirectory() as directory:
            authority, origin = local_identities(Path(directory))
            # A directly trusted anchor can bypass CA checks in LibreSSL's
            # verify command. Inspect the generated signing permission too;
            # the external Go client enforces it during the real handshake.
            authority_details = subprocess.check_output(
                [
                    "openssl",
                    "x509",
                    "-in",
                    str(authority.certificate),
                    "-text",
                    "-noout",
                ],
                text=True,
                timeout=10,
            )
            self.assertRegex(
                authority_details, r"X509v3 Basic Constraints: critical\s+CA:TRUE"
            )
            result = subprocess.run(
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    str(authority.certificate),
                    "-purpose",
                    "sslserver",
                    str(origin.certificate),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(authority.key.stat().st_mode & 0o777, 0o600)
            self.assertEqual(origin.key.stat().st_mode & 0o777, 0o600)
