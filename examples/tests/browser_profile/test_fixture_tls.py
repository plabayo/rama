"""Use the actual NSS verifier to prove fixture trust stays profile-local."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from fixture_tls import fixture_certificate, prepare_nss_trust


class FixtureTlsTests(unittest.TestCase):
    @unittest.skipUnless(
        shutil.which("openssl") and shutil.which("certutil"),
        "OpenSSL and NSS certutil required",
    )
    def test_nss_accepts_only_the_certificate_installed_in_the_owned_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _key, certificate, _spki = fixture_certificate(root)
            profile = root / "profile"
            profile.mkdir()
            prepare_nss_trust(profile, certificate=certificate, log=root / "nss.log")
            command = [
                "certutil",
                "-V",
                "-u",
                "V",
                "-n",
                "Owned localhost fixture",
                "-d",
                "sql:" + str(profile),
            ]
            accepted = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(
                accepted.returncode,
                0,
                "the owned fixture certificate must verify with NSS",
            )
            # Removing its SSL CA trust must restore rejection. No system trust
            # store or real browser profile is involved in either verification.
            subprocess.run(
                [
                    "certutil",
                    "-M",
                    "-t",
                    ",,",
                    "-n",
                    "Owned localhost fixture",
                    "-d",
                    "sql:" + str(profile),
                ],
                check=True,
                capture_output=True,
                timeout=10,
            )
            rejected = subprocess.run(command, capture_output=True, timeout=10)
            self.assertNotEqual(
                rejected.returncode, 0, "an untrusted self-signed fixture must reject"
            )

    def test_nss_setup_rejects_an_existing_profile_database_before_touching_it(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            for name in ("cert9.db", "user.js"):
                database = profile / name
                database.write_bytes(b"existing profile data")
                with self.subTest(name=name), self.assertRaisesRegex(
                    ValueError, "fresh NSS"
                ):
                    prepare_nss_trust(
                        profile,
                        certificate=profile / "missing.pem",
                        log=profile / "nss.log",
                    )
                self.assertEqual(database.read_bytes(), b"existing profile data")
                self.assertFalse((profile / "nss.log").exists())
                database.unlink()


if __name__ == "__main__":
    unittest.main()
