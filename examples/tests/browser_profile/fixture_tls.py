"""Ephemeral fixture identity and browser-local trust, never system trust."""

import base64
import hashlib
import subprocess


def fixture_certificate(root):
    """Create the owned localhost identity and its Chromium SPKI exception."""
    key, certificate = root / "key.pem", root / "cert.pem"
    with (root / "certificate.log").open("w") as log:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ],
            check=True,
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=30,
        )
    key.chmod(0o600)
    public = subprocess.check_output(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"], timeout=10
    )
    der = subprocess.check_output(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, timeout=10
    )
    return key, certificate, base64.b64encode(hashlib.sha256(der).digest()).decode()


def prepare_nss_trust(profile, *, certificate, log):
    """Install this fixture CA before Firefox starts in its new owned profile."""
    if any(profile.iterdir()):
        raise ValueError("fixture requires a fresh NSS trust store")
    database = "sql:" + str(profile)
    with log.open("w") as output:
        for command in [
            ["certutil", "-N", "-d", database, "--empty-password"],
            [
                "certutil",
                "-A",
                "-n",
                "Owned localhost fixture",
                "-t",
                "C,,",
                "-i",
                str(certificate),
                "-d",
                database,
            ],
        ]:
            subprocess.run(
                command, check=True, stdout=output, stderr=subprocess.STDOUT, timeout=10
            )
