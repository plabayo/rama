"""Ephemeral fixture identity and browser-local trust, never system trust."""

import base64
import hashlib
import subprocess


def fixture_certificate(root):
    """Return a server key, server certificate, fixture CA and Chromium SPKI."""
    key, certificate = root / "key.pem", root / "cert.pem"
    ca_key, ca = root / "ca-key.pem", root / "ca.pem"
    request = root / "server.csr"
    config = root / "openssl.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n"
        "[server]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
    )
    commands = [
        ["openssl", "req", "-config", str(config), "-x509", "-newkey",
         "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Owned fixture CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", str(ca_key), "-out", str(ca)],
        ["openssl", "req", "-config", str(config), "-new", "-newkey",
         "rsa:2048", "-nodes", "-subj", "/CN=localhost",
         "-keyout", str(key), "-out", str(request)],
        ["openssl", "x509", "-req", "-in", str(request), "-CA", str(ca),
         "-CAkey", str(ca_key), "-set_serial", "1", "-days", "1",
         "-extfile", str(config), "-extensions", "server", "-out", str(certificate)],
    ]
    with (root / "certificate.log").open("w") as log:
        for command in commands:
            subprocess.run(
                command, check=True, stdout=log, stderr=subprocess.STDOUT, timeout=30
            )
    key.chmod(0o600)
    ca_key.unlink()
    request.unlink()
    public = subprocess.check_output(
        ["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"], timeout=10
    )
    der = subprocess.check_output(
        ["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, timeout=10
    )
    return key, certificate, ca, base64.b64encode(hashlib.sha256(der).digest()).decode()


def prepare_nss_trust(profile, *, certificate, log):
    """Trust this fixture CA before Firefox starts in its new owned profile."""
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
