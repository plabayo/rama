"""Create a real local CA and origin leaf; neither enters the system trust store."""

from dataclasses import dataclass
from pathlib import Path
import subprocess


@dataclass(frozen=True)
class Identity:
    certificate: Path
    key: Path


def local_identities(root):
    authority = Identity(root / "ca.pem", root / "ca.key")
    origin = Identity(root / "origin.pem", root / "origin.key")
    request = root / "origin.csr"
    extensions = root / "origin.ext"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
    )
    commands = [
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
            "/CN=Owned native relay CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(authority.key),
            "-out",
            str(authority.certificate),
        ],
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(origin.key),
            "-out",
            str(request),
        ],
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(authority.certificate),
            "-CAkey",
            str(authority.key),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            str(extensions),
            "-out",
            str(origin.certificate),
        ],
    ]
    with (root / "certificates.log").open("w") as log:
        for command in commands:
            subprocess.run(
                command,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
                timeout=30,
            )
    authority.key.chmod(0o600)
    origin.key.chmod(0o600)
    return authority, origin
