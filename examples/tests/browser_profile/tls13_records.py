"""Authenticate TLS1.3 application records before discarding private traffic keys.

RFC 8446 sections 5.2, 5.3 and 7.3: remove only authenticated trailing zero
padding and the inner content type. Retain counts and hashes, never plaintext or
secrets. Native TLS-follow remains an independent application-stream witness.
"""

import hashlib
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from connection_fields import integer
from flows import require
from pdml import fields, identity, values

CIPHERS = {0x1301: (hashes.SHA256, AESGCM, 16),
           0x1302: (hashes.SHA384, AESGCM, 32),
           0x1303: (hashes.SHA256, ChaCha20Poly1305, 32)}


def expand(secret, label, length, algorithm):
    label = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(label)]) + label + b"\0"
    return HKDFExpand(algorithm=algorithm(), length=length, info=info).derive(secret)


def decrypt_record(raw, secret, cipher, sequence):
    require(cipher in CIPHERS and 0 <= sequence < 1 << 64, "unsupported TLS record parameters")
    algorithm, aead, key_length = CIPHERS[cipher]
    require(len(secret) == algorithm().digest_size, "TLS traffic secret length differs")
    require(len(raw) >= 22 and raw[:3] == b"\x17\x03\x03"
            and int.from_bytes(raw[3:5], "big") == len(raw) - 5
            and len(raw) - 5 <= (1 << 14) + 256, "invalid protected TLS record extent")
    key = expand(secret, b"key", key_length, algorithm)
    iv = expand(secret, b"iv", 12, algorithm)
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    try:
        plaintext = aead(key).decrypt(nonce, raw[5:], raw[:5])
    except InvalidTag:
        raise ValueError("TLS application record authentication failed") from None
    unpadded = plaintext.rstrip(b"\0")
    require(unpadded and unpadded[-1] == 23, "TLS application inner content type differs")
    return unpadded[:-1], len(plaintext) - len(unpadded)


def secrets_for(keylog, random):
    path = Path(keylog)
    require(path.stat().st_size <= 4 * 1024 * 1024, "TLS keylog byte budget")
    result = {}
    labels = {"CLIENT_TRAFFIC_SECRET_0": False, "SERVER_TRAFFIC_SECRET_0": True}
    for line in path.read_text().splitlines():
        parts = line.split()
        if not parts or parts[0].startswith("#") or parts[0] not in labels:
            continue
        require(len(parts) == 3, "malformed application traffic secret")
        if parts[1].lower() != random.hex():
            continue
        side, secret = labels[parts[0]], bytes.fromhex(parts[2])
        require(side not in result or result[side] == secret, "conflicting application traffic secrets")
        result[side] = secret
    return result


def application_witness(rows, bodies, records, keylog):
    selected = [(side, offset, length, node) for (side, offset), (length, kind, node)
                in sorted(records.items()) if kind == 23 and bodies[side][offset] == 23]
    if not selected:
        return dict(records=[], client=digest(b""), server=digest(b""))
    hellos = [node for row in rows for node in fields(row["packet"], "tls.handshake")]
    clients = [node for node in hellos if values(node, "tls.handshake.type") == ["1"]]
    servers = [node for node in hellos if values(node, "tls.handshake.type") == ["2"]]
    require(len(clients) == len(servers) == 1, "TLS record witness needs one handshake")
    randoms = fields(clients[0], "tls.handshake.random")
    require(len(randoms) == 1, "ambiguous TLS client random")
    random = bytes.fromhex(randoms[0].get("value", ""))
    require(len(random) == 32, "TLS client random length differs")
    cipher = integer(servers[0], "tls.handshake.ciphersuite", 2)
    secrets = secrets_for(keylog, random)
    content, details = {False: bytearray(), True: bytearray()}, []
    for side, offset, length, node in selected:
        require(side in secrets, "missing TLS application traffic secret")
        sequence = identity(node, "tls.record.sequence_number")
        raw = bodies[side][offset:offset + 5 + length]
        data, padding = decrypt_record(raw, secrets[side], cipher, sequence)
        content[side].extend(data)
        details.append(dict(side="server" if side else "client", offset=offset,
                            sequence=sequence, ciphertext_sha256=hashlib.sha256(raw).hexdigest(),
                            content_bytes=len(data), padding_bytes=padding))
    return dict(records=details, client=digest(content[False]), server=digest(content[True]))


def digest(data):
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
