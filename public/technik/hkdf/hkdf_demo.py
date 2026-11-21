"""Offline learning example for AuthzLedger. Run with Python and cryptography.

ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
Public test data from RFC 5869, Appendix A.1.
"""

import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand


def expand(prk, info, size):
    return HKDFExpand(hashes.SHA256(), length=size, info=info).derive(prk)


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify_reference():
    ikm = bytes([0x0B]) * 22
    salt = bytes(range(13))
    info = bytes(range(0xF0, 0xFA))
    expected_prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    expected_okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    prk = hmac.digest(salt, ikm, "sha256")
    okm = expand(prk, info, 42)
    combined = HKDF(hashes.SHA256(), length=42, salt=salt, info=info).derive(ikm)
    check(prk == expected_prk, "RFC 5869 A.1: PRK mismatch")
    check(okm == expected_okm == combined, "RFC 5869 A.1: OKM mismatch")
    print("PASS  RFC 5869 A.1: PRK (32 bytes), OKM (42 bytes)")


def traffic_keys(secret, salt, client_public, server_public):
    # Roles have a fixed order; both encoded public keys are exactly 32 bytes.
    transcript = hashlib.sha256(client_public + server_public).digest()
    context = b"AuthzLedger/offline-lesson/v1/X25519/HKDF-SHA256/" + transcript
    prk = hmac.digest(salt, secret, "sha256")
    return (
        expand(prk, context + b"/client-to-server", 32),
        expand(prk, context + b"/server-to-client", 32),
    )


def verify_roles():
    client = X25519PrivateKey.generate()
    server = X25519PrivateKey.generate()
    client_public = client.public_key().public_bytes_raw()
    server_public = server.public_key().public_bytes_raw()
    salt = secrets.token_bytes(32)
    client_secret = client.exchange(server.public_key())
    server_secret = server.exchange(client.public_key())

    client_keys = traffic_keys(client_secret, salt, client_public, server_public)
    server_keys = traffic_keys(server_secret, salt, client_public, server_public)
    check(client_keys == server_keys, "Peers disagree")
    check(client_keys[0] != client_keys[1], "Direction labels were not separated")
    reversed_context = traffic_keys(server_secret, salt, server_public, client_public)
    check(client_keys[0] != reversed_context[0], "Role binding was lost")
    print("PASS  Both peers agree, directions differ, swapped role context differs")


if __name__ == "__main__":
    verify_reference()
    verify_roles()
