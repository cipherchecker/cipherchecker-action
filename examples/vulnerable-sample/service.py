"""Sample file for the CipherChecker self-test. Deliberately quantum-vulnerable."""

import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, ec


def make_signing_key():
    # Quantum-critical: RSA private key.
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def make_exchange_key():
    # Quantum-critical: ECDSA / ECDH over P-256.
    return ec.generate_private_key(ec.SECP256R1())


def legacy_digest(data: bytes) -> str:
    # Weakened: SHA-1.
    return hashlib.sha1(data).hexdigest()
