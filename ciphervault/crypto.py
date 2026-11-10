"""Cryptographic primitives.

* Keys are derived from the master password with PBKDF2-HMAC-SHA256 and a
  random 16-byte salt per user (600,000 iterations, the OWASP 2023 baseline).
* Records are encrypted with AES-256-GCM, which gives confidentiality and
  integrity: any tampering with the ciphertext makes decryption fail.
* Each encryption uses a fresh random 12-byte nonce.
* Associated data binds a ciphertext to its owner and entry name, so a row
  cannot be copied onto another entry in the database and still decrypt.
"""

from __future__ import annotations

import os
import secrets
import string

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32  # AES-256
DEFAULT_ITERATIONS = 600_000


class DecryptionError(Exception):
    """Raised when a ciphertext fails authentication (wrong key or tampered)."""


def new_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    if not password:
        raise ValueError("password must not be empty")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext_with_tag)."""
    nonce = os.urandom(NONCE_BYTES)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc


def generate_password(length: int = 20, symbols: bool = True) -> str:
    """Cryptographically random password with at least one of each character class."""
    if length < 8:
        raise ValueError("length must be at least 8")
    classes = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if symbols:
        classes.append("!@#$%^&*()-_=+[]{}")
    alphabet = "".join(classes)
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if all(any(c in cls for c in pwd) for cls in classes):
            return pwd
