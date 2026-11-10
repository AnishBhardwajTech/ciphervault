"""Vault logic: master-password authentication and encrypted records.

How authentication works
------------------------
On registration we derive a key from the master password and a fresh salt,
then encrypt a fixed "verifier" token with it. The password itself is never
stored. To log in we derive the key again and try to decrypt the verifier:
AES-GCM's authentication tag only checks out with the right key.

After MAX_FAILED_ATTEMPTS wrong passwords the account is locked for
LOCKOUT_MINUTES. Every login attempt is written to the audit_log table.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import crypto
from .db import Database

VERIFIER_TOKEN = b"ciphervault-verifier-v1"
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


class AuthError(Exception):
    """Wrong username or master password."""


class VaultLocked(Exception):
    """Too many failed attempts; account temporarily locked."""


class EntryNotFound(KeyError):
    pass


@dataclass
class Entry:
    name: str
    secret: str
    username: str = ""
    url: str = ""
    notes: str = ""

    def to_bytes(self) -> bytes:
        return json.dumps(self.__dict__).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "Entry":
        return cls(**json.loads(data))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _parse_ts(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


class Vault:
    """An unlocked vault for one user. Create with Vault.register / Vault.unlock."""

    def __init__(self, db: Database, user_id: int, username: str, key: bytes):
        self._db = db
        self._user_id = user_id
        self.username = username
        self._key = key

    # -- account --------------------------------------------------------
    @classmethod
    def register(cls, db: Database, username: str, master_password: str,
                 iterations: int | None = None) -> "Vault":
        iterations = iterations or crypto.DEFAULT_ITERATIONS
        if len(master_password) < 12:
            raise ValueError("master password must be at least 12 characters")
        if db.fetchone("SELECT id FROM users WHERE username = ?", (username,)):
            raise ValueError(f"user {username!r} already exists")
        salt = crypto.new_salt()
        key = crypto.derive_key(master_password, salt, iterations)
        nonce, verifier = crypto.encrypt(key, VERIFIER_TOKEN, username.encode())
        db.execute(
            "INSERT INTO users (username, salt, kdf_iterations, verifier_nonce, verifier) "
            "VALUES (?, ?, ?, ?, ?)",
            (username, salt, iterations, nonce, verifier),
        )
        user_id = db.fetchone("SELECT id FROM users WHERE username = ?", (username,))[0]
        cls._audit(db, username, "register", True)
        db.commit()
        return cls(db, user_id, username, key)

    @classmethod
    def unlock(cls, db: Database, username: str, master_password: str) -> "Vault":
        row = db.fetchone(
            "SELECT id, salt, kdf_iterations, verifier_nonce, verifier, failed_attempts, locked_until "
            "FROM users WHERE username = ?",
            (username,),
        )
        if row is None:
            cls._audit(db, username, "login", False)
            db.commit()
            raise AuthError("invalid username or master password")
        user_id, salt, iterations, v_nonce, verifier, failed, locked_until = row

        locked_until = _parse_ts(locked_until)
        if locked_until and locked_until > _utcnow():
            cls._audit(db, username, "login_locked", False)
            db.commit()
            raise VaultLocked(f"account locked until {locked_until:%Y-%m-%d %H:%M} UTC")

        key = crypto.derive_key(master_password, bytes(salt), iterations)
        try:
            token = crypto.decrypt(key, bytes(v_nonce), bytes(verifier), username.encode())
            if token != VERIFIER_TOKEN:
                raise crypto.DecryptionError
        except crypto.DecryptionError:
            failed += 1
            lock = _utcnow() + timedelta(minutes=LOCKOUT_MINUTES) if failed >= MAX_FAILED_ATTEMPTS else None
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (0 if lock else failed, lock.isoformat(sep=" ") if lock else None, user_id),
            )
            cls._audit(db, username, "login", False)
            db.commit()
            if lock:
                raise VaultLocked(f"too many failed attempts; locked for {LOCKOUT_MINUTES} minutes")
            raise AuthError("invalid username or master password")

        db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
        cls._audit(db, username, "login", True)
        db.commit()
        return cls(db, user_id, username, key)

    def change_master_password(self, old_password: str, new_password: str) -> None:
        """Re-derive the key and re-encrypt every entry in one transaction."""
        Vault.unlock(self._db, self.username, old_password)  # re-authenticate
        if len(new_password) < 12:
            raise ValueError("master password must be at least 12 characters")
        entries = [self.get(n) for n in self.list_names()]
        salt = crypto.new_salt()
        iterations = crypto.DEFAULT_ITERATIONS
        new_key = crypto.derive_key(new_password, salt, iterations)
        nonce, verifier = crypto.encrypt(new_key, VERIFIER_TOKEN, self.username.encode())
        try:
            self._db.execute(
                "UPDATE users SET salt = ?, kdf_iterations = ?, verifier_nonce = ?, verifier = ? WHERE id = ?",
                (salt, iterations, nonce, verifier, self._user_id),
            )
            self._key = new_key
            for e in entries:
                n, ct = crypto.encrypt(new_key, e.to_bytes(), self._aad(e.name))
                self._db.execute(
                    "UPDATE entries SET nonce = ?, ciphertext = ? WHERE user_id = ? AND name = ?",
                    (n, ct, self._user_id, e.name),
                )
            self._audit(self._db, self.username, "change_password", True)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def lock(self) -> None:
        """Drop the key from memory."""
        self._key = b""

    # -- entries --------------------------------------------------------
    def add(self, entry: Entry, overwrite: bool = False) -> None:
        nonce, ct = crypto.encrypt(self._require_key(), entry.to_bytes(), self._aad(entry.name))
        exists = self._db.fetchone(
            "SELECT id FROM entries WHERE user_id = ? AND name = ?", (self._user_id, entry.name)
        )
        if exists and not overwrite:
            raise ValueError(f"entry {entry.name!r} already exists")
        if exists:
            self._db.execute(
                f"UPDATE entries SET nonce = ?, ciphertext = ?, updated_at = {self._db.now_sql()} WHERE id = ?",
                (nonce, ct, exists[0]),
            )
        else:
            self._db.execute(
                "INSERT INTO entries (user_id, name, nonce, ciphertext) VALUES (?, ?, ?, ?)",
                (self._user_id, entry.name, nonce, ct),
            )
        self._db.commit()

    def get(self, name: str) -> Entry:
        row = self._db.fetchone(
            "SELECT nonce, ciphertext FROM entries WHERE user_id = ? AND name = ?", (self._user_id, name)
        )
        if row is None:
            raise EntryNotFound(name)
        plaintext = crypto.decrypt(self._require_key(), bytes(row[0]), bytes(row[1]), self._aad(name))
        return Entry.from_bytes(plaintext)

    def list_names(self) -> list[str]:
        rows = self._db.fetchall(
            "SELECT name FROM entries WHERE user_id = ? ORDER BY name", (self._user_id,)
        )
        return [r[0] for r in rows]

    def delete(self, name: str) -> None:
        cur = self._db.execute("DELETE FROM entries WHERE user_id = ? AND name = ?", (self._user_id, name))
        if cur.rowcount == 0:
            raise EntryNotFound(name)
        self._db.commit()

    # -- internals ------------------------------------------------------
    def _aad(self, name: str) -> bytes:
        return f"{self._user_id}:{name}".encode("utf-8")

    def _require_key(self) -> bytes:
        if not self._key:
            raise AuthError("vault is locked")
        return self._key

    @staticmethod
    def _audit(db: Database, username: str, action: str, success: bool) -> None:
        db.execute(
            "INSERT INTO audit_log (username, action, success) VALUES (?, ?, ?)",
            (username, action, 1 if success else 0),
        )
