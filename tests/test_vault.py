import pytest

from ciphervault.vault import (
    MAX_FAILED_ATTEMPTS, AuthError, Entry, EntryNotFound, Vault, VaultLocked,
)
from conftest import FAST

PW = "a-long-master-password"


def test_register_and_unlock(db):
    Vault.register(db, "anish", PW, FAST)
    assert Vault.unlock(db, "anish", PW).username == "anish"


def test_password_never_stored(db):
    Vault.register(db, "anish", PW, FAST)
    for row in db.fetchall("SELECT * FROM users"):
        assert all(PW.encode() not in (v if isinstance(v, bytes) else str(v).encode()) for v in row)


def test_short_master_password_rejected(db):
    with pytest.raises(ValueError):
        Vault.register(db, "anish", "short", FAST)


def test_duplicate_user_rejected(db):
    Vault.register(db, "anish", PW, FAST)
    with pytest.raises(ValueError):
        Vault.register(db, "anish", PW, FAST)


def test_wrong_password(db):
    Vault.register(db, "anish", PW, FAST)
    with pytest.raises(AuthError):
        Vault.unlock(db, "anish", "wrong-password-here")


def test_unknown_user(db):
    with pytest.raises(AuthError):
        Vault.unlock(db, "nobody", PW)


def test_lockout_after_failed_attempts(db):
    Vault.register(db, "anish", PW, FAST)
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        with pytest.raises(AuthError):
            Vault.unlock(db, "anish", "wrong-password-here")
    with pytest.raises(VaultLocked):
        Vault.unlock(db, "anish", "wrong-password-here")
    with pytest.raises(VaultLocked):  # even the right password is refused while locked
        Vault.unlock(db, "anish", PW)


def test_audit_log_records_attempts(db):
    Vault.register(db, "anish", PW, FAST)
    Vault.unlock(db, "anish", PW)
    with pytest.raises(AuthError):
        Vault.unlock(db, "anish", "wrong-password-here")
    rows = db.fetchall("SELECT action, success FROM audit_log ORDER BY id")
    assert [(a, int(s)) for a, s in rows] == [("register", 1), ("login", 1), ("login", 0)]


def test_add_get_list_delete(db):
    v = Vault.register(db, "anish", PW, FAST)
    v.add(Entry("github", "s3cret", username="anish", url="https://github.com"))
    v.add(Entry("aws", "AKIA..."))
    assert v.list_names() == ["aws", "github"]
    assert v.get("github").secret == "s3cret"
    v.delete("aws")
    assert v.list_names() == ["github"]
    with pytest.raises(EntryNotFound):
        v.get("aws")


def test_secrets_are_encrypted_at_rest(db):
    v = Vault.register(db, "anish", PW, FAST)
    v.add(Entry("github", "plain-text-secret"))
    (ct,) = db.fetchone("SELECT ciphertext FROM entries")
    assert b"plain-text-secret" not in bytes(ct)


def test_duplicate_entry_needs_overwrite(db):
    v = Vault.register(db, "anish", PW, FAST)
    v.add(Entry("github", "one"))
    with pytest.raises(ValueError):
        v.add(Entry("github", "two"))
    v.add(Entry("github", "two"), overwrite=True)
    assert v.get("github").secret == "two"


def test_users_are_isolated(db):
    a = Vault.register(db, "anish", PW, FAST)
    b = Vault.register(db, "bob", "bobs-long-password", FAST)
    a.add(Entry("github", "anish-secret"))
    assert b.list_names() == []
    with pytest.raises(EntryNotFound):
        b.get("github")


def test_swapped_ciphertext_rejected(db):
    """A row's ciphertext copied onto another entry must not decrypt (AAD binding)."""
    v = Vault.register(db, "anish", PW, FAST)
    v.add(Entry("github", "gh"))
    v.add(Entry("gmail", "gm"))
    nonce, ct = db.fetchone("SELECT nonce, ciphertext FROM entries WHERE name = 'github'")
    db.execute("UPDATE entries SET nonce = ?, ciphertext = ? WHERE name = 'gmail'", (nonce, ct))
    with pytest.raises(Exception):
        v.get("gmail")


def test_change_master_password(db):
    v = Vault.register(db, "anish", PW, FAST)
    v.add(Entry("github", "s3cret"))
    v.change_master_password(PW, "a-brand-new-master-pw")
    with pytest.raises(AuthError):
        Vault.unlock(db, "anish", PW)
    assert Vault.unlock(db, "anish", "a-brand-new-master-pw").get("github").secret == "s3cret"


def test_locked_vault_refuses_access(db):
    v = Vault.register(db, "anish", PW, FAST)
    v.add(Entry("github", "s3cret"))
    v.lock()
    with pytest.raises(AuthError):
        v.get("github")
