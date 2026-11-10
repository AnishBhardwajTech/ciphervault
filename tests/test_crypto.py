import pytest

from ciphervault import crypto


def test_same_password_and_salt_give_same_key():
    salt = crypto.new_salt()
    assert crypto.derive_key("correct horse", salt, 1000) == crypto.derive_key("correct horse", salt, 1000)


def test_different_salt_gives_different_key():
    assert crypto.derive_key("pw", crypto.new_salt(), 1000) != crypto.derive_key("pw", crypto.new_salt(), 1000)


def test_key_is_256_bits():
    assert len(crypto.derive_key("pw", crypto.new_salt(), 1000)) == 32


def test_empty_password_rejected():
    with pytest.raises(ValueError):
        crypto.derive_key("", crypto.new_salt(), 1000)


def test_encrypt_roundtrip():
    key = crypto.derive_key("pw", crypto.new_salt(), 1000)
    nonce, ct = crypto.encrypt(key, b"hello", b"aad")
    assert b"hello" not in ct
    assert crypto.decrypt(key, nonce, ct, b"aad") == b"hello"


def test_nonce_is_unique_per_encryption():
    key = crypto.derive_key("pw", crypto.new_salt(), 1000)
    n1, c1 = crypto.encrypt(key, b"same")
    n2, c2 = crypto.encrypt(key, b"same")
    assert n1 != n2 and c1 != c2


def test_wrong_key_fails():
    key = crypto.derive_key("pw", crypto.new_salt(), 1000)
    nonce, ct = crypto.encrypt(key, b"secret")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(crypto.derive_key("other", crypto.new_salt(), 1000), nonce, ct)


def test_tampered_ciphertext_fails():
    key = crypto.derive_key("pw", crypto.new_salt(), 1000)
    nonce, ct = crypto.encrypt(key, b"secret")
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, nonce, tampered)


def test_wrong_aad_fails():
    key = crypto.derive_key("pw", crypto.new_salt(), 1000)
    nonce, ct = crypto.encrypt(key, b"secret", b"1:github")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, nonce, ct, b"1:gmail")


@pytest.mark.parametrize("length", [8, 20, 64])
def test_generate_password(length):
    pw = crypto.generate_password(length)
    assert len(pw) == length
    assert any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)


def test_generate_password_too_short():
    with pytest.raises(ValueError):
        crypto.generate_password(4)
