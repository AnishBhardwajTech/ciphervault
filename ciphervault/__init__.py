"""CipherVault: an encrypted secret vault with password-derived keys."""

from .vault import Vault, AuthError, VaultLocked, EntryNotFound

__all__ = ["Vault", "AuthError", "VaultLocked", "EntryNotFound"]
__version__ = "1.0.0"
