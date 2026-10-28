"""
vault_crypto.py
----------------
Encryption primitives for the password manager.

Design:
- Master password is NEVER stored anywhere, on disk or in memory longer
  than needed to derive a key.
- Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023+
  recommendation for PBKDF2-SHA256), with a random 16-byte salt stored
  alongside the vault (salt is not secret).
- Encryption: AES-256-GCM (authenticated encryption - detects tampering,
  not just confidentiality).
- Each save generates a fresh random 12-byte nonce (GCM requirement:
  never reuse a nonce with the same key).
"""

import os
import json
import base64
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256


class VaultError(Exception):
    """Raised for vault-level errors (wrong password, corrupt file, etc.)."""
    pass


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the master password + salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(master_password.encode("utf-8"))


def encrypt_payload(key: bytes, plaintext_bytes: bytes) -> tuple[bytes, bytes]:
    """Encrypt bytes with AES-256-GCM. Returns (nonce, ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
    return nonce, ciphertext


def decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt bytes with AES-256-GCM. Raises on wrong key or tampering."""
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        raise VaultError("Incorrect master password or corrupted vault.") from e


@dataclass
class VaultFile:
    """On-disk representation of the encrypted vault."""
    salt: bytes
    nonce: bytes
    ciphertext: bytes

    def to_json(self) -> str:
        return json.dumps({
            "version": 1,
            "kdf": "pbkdf2-sha256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }, indent=2)

    @staticmethod
    def from_json(data: str) -> "VaultFile":
        obj = json.loads(data)
        return VaultFile(
            salt=base64.b64decode(obj["salt"]),
            nonce=base64.b64decode(obj["nonce"]),
            ciphertext=base64.b64decode(obj["ciphertext"]),
        )


def save_vault(path: str, master_password: str, data_dict: dict) -> None:
    """Encrypt `data_dict` and write it to `path`."""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(master_password, salt)
    plaintext = json.dumps(data_dict).encode("utf-8")
    nonce, ciphertext = encrypt_payload(key, plaintext)
    vf = VaultFile(salt=salt, nonce=nonce, ciphertext=ciphertext)
    with open(path, "w") as f:
        f.write(vf.to_json())


def save_vault_existing_salt(path: str, master_password: str, salt: bytes, data_dict: dict) -> None:
    """Re-encrypt with the SAME salt (used on every save after unlock,
    so the key derivation doesn't change and we don't need to re-prompt)."""
    key = derive_key(master_password, salt)
    plaintext = json.dumps(data_dict).encode("utf-8")
    nonce, ciphertext = encrypt_payload(key, plaintext)
    vf = VaultFile(salt=salt, nonce=nonce, ciphertext=ciphertext)
    with open(path, "w") as f:
        f.write(vf.to_json())


def load_vault(path: str, master_password: str) -> dict:
    """Decrypt and return the vault's data dict. Raises VaultError on wrong password."""
    with open(path, "r") as f:
        vf = VaultFile.from_json(f.read())
    key = derive_key(master_password, vf.salt)
    plaintext = decrypt_payload(key, vf.nonce, vf.ciphertext)
    return json.loads(plaintext.decode("utf-8")), vf.salt


def vault_exists(path: str) -> bool:
    return os.path.isfile(path)
