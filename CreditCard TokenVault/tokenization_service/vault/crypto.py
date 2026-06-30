"""
Envelope encryption helpers for the tokenization vault.

Design:
- A Master Key (KEK - Key Encryption Key) lives outside this process in
  production (AWS KMS, GCP KMS, Thales/Luna HSM, HashiCorp Vault Transit, etc).
  Here it's simulated via an env var ONLY for local development/testing.
- For every PAN we generate a fresh random Data Encryption Key (DEK),
  encrypt the PAN with the DEK (AES-256-GCM), then encrypt the DEK with
  the KEK ("wrapping"). We store the wrapped DEK + ciphertext, never the
  raw DEK or raw PAN.
- This means compromising the database alone is not enough to recover
  PANs; the attacker would also need the KEK held by the external KMS/HSM.

PRODUCTION NOTE:
Replace `LocalKEKProvider` with a real KMS/HSM client (boto3 kms.encrypt /
kms.decrypt, or an HSM PKCS#11 call). Never let the KEK touch application
memory in plaintext for longer than a single wrap/unwrap call, and never
log it.
"""
import os
import base64
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KEKProvider:
    """Interface a real KMS/HSM client should implement."""

    def wrap_key(self, plaintext_dek: bytes) -> bytes:
        raise NotImplementedError

    def unwrap_key(self, wrapped_dek: bytes) -> bytes:
        raise NotImplementedError


class LocalKEKProvider(KEKProvider):
    """
    DEV/TEST ONLY. Uses a 256-bit key from the TOKENIZATION_MASTER_KEY env
    var to wrap/unwrap DEKs with AES-256-GCM.

    DO NOT use this in production. Swap for a KMS/HSM-backed provider
    (see module docstring) before handling real cardholder data.
    """

    def __init__(self):
        key_b64 = os.environ.get("TOKENIZATION_MASTER_KEY")
        if not key_b64:
            raise RuntimeError(
                "TOKENIZATION_MASTER_KEY env var not set. "
                "Generate one with: python -c \"import os,base64;"
                "print(base64.b64encode(os.urandom(32)).decode())\""
            )
        self._kek = base64.b64decode(key_b64)
        if len(self._kek) != 32:
            raise RuntimeError("Master key must decode to 32 bytes (AES-256).")

    def wrap_key(self, plaintext_dek: bytes) -> bytes:
        aesgcm = AESGCM(self._kek)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, plaintext_dek, None)
        return nonce + ct  # nonce || ciphertext+tag

    def unwrap_key(self, wrapped_dek: bytes) -> bytes:
        aesgcm = AESGCM(self._kek)
        nonce, ct = wrapped_dek[:12], wrapped_dek[12:]
        return aesgcm.decrypt(nonce, ct, None)


@dataclass
class EncryptedRecord:
    ciphertext: bytes      # AES-GCM(PAN) -> nonce || ct+tag
    wrapped_dek: bytes     # KEK-wrapped DEK


def encrypt_pan(pan: str, kek_provider: KEKProvider) -> EncryptedRecord:
    dek = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, pan.encode("utf-8"), None)
    wrapped_dek = kek_provider.wrap_key(dek)
    return EncryptedRecord(ciphertext=nonce + ct, wrapped_dek=wrapped_dek)


def decrypt_pan(record: EncryptedRecord, kek_provider: KEKProvider) -> str:
    dek = kek_provider.unwrap_key(record.wrapped_dek)
    aesgcm = AESGCM(dek)
    nonce, ct = record.ciphertext[:12], record.ciphertext[12:]
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext.decode("utf-8")
