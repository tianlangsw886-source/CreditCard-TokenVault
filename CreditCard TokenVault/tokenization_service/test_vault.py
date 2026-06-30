"""
Quick local smoke test of the vault library (no HTTP server needed).
Run: python3 test_vault.py
"""
import os
import base64
import tempfile

os.environ.setdefault(
    "TOKENIZATION_MASTER_KEY", base64.b64encode(os.urandom(32)).decode()
)

from vault.crypto import LocalKEKProvider, encrypt_pan, decrypt_pan
from vault.storage import Vault
from vault.tokens import generate_token, luhn_valid


def main():
    kek = LocalKEKProvider()
    vault = Vault(db_path=tempfile.mktemp(suffix=".db"))

    test_pans = [
        "4111111111111111",  # visa test PAN
        "5500000000000004",  # mastercard test PAN
        "340000000000009",   # amex test PAN
    ]

    tokens = []
    for pan in test_pans:
        assert luhn_valid(pan), f"{pan} should be Luhn-valid"
        token = generate_token()
        record = encrypt_pan(pan, kek)
        entry = vault.store(token, pan, record)
        print(f"Tokenized {pan[:6]}...{pan[-4:]} -> {token} ({entry.brand})")
        tokens.append((token, pan))

    print("\nDetokenizing...")
    for token, original_pan in tokens:
        record = vault.get_encrypted(token)
        recovered = decrypt_pan(record, kek)
        assert recovered == original_pan, "round trip mismatch!"
        print(f"{token} -> {recovered[:6]}...{recovered[-4:]} OK")

    print("\nDeleting first token...")
    token0 = tokens[0][0]
    assert vault.delete(token0)
    assert vault.get_encrypted(token0) is None
    print(f"{token0} no longer resolves after delete. OK")

    print("\nAll smoke tests passed.")


if __name__ == "__main__":
    main()
