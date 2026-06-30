"""
Vault storage.

PRODUCTION NOTE: SQLite is used here for a runnable, self-contained demo.
In production this table belongs in an isolated, encrypted-at-rest
database (e.g. RDS with encryption + a dedicated VPC subnet with no
public route), reachable only by the tokenization service itself, with
all access logged and alerted on. Treat this datastore as part of the
PCI cardholder data environment (CDE) and scope your network/firewalls
accordingly.

Nothing here ever stores a raw PAN — only:
  - token (random, see tokens.py)
  - ciphertext + wrapped_dek (see crypto.py)
  - last4 and card brand, for display/receipts (these alone are not
    considered sensitive cardholder data under PCI-DSS)
"""
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

from .crypto import EncryptedRecord


SCHEMA = """
CREATE TABLE IF NOT EXISTS vault (
    token TEXT PRIMARY KEY,
    ciphertext BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    last4 TEXT NOT NULL,
    brand TEXT NOT NULL,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
);
"""


@dataclass
class VaultEntry:
    token: str
    last4: str
    brand: str
    created_at: float
    status: str


def detect_brand(pan: str) -> str:
    if pan.startswith("4"):
        return "visa"
    if pan[:2] in {"51", "52", "53", "54", "55"} or (
        len(pan) >= 4 and 2221 <= int(pan[:4]) <= 2720
    ):
        return "mastercard"
    if pan[:2] in {"34", "37"}:
        return "amex"
    if pan[:4] == "6011" or pan[:2] == "65":
        return "discover"
    return "unknown"


class Vault:
    def __init__(self, db_path: str = "vault.db"):
        self.db_path = db_path
        with self._conn() as conn:
            conn.execute(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def token_exists(self, token: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM vault WHERE token = ?", (token,)
            ).fetchone()
            return row is not None

    def store(self, token: str, pan: str, record: EncryptedRecord) -> VaultEntry:
        last4 = pan[-4:]
        brand = detect_brand(pan)
        created_at = time.time()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO vault (token, ciphertext, wrapped_dek, last4, "
                "brand, created_at, status) VALUES (?, ?, ?, ?, ?, ?, 'active')",
                (token, record.ciphertext, record.wrapped_dek, last4, brand, created_at),
            )
        return VaultEntry(token, last4, brand, created_at, "active")

    def get_encrypted(self, token: str) -> Optional[EncryptedRecord]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT ciphertext, wrapped_dek FROM vault "
                "WHERE token = ? AND status = 'active'",
                (token,),
            ).fetchone()
            if row is None:
                return None
            return EncryptedRecord(ciphertext=row[0], wrapped_dek=row[1])

    def get_metadata(self, token: str) -> Optional[VaultEntry]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT token, last4, brand, created_at, status FROM vault "
                "WHERE token = ?",
                (token,),
            ).fetchone()
            if row is None:
                return None
            return VaultEntry(*row)

    def delete(self, token: str) -> bool:
        """Soft-delete: mark inactive rather than physically removing,
        so audit trails stay intact. A separate, access-controlled purge
        job should handle true erasure per your data retention policy."""
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE vault SET status = 'deleted' WHERE token = ? AND status = 'active'",
                (token,),
            )
            return cur.rowcount > 0
