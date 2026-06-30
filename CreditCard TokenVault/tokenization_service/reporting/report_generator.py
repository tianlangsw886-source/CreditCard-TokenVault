"""
Report generation: exports of vault data, gated by the caller's resolved
role (see auth.py).

Two output modes:
  - encrypted form  (Role.ENCRYPTED_VIEWER and above):
        token, last4, brand, created_at, status
        Card ciphertext is never included in a report — a report file is
        not the vault, and shipping ciphertext+wrapped_dek pairs out of
        the vault DB widens the attack surface for no operational benefit.
  - decrypted form  (Role.FULL_VIEWER only):
        same fields, plus optionally the full PAN.
        Full PAN inclusion requires `include_full_pan=True` to be passed
        explicitly AND a reason string — both are recorded in the audit
        log. Default decrypted-form reports still only show last4/brand,
        matching common PCI display-truncation practice; full PAN export
        is the exception, not the default.

Every report generation call is audit-logged: who, when, how many
records, which mode, and whether full PAN was included.
"""
import csv
import io
import json
import logging
import time
from dataclasses import dataclass, asdict
from typing import List, Optional

from vault.crypto import KEKProvider, decrypt_pan
from vault.storage import Vault, VaultEntry
from .auth import Role, require_role, current_windows_user

logger = logging.getLogger("tokenization_reporting.reports")
audit_logger = logging.getLogger("tokenization_reporting.audit")


@dataclass
class ReportRow:
    token: str
    last4: str
    brand: str
    created_at: float
    status: str
    pan: Optional[str] = None  # only ever populated in full-PAN mode


def _mask(last4: str, brand: str) -> str:
    return f"{brand.upper()} **** **** **** {last4}"


def generate_report(
    vault: Vault,
    tokens: List[str],
    kek_provider: Optional[KEKProvider] = None,
    include_full_pan: bool = False,
    reason: Optional[str] = None,
    username: Optional[str] = None,
) -> List[ReportRow]:
    """
    Builds a report for the given list of tokens.

    - If the caller's role is ENCRYPTED_VIEWER: always produces masked
      rows, no decryption happens at all (kek_provider isn't touched even
      if passed).
    - If the caller's role is FULL_VIEWER: produces decrypted last4/brand
      (which is already true vault metadata, not actually encrypted, so
      no behavior changes there) and, only if include_full_pan=True and
      a reason is supplied, decrypts and includes the full PAN per row.
    """
    user = username or current_windows_user()
    role = require_role(Role.ENCRYPTED_VIEWER, user)

    if include_full_pan and role != Role.FULL_VIEWER:
        raise PermissionError(
            f"User '{user}' is not authorized to view full PAN data."
        )
    if include_full_pan and not reason:
        raise ValueError("A reason is required when requesting full PAN data.")
    if include_full_pan and kek_provider is None:
        raise ValueError("kek_provider is required to decrypt full PAN data.")

    rows: List[ReportRow] = []
    for token in tokens:
        meta = vault.get_metadata(token)
        if meta is None:
            continue

        pan = None
        if include_full_pan and role == Role.FULL_VIEWER:
            record = vault.get_encrypted(token)
            if record is not None:
                pan = decrypt_pan(record, kek_provider)

        rows.append(
            ReportRow(
                token=meta.token,
                last4=meta.last4,
                brand=meta.brand,
                created_at=meta.created_at,
                status=meta.status,
                pan=pan,
            )
        )

    audit_logger.info(
        "REPORT_GENERATED user=%s role=%s record_count=%d full_pan=%s reason=%s",
        user,
        role.value,
        len(rows),
        include_full_pan,
        reason or "-",
    )
    return rows


def rows_to_csv(rows: List[ReportRow], mask_pan_column: bool) -> str:
    """
    Serializes rows to CSV. When mask_pan_column is True (encrypted-form
    reports, or decrypted-form reports without full PAN), the pan field
    is rendered as a masked string rather than omitted, so the report
    layout stays consistent across modes.
    """
    buf = io.StringIO()
    fieldnames = ["token", "card", "brand", "created_at", "status"]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        if row.pan and not mask_pan_column:
            card_display = row.pan
        else:
            card_display = _mask(row.last4, row.brand)
        writer.writerow(
            {
                "token": row.token,
                "card": card_display,
                "brand": row.brand,
                "created_at": time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(row.created_at)
                ),
                "status": row.status,
            }
        )
    return buf.getvalue()


def rows_to_json(rows: List[ReportRow], mask_pan_column: bool) -> str:
    out = []
    for row in rows:
        d = asdict(row)
        if mask_pan_column or not row.pan:
            d["pan"] = _mask(row.last4, row.brand)
        out.append(d)
    return json.dumps(out, indent=2)
