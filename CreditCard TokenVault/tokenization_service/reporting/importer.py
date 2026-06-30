"""
Import handling: the reporting app lets a user import a list of tokens
(e.g. from a batch settlement file) to generate a report against.

Only tokens are ever imported here — never raw PANs. If a file contains
something that looks like a raw card number (Luhn-valid, 12-19 digits),
the importer rejects that row rather than silently processing cardholder
data through a path that was never designed/scoped to handle it.
"""
import csv
import io
from typing import List

from vault.tokens import luhn_valid

# Must match the bin_prefix used in vault/tokens.py's generate_token().
# Real PANs cannot start with this prefix (it's an unassigned test range),
# so anything Luhn-valid that does NOT start with it is suspect.
TOKEN_BIN_PREFIX = "999999"


class ImportError_(Exception):
    pass


def _looks_like_raw_pan(value: str) -> bool:
    digits = value.strip().replace(" ", "").replace("-", "")
    if not (digits.isdigit() and 12 <= len(digits) <= 19 and luhn_valid(digits)):
        return False
    # Luhn-valid AND not in our reserved token range -> treat as a raw PAN.
    return not digits.startswith(TOKEN_BIN_PREFIX)


def parse_token_csv(file_content: str) -> List[str]:
    """
    Expects a CSV with a 'token' column (or a single column of tokens with
    no header). Returns a de-duplicated list of token strings.
    Rejects the whole file if any row looks like a raw PAN rather than a
    vault token (vault tokens use the reserved 999999 test BIN prefix).
    """
    tokens: List[str] = []
    reader = csv.reader(io.StringIO(file_content))
    rows = list(reader)
    if not rows:
        raise ImportError_("File is empty.")

    header = [c.strip().lower() for c in rows[0]]
    has_header = "token" in header
    data_rows = rows[1:] if has_header else rows
    token_col = header.index("token") if has_header else 0

    for i, row in enumerate(data_rows, start=1):
        if not row:
            continue
        value = row[token_col].strip()
        if not value:
            continue
        if _looks_like_raw_pan(value):
            raise ImportError_(
                f"Row {i} looks like a raw card number, not a token. "
                "Refusing to import. This tool only accepts vault tokens."
            )
        tokens.append(value)

    seen = set()
    deduped = []
    for t in tokens:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped
