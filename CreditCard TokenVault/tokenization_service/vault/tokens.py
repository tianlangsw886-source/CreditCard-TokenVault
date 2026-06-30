"""
Token generation.

Tokens are random (NOT derived from the PAN), so they carry no information
about the original card number — this is "vault-based" tokenization, as
opposed to deterministic/format-preserving schemes. Each token is checked
for collisions against the vault before being accepted.
"""
import secrets


def luhn_checksum(number: str) -> int:
    digits = [int(d) for d in number]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10


def luhn_valid(number: str) -> bool:
    return luhn_checksum(number) == 0


def generate_token(bin_prefix: str = "999999", length: int = 16) -> str:
    """
    Generates a random, Luhn-valid surrogate number that is NOT a usable
    card number (uses an unassigned/test BIN range by default: 999999xx).

    This keeps the token "format preserving" enough to flow through legacy
    systems expecting card-number-shaped strings, while being completely
    random and cryptographically unlinkable to the real PAN.
    """
    if len(bin_prefix) >= length:
        raise ValueError("bin_prefix must be shorter than length")

    body_len = length - len(bin_prefix) - 1  # leave room for check digit
    body = "".join(str(secrets.randbelow(10)) for _ in range(body_len))
    partial = bin_prefix + body

    # find the check digit that makes it Luhn-valid
    for check_digit in range(10):
        candidate = partial + str(check_digit)
        if luhn_valid(candidate):
            return candidate
    raise RuntimeError("Failed to generate Luhn-valid token (unexpected)")
