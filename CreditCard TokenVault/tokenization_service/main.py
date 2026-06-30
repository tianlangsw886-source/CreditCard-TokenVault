"""
Tokenization API.

Endpoints:
  POST   /v1/tokenize     {"pan": "..."}              -> {"token": "...", "last4": "...", "brand": "..."}
  POST   /v1/detokenize   {"token": "..."}             -> {"pan": "..."}   (restricted, see notes below)
  DELETE /v1/tokens/{tok}                              -> 204

SECURITY NOTES FOR PRODUCTION:
  - /v1/detokenize is the highest-risk endpoint in the whole system: it
    turns a token back into a real PAN. In production this should be:
      * restricted to a short allowlist of internal services (e.g. the
        payment processor integration), never exposed to client apps
      * authenticated with short-lived mTLS certs or signed service
        tokens, not a static API key
      * rate-limited and alerted on anomalous volume
      * logged (who/when/why) without ever logging the PAN itself
  - This demo uses a single static API key header for simplicity. Replace
    with OAuth2 client-credentials / mTLS / your IAM of choice.
  - Raw PANs must never appear in logs, error messages, or stack traces.
    The exception handler below redacts request bodies for that reason.
  - Run behind TLS termination (this app itself doesn't terminate TLS).
  - Rotate the master KEK on a schedule and on suspected compromise; with
    envelope encryption you can re-wrap all DEKs without re-encrypting
    every PAN.
"""
import os
import logging
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel, field_validator

from vault.crypto import LocalKEKProvider, encrypt_pan, decrypt_pan
from vault.storage import Vault
from vault.tokens import generate_token, luhn_valid

# Configure logging to never include raw request bodies.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tokenization_service")

app = FastAPI(title="Card Tokenization Service", version="1.0.0")

kek_provider = LocalKEKProvider()
vault = Vault(db_path=os.environ.get("VAULT_DB_PATH", "vault.db"))

API_KEYS = set(
    filter(None, os.environ.get("TOKENIZATION_API_KEYS", "").split(","))
)


def require_api_key(x_api_key: str = Header(default=None)):
    if not API_KEYS:
        raise HTTPException(
            status_code=503,
            detail="Service misconfigured: no API keys provisioned.",
        )
    if x_api_key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return x_api_key


class TokenizeRequest(BaseModel):
    pan: str

    @field_validator("pan")
    @classmethod
    def validate_pan(cls, v: str) -> str:
        v = v.strip().replace(" ", "").replace("-", "")
        if not v.isdigit():
            raise ValueError("PAN must contain only digits.")
        if not (12 <= len(v) <= 19):
            raise ValueError("PAN length must be between 12 and 19 digits.")
        if not luhn_valid(v):
            raise ValueError("PAN failed Luhn checksum validation.")
        return v


class TokenizeResponse(BaseModel):
    token: str
    last4: str
    brand: str


class DetokenizeRequest(BaseModel):
    token: str


class DetokenizeResponse(BaseModel):
    pan: str


@app.post("/v1/tokenize", response_model=TokenizeResponse)
def tokenize(req: TokenizeRequest, api_key: str = Depends(require_api_key)):
    # Generate a token, retrying on the astronomically unlikely chance of collision.
    for _ in range(5):
        token = generate_token()
        if not vault.token_exists(token):
            break
    else:
        raise HTTPException(status_code=500, detail="Could not allocate a unique token.")

    record = encrypt_pan(req.pan, kek_provider)
    entry = vault.store(token, req.pan, record)

    logger.info("Tokenized PAN ending in %s -> token issued", entry.last4)
    return TokenizeResponse(token=entry.token, last4=entry.last4, brand=entry.brand)


@app.post("/v1/detokenize", response_model=DetokenizeResponse)
def detokenize(req: DetokenizeRequest, api_key: str = Depends(require_api_key)):
    # PRODUCTION: add a second authorization check here scoped to
    # "may detokenize" — separate from general API access — since this
    # is the most sensitive operation in the service.
    record = vault.get_encrypted(req.token)
    if record is None:
        raise HTTPException(status_code=404, detail="Token not found.")

    pan = decrypt_pan(record, kek_provider)
    logger.info("Detokenized token %s", req.token)
    return DetokenizeResponse(pan=pan)


@app.delete("/v1/tokens/{token}", status_code=204)
def delete_token(token: str, api_key: str = Depends(require_api_key)):
    deleted = vault.delete(token)
    if not deleted:
        raise HTTPException(status_code=404, detail="Token not found or already deleted.")
    logger.info("Soft-deleted token %s", token)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}
