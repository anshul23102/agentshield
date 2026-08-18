"""
AgentShield API key authentication.

Design notes:
  - Keys are high-entropy random tokens (32 bytes = 256 bits), not human
    passwords. Argon2/bcrypt are deliberately NOT used here: their whole
    purpose is making brute force of a *low-entropy* human-chosen secret
    expensive, at the cost of being slow by design. Every authenticated
    request would pay that cost. A 256-bit random token is already
    computationally infeasible to brute force, so a fast, salted/peppered
    SHA-256 hash is the correct tool - this is the same tradeoff Stripe,
    GitHub, and AWS make for their own API key storage.
  - The raw key is shown exactly once, at creation time, and is never
    stored or logged - only its hash is persisted.
"""
import hashlib
import os
import secrets
from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException

from database.db import get_api_key_by_hash, insert_api_key, touch_api_key_last_used

KEY_PREFIX = "ash_live_"
_PEPPER = os.getenv("AGENTSHIELD_KEY_PEPPER", "")


@dataclass
class ApiKeyRecord:
    id: str
    label: Optional[str]


def _hash_key(raw_key: str) -> str:
    # The pepper is a server-side secret separate from the DB - even a full
    # database dump doesn't let an attacker rebuild valid key hashes without it.
    return hashlib.sha256((_PEPPER + raw_key).encode()).hexdigest()


def generate_key_id() -> str:
    return "ak_" + secrets.token_hex(8)


async def create_api_key(label: Optional[str] = None) -> tuple[str, str]:
    """Creates a new key, returns (key_id, raw_key). raw_key is shown exactly once."""
    key_id = generate_key_id()
    raw_key = KEY_PREFIX + secrets.token_urlsafe(32)
    await insert_api_key(key_id, _hash_key(raw_key), label)
    return key_id, raw_key


async def verify_api_key(raw_key: str) -> Optional[ApiKeyRecord]:
    if not raw_key or not raw_key.startswith(KEY_PREFIX):
        return None
    record = await get_api_key_by_hash(_hash_key(raw_key))
    if not record:
        return None
    await touch_api_key_last_used(record["id"])
    return ApiKeyRecord(id=record["id"], label=record.get("label"))


def _extract_raw_key(x_api_key: Optional[str], authorization: Optional[str]) -> Optional[str]:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


async def require_api_key(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
) -> ApiKeyRecord:
    """FastAPI dependency: accepts either `X-API-Key: <key>` or `Authorization: Bearer <key>`."""
    raw_key = _extract_raw_key(x_api_key, authorization)
    if not raw_key:
        raise HTTPException(401, "Missing API key. Send it as 'X-API-Key' or 'Authorization: Bearer <key>'.")
    record = await verify_api_key(raw_key)
    if not record:
        raise HTTPException(401, "Invalid or revoked API key.")
    return record
