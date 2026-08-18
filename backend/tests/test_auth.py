"""Tests for API key generation, hashing, and the FastAPI auth dependency."""
import pytest
from fastapi import HTTPException

from database.db import init_db
from shield.auth import create_api_key, verify_api_key, require_api_key, KEY_PREFIX


@pytest.fixture(autouse=True)
async def _ensure_tables_exist():
    await init_db()


async def test_created_key_has_expected_prefix_and_verifies():
    key_id, raw_key = await create_api_key("test key")
    assert raw_key.startswith(KEY_PREFIX)

    record = await verify_api_key(raw_key)
    assert record is not None
    assert record.id == key_id
    assert record.label == "test key"


async def test_wrong_key_does_not_verify():
    await create_api_key("real key")
    record = await verify_api_key(KEY_PREFIX + "totally-made-up-value")
    assert record is None


async def test_key_without_prefix_is_rejected_without_a_query():
    # Malformed/garbage input should short-circuit before ever hitting the DB.
    record = await verify_api_key("not-even-the-right-shape")
    assert record is None


async def test_empty_key_is_rejected():
    assert await verify_api_key("") is None
    assert await verify_api_key(None) is None


async def test_raw_key_is_never_persisted_in_plaintext():
    from database.db import get_db_conn
    key_id, raw_key = await create_api_key("plaintext check")
    async with get_db_conn() as db:
        async with db.execute("SELECT key_hash FROM api_keys WHERE id = ?", (key_id,)) as cur:
            row = await cur.fetchone()
    assert raw_key not in row["key_hash"]


async def test_require_api_key_dependency_accepts_x_api_key_header():
    key_id, raw_key = await create_api_key("header test")
    record = await require_api_key(x_api_key=raw_key, authorization=None)
    assert record.id == key_id


async def test_require_api_key_dependency_accepts_bearer_authorization():
    key_id, raw_key = await create_api_key("bearer test")
    record = await require_api_key(x_api_key=None, authorization=f"Bearer {raw_key}")
    assert record.id == key_id


async def test_require_api_key_dependency_rejects_missing_key():
    with pytest.raises(HTTPException) as exc_info:
        await require_api_key(x_api_key=None, authorization=None)
    assert exc_info.value.status_code == 401


async def test_require_api_key_dependency_rejects_invalid_key():
    with pytest.raises(HTTPException) as exc_info:
        await require_api_key(x_api_key=KEY_PREFIX + "bogus", authorization=None)
    assert exc_info.value.status_code == 401


async def test_revoked_key_no_longer_verifies():
    from database.db import revoke_api_key
    key_id, raw_key = await create_api_key("to be revoked")
    assert await verify_api_key(raw_key) is not None
    await revoke_api_key(key_id)
    assert await verify_api_key(raw_key) is None
