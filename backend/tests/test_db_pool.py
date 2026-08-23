"""Tests for the aiosqlite connection pool. Previously get_db_conn() opened
and closed a brand-new connection on every single call - these confirm
connections are actually being reused, not just that queries still work."""
import os

import pytest

from database.db import init_db, get_db_conn, close_pool, DB_POOL_SIZE
import database.db as db_module


@pytest.fixture(autouse=True)
async def _ensure_tables_exist():
    await init_db()


async def test_pool_reuses_the_same_connection_objects_across_calls():
    seen_ids = set()
    for _ in range(DB_POOL_SIZE * 3):  # cycle through the whole pool several times over
        async with get_db_conn() as conn:
            seen_ids.add(id(conn))
    # Reused connections mean far fewer distinct objects than total calls,
    # and never more than the pool size.
    assert len(seen_ids) <= DB_POOL_SIZE


async def test_init_db_falls_back_to_default_path_when_configured_path_is_unwritable(tmp_path, monkeypatch):
    # Regression guard for a real production incident: AGENTSHIELD_DB_PATH
    # pointed at a directory this process couldn't create (a platform disk
    # mount that was configured without the disk actually attached), and
    # init_db() crashed the whole app on boot instead of degrading. A locked
    # directory reproduces the same OSError a real unwritable mount raises.
    locked_dir = tmp_path / "locked"
    locked_dir.mkdir()
    os.chmod(locked_dir, 0o444)
    bad_path = locked_dir / "nested" / "agentshield.db"
    monkeypatch.setattr(db_module, "DB_PATH", bad_path)
    try:
        await init_db()
        assert db_module.DB_PATH == db_module._DEFAULT_DB_PATH
    finally:
        os.chmod(locked_dir, 0o755)  # tmp_path cleanup needs write access back


async def test_pool_connection_is_returned_even_if_the_caller_raises():
    with pytest.raises(ValueError):
        async with get_db_conn():
            raise ValueError("boom")
    # The pool must still be able to hand out a connection afterward - if the
    # broken caller's connection was never returned, this would hang/fail.
    async with get_db_conn() as conn:
        await conn.execute("SELECT 1")


async def test_pool_connections_actually_execute_queries():
    async with get_db_conn() as conn:
        cursor = await conn.execute("SELECT 1 AS one")
        row = await cursor.fetchone()
        assert row["one"] == 1


async def test_close_pool_allows_a_fresh_pool_to_be_created_afterward():
    async with get_db_conn():
        pass
    assert db_module._pool is not None

    await close_pool()
    assert db_module._pool is None

    # Using it again after close should transparently rebuild the pool.
    async with get_db_conn() as conn:
        await conn.execute("SELECT 1")
    assert db_module._pool is not None
