"""Tests for the retention-purge logic that main.py's retention_cleanup_worker calls
on a timer. Previously EVENT_RETENTION_DAYS was read from env and never used anywhere."""
import time

import pytest

from database.db import (
    init_db, get_recent_events, purge_expired_events, EVENT_RETENTION_DAYS, get_db_conn,
)


@pytest.fixture(autouse=True)
async def _ensure_tables_exist():
    await init_db()  # idempotent (CREATE TABLE IF NOT EXISTS); safe regardless of test order


async def _insert_event_at(timestamp: float, session_id: str):
    async with get_db_conn() as db:
        await db.execute(
            """INSERT INTO threat_events
               (timestamp, session_id, input_hash, input_preview, action, trust_score)
               VALUES (?, ?, 'hash', 'preview', 'allow', 100)""",
            (timestamp, session_id),
        )
        await db.commit()


async def test_purge_removes_events_older_than_retention_window():
    old_ts = time.time() - ((EVENT_RETENTION_DAYS + 5) * 86400)
    recent_ts = time.time() - 3600

    await _insert_event_at(old_ts, "retention-old")
    await _insert_event_at(recent_ts, "retention-recent")

    deleted = await purge_expired_events()
    assert deleted >= 1

    events = await get_recent_events(limit=200)
    session_ids = {e["session_id"] for e in events}
    assert "retention-old" not in session_ids
    assert "retention-recent" in session_ids


async def test_purge_is_a_no_op_when_nothing_is_expired():
    deleted = await purge_expired_events()
    second_pass = await purge_expired_events()
    assert second_pass == 0
