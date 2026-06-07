"""
AgentShield Database Layer
SQLite with aiosqlite — zero-config, async, production-suitable for prototype scale.
"""

import json
import time
import asyncio
import aiosqlite
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent.parent / "data" / "agentshield.db"


CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS threat_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     REAL    NOT NULL,
    session_id    TEXT,
    input_hash    TEXT,
    input_preview TEXT,
    action        TEXT    NOT NULL,
    trust_score   INTEGER NOT NULL,
    threat_category TEXT,
    threat_level  TEXT,
    pattern_ids   TEXT,
    llm_used      INTEGER DEFAULT 0,
    processing_ms REAL,
    reasoning     TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_events_timestamp ON threat_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_threat_events_action    ON threat_events(action);
CREATE INDEX IF NOT EXISTS idx_threat_events_session   ON threat_events(session_id);

CREATE TABLE IF NOT EXISTS pattern_hit_stats (
    pattern_id  TEXT    PRIMARY KEY,
    hit_count   INTEGER DEFAULT 0,
    last_seen   REAL
);

CREATE TABLE IF NOT EXISTS daily_stats (
    date        TEXT    PRIMARY KEY,
    total       INTEGER DEFAULT 0,
    blocked     INTEGER DEFAULT 0,
    warned      INTEGER DEFAULT 0,
    allowed     INTEGER DEFAULT 0,
    avg_score   REAL    DEFAULT 100.0
);
"""


async def get_db() -> aiosqlite.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = await aiosqlite.connect(str(DB_PATH))
    db.row_factory = aiosqlite.Row
    await db.executescript(CREATE_TABLES)
    await db.commit()
    return db


_db_instance: Optional[aiosqlite.Connection] = None
_lock = asyncio.Lock()


async def get_shared_db() -> aiosqlite.Connection:
    global _db_instance
    async with _lock:
        if _db_instance is None:
            _db_instance = await get_db()
    return _db_instance


async def log_event(result_dict: dict, input_text: str, session_id: Optional[str] = None):
    import hashlib
    db = await get_shared_db()

    input_hash = hashlib.sha256(input_text.encode()).hexdigest()[:16]
    input_preview = input_text[:200].replace("\n", " ")
    pattern_ids = json.dumps([m["id"] for m in result_dict.get("pattern_matches", [])])

    ts = time.time()
    await db.execute(
        """INSERT INTO threat_events
           (timestamp, session_id, input_hash, input_preview, action, trust_score,
            threat_category, threat_level, pattern_ids, llm_used, processing_ms, reasoning)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            ts,
            session_id,
            input_hash,
            input_preview,
            result_dict["action"],
            result_dict["trust_score"],
            result_dict.get("threat_category"),
            result_dict.get("threat_level"),
            pattern_ids,
            1 if result_dict.get("llm_analysis") else 0,
            result_dict.get("processing_time_ms", 0),
            result_dict.get("reasoning", ""),
        ),
    )

    # Update pattern stats
    for match in result_dict.get("pattern_matches", []):
        await db.execute(
            """INSERT INTO pattern_hit_stats (pattern_id, hit_count, last_seen)
               VALUES (?, 1, ?)
               ON CONFLICT(pattern_id) DO UPDATE SET
                 hit_count = hit_count + 1,
                 last_seen = excluded.last_seen""",
            (match["id"], ts),
        )

    # Update daily stats
    from datetime import date
    today = date.today().isoformat()
    action = result_dict["action"]
    await db.execute(
        """INSERT INTO daily_stats (date, total, blocked, warned, allowed, avg_score)
           VALUES (?, 1, ?, ?, ?, ?)
           ON CONFLICT(date) DO UPDATE SET
             total   = total + 1,
             blocked = blocked + ?,
             warned  = warned + ?,
             allowed = allowed + ?,
             avg_score = (avg_score * (total - 1) + ?) / total""",
        (
            today,
            1 if action == "block" else 0,
            1 if action == "warn" else 0,
            1 if action == "allow" else 0,
            result_dict["trust_score"],
            1 if action == "block" else 0,
            1 if action == "warn" else 0,
            1 if action == "allow" else 0,
            result_dict["trust_score"],
        ),
    )

    await db.commit()


async def get_recent_events(limit: int = 50) -> list[dict]:
    db = await get_shared_db()
    async with db.execute(
        "SELECT * FROM threat_events ORDER BY timestamp DESC LIMIT ?", (limit,)
    ) as cursor:
        rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_analytics() -> dict:
    db = await get_shared_db()

    # Total stats
    async with db.execute(
        "SELECT COUNT(*) as total, SUM(action='block') as blocked, "
        "SUM(action='warn') as warned, SUM(action='allow') as allowed, "
        "AVG(trust_score) as avg_score FROM threat_events"
    ) as cur:
        totals = dict(await cur.fetchone() or {})

    # Category breakdown
    async with db.execute(
        "SELECT threat_category, COUNT(*) as count FROM threat_events "
        "WHERE threat_category IS NOT NULL GROUP BY threat_category ORDER BY count DESC"
    ) as cur:
        categories = [dict(row) for row in await cur.fetchall()]

    # Daily trend (last 7 days)
    async with db.execute(
        "SELECT * FROM daily_stats ORDER BY date DESC LIMIT 7"
    ) as cur:
        daily = [dict(row) for row in await cur.fetchall()]

    # Top triggered patterns
    async with db.execute(
        "SELECT pattern_id, hit_count FROM pattern_hit_stats ORDER BY hit_count DESC LIMIT 10"
    ) as cur:
        top_patterns = [dict(row) for row in await cur.fetchall()]

    # Threat level breakdown
    async with db.execute(
        "SELECT threat_level, COUNT(*) as count FROM threat_events "
        "WHERE threat_level IS NOT NULL GROUP BY threat_level"
    ) as cur:
        levels = [dict(row) for row in await cur.fetchall()]

    # Hourly distribution today
    async with db.execute(
        "SELECT CAST(strftime('%H', datetime(timestamp, 'unixepoch')) AS INT) as hour, "
        "COUNT(*) as count FROM threat_events "
        "WHERE date(datetime(timestamp, 'unixepoch')) = date('now') "
        "GROUP BY hour ORDER BY hour"
    ) as cur:
        hourly = [dict(row) for row in await cur.fetchall()]

    return {
        "totals": totals,
        "categories": categories,
        "daily_trend": daily,
        "top_patterns": top_patterns,
        "threat_levels": levels,
        "hourly_today": hourly,
    }
