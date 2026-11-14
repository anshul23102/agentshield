"""
AgentShield Database Layer
SQLite with aiosqlite for async prototype-scale persistence.
"""

import json
import logging
import os
import time
import asyncio
import aiosqlite
from pathlib import Path
from typing import Optional

from shield.input_redactor import redact_for_storage

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "agentshield.db"
DB_PATH = Path(os.getenv("AGENTSHIELD_DB_PATH") or _DEFAULT_DB_PATH)
EVENT_RETENTION_DAYS = int(os.getenv("AGENTSHIELD_EVENT_RETENTION_DAYS", "30"))
EVENT_CLEANUP_INTERVAL_SECONDS = int(os.getenv("AGENTSHIELD_EVENT_CLEANUP_INTERVAL_SECONDS", "3600"))


CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS threat_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     REAL    NOT NULL,
    tenant_id     TEXT,
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
CREATE INDEX IF NOT EXISTS idx_threat_events_tenant    ON threat_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_threat_events_tenant_ts ON threat_events(tenant_id, timestamp);

CREATE TABLE IF NOT EXISTS api_keys (
    id            TEXT    PRIMARY KEY,
    key_hash      TEXT    NOT NULL UNIQUE,
    label         TEXT,
    created_at    REAL    NOT NULL,
    last_used_at  REAL,
    revoked       INTEGER DEFAULT 0,
    kind          TEXT    NOT NULL DEFAULT 'standard',
    expires_at    REAL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
"""


from contextlib import asynccontextmanager

# ── Connection pool ────────────────────────────────────────────────────────────
# Previously every call opened a brand-new aiosqlite connection and closed it
# immediately after - real file-open + PRAGMA overhead on every single query,
# repeated for the life of the process. This pool opens DB_POOL_SIZE
# connections once and hands them out/back via a queue, so steady-state
# traffic reuses already-open connections instead of paying that cost per
# call.
#
# Be honest about what this does and doesn't fix: SQLite still serializes
# writers even in WAL mode (multiple readers can proceed concurrently, but
# only one writer at a time), so this pool helps connection-reuse overhead
# and concurrent-read throughput, not fundamental multi-writer scaling. If
# write throughput genuinely bottlenecks at the SQLite layer, the real fix is
# switching to Postgres, not a bigger SQLite pool - see the "Scaling the
# database" section in the README for the honest boundary here.

DB_POOL_SIZE = int(os.getenv("AGENTSHIELD_DB_POOL_SIZE", "5"))

_pool: Optional[asyncio.Queue] = None
_pool_init_lock = asyncio.Lock()


async def _open_pooled_connection() -> aiosqlite.Connection:
    # aiosqlite.Connection is a threading.Thread subclass backing every
    # connection with a dedicated worker thread; aiosqlite.connect() starts
    # that thread as non-daemon, which means an unclosed pooled connection
    # blocks process/interpreter exit even after the app has nothing left to
    # do. Constructing the Connection directly (matching what connect() does
    # internally) lets the thread be marked daemon *before* it starts, so a
    # pool that's never explicitly closed can't hang shutdown.
    import sqlite3

    def _connector() -> sqlite3.Connection:
        return sqlite3.connect(str(DB_PATH), timeout=30.0)

    conn = aiosqlite.Connection(_connector, 64)
    conn.daemon = True
    conn = await conn  # triggers Connection.__await__ -> start() + connect

    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA journal_mode=WAL")
    await conn.execute("PRAGMA synchronous=NORMAL")
    return conn


async def _get_pool() -> asyncio.Queue:
    global _pool
    if _pool is not None:
        return _pool
    async with _pool_init_lock:
        if _pool is None:  # re-check: another task may have won the race
            pool: asyncio.Queue = asyncio.Queue(maxsize=DB_POOL_SIZE)
            for _ in range(DB_POOL_SIZE):
                await pool.put(await _open_pooled_connection())
            _pool = pool
    return _pool


async def close_pool():
    """Closes every pooled connection. Call on app shutdown; tests that swap
    AGENTSHIELD_DB_PATH between runs should also call this so a stale pool
    doesn't keep pointing at the previous test's database file."""
    global _pool
    if _pool is None:
        return
    while not _pool.empty():
        conn = _pool.get_nowait()
        await conn.close()
    _pool = None


@asynccontextmanager
async def get_db_conn():
    pool = await _get_pool()
    conn = await pool.get()
    try:
        yield conn
    finally:
        await pool.put(conn)


async def init_db():
    global DB_PATH
    # A misconfigured AGENTSHIELD_DB_PATH (pointing at a path this process
    # can't create/write - e.g. a platform disk-mount path that was set in
    # the hosting dashboard without the disk actually being attached) used
    # to crash the entire app on boot. One bad env var taking down the whole
    # service is worse than falling back to local storage with a loud
    # warning - so on any OS-level failure here, retry once against the
    # bundled default path instead of exiting.
    try:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        if DB_PATH != _DEFAULT_DB_PATH:
            logger.warning(
                "Cannot use AGENTSHIELD_DB_PATH=%s (%s) - falling back to %s. "
                "Fix or unset AGENTSHIELD_DB_PATH in your hosting platform's "
                "environment settings.",
                DB_PATH, exc, _DEFAULT_DB_PATH,
            )
            DB_PATH = _DEFAULT_DB_PATH
            DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        else:
            raise
    async with aiosqlite.connect(str(DB_PATH), timeout=30.0) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA synchronous=NORMAL")
        await db.executescript(CREATE_TABLES)
        await _ensure_api_key_columns(db)
        await db.commit()


async def _ensure_api_key_columns(db: aiosqlite.Connection):
    """CREATE TABLE IF NOT EXISTS never alters a table that already exists, so a
    database created before demo keys existed needs the new columns added once.
    Idempotent: it only adds what is missing."""
    async with db.execute("PRAGMA table_info(api_keys)") as cur:
        existing = {row[1] for row in await cur.fetchall()}
    if "kind" not in existing:
        await db.execute("ALTER TABLE api_keys ADD COLUMN kind TEXT NOT NULL DEFAULT 'standard'")
    if "expires_at" not in existing:
        await db.execute("ALTER TABLE api_keys ADD COLUMN expires_at REAL")


async def purge_expired_events() -> int:
    """Delete threat_events older than EVENT_RETENTION_DAYS. Returns rows deleted."""
    cutoff = time.time() - (EVENT_RETENTION_DAYS * 86400)
    async with get_db_conn() as db:
        cursor = await db.execute("DELETE FROM threat_events WHERE timestamp < ?", (cutoff,))
        await db.commit()
        return cursor.rowcount if cursor.rowcount is not None else 0


async def log_event(result_dict: dict, input_text: str, session_id: Optional[str] = None,
                     tenant_id: Optional[str] = None):
    import hashlib
    input_hash = hashlib.sha256(input_text.encode()).hexdigest()[:16]
    # Presidio/spaCy redaction is synchronous, CPU-bound work. FastAPI runs an
    # `async def` BackgroundTask on the event loop itself (only plain `def`
    # tasks go to the threadpool), so calling it inline stalled every other
    # request, WebSocket and health check for up to ~19 ms per logged event.
    # Measured: moving it to a worker thread drops the stall to about 1 ms.
    # It also runs before a pooled connection is taken, so a slow redaction
    # never holds one of the few database connections.
    input_preview = await asyncio.to_thread(
        redact_for_storage, input_text[:200].replace("\n", " ")
    )
    pattern_ids = json.dumps([m["id"] for m in result_dict.get("pattern_matches", [])])

    async with get_db_conn() as db:
        try:
            await db.execute(
                """INSERT INTO threat_events
                   (timestamp, tenant_id, session_id, input_hash, input_preview, action, trust_score,
                    threat_category, threat_level, pattern_ids, llm_used, processing_ms, reasoning)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    time.time(),
                    tenant_id,
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
            await db.commit()
        except Exception:
            await db.rollback()
            raise


async def get_recent_events(limit: int = 50, tenant_id: Optional[str] = None) -> list[dict]:
    async with get_db_conn() as db:
        if tenant_id is not None:
            query = "SELECT * FROM threat_events WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?"
            params = (tenant_id, limit)
        else:
            query = "SELECT * FROM threat_events ORDER BY timestamp DESC LIMIT ?"
            params = (limit,)
        async with db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_analytics(tenant_id: Optional[str] = None) -> dict:
    """Everything here is computed from the caller's own rows in threat_events.

    The previous version read the 7-day trend and the top-pattern list from two
    global aggregate tables with no tenant column, so one caller's dashboard
    showed everyone's activity next to its own totals (and the two numbers
    disagreed). Deriving them from threat_events with the same tenant filter
    keeps every figure on the page about the same traffic, and retention
    purges now shrink them consistently instead of leaving stale aggregates.
    All dates are UTC.
    """
    tenant_clause = "WHERE tenant_id = ?" if tenant_id is not None else ""
    tenant_and_clause = "AND tenant_id = ?" if tenant_id is not None else ""
    tenant_params = (tenant_id,) if tenant_id is not None else ()

    async with get_db_conn() as db:
        # Total stats (COALESCE so an empty tenant gets zeros, not nulls)
        async with db.execute(
            f"SELECT COUNT(*) AS total, "
            f"COALESCE(SUM(action='block'), 0) AS blocked, "
            f"COALESCE(SUM(action='warn'), 0) AS warned, "
            f"COALESCE(SUM(action='allow'), 0) AS allowed, "
            f"AVG(trust_score) AS avg_score FROM threat_events {tenant_clause}",
            tenant_params,
        ) as cur:
            totals = dict(await cur.fetchone() or {})

        # Category breakdown
        async with db.execute(
            f"SELECT threat_category, COUNT(*) AS count FROM threat_events "
            f"WHERE threat_category IS NOT NULL {tenant_and_clause} GROUP BY threat_category ORDER BY count DESC",
            tenant_params,
        ) as cur:
            categories = [dict(row) for row in await cur.fetchall()]

        # Daily trend, last 7 days that have traffic, newest first (UTC dates)
        async with db.execute(
            f"SELECT date(timestamp, 'unixepoch') AS date, COUNT(*) AS total, "
            f"SUM(action='block') AS blocked, SUM(action='warn') AS warned, "
            f"SUM(action='allow') AS allowed, AVG(trust_score) AS avg_score "
            f"FROM threat_events {tenant_clause} GROUP BY date ORDER BY date DESC LIMIT 7",
            tenant_params,
        ) as cur:
            daily = [dict(row) for row in await cur.fetchall()]

        # Top triggered patterns: unpack each event's JSON list of pattern ids
        async with db.execute(
            f"SELECT je.value AS pattern_id, COUNT(*) AS hit_count "
            f"FROM threat_events AS te, json_each(te.pattern_ids) AS je "
            f"WHERE json_valid(te.pattern_ids) {tenant_and_clause.replace('tenant_id', 'te.tenant_id')} "
            f"GROUP BY je.value ORDER BY hit_count DESC LIMIT 10",
            tenant_params,
        ) as cur:
            top_patterns = [dict(row) for row in await cur.fetchall()]

        # Threat level breakdown
        async with db.execute(
            f"SELECT threat_level, COUNT(*) AS count FROM threat_events "
            f"WHERE threat_level IS NOT NULL {tenant_and_clause} GROUP BY threat_level",
            tenant_params,
        ) as cur:
            levels = [dict(row) for row in await cur.fetchall()]

        # Hourly distribution for today, in UTC
        async with db.execute(
            f"SELECT CAST(strftime('%H', timestamp, 'unixepoch') AS INT) AS hour, "
            f"COUNT(*) AS count FROM threat_events "
            f"WHERE date(timestamp, 'unixepoch') = date('now') {tenant_and_clause} "
            f"GROUP BY hour ORDER BY hour",
            tenant_params,
        ) as cur:
            hourly = [dict(row) for row in await cur.fetchall()]

        return {
            "totals": totals,
            "categories": categories,
            "daily_trend": daily,
            "top_patterns": top_patterns,
            "threat_levels": levels,
            "hourly_today": hourly,
            "timezone": "UTC",
        }


# ── API keys ──────────────────────────────────────────────────────────────────

async def insert_api_key(key_id: str, key_hash: str, label: Optional[str],
                         kind: str = "standard", expires_at: Optional[float] = None) -> None:
    async with get_db_conn() as db:
        await db.execute(
            "INSERT INTO api_keys (id, key_hash, label, created_at, kind, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (key_id, key_hash, label, time.time(), kind, expires_at),
        )
        await db.commit()


async def get_api_key_by_hash(key_hash: str) -> Optional[dict]:
    # An expired key is rejected here, at the query, so expiry does not depend
    # on the cleanup worker having run yet.
    async with get_db_conn() as db:
        async with db.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0 "
            "AND (expires_at IS NULL OR expires_at > ?)",
            (key_hash, time.time()),
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None


async def count_active_demo_keys() -> int:
    async with get_db_conn() as db:
        async with db.execute(
            "SELECT COUNT(*) FROM api_keys WHERE kind = 'demo' AND revoked = 0 AND expires_at > ?",
            (time.time(),),
        ) as cur:
            row = await cur.fetchone()
        return int(row[0]) if row else 0


async def purge_expired_demo_keys() -> int:
    """Deletes expired demo keys AND every event they produced, so a visitor's
    data does not outlive their session. Returns the number of keys removed."""
    now = time.time()
    async with get_db_conn() as db:
        async with db.execute(
            "SELECT id FROM api_keys WHERE kind = 'demo' AND expires_at IS NOT NULL AND expires_at <= ?", (now,)
        ) as cur:
            expired_ids = [row[0] for row in await cur.fetchall()]
        if not expired_ids:
            return 0
        marks = ",".join("?" for _ in expired_ids)
        await db.execute(f"DELETE FROM threat_events WHERE tenant_id IN ({marks})", expired_ids)
        await db.execute(f"DELETE FROM api_keys WHERE id IN ({marks})", expired_ids)
        await db.commit()
        return len(expired_ids)


async def touch_api_key_last_used(key_id: str) -> None:
    async with get_db_conn() as db:
        await db.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (time.time(), key_id))
        await db.commit()


async def list_api_keys(include_demo: bool = False) -> list[dict]:
    # Demo keys are throwaway and can number in the hundreds, so the admin
    # listing (and the "does any key exist yet" check) ignores them by default.
    where = "" if include_demo else "WHERE kind != 'demo'"
    async with get_db_conn() as db:
        async with db.execute(
            f"SELECT id, label, kind, created_at, last_used_at, revoked FROM api_keys {where} ORDER BY created_at DESC"
        ) as cur:
            return [dict(row) for row in await cur.fetchall()]


async def revoke_api_key(key_id: str) -> bool:
    async with get_db_conn() as db:
        cursor = await db.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,))
        await db.commit()
        return cursor.rowcount > 0
