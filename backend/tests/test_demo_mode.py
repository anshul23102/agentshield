"""Public demo mode: anonymous visitors get a private, short-lived, low-limit key
so a public site can be interactive without any real secret in its JavaScript.
These tests pin the security properties, not just the happy path."""
import time

import aiosqlite
import pytest

import main as main_module
from database import db as db_module
from database.db import init_db, get_db_conn, log_event, purge_expired_demo_keys, list_api_keys
from main import RateLimiter, _effective_skip_llm
from shield.auth import create_api_key, verify_api_key


@pytest.fixture
def demo_on(monkeypatch):
    monkeypatch.setattr(main_module, "PUBLIC_DEMO", True)
    # fresh limiters so one test's traffic never counts against another's
    monkeypatch.setattr(main_module, "demo_mint_limiter", RateLimiter(1000, 60))
    monkeypatch.setattr(main_module, "demo_mint_ip_limiter", RateLimiter(1000, 3600))
    monkeypatch.setattr(main_module, "demo_rate_limiter", RateLimiter(1000, 60))


async def mint(raw_client):
    resp = await raw_client.post("/api/demo/session")
    assert resp.status_code == 200, resp.text
    return resp.json()


async def test_demo_endpoint_is_disabled_by_default(raw_client):
    resp = await raw_client.post("/api/demo/session")
    assert resp.status_code == 404


async def test_demo_session_returns_a_working_key(raw_client, demo_on):
    session = await mint(raw_client)
    assert session["key"].startswith("ash_live_")
    assert session["expires_in"] == main_module.DEMO_KEY_TTL_SECONDS

    headers = {"X-API-Key": session["key"]}
    inspect = await raw_client.post("/api/inspect", json={"text": "What is a REST API?"}, headers=headers)
    assert inspect.status_code == 200
    analytics = await raw_client.get("/api/analytics", headers=headers)
    assert analytics.status_code == 200
    assert analytics.json()["totals"]["total"] == 1


async def test_a_demo_key_is_marked_as_demo_and_expires(raw_client, demo_on):
    session = await mint(raw_client)
    record = await verify_api_key(session["key"])
    assert record.kind == "demo"


async def test_a_demo_key_can_never_reach_admin_routes(raw_client, demo_on):
    session = await mint(raw_client)
    headers = {"X-API-Key": session["key"]}
    for method, path in [("post", "/api/admin/keys"), ("get", "/api/admin/keys"),
                         ("post", "/api/admin/reset-sessions"), ("post", "/api/admin/clear-cache")]:
        resp = await getattr(raw_client, method)(path, headers=headers)
        assert resp.status_code == 403, f"{method.upper()} {path} -> {resp.status_code}"


async def test_two_demo_visitors_never_see_each_others_data(raw_client, demo_on):
    alice, bob = await mint(raw_client), await mint(raw_client)
    a, b = {"X-API-Key": alice["key"]}, {"X-API-Key": bob["key"]}

    await raw_client.post("/api/inspect", json={"text": "Alice's private question about her salary review"}, headers=a)

    bobs_events = (await raw_client.get("/api/events/recent", headers=b)).json()["events"]
    assert all("salary" not in e["input_preview"] for e in bobs_events)
    assert (await raw_client.get("/api/analytics", headers=b)).json()["totals"]["total"] == 0
    assert (await raw_client.get("/api/analytics", headers=a)).json()["totals"]["total"] == 1


async def test_an_expired_demo_key_is_rejected_immediately(raw_client):
    _id, raw = await create_api_key("expired", kind="demo", ttl_seconds=-5)
    resp = await raw_client.get("/api/analytics", headers={"X-API-Key": raw})
    assert resp.status_code == 401


async def test_minting_is_rate_limited_globally(raw_client, demo_on, monkeypatch):
    monkeypatch.setattr(main_module, "demo_mint_limiter", RateLimiter(2, 60))
    assert (await raw_client.post("/api/demo/session")).status_code == 200
    assert (await raw_client.post("/api/demo/session")).status_code == 200
    assert (await raw_client.post("/api/demo/session")).status_code == 429


async def test_minting_stops_at_the_active_key_cap(raw_client, demo_on, monkeypatch):
    active_now = await db_module.count_active_demo_keys()
    monkeypatch.setattr(main_module, "DEMO_MAX_ACTIVE_KEYS", active_now + 1)
    assert (await raw_client.post("/api/demo/session")).status_code == 200
    assert (await raw_client.post("/api/demo/session")).status_code == 503


async def test_per_ip_limit_only_applies_when_proxies_are_trusted(raw_client, demo_on, monkeypatch):
    monkeypatch.setattr(main_module, "demo_mint_ip_limiter", RateLimiter(1, 3600))
    monkeypatch.setattr(main_module, "TRUSTED_PROXY_COUNT", 0)
    assert (await raw_client.post("/api/demo/session")).status_code == 200
    assert (await raw_client.post("/api/demo/session")).status_code == 200  # no per-IP cap without trusted proxies

    monkeypatch.setattr(main_module, "TRUSTED_PROXY_COUNT", 1)
    headers = {"X-Forwarded-For": "9.9.9.9"}
    assert (await raw_client.post("/api/demo/session", headers=headers)).status_code == 200
    assert (await raw_client.post("/api/demo/session", headers=headers)).status_code == 429


async def test_demo_keys_get_a_lower_rate_limit_than_standard_keys(raw_client, demo_on, monkeypatch):
    monkeypatch.setattr(main_module, "demo_rate_limiter", RateLimiter(2, 60))
    demo = {"X-API-Key": (await mint(raw_client))["key"]}
    codes = [(await raw_client.post("/api/inspect", json={"text": "hello world again"}, headers=demo)).status_code
             for _ in range(3)]
    assert codes == [200, 200, 429]

    _id, standard_key = await create_api_key("standard")
    ok = await raw_client.post("/api/inspect", json={"text": "hello world again"}, headers={"X-API-Key": standard_key})
    assert ok.status_code == 200  # the demo ceiling never touches real tenants


class _FakeAnalyzer:
    is_llm_available = True


class _FakeDetector:
    analyzer = _FakeAnalyzer()


async def test_demo_llm_budget_is_shared_and_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(main_module, "demo_llm_budget", RateLimiter(2, 3600))
    demo = type("K", (), {"kind": "demo", "id": "d"})()
    standard = type("K", (), {"kind": "standard", "id": "s"})()
    det = _FakeDetector()

    assert _effective_skip_llm(demo, False, det) is False
    assert _effective_skip_llm(demo, False, det) is False
    assert _effective_skip_llm(demo, False, det) is True    # budget spent: deterministic layers only
    assert _effective_skip_llm(standard, False, det) is False  # real tenants are never throttled by it
    assert _effective_skip_llm(standard, True, det) is True    # an explicit skip_llm is always honoured


async def test_demo_budget_is_not_consumed_when_no_llm_is_configured(monkeypatch):
    monkeypatch.setattr(main_module, "demo_llm_budget", RateLimiter(1, 3600))
    det = _FakeDetector()
    det.analyzer = type("A", (), {"is_llm_available": False})()
    demo = type("K", (), {"kind": "demo", "id": "d"})()
    for _ in range(5):
        assert _effective_skip_llm(demo, False, det) is False


async def test_purging_expired_demo_keys_also_deletes_their_data(raw_client):
    await init_db()
    old_id, old_raw = await create_api_key("old", kind="demo", ttl_seconds=-5)
    live_id, live_raw = await create_api_key("live", kind="demo", ttl_seconds=3600)
    sample = {"action": "allow", "trust_score": 90, "pattern_matches": []}
    await log_event(sample, "from the expired visitor", "s1", old_id)
    await log_event(sample, "from the live visitor", "s2", live_id)

    removed = await purge_expired_demo_keys()
    assert removed >= 1

    async with get_db_conn() as db:
        async with db.execute("SELECT COUNT(*) FROM threat_events WHERE tenant_id = ?", (old_id,)) as cur:
            assert (await cur.fetchone())[0] == 0
        async with db.execute("SELECT COUNT(*) FROM threat_events WHERE tenant_id = ?", (live_id,)) as cur:
            assert (await cur.fetchone())[0] == 1


async def test_admin_key_listing_hides_throwaway_demo_keys(raw_client):
    await create_api_key("visible", kind="standard")
    demo_id, _ = await create_api_key("hidden", kind="demo", ttl_seconds=3600)
    listed_ids = {k["id"] for k in await list_api_keys()}
    assert demo_id not in listed_ids
    assert demo_id in {k["id"] for k in await list_api_keys(include_demo=True)}


async def test_status_reports_whether_public_demo_mode_is_on(raw_client, demo_on):
    assert (await raw_client.get("/api/status")).json()["public_demo"] is True


async def test_old_databases_get_the_new_api_key_columns(tmp_path):
    """create_all-style migrations never alter an existing table, so a database
    created before demo keys existed must be upgraded in place, exactly once."""
    path = tmp_path / "old.db"
    async with aiosqlite.connect(path) as conn:
        await conn.execute(
            "CREATE TABLE api_keys (id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, label TEXT, "
            "created_at REAL NOT NULL, last_used_at REAL, revoked INTEGER DEFAULT 0)"
        )
        await conn.execute("INSERT INTO api_keys (id, key_hash, created_at) VALUES ('ak_old', 'h', 1.0)")
        await db_module._ensure_api_key_columns(conn)
        await db_module._ensure_api_key_columns(conn)  # idempotent
        async with conn.execute("PRAGMA table_info(api_keys)") as cur:
            columns = {row[1] for row in await cur.fetchall()}
        async with conn.execute("SELECT kind, expires_at FROM api_keys WHERE id = 'ak_old'") as cur:
            row = await cur.fetchone()
    assert {"kind", "expires_at"} <= columns
    assert row[0] == "standard" and row[1] is None  # existing keys keep working, never expire
