"""Regression tests for gaps found in the second full audit."""
import logging

import pytest
from httpx import ASGITransport, AsyncClient

import main as main_module
from shield import detector as detector_module
from shield import patterns as patterns_module
from shield.detector import ThreatDetector
from shield.patterns import AttackPattern, ThreatCategory, ThreatLevel
from shield.session_manager import InMemorySessionStore


# ── input bounds ──────────────────────────────────────────────────────────────

async def test_an_overlong_session_id_is_rejected(client):
    resp = await client.post("/api/inspect", json={"text": "hello there", "session_id": "s" * 129})
    assert resp.status_code == 422


async def test_an_overlong_agent_name_is_rejected(client):
    resp = await client.post("/api/inspect", json={"text": "hello there", "agent_name": "a" * 65})
    assert resp.status_code == 422


async def test_identifiers_at_the_limit_are_accepted(client):
    resp = await client.post("/api/inspect", json={"text": "hello there", "session_id": "s" * 128, "agent_name": "a" * 64})
    assert resp.status_code == 200


# ── errors must be logged, never shown ────────────────────────────────────────

async def test_unhandled_errors_are_logged_but_not_leaked(api_key, monkeypatch, caplog):
    async def boom(*args, **kwargs):
        raise RuntimeError("database exploded: secret-internal-detail")

    monkeypatch.setattr(main_module, "get_recent_events", boom)
    transport = ASGITransport(app=main_module.app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        with caplog.at_level(logging.ERROR, logger="main"):
            resp = await ac.get("/api/events/recent", headers={"X-API-Key": api_key})

    assert resp.status_code == 500
    assert resp.json() == {"detail": "Internal server error"}
    assert "secret-internal-detail" not in resp.text            # not leaked to the client
    assert "secret-internal-detail" in caplog.text               # but present for the operator
    assert "Unhandled exception on GET /api/events/recent" in caplog.text


# ── secrets must not reach hosted logs ────────────────────────────────────────

def test_production_never_logs_or_persists_a_generated_admin_key(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(main_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(main_module, "DATA_DIR", tmp_path)
    monkeypatch.delenv("AGENTSHIELD_ADMIN_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="main"):
        key = main_module._load_or_create_admin_key()
    assert key and key not in caplog.text
    assert not (tmp_path / ".admin_key").exists()
    assert "admin API is disabled" in caplog.text


def test_production_still_honours_an_explicit_admin_key(monkeypatch):
    monkeypatch.setattr(main_module, "IS_PRODUCTION", True)
    monkeypatch.setenv("AGENTSHIELD_ADMIN_KEY", "explicit-secret-from-the-environment")
    assert main_module._load_or_create_admin_key() == "explicit-secret-from-the-environment"


def test_development_still_prints_the_generated_key_for_convenience(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(main_module, "IS_PRODUCTION", False)
    monkeypatch.setattr(main_module, "DATA_DIR", tmp_path)
    monkeypatch.delenv("AGENTSHIELD_ADMIN_KEY", raising=False)
    with caplog.at_level(logging.WARNING, logger="main"):
        key = main_module._load_or_create_admin_key()
    assert key in caplog.text
    assert (tmp_path / ".admin_key").read_text() == key


async def test_production_never_mints_a_printed_bootstrap_key(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "IS_PRODUCTION", True)
    monkeypatch.setattr(main_module, "DATA_DIR", tmp_path)

    async def no_keys():
        return []

    async def must_not_be_called(*a, **k):
        raise AssertionError("a bootstrap key was created in production")

    monkeypatch.setattr(main_module, "list_api_keys", no_keys)
    monkeypatch.setattr(main_module, "create_api_key", must_not_be_called)
    await main_module._ensure_bootstrap_api_key()
    assert not (tmp_path / ".bootstrap_api_key").exists()


# ── pattern database integrity ────────────────────────────────────────────────

def test_every_attack_pattern_id_is_unique():
    ids = [p.id for p in patterns_module.ATTACK_PATTERNS]
    assert len(ids) == len(set(ids))


def test_a_broken_pattern_fails_loudly_instead_of_vanishing(monkeypatch):
    broken = AttackPattern(id="BAD-001", pattern="(unclosed", threat_level=ThreatLevel.HIGH,
                           category=ThreatCategory.JAILBREAK, description="x", example="x")
    monkeypatch.setattr(patterns_module, "ATTACK_PATTERNS", [broken])
    with pytest.raises(Exception):
        patterns_module.compile_patterns()   # used to be swallowed by `except re.error: pass`


def test_a_duplicate_pattern_id_is_rejected(monkeypatch):
    dup = [
        AttackPattern(id="X-1", pattern="a", threat_level=ThreatLevel.LOW, category=ThreatCategory.JAILBREAK, description="", example=""),
        AttackPattern(id="X-1", pattern="b", threat_level=ThreatLevel.LOW, category=ThreatCategory.JAILBREAK, description="", example=""),
    ]
    monkeypatch.setattr(patterns_module, "ATTACK_PATTERNS", dup)
    with pytest.raises(ValueError):
        patterns_module.compile_patterns()


# ── the reported category is the most severe one, not the first listed ────────

async def test_threat_category_comes_from_the_most_severe_match(monkeypatch):
    import re
    low = AttackPattern(id="L-1", pattern="alpha", threat_level=ThreatLevel.LOW,
                        category=ThreatCategory.CONTEXT_POISONING, description="low", example="")
    critical = AttackPattern(id="C-1", pattern="beta", threat_level=ThreatLevel.CRITICAL,
                             category=ThreatCategory.JAILBREAK, description="crit", example="")
    # The low-severity pattern is listed FIRST, so taking matches[0] picks it.
    monkeypatch.setattr(detector_module, "COMPILED_PATTERNS", [(low, re.compile("alpha")), (critical, re.compile("beta"))])
    result = await ThreatDetector().inspect("alpha and beta together", session_id=None)
    assert result.threat_category == ThreatCategory.JAILBREAK.value
    assert result.threat_level == "critical"


# ── session store housekeeping ────────────────────────────────────────────────

async def test_expired_sessions_are_swept_but_not_on_every_single_call():
    store = InMemorySessionStore(session_ttl=10)
    await store.get_or_create("old")
    store._sessions["old"].last_activity -= 1000     # long expired
    store._last_sweep = 0.0
    await store.get_or_create("trigger-a-sweep")      # first call after the interval sweeps
    assert "old" not in store._sessions

    await store.get_or_create("old2")
    store._sessions["old2"].last_activity -= 1000
    await store.get_or_create("another")              # within the 30s interval: no O(n) scan
    assert "old2" in store._sessions                  # still there until the next scheduled sweep


# ── authorization runs before request validation ──────────────────────────────

async def test_admin_routes_authorize_before_they_validate_the_schema(raw_client):
    # Well-formed JSON whose schema is wrong ("label" must be a string) and no
    # admin key: it must be a 403, not a 422. A 422 would mean the server ran
    # validation on input from a caller it had never authorized. (Malformed
    # JSON is decoded by FastAPI before any dependency runs; that is bounded by
    # the Content-Length cap and is the same for every route.)
    resp = await raw_client.post("/api/admin/keys", json={"label": 12345})
    assert resp.status_code == 403
    resp = await raw_client.post("/api/admin/keys", json={"label": "x"})
    assert resp.status_code == 403
