"""Tests for the rate limiter: identity is the authenticated API key (not a
spoofable header), and the trusted-proxy-aware IP extraction."""
import pytest
from fastapi import HTTPException

import main as main_module
from database.db import init_db
from main import RateLimiter, _client_ip, check_rate_limit


@pytest.fixture(autouse=True)
async def _ensure_tables_exist():
    await init_db()


def make_request(client_host="1.2.3.4", xff=None):
    class FakeClient:
        host = client_host

    class FakeRequest:
        client = FakeClient()
        headers = {"x-forwarded-for": xff} if xff else {}

    return FakeRequest()


def test_client_ip_ignores_xff_when_no_trusted_proxies_configured(monkeypatch):
    monkeypatch.setattr(main_module, "TRUSTED_PROXY_COUNT", 0)
    req = make_request(client_host="10.0.0.5", xff="8.8.8.8, 1.1.1.1")
    assert _client_ip(req) == "10.0.0.5"  # XFF ignored entirely - can't be spoofed to change this


def test_client_ip_honors_configured_trusted_proxy_hops(monkeypatch):
    monkeypatch.setattr(main_module, "TRUSTED_PROXY_COUNT", 1)
    req = make_request(client_host="10.0.0.5", xff="8.8.8.8, 1.1.1.1")
    # rightmost hop = the one added by *our* trusted proxy, not attacker-controlled
    assert _client_ip(req) == "1.1.1.1"


def test_rate_limiter_allows_up_to_the_limit_then_blocks():
    limiter = RateLimiter(limit=3, window_seconds=60)
    assert limiter.allow("id-a") is True
    assert limiter.allow("id-a") is True
    assert limiter.allow("id-a") is True
    assert limiter.allow("id-a") is False  # 4th request in the window is over budget


def test_rate_limiter_tracks_identities_independently():
    limiter = RateLimiter(limit=1, window_seconds=60)
    assert limiter.allow("id-a") is True
    assert limiter.allow("id-b") is True  # different identity, separate budget
    assert limiter.allow("id-a") is False


async def test_spoofed_xff_headers_do_not_grant_a_fresh_rate_limit_bucket(monkeypatch):
    """The actual security property: before this fix, changing X-Forwarded-For
    on every request bought an attacker a brand new rate-limit identity. Now
    the limiter is keyed by the authenticated API key, so header-spoofing
    changes nothing about which bucket a request lands in."""
    from shield.auth import create_api_key

    monkeypatch.setattr(main_module, "rate_limiter", RateLimiter(limit=2, window_seconds=60))
    monkeypatch.setattr(main_module, "_distributed_limiter", None)

    _key_id, raw_key = await create_api_key("spoof-test")

    class FakeKey:
        id = _key_id

    req1 = make_request(xff="1.1.1.1")
    req2 = make_request(xff="2.2.2.2")  # different claimed IP, same underlying key
    req3 = make_request(xff="3.3.3.3")

    check_rate_limit(req1, FakeKey())  # 1/2
    check_rate_limit(req2, FakeKey())  # 2/2
    with pytest.raises(HTTPException) as exc_info:
        check_rate_limit(req3, FakeKey())  # still the same identity - over budget
    assert exc_info.value.status_code == 429
