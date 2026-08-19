"""
Shared state for multi-worker deployments.

By default, AgentShield's session tracking, LLM cache, WebSocket-ticket store,
and cross-client broadcast all live in plain process memory - correct and
fast for a single process, but wrong the moment there's more than one. With N
uvicorn workers behind a load balancer, each worker has a disjoint view: a
session that escalates on worker A is invisible on worker B, an LLM result
cached by worker A gets recomputed by worker B, and a WebSocket client
connected to worker B never sees an event broadcast because of a request that
landed on worker A.

Setting REDIS_URL switches all of the above onto Redis-backed implementations
that share state across every worker process. Leaving it unset keeps the
original single-process in-memory behavior, so local dev and single-worker
deployments need zero extra infrastructure - this module is additive, not a
hard dependency.
"""
import os
from typing import Optional

REDIS_URL = os.getenv("REDIS_URL", "")

_client = None


def redis_enabled() -> bool:
    # A client injected via set_redis_client_for_testing() also counts - this
    # is what lets tests exercise the Redis code paths with fakeredis without
    # a real REDIS_URL, rather than every Redis-backed class silently taking
    # the in-memory fallback branch during tests and never actually being run.
    return bool(REDIS_URL) or _client is not None


def get_redis():
    """Returns a shared redis.asyncio client, or None if Redis isn't enabled.
    Lazily constructed so importing this module never requires the `redis`
    package to be usable when Redis isn't configured at all.
    """
    global _client
    if _client is not None:
        return _client
    if not REDIS_URL:
        return None
    import redis.asyncio as redis
    _client = redis.from_url(REDIS_URL, decode_responses=True)
    return _client


def set_redis_client_for_testing(client) -> None:
    """Test hook: inject a fakeredis client (or None to reset) without
    needing a real REDIS_URL / network connection."""
    global _client
    _client = client
