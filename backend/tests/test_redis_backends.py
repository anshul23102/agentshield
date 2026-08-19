"""
Tests for the Redis-backed shared state (session store, LLM cache, WS
tickets). Uses fakeredis so these exercise the actual Redis code paths -
otherwise unpinned REDIS_URL in the rest of the suite means this logic is
never touched at all, in-memory fallback or not.
"""
import pytest
import fakeredis

from shield import shared_state
from shield.session_manager import RedisSessionStore
from shield.analyzer import RedisLLMCache, LLMAnalysisResult


@pytest.fixture(autouse=True)
def _fake_redis():
    client = fakeredis.FakeAsyncRedis(decode_responses=True)
    shared_state.set_redis_client_for_testing(client)
    yield client
    shared_state.set_redis_client_for_testing(None)


# ── Session store ─────────────────────────────────────────────────────────────

async def test_redis_session_store_persists_across_instances():
    # Two separate RedisSessionStore objects sharing the same backing Redis -
    # simulates two different worker processes.
    store_a = RedisSessionStore(session_ttl=3600)
    store_b = RedisSessionStore(session_ttl=3600)

    await store_a.add_message("s1", "hello from worker A")
    ctx = await store_b.get_or_create("s1")

    assert ctx.message_count == 1
    assert ctx.messages == ["hello from worker A"]


async def test_redis_session_store_records_threat_scores():
    store = RedisSessionStore()
    await store.add_message("s2", "msg")
    await store.record_threat_score("s2", 20)
    await store.record_threat_score("s2", 45)

    stats = await store.get_session_stats("s2")
    assert stats["block_count"] == 1  # score <= 30
    assert stats["warn_count"] == 1   # 30 < score <= 60


async def test_redis_session_store_returns_none_for_unknown_session():
    store = RedisSessionStore()
    assert await store.get_session_stats("never-created") is None


async def test_redis_session_store_get_all_stats_aggregates_across_sessions():
    store = RedisSessionStore()
    await store.add_message("agg-1", "hi")
    await store.add_message("agg-2", "hi")
    await store.record_threat_score("agg-1", 10)  # block
    await store.record_threat_score("agg-1", 10)  # block -> high risk

    stats = await store.get_all_stats()
    assert stats["total_sessions"] >= 2
    assert stats["high_risk_sessions"] >= 1


async def test_redis_session_store_reset_all_clears_everything():
    store = RedisSessionStore()
    await store.add_message("to-clear", "hi")
    await store.reset_all()
    assert await store.get_session_stats("to-clear") is None


async def test_redis_session_store_recent_messages_respects_n():
    store = RedisSessionStore()
    for i in range(5):
        await store.add_message("s3", f"message {i}")
    recent = await store.get_recent_messages("s3", n=2)
    assert recent == ["message 3", "message 4"]


# ── LLM cache ──────────────────────────────────────────────────────────────────

def _result(reasoning="test") -> LLMAnalysisResult:
    return LLMAnalysisResult(
        is_threat=True, threat_type="injection", confidence=0.9, severity="high",
        reasoning=reasoning, recommended_action="block", attack_vector="test", mitigation="n/a",
    )


async def test_redis_llm_cache_roundtrips_a_result():
    cache = RedisLLMCache()
    await cache.set("key1", _result("stored value"))
    cached = await cache.get("key1")
    assert cached.reasoning == "stored value"
    assert cached.is_threat is True


async def test_redis_llm_cache_miss_returns_none():
    cache = RedisLLMCache()
    assert await cache.get("never-set") is None


async def test_redis_llm_cache_shared_across_instances():
    cache_a = RedisLLMCache()
    cache_b = RedisLLMCache()
    await cache_a.set("shared-key", _result("from A"))
    cached = await cache_b.get("shared-key")
    assert cached is not None and cached.reasoning == "from A"


async def test_redis_llm_cache_clear_empties_all_entries():
    cache = RedisLLMCache()
    await cache.set("a", _result())
    await cache.set("b", _result())
    assert await cache.size() == 2
    await cache.clear()
    assert await cache.size() == 0


# ── WS tickets ─────────────────────────────────────────────────────────────────

async def test_redis_ws_ticket_mint_and_consume_roundtrip():
    import main as main_module
    ticket = await main_module._mint_ws_ticket("tenant-redis")
    assert await main_module._consume_ws_ticket(ticket) == "tenant-redis"


async def test_redis_ws_ticket_is_single_use():
    import main as main_module
    ticket = await main_module._mint_ws_ticket("tenant-redis-2")
    await main_module._consume_ws_ticket(ticket)
    assert await main_module._consume_ws_ticket(ticket) is None


async def test_redis_ws_ticket_usable_from_a_different_store_instance():
    # The whole point: a ticket minted while handling a request on "worker A"
    # must be redeemable when the WS handshake lands on "worker B" - modeled
    # here as two calls sharing only the fake Redis backend, not any
    # in-process state.
    import main as main_module
    ticket = await main_module._mint_ws_ticket("tenant-cross-worker")
    # Simulate a different worker's in-memory dict being empty/unrelated.
    main_module._local_ws_tickets.clear()
    assert await main_module._consume_ws_ticket(ticket) == "tenant-cross-worker"
