"""Unit tests for the in-memory session store, in particular the
avg_threat_score semantics: a brand-new session (no data yet) must be
distinguishable from a session confirmed clean over real traffic (average
100), which returning a bare 100.0 default for both previously collapsed."""
from shield.session_manager import InMemorySessionStore


async def test_avg_threat_score_is_none_for_a_brand_new_session():
    store = InMemorySessionStore()
    ctx = await store.get_or_create("brand-new")
    assert ctx.avg_threat_score is None


async def test_avg_threat_score_is_a_real_average_once_scored():
    store = InMemorySessionStore()
    await store.add_message("scored", "hi")
    await store.record_threat_score("scored", 100)
    await store.record_threat_score("scored", 80)
    ctx = await store.get_or_create("scored")
    assert ctx.avg_threat_score == 90.0


async def test_session_stats_reports_null_not_100_for_a_session_with_no_scores():
    store = InMemorySessionStore()
    await store.add_message("no-scores-yet", "hi")
    stats = await store.get_session_stats("no-scores-yet")
    assert stats["avg_threat_score"] is None


async def test_session_stats_reports_100_only_when_actually_confirmed_clean():
    store = InMemorySessionStore()
    await store.add_message("actually-clean", "hi")
    await store.record_threat_score("actually-clean", 100)
    stats = await store.get_session_stats("actually-clean")
    assert stats["avg_threat_score"] == 100.0
