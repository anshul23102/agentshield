"""Confirms log_event() actually persists the redacted preview, not the raw one -
the whole point of wiring the redactor into the storage path rather than leaving
it as a standalone function nothing calls."""
from database.db import log_event, get_recent_events


async def test_stored_preview_has_secret_redacted():
    result_dict = {
        "action": "block", "trust_score": 10, "threat_category": "Data Exfiltration",
        "threat_level": "critical", "pattern_matches": [], "llm_analysis": None,
        "processing_time_ms": 1.0, "reasoning": "test",
    }
    raw_input = "is this AWS key valid: AKIAIOSFODNN7EXAMPLE"
    await log_event(result_dict, raw_input, session_id="redaction-test")

    events = await get_recent_events(limit=5)
    matching = [e for e in events if e["session_id"] == "redaction-test"]
    assert matching, "expected the just-logged event to be in recent_events"
    assert "AKIA" not in matching[0]["input_preview"]
