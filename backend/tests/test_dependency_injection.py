"""Proves the actual point of moving ThreatDetector/OutputGuard onto
app.state + Depends(): a test can swap the real implementation for a fake one
by assigning app.state directly, with no monkeypatching of main's module
internals required (which is what a bare module-level global would force)."""
import pytest

import main as main_module
from shield.detector import DetectionResult
from shield.output_guard import OutputScanResult


class StubDetector:
    """Minimal stand-in for ThreatDetector - only implements what the routes
    under test actually call."""

    async def inspect(self, text, session_id=None, skip_llm=False):
        return DetectionResult(
            action="block", trust_score=1, threat_detected=True,
            threat_category="Stubbed", threat_level="critical", pattern_matches=[],
            llm_analysis=None, behavioral_flags=["stub_detector_was_used"],
            processing_time_ms=0.1, layers_executed=["stub"], reasoning="stubbed for test",
            mitigation="n/a",
        )


class StubOutputGuard:
    def scan(self, text, redact=True):
        return OutputScanResult(
            is_safe=False, action="block", risk_score=0, leaks_found=[],
            redacted_text="[STUBBED]", leak_summary={}, reasoning="stubbed for test",
        )


async def test_swapping_app_state_detector_changes_inspect_behavior(client):
    # Sanity check first: the real detector allows a clearly benign prompt.
    resp = await client.post("/api/inspect", json={"text": "What's a good pasta recipe?"})
    assert resp.json()["action"] == "allow"

    # Swap in the stub - no monkeypatching of `main.detector` needed, because
    # there is no such module-level global anymore.
    main_module.app.state.detector = StubDetector()
    try:
        resp = await client.post("/api/inspect", json={"text": "What's a good pasta recipe?"})
        body = resp.json()
        assert body["action"] == "block"
        assert body["threat_category"] == "Stubbed"
        assert "stub_detector_was_used" in body["behavioral_flags"]
    finally:
        # Other tests in this session share the same app object.
        from shield import ThreatDetector
        main_module.app.state.detector = ThreatDetector()


async def test_swapping_app_state_output_guard_changes_scan_behavior(client):
    resp = await client.post("/api/scan/output", json={"text": "nothing sensitive here"})
    assert resp.json()["is_safe"] is True

    main_module.app.state.output_guard = StubOutputGuard()
    try:
        resp = await client.post("/api/scan/output", json={"text": "nothing sensitive here"})
        body = resp.json()
        assert body["is_safe"] is False
        assert body["redacted_text"] == "[STUBBED]"
    finally:
        from shield.output_guard import OutputGuard
        main_module.app.state.output_guard = OutputGuard()
