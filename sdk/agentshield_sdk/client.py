"""
AgentShield Python SDK
Drop-in security wrapper for any agent pipeline.
"""

import httpx
import os
import uuid
from dataclasses import dataclass
from typing import Optional


@dataclass
class ShieldResult:
    action: str               # "block" | "warn" | "allow"
    trust_score: int          # 0–100
    threat_detected: bool
    threat_category: Optional[str]
    threat_level: Optional[str]
    reasoning: str
    mitigation: str
    processing_time_ms: float
    pattern_matches: list
    llm_analysis: Optional[dict]
    behavioral_flags: list
    session_id: str
    raw: dict
    # True when the AgentShield server could not be reached and the client was
    # configured with fail_open=True. The text was NOT inspected; log this.
    degraded: bool = False

    @property
    def is_safe(self) -> bool:
        """True only for an "allow" verdict. A "warn" is not safe: it means the
        prompt scored in the suspicious band, and the caller decides what to do."""
        return self.action == "allow"

    @property
    def is_blocked(self) -> bool:
        return self.action == "block"

    @property
    def is_warned(self) -> bool:
        return self.action == "warn"

    def __str__(self):
        note = " (NOT INSPECTED: server unreachable)" if self.degraded else ""
        return f"[{self.action.upper()}] Score={self.trust_score}/100 | {self.reasoning[:80]}{note}"


@dataclass
class OutputScanResult:
    is_safe: bool
    action: str               # "block" | "redact" | "allow"
    risk_score: int           # 0–100
    leaks_found: list
    redacted_text: str
    leak_summary: dict
    reasoning: str
    raw: dict
    degraded: bool = False

    def __str__(self):
        note = " (NOT SCANNED: server unreachable)" if self.degraded else ""
        return f"[{self.action.upper()}] Safety={self.risk_score}/100 | {len(self.leaks_found)} leak(s){note}"


class AgentShield:
    """
    AgentShield client: wrap any agent call with one line.

    Example:
        shield = AgentShield(api_key="ash_live_...")
        result = shield.inspect(user_input)
        if result.is_safe:
            response = agent.run(user_input)

    The server requires an API key on every inspect/scan/analytics call. Pass
    one explicitly, or set the AGENTSHIELD_API_KEY environment variable - issue
    one with `python scripts/create_api_key.py "label"` on the server.

    What happens when AgentShield itself is down? That is a real policy choice,
    so it is explicit:
      * fail_open=False (default, "fail closed"): network and HTTP errors are
        raised to the caller, so an agent never runs on an uninspected prompt by
        accident. Safer; an outage becomes an exception you must handle.
      * fail_open=True: the call returns an "allow" result flagged
        degraded=True and the agent keeps working, uninspected. More available;
        you accept that attacks pass during an outage. Log result.degraded.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: float = 15.0,
        default_session_id: Optional[str] = None,
        fail_open: bool = False,
        transport=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.getenv("AGENTSHIELD_API_KEY")
        self.timeout = timeout
        self.default_session_id = default_session_id
        self.fail_open = fail_open
        headers = {"X-API-Key": self.api_key} if self.api_key else {}
        # `transport` exists for tests (httpx.MockTransport) and custom networking.
        extra = {"transport": transport} if transport is not None else {}
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout, headers=headers, **extra)
        self._async_client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout, headers=headers, **extra)

    # ── failure policy ────────────────────────────────────────────────────────

    def _degraded_inspect(self, exc: Exception) -> "ShieldResult":
        if not self.fail_open:
            raise exc
        return ShieldResult(
            action="allow", trust_score=0, threat_detected=False, threat_category=None, threat_level=None,
            reasoning=f"AgentShield unreachable ({type(exc).__name__}); failing open. The prompt was NOT inspected.",
            mitigation="", processing_time_ms=0.0, pattern_matches=[], llm_analysis=None,
            behavioral_flags=["agentshield_unreachable"], session_id="", raw={"error": str(exc)}, degraded=True,
        )

    def _degraded_scan(self, exc: Exception, text: str) -> "OutputScanResult":
        if not self.fail_open:
            raise exc
        return OutputScanResult(
            is_safe=True, action="allow", risk_score=0, leaks_found=[], redacted_text=text, leak_summary={},
            reasoning=f"AgentShield unreachable ({type(exc).__name__}); failing open. The output was NOT scanned.",
            raw={"error": str(exc)}, degraded=True,
        )

    # ── input inspection ──────────────────────────────────────────────────────

    def inspect(
        self,
        text: str,
        session_id: Optional[str] = None,
        skip_llm: bool = False,
    ) -> ShieldResult:
        """Synchronously inspect a prompt. Blocks until result is available."""
        payload = {
            "text": text,
            "session_id": session_id or self.default_session_id,
            "skip_llm": skip_llm,
        }
        try:
            resp = self._client.post("/api/inspect", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._degraded_inspect(exc)
        return self._parse(resp.json())

    async def ainspect(
        self,
        text: str,
        session_id: Optional[str] = None,
        skip_llm: bool = False,
    ) -> ShieldResult:
        """Async inspect for use in async agent pipelines."""
        payload = {
            "text": text,
            "session_id": session_id or self.default_session_id,
            "skip_llm": skip_llm,
        }
        try:
            resp = await self._async_client.post("/api/inspect", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._degraded_inspect(exc)
        return self._parse(resp.json())

    def inspect_batch(self, texts: list[str], skip_llm: bool = False) -> list[ShieldResult]:
        """Inspect multiple prompts in a single API call."""
        payload = {
            "items": [{"text": t, "skip_llm": skip_llm} for t in texts]
        }
        try:
            resp = self._client.post("/api/inspect/batch", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return [self._degraded_inspect(exc) for _ in texts]
        return [self._parse(r) for r in resp.json()]

    # ── output scanning ───────────────────────────────────────────────────────

    def scan_output(self, text: str, redact: bool = True, session_id: Optional[str] = None) -> "OutputScanResult":
        """
        Bidirectional protection: scan an AGENT OUTPUT for leaked secrets,
        PII, and financial data before transmitting it to the user.
        """
        payload = {"text": text, "redact": redact, "session_id": session_id or self.default_session_id}
        try:
            resp = self._client.post("/api/scan/output", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._degraded_scan(exc, text)
        return self._parse_scan(resp.json(), text)

    async def ascan_output(self, text: str, redact: bool = True, session_id: Optional[str] = None) -> "OutputScanResult":
        """Async counterpart of scan_output."""
        payload = {"text": text, "redact": redact, "session_id": session_id or self.default_session_id}
        try:
            resp = await self._async_client.post("/api/scan/output", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            return self._degraded_scan(exc, text)
        return self._parse_scan(resp.json(), text)

    def status(self) -> dict:
        resp = self._client.get("/api/status")
        resp.raise_for_status()
        return resp.json()

    # ── parsing ───────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_scan(d: dict, original_text: str) -> "OutputScanResult":
        return OutputScanResult(
            is_safe=d.get("is_safe", True),
            action=d.get("action", "allow"),
            risk_score=d.get("risk_score", 100),
            leaks_found=d.get("leaks_found", []),
            redacted_text=d.get("redacted_text", original_text),
            leak_summary=d.get("leak_summary", {}),
            reasoning=d.get("reasoning", ""),
            raw=d,
        )

    @staticmethod
    def _parse(data: dict) -> ShieldResult:
        return ShieldResult(
            action=data.get("action", "allow"),
            trust_score=data.get("trust_score", 100),
            threat_detected=data.get("threat_detected", False),
            threat_category=data.get("threat_category"),
            threat_level=data.get("threat_level"),
            reasoning=data.get("reasoning", ""),
            mitigation=data.get("mitigation", ""),
            processing_time_ms=data.get("processing_time_ms", 0.0),
            pattern_matches=data.get("pattern_matches", []),
            llm_analysis=data.get("llm_analysis"),
            behavioral_flags=data.get("behavioral_flags", []),
            session_id=data.get("session_id", ""),
            raw=data,
        )

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def close(self):
        self._client.close()

    async def aclose(self):
        """Close the async client too. It used to be left open forever, which
        leaks sockets and triggers 'unclosed client' warnings."""
        await self._async_client.aclose()
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.aclose()


class ShieldedSession:
    """Context manager for multi-turn protected conversations."""

    def __init__(self, shield: AgentShield, session_id: Optional[str] = None):
        self.shield = shield
        self.session_id = session_id or str(uuid.uuid4())
        self.history: list[ShieldResult] = []

    def inspect(self, text: str, **kwargs) -> ShieldResult:
        result = self.shield.inspect(text, session_id=self.session_id, **kwargs)
        self.history.append(result)
        return result

    async def ainspect(self, text: str, **kwargs) -> ShieldResult:
        result = await self.shield.ainspect(text, session_id=self.session_id, **kwargs)
        self.history.append(result)
        return result

    @property
    def block_count(self) -> int:
        return sum(1 for r in self.history if r.is_blocked)

    @property
    def is_compromised(self) -> bool:
        return self.block_count >= 2

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass
