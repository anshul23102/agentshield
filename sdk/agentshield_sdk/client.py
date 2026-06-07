"""
AgentShield Python SDK
Drop-in security wrapper for any AI agent pipeline.
"""

import httpx
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

    @property
    def is_safe(self) -> bool:
        return self.action == "allow"

    @property
    def is_blocked(self) -> bool:
        return self.action == "block"

    @property
    def is_warned(self) -> bool:
        return self.action == "warn"

    def __str__(self):
        icon = {"block": "🛑", "warn": "⚠️", "allow": "✅"}.get(self.action, "?")
        return f"{icon} [{self.action.upper()}] Score={self.trust_score}/100 | {self.reasoning[:80]}"


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

    def __str__(self):
        icon = "✅" if self.is_safe else "🛑"
        return f"{icon} [{self.action.upper()}] Safety={self.risk_score}/100 | {len(self.leaks_found)} leak(s)"


class AgentShield:
    """
    AgentShield client — wrap any agent call with one line.

    Example:
        shield = AgentShield()
        result = shield.inspect(user_input)
        if result.is_safe:
            response = agent.run(user_input)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 15.0,
        default_session_id: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.default_session_id = default_session_id
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout)
        self._async_client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)

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
        resp = self._client.post("/api/inspect", json=payload)
        resp.raise_for_status()
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
        resp = await self._async_client.post("/api/inspect", json=payload)
        resp.raise_for_status()
        return self._parse(resp.json())

    def inspect_batch(self, texts: list[str], skip_llm: bool = False) -> list[ShieldResult]:
        """Inspect multiple prompts in a single API call."""
        payload = {
            "items": [{"text": t, "skip_llm": skip_llm} for t in texts]
        }
        resp = self._client.post("/api/inspect/batch", json=payload)
        resp.raise_for_status()
        return [self._parse(r) for r in resp.json()]

    def scan_output(self, text: str, redact: bool = True) -> "OutputScanResult":
        """
        Bidirectional protection — scan an AGENT OUTPUT for leaked secrets,
        PII, and financial data before transmitting it to the user.
        """
        resp = self._client.post("/api/scan/output", json={"text": text, "redact": redact})
        resp.raise_for_status()
        d = resp.json()
        return OutputScanResult(
            is_safe=d.get("is_safe", True),
            action=d.get("action", "allow"),
            risk_score=d.get("risk_score", 100),
            leaks_found=d.get("leaks_found", []),
            redacted_text=d.get("redacted_text", text),
            leak_summary=d.get("leak_summary", {}),
            reasoning=d.get("reasoning", ""),
            raw=d,
        )

    def status(self) -> dict:
        return self._client.get("/api/status").json()

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

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._client.close()


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
