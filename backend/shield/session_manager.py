"""
AgentShield Session Manager
Tracks multi-turn conversations to detect escalating / multi-step attacks.
"""

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SessionContext:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    message_count: int = 0
    messages: deque = field(default_factory=lambda: deque(maxlen=20))
    threat_score_history: list[int] = field(default_factory=list)
    block_count: int = 0
    warn_count: int = 0

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def avg_threat_score(self) -> float:
        if not self.threat_score_history:
            return 100.0
        return sum(self.threat_score_history) / len(self.threat_score_history)

    @property
    def is_high_risk(self) -> bool:
        return self.block_count >= 2 or self.warn_count >= 4


class SessionManager:
    def __init__(self, max_sessions: int = 10_000, session_ttl: int = 3600):
        self._sessions: dict[str, SessionContext] = {}
        self._max_sessions = max_sessions
        self._session_ttl = session_ttl

    def get_or_create(self, session_id: str) -> SessionContext:
        self._evict_expired()
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionContext(session_id=session_id)
        else:
            self._sessions[session_id].last_activity = time.time()
        return self._sessions[session_id]

    def add_message(self, session_id: str, message: str):
        ctx = self.get_or_create(session_id)
        ctx.messages.append(message)
        ctx.message_count += 1
        ctx.last_activity = time.time()

    def record_threat_score(self, session_id: str, score: int):
        ctx = self.get_or_create(session_id)
        ctx.threat_score_history.append(score)
        if len(ctx.threat_score_history) > 100:
            ctx.threat_score_history.pop(0)
        if score <= 30:
            ctx.block_count += 1
        elif score <= 60:
            ctx.warn_count += 1

    def get_recent_messages(self, session_id: str, n: int = 5) -> list[str]:
        if session_id not in self._sessions:
            return []
        return list(self._sessions[session_id].messages)[-n:]

    def get_session_stats(self, session_id: str) -> Optional[dict]:
        ctx = self._sessions.get(session_id)
        if not ctx:
            return None
        return {
            "session_id": session_id,
            "message_count": ctx.message_count,
            "block_count": ctx.block_count,
            "warn_count": ctx.warn_count,
            "avg_threat_score": round(ctx.avg_threat_score, 1),
            "is_high_risk": ctx.is_high_risk,
            "elapsed_seconds": round(ctx.elapsed_seconds, 1),
        }

    def get_all_stats(self) -> dict:
        return {
            "total_sessions": len(self._sessions),
            "high_risk_sessions": sum(1 for s in self._sessions.values() if s.is_high_risk),
            "total_messages": sum(s.message_count for s in self._sessions.values()),
            "total_blocks": sum(s.block_count for s in self._sessions.values()),
        }

    def _evict_expired(self):
        now = time.time()
        expired = [
            sid for sid, ctx in self._sessions.items()
            if (now - ctx.last_activity) > self._session_ttl
        ]
        for sid in expired:
            del self._sessions[sid]
        # LRU eviction if at capacity
        if len(self._sessions) >= self._max_sessions:
            oldest = sorted(self._sessions.items(), key=lambda x: x[1].last_activity)
            for sid, _ in oldest[:100]:
                del self._sessions[sid]
