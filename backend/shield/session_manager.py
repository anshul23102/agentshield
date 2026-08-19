"""
AgentShield Session Manager
Tracks multi-turn conversations to detect escalating / multi-step attacks.

Two implementations behind the same async interface: InMemorySessionStore
(default, single process) and RedisSessionStore (shared across every worker
process when REDIS_URL is set). See shield/shared_state.py for why this
matters - without it, a session that escalates on worker A is invisible to
worker B, so the escalating_threat_pattern behavioral flag only ever sees
part of a multi-turn attack.
"""
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from . import shared_state

SESSION_KEY_PREFIX = "agentshield:session:"


@dataclass
class SessionContext:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    message_count: int = 0
    messages: list[str] = field(default_factory=list)
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

    def to_stats(self) -> dict:
        return {
            "session_id": self.session_id,
            "message_count": self.message_count,
            "block_count": self.block_count,
            "warn_count": self.warn_count,
            "avg_threat_score": round(self.avg_threat_score, 1),
            "is_high_risk": self.is_high_risk,
            "elapsed_seconds": round(self.elapsed_seconds, 1),
        }


class InMemorySessionStore:
    """Single-process session store. Correct and fast, but each worker
    process has its own disjoint set of sessions - see module docstring."""

    def __init__(self, max_sessions: int = 10_000, session_ttl: int = 3600):
        self._sessions: dict[str, SessionContext] = {}
        self._max_sessions = max_sessions
        self._session_ttl = session_ttl

    async def get_or_create(self, session_id: str) -> SessionContext:
        self._evict_expired()
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionContext(session_id=session_id)
        else:
            self._sessions[session_id].last_activity = time.time()
        return self._sessions[session_id]

    async def add_message(self, session_id: str, message: str) -> SessionContext:
        ctx = await self.get_or_create(session_id)
        ctx.messages = (ctx.messages + [message])[-20:]
        ctx.message_count += 1
        ctx.last_activity = time.time()
        return ctx

    async def record_threat_score(self, session_id: str, score: int):
        ctx = await self.get_or_create(session_id)
        ctx.threat_score_history = (ctx.threat_score_history + [score])[-100:]
        if score <= 30:
            ctx.block_count += 1
        elif score <= 60:
            ctx.warn_count += 1

    async def get_recent_messages(self, session_id: str, n: int = 5) -> list[str]:
        if session_id not in self._sessions:
            return []
        return self._sessions[session_id].messages[-n:]

    async def get_session_stats(self, session_id: str) -> Optional[dict]:
        ctx = self._sessions.get(session_id)
        return ctx.to_stats() if ctx else None

    async def get_all_stats(self) -> dict:
        return {
            "total_sessions": len(self._sessions),
            "high_risk_sessions": sum(1 for s in self._sessions.values() if s.is_high_risk),
            "total_messages": sum(s.message_count for s in self._sessions.values()),
            "total_blocks": sum(s.block_count for s in self._sessions.values()),
        }

    async def reset_all(self):
        self._sessions.clear()

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


class RedisSessionStore:
    """Redis-backed session store: every worker process reads and writes the
    same session state, so multi-turn escalation detection and session stats
    are correct regardless of which worker handles which request in a
    session. TTL is enforced by Redis itself (EX on every write) rather than
    a manual sweep, which is also what makes it correct across processes -
    no single worker "owns" eviction.
    """

    def __init__(self, session_ttl: int = 3600):
        self._ttl = session_ttl

    def _key(self, session_id: str) -> str:
        return f"{SESSION_KEY_PREFIX}{session_id}"

    async def _load(self, session_id: str) -> Optional[SessionContext]:
        raw = await shared_state.get_redis().get(self._key(session_id))
        if not raw:
            return None
        return SessionContext(**json.loads(raw))

    async def _save(self, ctx: SessionContext):
        payload = json.dumps(ctx.__dict__)
        await shared_state.get_redis().set(self._key(ctx.session_id), payload, ex=self._ttl)

    async def get_or_create(self, session_id: str) -> SessionContext:
        ctx = await self._load(session_id)
        if ctx is None:
            ctx = SessionContext(session_id=session_id)
        else:
            ctx.last_activity = time.time()
        await self._save(ctx)
        return ctx

    async def add_message(self, session_id: str, message: str) -> SessionContext:
        ctx = await self.get_or_create(session_id)
        ctx.messages = (ctx.messages + [message])[-20:]
        ctx.message_count += 1
        ctx.last_activity = time.time()
        await self._save(ctx)
        return ctx

    async def record_threat_score(self, session_id: str, score: int):
        ctx = await self.get_or_create(session_id)
        ctx.threat_score_history = (ctx.threat_score_history + [score])[-100:]
        if score <= 30:
            ctx.block_count += 1
        elif score <= 60:
            ctx.warn_count += 1
        await self._save(ctx)

    async def get_recent_messages(self, session_id: str, n: int = 5) -> list[str]:
        ctx = await self._load(session_id)
        return ctx.messages[-n:] if ctx else []

    async def get_session_stats(self, session_id: str) -> Optional[dict]:
        ctx = await self._load(session_id)
        return ctx.to_stats() if ctx else None

    async def get_all_stats(self) -> dict:
        # A key scan is O(n) in session count, but this is an admin/status
        # endpoint called rarely, not a hot path.
        client = shared_state.get_redis()
        total = high_risk = messages = blocks = 0
        async for key in client.scan_iter(match=f"{SESSION_KEY_PREFIX}*"):
            raw = await client.get(key)
            if not raw:
                continue
            ctx = SessionContext(**json.loads(raw))
            total += 1
            messages += ctx.message_count
            blocks += ctx.block_count
            if ctx.is_high_risk:
                high_risk += 1
        return {
            "total_sessions": total, "high_risk_sessions": high_risk,
            "total_messages": messages, "total_blocks": blocks,
        }

    async def reset_all(self):
        client = shared_state.get_redis()
        keys = [key async for key in client.scan_iter(match=f"{SESSION_KEY_PREFIX}*")]
        if keys:
            await client.delete(*keys)


def create_session_store(max_sessions: int = 10_000, session_ttl: int = 3600):
    """Picks the Redis-backed store when REDIS_URL is configured, otherwise
    the in-memory one. Both expose the identical async interface above."""
    if shared_state.redis_enabled():
        return RedisSessionStore(session_ttl=session_ttl)
    return InMemorySessionStore(max_sessions=max_sessions, session_ttl=session_ttl)
