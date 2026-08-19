"""
AgentShield Multi-Layer Threat Detector
4-layer detection pipeline: Pattern → Semantic → LLM → Behavioral
"""

import re
import time
import asyncio
import unicodedata
from typing import Optional
from dataclasses import dataclass, field

from confusable_homoglyphs import confusables

from .patterns import (
    COMPILED_PATTERNS, ThreatLevel, ThreatCategory, AttackPattern
)
from .analyzer import LLMAnalyzer, LLMAnalysisResult
from .trust_scorer import TrustScorer
from .session_manager import SessionManager, SessionContext


@dataclass
class PatternMatch:
    pattern_id: str
    category: ThreatCategory
    threat_level: ThreatLevel
    description: str
    matched_text: str
    position: int


@dataclass
class DetectionResult:
    # Core verdict
    action: str                     # "block" | "warn" | "allow"
    trust_score: int                 # 0–100
    threat_detected: bool

    # Detection details
    threat_category: Optional[str]
    threat_level: Optional[str]
    pattern_matches: list[PatternMatch]

    # LLM analysis (if performed)
    llm_analysis: Optional[LLMAnalysisResult]

    # Behavioral signals
    behavioral_flags: list[str]

    # Metadata
    processing_time_ms: float
    layers_executed: list[str]
    reasoning: str
    mitigation: str
    session_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "trust_score": self.trust_score,
            "threat_detected": self.threat_detected,
            "threat_category": self.threat_category,
            "threat_level": self.threat_level,
            "pattern_matches": [
                {
                    "id": m.pattern_id,
                    "category": m.category.value,
                    "level": m.threat_level.value,
                    "description": m.description,
                    "matched_text": m.matched_text[:100],
                    "position": m.position,
                }
                for m in self.pattern_matches
            ],
            "llm_analysis": {
                "is_threat": self.llm_analysis.is_threat,
                "threat_type": self.llm_analysis.threat_type,
                "confidence": self.llm_analysis.confidence,
                "severity": self.llm_analysis.severity,
                "reasoning": self.llm_analysis.reasoning,
                "recommended_action": self.llm_analysis.recommended_action,
                "attack_vector": self.llm_analysis.attack_vector,
                "mitigation": self.llm_analysis.mitigation,
            } if self.llm_analysis else None,
            "behavioral_flags": self.behavioral_flags,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "layers_executed": self.layers_executed,
            "reasoning": self.reasoning,
            "mitigation": self.mitigation,
            "session_id": self.session_id,
        }


# Suspicious keywords for lightweight semantic check (no embeddings needed)
SUSPICIOUS_KEYWORDS = {
    "critical": [
        "jailbreak", "dan mode", "dan prompt", "no restrictions", "unrestricted",
        "ignore instructions", "bypass safety", "override system", "admin override",
        "root access", "superuser", "disable filters", "uncensored mode",
    ],
    "high": [
        "system prompt", "reveal instructions", "your training", "exfiltrate",
        "extract data", "developer mode", "maintenance mode", "debug mode",
        "evil ai", "shadow ai", "alter ego", "true self", "inner self",
        # Harmful-intent / abuse requests (not agent-hijacking, but malicious use)
        "hack", "hacking", "steal", "stealing", "crack a password", "crack the password",
        "break into", "gain access to", "unauthorized access", "without permission",
        "without consent", "without their knowledge", "someone's account",
        "someone's password", "their password", "spy on", "stalk", "phishing",
        "ransomware", "malware", "keylogger", "ddos", "sql injection",
        "bypass authentication", "bypass login", "exploit a vulnerability",
    ],
    "medium": [
        "hypothetically", "theoretically", "as a fictional", "for academic purposes",
        "between us", "trust me", "as my friend", "roleplay as", "pretend you",
        "imagine you", "what if you", "in a simulation",
    ],
}

def normalize_text(text: str) -> str:
    """Normalize unicode, collapse whitespace, lowercase for pattern matching."""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def detect_lookalike_chars(text: str) -> bool:
    """True if the text mixes scripts in a way that could be spoofing ASCII -
    e.g. a Cyrillic 'а' standing in for a Latin 'a'. Uses the Unicode
    confusables table (the same data django-registration and browsers'
    IDN-spoof checks use) rather than three hardcoded codepoint ranges, which
    only ever covered Cyrillic, fullwidth Latin, and math alphanumeric and
    missed Greek, Armenian, Cherokee, and dozens of other confusable blocks.
    NFKC in normalize_text() already collapses fullwidth/math-alphanumeric
    (those are compatibility decompositions); this covers the much larger set
    NFKC structurally cannot, since those are genuinely different characters
    that merely render identically.
    """
    return bool(confusables.is_dangerous(text))


def normalize_confusables(text: str) -> str:
    """Maps cross-script confusable characters back to their ASCII look-alike
    (Cyrillic а -> a, Greek ο -> o, Armenian ա -> w, ...) before pattern
    matching runs, so a homoglyph-obfuscated attack string still gets caught
    instead of just flagged after the fact.
    """
    findings = confusables.is_confusable(text, preferred_aliases=["latin", "common"], greedy=True)
    if not findings:
        return text
    replacements = {}
    for f in findings:
        ch = f["character"]
        if ord(ch) < 128:
            continue
        for h in f["homoglyphs"]:
            candidate = h["c"]
            if len(candidate) == 1 and ord(candidate) < 128:
                replacements[ch] = candidate
                break
    if not replacements:
        return text
    return "".join(replacements.get(c, c) for c in text)


_COLLAPSE_SEPARATORS_RE = re.compile(r"(?<=[A-Za-z0-9])[\s.\-_*]{1,2}(?=[A-Za-z0-9])")


def collapse_spacing_evasion(text: str) -> str:
    """Strips single separator characters wedged between letters/digits, e.g.
    'i.g.n.o.r.e' or 'i g n o r e' or 'i-g-n-o-r-e' -> 'ignore'. Deliberately
    aggressive: it also collapses ordinary prose ('New York' -> 'NewYork'),
    but the output is only ever used for a substring check against a short,
    specific attack-signature list below, never shown to a user or matched
    against the full regex pattern set - so over-collapsing normal text is
    harmless, it just can't accidentally spell out one of those signatures.
    """
    return _COLLAPSE_SEPARATORS_RE.sub("", text)


# Attack-intent phrases worth catching even when spelled with inserted
# separators or padding whitespace, since Layer 1's regexes match on
# contiguous text and a trivial "i.g.n.o.r.e" rewrite defeats them outright.
OBFUSCATION_SIGNATURES = [
    "ignoreallpreviousinstructions", "ignoretheabovepreviousinstructions",
    "disableallfilters", "disablesafetyfilters", "disablecontentfilters",
    "bypassallsafety", "bypasssafetyfilters", "bypasssafetymeasures",
    "danmode", "developermode", "jailbreakmode", "uncensoredmode",
    "revealsystemprompt", "revealyoursysteminstructions", "printsystemprompt",
    "unrestrictedmode", "havenorestrictions", "nolongerrestricted",
]


class ThreatDetector:
    def __init__(self):
        self.analyzer = LLMAnalyzer()
        self.scorer = TrustScorer()
        self.session_manager = SessionManager()

    async def inspect(
        self,
        text: str,
        session_id: Optional[str] = None,
        skip_llm: bool = False,
    ) -> DetectionResult:
        t0 = time.perf_counter()
        layers_executed = []
        pattern_matches: list[PatternMatch] = []
        behavioral_flags: list[str] = []
        llm_result: Optional[LLMAnalysisResult] = None

        # ── Pre-processing ────────────────────────────────────────────────────
        # Undo cross-script homoglyph substitution before matching, not just
        # flag it - otherwise a Cyrillic 'а' standing in for 'a' silently
        # defeats every Layer 1 pattern built around the Latin spelling.
        deconfused = normalize_confusables(text)
        normalized = normalize_text(deconfused)
        lower = normalized.lower()

        # Unicode obfuscation check (flagged even though we already corrected
        # for it above - a legitimate input has no reason to mix scripts)
        if detect_lookalike_chars(text):
            behavioral_flags.append("unicode_lookalike_chars_detected")

        # Unusually long input check (potential token-stuffing)
        if len(text) > 2000:
            behavioral_flags.append("unusually_long_input")

        # Punctuation/spacing evasion check ("i.g.n.o.r.e" -> "ignore"):
        # collapse separators and look for a known attack-intent phrase that
        # would otherwise slip past every space/period-anchored regex above.
        collapsed = collapse_spacing_evasion(lower)
        if any(sig in collapsed for sig in OBFUSCATION_SIGNATURES):
            behavioral_flags.append("obfuscated_attack_signature_detected")

        # ── Layer 1: Pattern Matching ─────────────────────────────────────────
        layers_executed.append("pattern_matching")
        for pattern_obj, compiled_re in COMPILED_PATTERNS:
            match = compiled_re.search(normalized)
            if match:
                pattern_matches.append(PatternMatch(
                    pattern_id=pattern_obj.id,
                    category=pattern_obj.category,
                    threat_level=pattern_obj.threat_level,
                    description=pattern_obj.description,
                    matched_text=match.group(0),
                    position=match.start(),
                ))

        # Critical pattern → immediate block without LLM call
        critical_matches = [m for m in pattern_matches if m.threat_level == ThreatLevel.CRITICAL]
        high_matches = [m for m in pattern_matches if m.threat_level == ThreatLevel.HIGH]

        # ── Layer 2: Keyword Semantic Check ───────────────────────────────────
        layers_executed.append("semantic_keywords")
        keyword_hits: list[tuple[str, str]] = []
        for level, kw_list in SUSPICIOUS_KEYWORDS.items():
            for kw in kw_list:
                if kw in lower:
                    keyword_hits.append((level, kw))

        # ── Layer 3: Behavioral Analysis ──────────────────────────────────────
        layers_executed.append("behavioral_analysis")
        session_context: Optional[SessionContext] = None

        if session_id:
            session_context = self.session_manager.get_or_create(session_id)
            self.session_manager.add_message(session_id, text)

            # Multi-turn attack signals: strictly decreasing trust scores ending
            # in risky territory. Equal scores (e.g. a clean streak of 95s) must
            # not trigger this flag.
            history = session_context.threat_score_history
            if session_context.message_count > 5 and len(history) >= 3:
                if history[-1] < 60 and history[-1] < history[-2] < history[-3]:
                    behavioral_flags.append("escalating_threat_pattern")

            # Rapid message rate
            if session_context.message_count > 20 and session_context.elapsed_seconds < 60:
                behavioral_flags.append("high_message_rate_detected")

        # ── Layer 4: LLM Deep Analysis ────────────────────────────────────────
        # The LLM is the semantic safety net for anything the lightweight layers
        # can't structurally match (e.g. plain-language harmful-intent requests).
        # Run it whenever available on any non-trivial input; only skip the
        # genuinely tiny/empty prompts where there is nothing to reason about.
        word_count = len(lower.split())
        should_run_llm = (
            not skip_llm
            and self.analyzer.is_llm_available
            and (
                len(pattern_matches) > 0        # confirm pattern matches
                or len(keyword_hits) > 0        # any keyword signal
                or len(behavioral_flags) > 0    # behavioral anomaly
                or word_count >= 4              # any real sentence / request
            )
        )

        if should_run_llm:
            layers_executed.append("llm_deep_analysis")
            ctx_str = None
            if session_context and session_context.message_count > 1:
                recent = self.session_manager.get_recent_messages(session_id, 3)
                ctx_str = "\n".join(recent[:-1])  # all but current
            llm_result = await self.analyzer.analyze(text, ctx_str)

        # ── Scoring & Final Decision ──────────────────────────────────────────
        trust_score = self.scorer.compute(
            pattern_matches=pattern_matches,
            keyword_hits=keyword_hits,
            llm_result=llm_result,
            behavioral_flags=behavioral_flags,
            text_length=len(text),
        )

        # Update session threat history
        if session_id:
            self.session_manager.record_threat_score(session_id, trust_score)

        # Determine action
        if trust_score <= 30:
            action = "block"
        elif trust_score <= 60:
            action = "warn"
        else:
            action = "allow"

        # Override: explicit critical pattern or LLM says block with high confidence
        if critical_matches:
            action = "block"
            trust_score = min(trust_score, 15)
        if llm_result and llm_result.recommended_action == "block" and llm_result.confidence > 0.8:
            action = "block"
            trust_score = min(trust_score, 20)

        # Build reasoning
        reasoning_parts = []
        if pattern_matches:
            cats = list({m.category.value for m in pattern_matches})
            reasoning_parts.append(f"Pattern matches: {', '.join(cats)}")
        if keyword_hits:
            reasoning_parts.append(f"Suspicious keywords detected ({len(keyword_hits)})")
        if behavioral_flags:
            reasoning_parts.append(f"Behavioral signals: {', '.join(behavioral_flags)}")
        if llm_result and llm_result.is_threat:
            reasoning_parts.append(f"LLM: {llm_result.reasoning}")
        if not reasoning_parts:
            reasoning_parts.append("No threats detected. Input appears safe")

        reasoning = " | ".join(reasoning_parts)

        # Mitigation advice
        mitigation = "n/a"
        if llm_result and llm_result.mitigation and llm_result.mitigation != "n/a":
            mitigation = llm_result.mitigation
        elif pattern_matches:
            mitigation = "Sanitize input before passing to agent. Log and monitor this session."

        # Primary threat info
        top_match = pattern_matches[0] if pattern_matches else None
        threat_category = top_match.category.value if top_match else (
            llm_result.threat_type if llm_result and llm_result.is_threat else None
        )
        threat_level = top_match.threat_level.value if top_match else (
            llm_result.severity if llm_result and llm_result.is_threat else None
        )

        elapsed = (time.perf_counter() - t0) * 1000

        return DetectionResult(
            action=action,
            trust_score=trust_score,
            threat_detected=(action in ("block", "warn")),
            threat_category=threat_category,
            threat_level=threat_level,
            pattern_matches=pattern_matches,
            llm_analysis=llm_result,
            behavioral_flags=behavioral_flags,
            processing_time_ms=elapsed,
            layers_executed=layers_executed,
            reasoning=reasoning,
            mitigation=mitigation,
            session_id=session_id,
        )
