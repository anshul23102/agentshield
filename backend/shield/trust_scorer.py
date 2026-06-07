"""
AgentShield Trust Scorer
Computes a 0-100 trust score from multi-layer detection signals.
100 = completely trusted, 0 = definitely malicious.
"""

from typing import Optional
from .patterns import ThreatLevel


LEVEL_DEDUCTIONS = {
    ThreatLevel.CRITICAL: 75,
    ThreatLevel.HIGH: 45,
    ThreatLevel.MEDIUM: 25,
    ThreatLevel.LOW: 10,
}

KEYWORD_DEDUCTIONS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
}

BEHAVIORAL_DEDUCTIONS = {
    "escalating_threat_pattern": 25,
    "unicode_lookalike_chars_detected": 15,
    "unusually_long_input": 5,
    "high_message_rate_detected": 10,
}

LLM_SEVERITY_DEDUCTIONS = {
    "critical": 40,
    "high": 30,
    "medium": 15,
    "low": 5,
    "safe": 0,
}


class TrustScorer:
    def compute(
        self,
        pattern_matches,
        keyword_hits: list,
        llm_result,
        behavioral_flags: list,
        text_length: int,
    ) -> int:
        score = 100

        # Pattern match deductions (worst match dominates, others add diminishing penalty)
        if pattern_matches:
            sorted_matches = sorted(
                pattern_matches,
                key=lambda m: LEVEL_DEDUCTIONS.get(m.threat_level, 0),
                reverse=True,
            )
            # Primary deduction from worst match
            score -= LEVEL_DEDUCTIONS.get(sorted_matches[0].threat_level, 0)
            # Additional matches: 30% of their deduction each
            for m in sorted_matches[1:]:
                score -= int(LEVEL_DEDUCTIONS.get(m.threat_level, 0) * 0.3)

        # Keyword deductions (max 3 contribute)
        unique_keyword_signals = {}
        for level, kw in keyword_hits:
            if level not in unique_keyword_signals:
                unique_keyword_signals[level] = 0
            unique_keyword_signals[level] += 1

        for level, count in unique_keyword_signals.items():
            base = KEYWORD_DEDUCTIONS.get(level, 0)
            # First hit full, subsequent diminishing
            score -= base + (count - 1) * (base // 3)

        # LLM analysis deduction
        if llm_result and llm_result.is_threat:
            llm_deduction = LLM_SEVERITY_DEDUCTIONS.get(llm_result.severity, 0)
            # Weight by confidence
            score -= int(llm_deduction * llm_result.confidence)
        elif llm_result and not llm_result.is_threat:
            # LLM says safe: small positive signal if no patterns matched
            if not pattern_matches:
                score = min(100, score + 5)

        # Behavioral deductions
        for flag in behavioral_flags:
            score -= BEHAVIORAL_DEDUCTIONS.get(flag, 5)

        # Clamp to [0, 100]
        return max(0, min(100, score))
