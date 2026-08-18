"""Unit tests for the trust-scoring math."""
from shield.trust_scorer import TrustScorer
from shield.patterns import ThreatLevel, ThreatCategory
from shield.detector import PatternMatch


def make_match(level: ThreatLevel) -> PatternMatch:
    return PatternMatch(
        pattern_id="TEST-001",
        category=ThreatCategory.DIRECT_INJECTION,
        threat_level=level,
        description="test",
        matched_text="test",
        position=0,
    )


def test_no_signals_scores_100():
    scorer = TrustScorer()
    score = scorer.compute(pattern_matches=[], keyword_hits=[], llm_result=None, behavioral_flags=[], text_length=10)
    assert score == 100


def test_critical_pattern_dominates_score():
    scorer = TrustScorer()
    score = scorer.compute(
        pattern_matches=[make_match(ThreatLevel.CRITICAL)],
        keyword_hits=[],
        llm_result=None,
        behavioral_flags=[],
        text_length=10,
    )
    assert score == 25  # 100 - 75


def test_secondary_matches_apply_diminished_penalty():
    scorer = TrustScorer()
    score = scorer.compute(
        pattern_matches=[make_match(ThreatLevel.CRITICAL), make_match(ThreatLevel.HIGH)],
        keyword_hits=[],
        llm_result=None,
        behavioral_flags=[],
        text_length=10,
    )
    # 100 - 75 (primary) - int(45 * 0.3)=13 (secondary, diminished)
    assert score == 100 - 75 - 13


def test_score_never_goes_below_zero():
    scorer = TrustScorer()
    score = scorer.compute(
        pattern_matches=[make_match(ThreatLevel.CRITICAL)] * 5,
        keyword_hits=[("critical", "jailbreak")] * 3,
        llm_result=None,
        behavioral_flags=["escalating_threat_pattern", "unicode_lookalike_chars_detected"],
        text_length=10,
    )
    assert score == 0


def test_behavioral_flags_deduct_points():
    scorer = TrustScorer()
    score = scorer.compute(
        pattern_matches=[], keyword_hits=[], llm_result=None,
        behavioral_flags=["unusually_long_input"], text_length=3000,
    )
    assert score == 95  # 100 - 5
