"""Unit tests for the Output Guard: leak detection, checksum validation, redaction."""
from shield.output_guard import OutputGuard


def test_clean_output_is_safe():
    guard = OutputGuard()
    result = guard.scan("The sorted list is [1, 2, 3].")
    assert result.is_safe is True
    assert result.action == "allow"
    assert result.risk_score == 100


def test_aws_access_key_is_detected_and_redacted():
    guard = OutputGuard()
    result = guard.scan("Sure, here it is: AKIAIOSFODNN7EXAMPLE")
    assert result.is_safe is False
    assert any(m.pattern_id == "SEC-AWS-AKID" for m in result.leaks_found)
    assert "AKIAIOSFODNN7EXAMPLE" not in result.redacted_text
    assert "[AWS_ACCESS_KEY_REDACTED]" in result.redacted_text


def test_db_connection_string_is_critical_and_blocks():
    guard = OutputGuard()
    result = guard.scan("Connect with postgresql://admin:secret@10.0.1.42/prod")
    assert result.action in ("block", "redact")
    assert any(m.leak_type == "Network / Infrastructure" for m in result.leaks_found)


def test_luhn_invalid_card_number_is_not_flagged():
    guard = OutputGuard()
    # Visa-shaped (starts with 4, 16 digits) but fails the Luhn checksum.
    result = guard.scan("Card on file: 4111111111111112")
    assert not any(m.pattern_id.startswith("FIN-CC") for m in result.leaks_found)


def test_luhn_valid_card_number_is_flagged():
    guard = OutputGuard()
    # Well-known Luhn-valid Visa test number.
    result = guard.scan("Card on file: 4532015112830366")
    assert any(m.pattern_id.startswith("FIN-CC") for m in result.leaks_found)


def test_redaction_disabled_returns_original_text():
    guard = OutputGuard()
    text = "Key: AKIAIOSFODNN7EXAMPLE"
    result = guard.scan(text, redact=False)
    assert result.redacted_text == text
    assert result.is_safe is False


def test_overlapping_matches_do_not_corrupt_output():
    guard = OutputGuard()
    text = "AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE again"
    result = guard.scan(text)
    assert result.redacted_text.count("[AWS_ACCESS_KEY_REDACTED]") == 2
    assert "AKIA" not in result.redacted_text
