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


def test_valid_iban_is_flagged():
    guard = OutputGuard()
    # Well-known valid German test IBAN (MOD-97 checksum passes).
    result = guard.scan("Wire to: DE89370400440532013000")
    assert any(m.pattern_id == "FIN-IBAN" for m in result.leaks_found)


def test_iban_shaped_string_that_fails_checksum_is_not_flagged():
    guard = OutputGuard()
    # Right shape (2 letters, 2 digits, alphanumerics) but not a real IBAN -
    # this is exactly the false-positive class (hashes, license keys) the
    # bare regex used to redact needlessly.
    result = guard.scan("License key: AB12CDEF3456789012345678")
    assert not any(m.pattern_id == "FIN-IBAN" for m in result.leaks_found)


def test_iban_with_wrong_length_for_its_country_is_rejected():
    guard = OutputGuard()
    # DE IBANs are always 22 chars; this is shaped right but truncated.
    result = guard.scan("Account: DE8937040044053201300")
    assert not any(m.pattern_id == "FIN-IBAN" for m in result.leaks_found)


def test_real_phone_number_is_flagged():
    guard = OutputGuard()
    result = guard.scan("Call the customer at (212) 555-0147.")
    assert any(m.pattern_id == "PII-PHONE" for m in result.leaks_found)


def test_classic_fake_555_number_is_not_flagged():
    guard = OutputGuard()
    # The universal "not a real phone number" placeholder used in fiction,
    # docs, and examples - the old regex-only check redacted this as if it
    # were real PII.
    result = guard.scan("Example: call 555-123-4567 for support.")
    assert not any(m.pattern_id == "PII-PHONE" for m in result.leaks_found)


def test_obviously_fake_sequential_number_is_not_flagged():
    guard = OutputGuard()
    result = guard.scan("Placeholder: 123-456-7890")
    assert not any(m.pattern_id == "PII-PHONE" for m in result.leaks_found)


def test_international_phone_number_is_flagged():
    guard = OutputGuard()
    result = guard.scan("Reach us at +44 20 7946 0958 during business hours.")
    assert any(m.pattern_id == "PII-PHONE" for m in result.leaks_found)


def test_real_looking_credential_is_still_flagged():
    guard = OutputGuard()
    result = guard.scan('config: password: "hunter2Secure!"')
    assert any(m.pattern_id == "SEC-GENERIC-PWD" for m in result.leaks_found)


def test_placeholder_credential_value_is_not_flagged():
    guard = OutputGuard()
    result = guard.scan('Set this in your .env: api_key: "your_api_key_here"')
    assert not any(m.pattern_id == "SEC-GENERIC-PWD" for m in result.leaks_found)


def test_low_diversity_dummy_credential_is_not_flagged():
    guard = OutputGuard()
    result = guard.scan('token: "aaaaaaaaaa"')
    assert not any(m.pattern_id == "SEC-GENERIC-PWD" for m in result.leaks_found)


def test_weak_but_real_looking_credential_is_still_flagged():
    # A weak real password is still a real password - this only screens out
    # values that could never plausibly be anyone's actual secret.
    guard = OutputGuard()
    result = guard.scan('password: "qwerty12"')
    assert any(m.pattern_id == "SEC-GENERIC-PWD" for m in result.leaks_found)


def test_role_based_email_is_not_flagged():
    guard = OutputGuard()
    result = guard.scan("For help, contact support@acme.com.")
    assert not any(m.pattern_id == "PII-EMAIL" for m in result.leaks_found)


def test_personal_looking_email_is_still_flagged():
    guard = OutputGuard()
    result = guard.scan("The customer's email on file is jane.doe@example.com.")
    assert any(m.pattern_id == "PII-EMAIL" for m in result.leaks_found)
