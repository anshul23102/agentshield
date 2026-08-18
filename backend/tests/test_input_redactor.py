"""Tests for the input-log redaction pass (regex/checksum + Presidio NER)."""
from shield.input_redactor import redact_for_storage, PRESIDIO_AVAILABLE


def test_presidio_loaded_with_the_small_model():
    # If this is False, redaction silently degraded to regex-only - a CI
    # environment missing the spaCy model should fail loudly, not quietly.
    assert PRESIDIO_AVAILABLE is True


def test_aws_key_is_redacted_before_storage():
    text = "is this AWS key valid: AKIAIOSFODNN7EXAMPLE"
    redacted = redact_for_storage(text)
    assert "AKIA" not in redacted


def test_empty_input_returns_empty():
    assert redact_for_storage("") == ""


def test_clean_text_is_left_unchanged():
    # Avoids capitalized proper-noun-shaped words (language/product names etc) -
    # the small spaCy model's NER can and does false-positive on those (e.g. it
    # tags "Python" as a LOCATION at its default 0.85 confidence). That's a real,
    # known accuracy tradeoff of en_core_web_sm vs the much larger _lg model, not
    # a redactor bug - see the module docstring in input_redactor.py.
    text = "please sort this list of numbers in ascending order"
    assert redact_for_storage(text) == text


def test_person_name_is_redacted_by_presidio():
    text = "My name is Alexander Whitfield and I need help with my account."
    redacted = redact_for_storage(text)
    assert "Alexander Whitfield" not in redacted


def test_email_is_redacted():
    text = "Contact me at jane.doe@example.com about this."
    redacted = redact_for_storage(text)
    assert "jane.doe@example.com" not in redacted
