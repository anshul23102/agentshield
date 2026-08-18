"""
AgentShield Input Redactor
Scrubs sensitive data out of an input prompt before it is persisted to storage.

The live detection path (ThreatDetector) never touches this - it needs to run in
single-digit milliseconds. This module runs once, off the request's critical path
(called from a FastAPI BackgroundTask right before the DB write), so it can afford
a heavier, more accurate pass than the request path can.

Two independent techniques run as defense-in-depth:
  1. The existing regex + checksum leak patterns from OutputGuard (secrets, cards,
     DB connection strings...) - fast, deterministic, exact-match.
  2. Microsoft Presidio's NER-based PII analyzer (names, addresses, phone numbers...)
     - catches PII that is structurally impossible for a regex to recognize, because
     it requires actual language understanding, not a fixed shape.

If Presidio/spaCy isn't installed or the model fails to load, this degrades to the
regex-only pass rather than failing the request - persistence must never depend on
an optional NLP dependency being present.
"""
import logging

from .output_guard import OutputGuard

logger = logging.getLogger(__name__)

_output_guard = OutputGuard()

PRESIDIO_AVAILABLE = False
_analyzer = None
_anonymizer = None

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine

    # Pin explicitly to the small spaCy model. Presidio's default config pulls
    # en_core_web_lg (~400MB) the first time it runs, which turns a one-line
    # `pip install` into a multi-hundred-megabyte surprise. en_core_web_sm
    # (~12MB) is materially less accurate on entity boundaries but is the right
    # tradeoff for a background redaction pass, not the primary detector.
    _nlp_config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
    }
    _engine = NlpEngineProvider(nlp_configuration=_nlp_config).create_engine()
    _analyzer = AnalyzerEngine(nlp_engine=_engine, supported_languages=["en"])
    _anonymizer = AnonymizerEngine()
    PRESIDIO_AVAILABLE = True
except Exception as exc:  # pragma: no cover - exercised only when the model/deps are missing
    logger.warning("Presidio unavailable (%s); input redaction is regex-only.", exc)

# Entities worth an NER pass on top of what regex/checksum already covers.
# Deliberately excludes entity types the regex layer already validates with a
# checksum (CREDIT_CARD, US_SSN, IBAN_CODE) to avoid Presidio's un-checksummed
# guess overriding a more precise match already made.
_PRESIDIO_ENTITIES = ["PERSON", "LOCATION", "PHONE_NUMBER", "EMAIL_ADDRESS", "NRP"]


def redact_for_storage(text: str) -> str:
    """Best-effort scrub of a string before it is written to persistent storage."""
    if not text:
        return text

    working = _output_guard.scan(text, redact=True).redacted_text

    if PRESIDIO_AVAILABLE:
        try:
            results = _analyzer.analyze(text=working, language="en", entities=_PRESIDIO_ENTITIES)
            if results:
                working = _anonymizer.anonymize(text=working, analyzer_results=results).text
        except Exception:
            logger.exception("Presidio redaction pass failed; keeping regex-only result.")

    return working
