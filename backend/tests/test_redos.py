"""ReDoS regression guard.

A real bug motivated this file: the Output Guard's email pattern used an
unbounded quantifier and took about 9 seconds on a 50,000-character input of
"a.a.a.a...". Python's `re` holds the GIL while matching, so inside an async
handler that one request froze the whole service (a health check issued
during the attack took 10.9 seconds instead of roughly 10 ms).

Rather than trusting that no other pattern has the same flaw, every input
signature and every output signature is run against a corpus of adversarial
strings (long repeated runs, near-misses of each pattern's own keywords) and
must finish inside a fixed time budget. Add a pattern with a pathological
shape and this suite fails in CI, before it can ship.
"""
import time

import pytest

from shield.output_guard import COMPILED_LEAK_PATTERNS, OutputGuard
from shield.patterns import COMPILED_PATTERNS

SIZE = 30_000
# Generous for slow CI runners: a linear pattern needs a few milliseconds at
# this size, while the old email pattern needed roughly 3 seconds.
BUDGET_SECONDS = 1.0

FRAGMENTS = [
    "a", "1", " ", "a.", "a@", "@", "10.", "1234-", "A1B2 ", "+1 ", "(555) ",
    "ignore ", "ignore all previous ", "disregard your ", "forget the ",
    "DAN ", "system ", "admin prompt ", "pretend you are ", "remember that ",
    "model provider says ", "this is an official ", "decode and run ",
    'password="', "Bearer ", "AKIA", "eyJ", "sk-", "-----BEGIN ", "postgres://",
    "a-", "ab12 ", "ignore\t", "ignore\n", "a.a@", "x@y.", "user@host.",
]


def _corpus():
    for frag in FRAGMENTS:
        yield frag, (frag * (SIZE // len(frag) + 1))[:SIZE]


INPUT_PATTERNS = [(p.id, rx) for p, rx in COMPILED_PATTERNS]
OUTPUT_PATTERNS = [(lp.id, rx) for lp, rx in COMPILED_LEAK_PATTERNS]


@pytest.mark.parametrize("pattern_id,rx", INPUT_PATTERNS, ids=[i for i, _ in INPUT_PATTERNS])
def test_input_pattern_stays_fast_on_adversarial_input(pattern_id, rx):
    for fragment, text in _corpus():
        start = time.perf_counter()
        rx.search(text)
        elapsed = time.perf_counter() - start
        assert elapsed < BUDGET_SECONDS, f"{pattern_id} took {elapsed:.2f}s on {fragment!r} x {SIZE}"


@pytest.mark.parametrize("pattern_id,rx", OUTPUT_PATTERNS, ids=[i for i, _ in OUTPUT_PATTERNS])
def test_output_pattern_stays_fast_on_adversarial_input(pattern_id, rx):
    for fragment, text in _corpus():
        start = time.perf_counter()
        for _ in rx.finditer(text):
            pass
        elapsed = time.perf_counter() - start
        assert elapsed < BUDGET_SECONDS, f"{pattern_id} took {elapsed:.2f}s on {fragment!r} x {SIZE}"


def test_full_output_scan_of_the_original_attack_string_is_fast():
    start = time.perf_counter()
    OutputGuard().scan("a." * 50_000)  # 100,000 chars: the endpoint's real maximum
    assert time.perf_counter() - start < BUDGET_SECONDS * 2


def test_email_detection_still_works_after_bounding_the_quantifiers():
    guard = OutputGuard()
    result = guard.scan("Reach me at jane.doe+work@mail.example.co.uk tomorrow.")
    assert not result.is_safe
    assert "jane.doe" not in result.redacted_text
    assert "[EMAIL_REDACTED]" in result.redacted_text


def test_an_overlong_local_part_cannot_be_used_to_dodge_the_email_pattern():
    guard = OutputGuard()
    result = guard.scan(("x" * 120) + "@example.com")
    assert "@example.com" not in result.redacted_text
