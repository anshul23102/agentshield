"""
AgentShield Output Guard: bidirectional protection
Scans AGENT OUTPUTS (not just inputs) for data exfiltration, leaked secrets,
and PII before they ever leave the system. Includes a redaction engine.

This is what makes AgentShield bidirectional: it protects the input surface
(adversarial attacks coming in) AND the output surface (sensitive data leaking out).
"""

import re
from enum import Enum
from dataclasses import dataclass
from typing import Optional


class LeakSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class LeakType(str, Enum):
    SECRET = "Secret / Credential"
    PII = "Personal Identifiable Information"
    FINANCIAL = "Financial Data"
    NETWORK = "Network / Infrastructure"
    SYSTEM_LEAK = "System Prompt Leak"


@dataclass
class LeakPattern:
    id: str
    pattern: str
    leak_type: LeakType
    severity: LeakSeverity
    description: str
    redact_with: str
    flags: int = re.IGNORECASE


# ── Comprehensive leak signature database ────────────────────────────────────
LEAK_PATTERNS: list[LeakPattern] = [

    # ─── SECRETS & CREDENTIALS ───────────────────────────────────────────────
    LeakPattern(
        id="SEC-AWS-AKID",
        pattern=r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        leak_type=LeakType.SECRET, severity=LeakSeverity.CRITICAL,
        description="AWS Access Key ID",
        redact_with="[AWS_ACCESS_KEY_REDACTED]",
    ),
    LeakPattern(
        id="SEC-AWS-SECRET",
        pattern=r"\baws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
        leak_type=LeakType.SECRET, severity=LeakSeverity.CRITICAL,
        description="AWS Secret Access Key",
        redact_with="[AWS_SECRET_REDACTED]",
    ),
    LeakPattern(
        id="SEC-GH-PAT",
        pattern=r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
        leak_type=LeakType.SECRET, severity=LeakSeverity.CRITICAL,
        description="GitHub Personal Access Token",
        redact_with="[GITHUB_TOKEN_REDACTED]",
    ),
    LeakPattern(
        id="SEC-OPENAI",
        pattern=r"\bsk-[A-Za-z0-9]{20,}\b",
        leak_type=LeakType.SECRET, severity=LeakSeverity.CRITICAL,
        description="Provider API Key",
        redact_with="[API_KEY_REDACTED]",
    ),
    LeakPattern(
        id="SEC-SLACK",
        pattern=r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        leak_type=LeakType.SECRET, severity=LeakSeverity.CRITICAL,
        description="Slack Token",
        redact_with="[SLACK_TOKEN_REDACTED]",
    ),
    LeakPattern(
        id="SEC-GOOGLE",
        pattern=r"\bAIza[0-9A-Za-z\-_]{35}\b",
        leak_type=LeakType.SECRET, severity=LeakSeverity.CRITICAL,
        description="Google API Key",
        redact_with="[GOOGLE_API_KEY_REDACTED]",
    ),
    LeakPattern(
        id="SEC-STRIPE",
        pattern=r"\b(sk|pk)_(live|test)_[A-Za-z0-9]{24,}\b",
        leak_type=LeakType.SECRET, severity=LeakSeverity.CRITICAL,
        description="Stripe API Key",
        redact_with="[STRIPE_KEY_REDACTED]",
    ),
    LeakPattern(
        id="SEC-JWT",
        pattern=r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        leak_type=LeakType.SECRET, severity=LeakSeverity.HIGH,
        description="JSON Web Token (JWT)",
        redact_with="[JWT_REDACTED]",
    ),
    LeakPattern(
        id="SEC-PRIVKEY",
        pattern=r"-{5}BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-{5}",
        leak_type=LeakType.SECRET, severity=LeakSeverity.CRITICAL,
        description="Private Key Block",
        redact_with="[PRIVATE_KEY_REDACTED]",
    ),
    LeakPattern(
        id="SEC-GENERIC-PWD",
        pattern=r"\b(password|passwd|pwd|secret|api_?key|token|auth)\s*[=:]\s*['\"][^'\"\s]{6,}['\"]",
        leak_type=LeakType.SECRET, severity=LeakSeverity.HIGH,
        description="Hardcoded credential assignment",
        redact_with="[CREDENTIAL_REDACTED]",
    ),
    LeakPattern(
        id="SEC-BEARER",
        pattern=r"\b[Bb]earer\s+[A-Za-z0-9_\-\.=]{20,}",
        leak_type=LeakType.SECRET, severity=LeakSeverity.HIGH,
        description="Bearer authorization token",
        redact_with="[BEARER_TOKEN_REDACTED]",
    ),

    # ─── FINANCIAL DATA ──────────────────────────────────────────────────────
    LeakPattern(
        id="FIN-CC-VISA",
        pattern=r"\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        leak_type=LeakType.FINANCIAL, severity=LeakSeverity.CRITICAL,
        description="Visa Credit Card Number",
        redact_with="[CREDIT_CARD_REDACTED]",
    ),
    LeakPattern(
        id="FIN-CC-MC",
        pattern=r"\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        leak_type=LeakType.FINANCIAL, severity=LeakSeverity.CRITICAL,
        description="Mastercard Credit Card Number",
        redact_with="[CREDIT_CARD_REDACTED]",
    ),
    LeakPattern(
        id="FIN-CC-AMEX",
        pattern=r"\b3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}\b",
        leak_type=LeakType.FINANCIAL, severity=LeakSeverity.CRITICAL,
        description="American Express Card Number",
        redact_with="[CREDIT_CARD_REDACTED]",
    ),
    LeakPattern(
        id="FIN-IBAN",
        pattern=r"\b[A-Z]{2}[0-9]{2}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}\b",
        leak_type=LeakType.FINANCIAL, severity=LeakSeverity.HIGH,
        description="IBAN Bank Account Number",
        redact_with="[IBAN_REDACTED]",
    ),

    # ─── PII ─────────────────────────────────────────────────────────────────
    LeakPattern(
        id="PII-SSN",
        pattern=r"\b(?!000|666|9\d\d)[0-8]\d{2}[\s-](?!00)\d{2}[\s-](?!0000)\d{4}\b",
        leak_type=LeakType.PII, severity=LeakSeverity.CRITICAL,
        description="US Social Security Number",
        redact_with="[SSN_REDACTED]",
    ),
    LeakPattern(
        id="PII-EMAIL",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        leak_type=LeakType.PII, severity=LeakSeverity.MEDIUM,
        description="Email Address",
        redact_with="[EMAIL_REDACTED]",
    ),
    LeakPattern(
        id="PII-PHONE",
        pattern=r"(?:\+\d{1,3}[\s-]?)?(?:\(\d{3}\)|\b\d{3})[\s.-]\d{3}[\s.-]\d{4}\b",
        leak_type=LeakType.PII, severity=LeakSeverity.MEDIUM,
        description="Phone Number",
        redact_with="[PHONE_REDACTED]",
    ),
    LeakPattern(
        id="PII-AADHAAR",
        pattern=r"\b[2-9]{1}[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
        leak_type=LeakType.PII, severity=LeakSeverity.CRITICAL,
        description="Indian Aadhaar Number",
        redact_with="[AADHAAR_REDACTED]",
    ),
    LeakPattern(
        id="PII-PASSPORT",
        pattern=r"\b[A-PR-WY][1-9]\d\s?\d{4}[1-9]\b",
        leak_type=LeakType.PII, severity=LeakSeverity.HIGH,
        description="Passport Number",
        redact_with="[PASSPORT_REDACTED]",
    ),

    # ─── NETWORK / INFRASTRUCTURE ────────────────────────────────────────────
    LeakPattern(
        id="NET-PRIVATE-IP",
        pattern=r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
        leak_type=LeakType.NETWORK, severity=LeakSeverity.MEDIUM,
        description="Private/Internal IP Address",
        redact_with="[INTERNAL_IP_REDACTED]",
    ),
    LeakPattern(
        id="NET-DB-CONN",
        pattern=r"\b(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^\s'\"]+",
        leak_type=LeakType.NETWORK, severity=LeakSeverity.CRITICAL,
        description="Database Connection String",
        redact_with="[DB_CONNECTION_REDACTED]",
    ),

    # ─── SYSTEM PROMPT LEAK (agent revealing its own instructions) ───────────
    LeakPattern(
        id="SYS-PROMPT-LEAK",
        pattern=r"(my\s+(system\s+)?(instructions?|prompt)\s+(are|is|state|says?)|i\s+was\s+(told|instructed|programmed)\s+to|my\s+(initial|base)\s+prompt)",
        leak_type=LeakType.SYSTEM_LEAK, severity=LeakSeverity.HIGH,
        description="Agent revealing its system prompt/instructions",
        redact_with="[SYSTEM_PROMPT_LEAK_BLOCKED]",
    ),
]


COMPILED_LEAK_PATTERNS = [
    (lp, re.compile(lp.pattern, lp.flags)) for lp in LEAK_PATTERNS
]


# Verhoeff dihedral group tables for Aadhaar checksum validation
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def _verhoeff_valid(number: str) -> bool:
    """Aadhaar uses the Verhoeff checksum; rejects arbitrary 12-digit numbers."""
    digits = re.sub(r"\D", "", number)
    if len(digits) != 12:
        return False
    c = 0
    for i, d in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(d)]]
    return c == 0


def _luhn_valid(number: str) -> bool:
    """Luhn checksum to reduce credit-card false positives."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


@dataclass
class LeakMatch:
    pattern_id: str
    leak_type: str
    severity: str
    description: str
    matched_preview: str
    position: int


@dataclass
class OutputScanResult:
    is_safe: bool
    action: str                       # "block" | "redact" | "allow"
    risk_score: int                   # 0–100 (100 = fully safe)
    leaks_found: list[LeakMatch]
    redacted_text: str
    leak_summary: dict                # {leak_type: count}
    reasoning: str

    def to_dict(self) -> dict:
        return {
            "is_safe": self.is_safe,
            "action": self.action,
            "risk_score": self.risk_score,
            "leaks_found": [
                {
                    "id": m.pattern_id,
                    "leak_type": m.leak_type,
                    "severity": m.severity,
                    "description": m.description,
                    "matched_preview": m.matched_preview,
                    "position": m.position,
                }
                for m in self.leaks_found
            ],
            "redacted_text": self.redacted_text,
            "leak_summary": self.leak_summary,
            "reasoning": self.reasoning,
        }


SEVERITY_DEDUCTION = {
    LeakSeverity.CRITICAL: 50,
    LeakSeverity.HIGH: 30,
    LeakSeverity.MEDIUM: 15,
    LeakSeverity.LOW: 5,
}


class OutputGuard:
    """Scans agent outputs for sensitive data leakage and redacts it."""

    def scan(self, text: str, redact: bool = True) -> OutputScanResult:
        leaks: list[LeakMatch] = []
        risk_score = 100

        # Collect all matches with validation filters
        all_matches = []
        for lp, compiled in COMPILED_LEAK_PATTERNS:
            for m in compiled.finditer(text):
                matched = m.group(0)

                # Luhn validation for credit cards to cut false positives
                if lp.leak_type == LeakType.FINANCIAL and lp.id.startswith("FIN-CC"):
                    if not _luhn_valid(matched):
                        continue

                # Verhoeff validation for Aadhaar numbers
                if lp.id == "PII-AADHAAR" and not _verhoeff_valid(matched):
                    continue

                all_matches.append((lp, m, matched))

        # Sort by position for deterministic redaction
        all_matches.sort(key=lambda x: x[1].start())

        seen_spans = []
        accepted = []
        for lp, m, matched in all_matches:
            # Skip overlapping matches (first/most-specific wins)
            span = (m.start(), m.end())
            if any(span[0] < e and span[1] > s for s, e in seen_spans):
                continue
            seen_spans.append(span)
            accepted.append((lp, span, matched))

            preview = matched[:6] + "***" if len(matched) > 6 else "***"
            leaks.append(LeakMatch(
                pattern_id=lp.id,
                leak_type=lp.leak_type.value,
                severity=lp.severity.value,
                description=lp.description,
                matched_preview=preview,
                position=m.start(),
            ))
            risk_score -= SEVERITY_DEDUCTION.get(lp.severity, 10)

        # Span-based reconstruction: each match is replaced exactly once at its
        # own position, so repeated or nested values cannot corrupt the output.
        if redact and accepted:
            parts = []
            cursor = 0
            for lp, (start, end), _ in accepted:
                parts.append(text[cursor:start])
                parts.append(lp.redact_with)
                cursor = end
            parts.append(text[cursor:])
            redacted = "".join(parts)
        else:
            redacted = text

        risk_score = max(0, min(100, risk_score))

        # Decision
        has_critical = any(m.severity == "critical" for m in leaks)
        if has_critical or risk_score <= 40:
            action = "block" if not redact else "redact"
        elif leaks:
            action = "redact"
        else:
            action = "allow"

        # Summary by type
        summary: dict = {}
        for m in leaks:
            summary[m.leak_type] = summary.get(m.leak_type, 0) + 1

        # Reasoning
        if leaks:
            types = ", ".join(summary.keys())
            reasoning = f"Detected {len(leaks)} potential data leak(s): {types}. Output {'redacted' if redact else 'blocked'} before transmission."
        else:
            reasoning = "No sensitive data detected. Output is safe to transmit."

        return OutputScanResult(
            is_safe=(len(leaks) == 0),
            action=action,
            risk_score=risk_score,
            leaks_found=leaks,
            redacted_text=redacted if redact else text,
            leak_summary=summary,
            reasoning=reasoning,
        )


LEAK_CATEGORY_STATS = {}
for _lp in LEAK_PATTERNS:
    LEAK_CATEGORY_STATS[_lp.leak_type.value] = LEAK_CATEGORY_STATS.get(_lp.leak_type.value, 0) + 1
