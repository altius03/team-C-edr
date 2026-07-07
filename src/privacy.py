"""Remove or mask personal data before events enter detection logic."""

from __future__ import annotations

import re
from typing import Any

from .config import PRIVACY_SENSITIVE_FIELDS

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"01[016789]-?\d{3,4}-?\d{4}")
KOREAN_RRN_RE = re.compile(r"\d{6}-?[1-4]\d{6}")


def sanitize_event(event: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Return a sanitized event plus audit records for each masking action."""

    sanitized: dict[str, Any] = {}
    masks: list[dict[str, str]] = []

    for key, value in event.items():
        if key in PRIVACY_SENSITIVE_FIELDS:
            masks.append({"field": key, "action": "removed_sensitive_field"})
            continue

        if isinstance(value, str):
            masked_value, changed = mask_text(value)
            sanitized[key] = masked_value
            if changed:
                masks.append({"field": key, "action": "masked_sensitive_pattern"})
            continue

        sanitized[key] = value

    if masks:
        sanitized["privacy_masked_fields"] = [item["field"] for item in masks]

    return sanitized, masks


def mask_text(value: str) -> tuple[str, bool]:
    """Mask sensitive text patterns while preserving non-sensitive context."""

    masked = EMAIL_RE.sub("[redacted-email]", value)
    masked = PHONE_RE.sub("[redacted-phone]", masked)
    masked = KOREAN_RRN_RE.sub("[redacted-id]", masked)
    return masked, masked != value
