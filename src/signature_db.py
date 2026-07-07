"""Load malicious indicator and policy signatures for detection rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import (
    KNOWN_MALICIOUS_DOMAINS,
    KNOWN_MALICIOUS_IPS,
    KNOWN_MALWARE_HASHES,
    SIGNATURE_DB_PATH,
)


def load_signature_db(path: Path | None = None) -> dict[str, Any]:
    """Return normalized signatures from disk, falling back to built-ins."""

    signature_path = path or SIGNATURE_DB_PATH
    payload: dict[str, Any] = {}
    if signature_path.exists():
        payload = json.loads(signature_path.read_text(encoding="utf-8"))

    return {
        "version": payload.get("version", "builtin"),
        "malicious_domains": _lower_set(payload.get("malicious_domains", KNOWN_MALICIOUS_DOMAINS)),
        "malicious_urls": _lower_set(payload.get("malicious_urls", [])),
        "malicious_ips": set(payload.get("malicious_ips", KNOWN_MALICIOUS_IPS)),
        "malware_hashes": _lower_set(payload.get("malware_hashes", KNOWN_MALWARE_HASHES)),
        "monitored_app_actions": list(payload.get("monitored_app_actions", [])),
        "blocked_categories": _lower_set(payload.get("blocked_categories", [])),
    }


def _lower_set(values: Any) -> set[str]:
    """Convert optional iterable values into lowercase string indicators."""

    return {str(value).lower() for value in values or []}
