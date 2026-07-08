from __future__ import annotations

import ipaddress
import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CollectorPolicyError(Exception):
    code: str
    message: str
    exit_code: int


def api_token_for_collector(collector_url: str, api_token: str) -> str:
    if not collector_url:
        return api_token or "local-dev-token"

    parsed = urllib.parse.urlparse(collector_url)
    is_loopback = _is_loopback_hostname(parsed.hostname or "")
    if not is_loopback and parsed.scheme != "https":
        raise CollectorPolicyError("insecure_collector_url", "non-loopback collectors must use https", 2)
    if api_token:
        return api_token
    if is_loopback:
        return "local-dev-token"
    raise CollectorPolicyError("missing_api_token", "LAYERTRACE_API_TOKEN or --api-token is required for non-loopback collectors", 2)


def _is_loopback_hostname(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
