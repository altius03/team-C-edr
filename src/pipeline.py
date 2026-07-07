"""Package detector output into compressed telemetry bundles for handoff."""

from __future__ import annotations

import gzip
import hashlib
import json
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import (
    AGENT_VERSION,
    CUSTOMER_ID,
    LATEST_PIPELINE_DIR,
    PAYLOAD_VERSION,
    PIPELINE_RUNS_DIR,
    TENANT_ID,
)


def build_pipeline_bundle(payload: dict[str, Any], *, ship_url: str | None = None) -> dict[str, Any]:
    """Write latest and run-scoped gzip bundles, optionally shipping them."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = PIPELINE_RUNS_DIR / timestamp
    latest_dir = LATEST_PIPELINE_DIR
    run_dir.mkdir(parents=True, exist_ok=True)
    latest_dir.mkdir(parents=True, exist_ok=True)

    sanitized = _pipeline_payload(payload)
    raw = json.dumps(sanitized, ensure_ascii=False, sort_keys=True).encode("utf-8")
    compressed = gzip.compress(raw, compresslevel=6)

    latest_path = latest_dir / "telemetry_bundle.json.gz"
    run_path = run_dir / "telemetry_bundle.json.gz"
    latest_path.write_bytes(compressed)
    run_path.write_bytes(compressed)

    delivery = {
        "compression": "gzip",
        "raw_bytes": len(raw),
        "compressed_bytes": len(compressed),
        "compression_ratio": round(len(compressed) / max(1, len(raw)), 3),
        "sha256": hashlib.sha256(compressed).hexdigest(),
        "latest_bundle_path": str(latest_path),
        "run_bundle_path": str(run_path),
        "ship_url": ship_url or "",
        "ship_status": "not_requested",
    }
    if ship_url:
        delivery.update(_ship_bundle(ship_url, compressed))
    return delivery


def _pipeline_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Select the review-safe subset of detector output for the bundle."""

    # 전송 가능한 묶음은 원본 이벤트와 DLQ 페이로드를 의도적으로 제외합니다.
    # 검토자는 대용량 텔레메트리를 배포하지 않고도 탐지를 감사할 수 있습니다.
    return {
        "status": payload.get("status"),
        "generated_at": payload.get("generated_at"),
        "summary": payload.get("summary", {}),
        "alerts": payload.get("alerts", []),
        "incidents": payload.get("incidents", []),
        "endpoint_risk": payload.get("endpoint_risk", []),
        "edr_state": payload.get("edr_state", {}),
        "telemetry_metadata": payload.get("telemetry_metadata", {}),
        "siem_analysis": payload.get("siem_analysis", {}),
        "ai_predictions": payload.get("ai_predictions", {}),
        "response_plan": payload.get("response_plan", {}),
    }


def _ship_bundle(ship_url: str, compressed: bytes) -> dict[str, Any]:
    """POST a gzip telemetry bundle and return delivery status metadata."""

    request = urllib.request.Request(
        ship_url,
        data=compressed,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "X-EDR-PoC": "layertrace_edr_siem_poc",
            "X-Customer-Id": CUSTOMER_ID,
            "X-Tenant-Id": TENANT_ID,
            "X-Agent-Version": AGENT_VERSION,
            "X-Payload-Version": PAYLOAD_VERSION,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            response.read()
            return {"ship_status": "sent", "ship_http_status": response.status}
    except (urllib.error.URLError, TimeoutError) as error:
        return {"ship_status": "failed", "ship_error": str(error)}
