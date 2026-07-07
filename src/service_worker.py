"""Service-layer job runner that mirrors the CLI analysis/result flow."""

from __future__ import annotations

import json

from .ai_predictor import build_ai_predictions
from .detection_engine import analyze_events
from .pipeline import build_pipeline_bundle
from .response_engine import build_response_plan
from .result_writer import write_result
from .service_store import JsonObject, ServiceStore


def run_default_analysis_job(
    store: ServiceStore,
    *,
    events: list[JsonObject],
    input_meta: JsonObject,
    response_mode: str = "queued",
) -> str:
    """Run analysis for API-provided events and persist the saved run result."""
    result = analyze_events(events, input_meta=input_meta)
    result["response_plan"] = build_response_plan(result, mode=response_mode)
    result["ai_predictions"] = build_ai_predictions(result)
    result["summary"]["response_action_count"] = result["response_plan"]["action_count"]
    result["summary"]["ai_prediction_count"] = result["ai_predictions"]["prediction_count"]
    result["summary"]["predicted_high_or_critical_count"] = result["ai_predictions"]["high_or_critical_count"]
    result["pipeline_delivery"] = build_pipeline_bundle(result)
    written_paths = write_result(result)
    # The service store persists the exact JSON payload produced for the CLI
    # dashboard so API and local artifacts share one result contract.
    saved_payload = json.loads(written_paths["latest_path"].read_text(encoding="utf-8"))
    return store.save_run_result(saved_payload)
