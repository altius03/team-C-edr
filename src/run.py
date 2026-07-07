"""CLI entry point that normalizes inputs, runs analysis, and writes results."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .ai_predictor import build_ai_predictions
from .config import DEFAULT_EVENTS_PATH
from .detection_engine import DetectionError, analyze_events, build_failure_result
from .l7_inspector import L7InspectionError, events_from_l7_file
from .local_collector import LocalCollectionError, collect_local_events
from .pcap_flow import PcapFlowError, events_from_pcap
from .pipeline import build_pipeline_bundle
from .response_engine import build_response_plan
from .result_writer import write_result
from .sample_loader import SampleLoadError, load_events


def main(argv: list[str] | None = None) -> int:
    """Run the offline analysis pipeline and return a process exit code."""
    parser = argparse.ArgumentParser(description="Offline EDR agent telemetry parser PoC")
    parser.add_argument("--events-file", help="Path to sample endpoint/network event JSON.")
    parser.add_argument("--collect-local", action="store_true", help="Collect local Windows endpoint/network metadata.")
    parser.add_argument("--pcap-file", help="Optional PCAP file to convert into TCP flow and plaintext HTTP events.")
    parser.add_argument("--l7-file", help="Optional decrypted L7 proxy log JSON file to convert into application events.")
    parser.add_argument("--include-dns-cache", action="store_true", help="Include DNS cache entries in local collection.")
    parser.add_argument("--lookback-hours", type=int, default=24, help="Recent Downloads lookback window for local collection.")
    parser.add_argument("--max-processes", type=int, default=80, help="Maximum local process snapshot rows.")
    parser.add_argument("--max-connections", type=int, default=120, help="Maximum local TCP/DNS snapshot rows.")
    parser.add_argument("--response-mode", choices=["dry-run", "queued"], default="dry-run", help="Response action mode.")
    parser.add_argument("--no-pipeline-bundle", action="store_true", help="Do not write gzip telemetry pipeline bundle.")
    parser.add_argument("--ship-url", help="Optional HTTP endpoint that receives gzip telemetry bundle.")
    args = parser.parse_args(argv)

    input_meta: dict[str, Any] = {}
    try:
        # Only one primary source feeds the first event set: either live local
        # metadata collection or a sample event file. Optional PCAP/L7 sources
        # are merged later so downstream analysis sees one normalized stream.
        if args.collect_local:
            raw_events, input_meta = collect_local_events(
                lookback_hours=args.lookback_hours,
                max_processes=args.max_processes,
                max_connections=args.max_connections,
                include_dns_cache=args.include_dns_cache,
            )
        else:
            events_path = _resolve_events_path(args.events_file)
            raw_events, input_meta = load_events(events_path)
        # Optional PCAP/L7 inputs are appended here so the detection engine always
        # receives one normalized event stream regardless of collection source.
        raw_events, input_meta = _extend_with_optional_sources(
            raw_events,
            input_meta,
            pcap_file=args.pcap_file,
            l7_file=args.l7_file,
        )
        result = analyze_events(raw_events, input_meta=input_meta)
        result["response_plan"] = build_response_plan(result, mode=args.response_mode)
        result["ai_predictions"] = build_ai_predictions(result)
        result["summary"]["response_action_count"] = result["response_plan"]["action_count"]
        result["summary"]["ai_prediction_count"] = result["ai_predictions"]["prediction_count"]
        result["summary"]["predicted_high_or_critical_count"] = result["ai_predictions"]["high_or_critical_count"]
        if not args.no_pipeline_bundle:
            result["pipeline_delivery"] = build_pipeline_bundle(result, ship_url=args.ship_url)
        paths = write_result(result)
        _print_result(paths, result["status"], result.get("decision", ""))
        return 0

    except SampleLoadError as error:
        result = build_failure_result(
            code=error.code,
            message=str(error),
            error_type=type(error).__name__,
            input_meta=input_meta,
            partial_result=error.partial_result,
        )
        paths = write_result(result)
        _print_result(paths, result["status"], "input_failed")
        return 1

    except DetectionError as error:
        result = build_failure_result(
            code=error.code,
            message=str(error),
            error_type=type(error).__name__,
            input_meta=input_meta,
            partial_result=error.partial_result,
        )
        paths = write_result(result)
        _print_result(paths, result["status"], "detection_failed")
        return 1

    except LocalCollectionError as error:
        result = build_failure_result(
            code=error.code,
            message=str(error),
            error_type=type(error).__name__,
            input_meta=input_meta,
            partial_result=error.partial_result,
        )
        paths = write_result(result)
        _print_result(paths, result["status"], "collection_failed")
        return 1

    except (PcapFlowError, L7InspectionError) as error:
        result = build_failure_result(
            code="ADVANCED_COLLECTION_FAILED",
            message=str(error),
            error_type=type(error).__name__,
            input_meta=input_meta,
            partial_result={},
        )
        paths = write_result(result)
        _print_result(paths, result["status"], "advanced_collection_failed")
        return 1

    except Exception as error:
        result = build_failure_result(
            code="UNEXPECTED_ERROR",
            message=str(error),
            error_type=type(error).__name__,
            input_meta=input_meta,
            partial_result={},
        )
        paths = write_result(result)
        _print_result(paths, result["status"], "unexpected_error")
        return 1


def _resolve_events_path(requested_path: str | None) -> Path:
    """Resolve a CLI-provided event path or fall back to the bundled sample."""
    if requested_path:
        path = Path(requested_path)
        return path if path.is_absolute() else Path.cwd() / path
    return DEFAULT_EVENTS_PATH


def _extend_with_optional_sources(
    raw_events: list[dict[str, Any]],
    input_meta: dict[str, Any],
    *,
    pcap_file: str | None,
    l7_file: str | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Append optional PCAP and L7-derived events while preserving source metadata."""
    combined = list(raw_events)
    sources = [input_meta]
    if pcap_file:
        pcap_path = Path(pcap_file)
        if not pcap_path.is_absolute():
            pcap_path = Path.cwd() / pcap_path
        pcap_events, pcap_meta = events_from_pcap(pcap_path)
        combined.extend(pcap_events)
        sources.append(pcap_meta)
    if l7_file:
        l7_path = Path(l7_file)
        if not l7_path.is_absolute():
            l7_path = Path.cwd() / l7_path
        l7_events, l7_meta = events_from_l7_file(l7_path)
        combined.extend(l7_events)
        sources.append(l7_meta)
    if len(sources) == 1:
        return combined, input_meta
    return combined, {
        "source": "combined",
        "sources": sources,
        "raw_event_count": len(combined),
    }


def _print_result(paths: dict[str, Path], status: str, decision: str) -> None:
    """Print the persisted result locations expected by humans and scripts."""
    print(f"status={status}")
    if decision:
        print(f"decision={decision}")
    print(f"latest={paths['latest_path']}")
    print(f"run={paths['run_path']}")
    print(f"dashboard={paths['index_path']}")


if __name__ == "__main__":
    sys.exit(main())
