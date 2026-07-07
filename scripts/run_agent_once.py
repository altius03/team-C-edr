from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

def main(argv: list[str] | None = None) -> int:
    from src.agent_shipper import AgentIdentity, AgentShipConfig, json_objects_from_dicts, ship_events
    from src.config import AGENT_VERSION, CUSTOMER_ID, OUTPUTS_DIR, PAYLOAD_VERSION, TENANT_ID
    from src.local_collector import collect_local_events

    parser = argparse.ArgumentParser(description="Collect local endpoint metadata once and ship it to LayerTrace REST ingest.")
    parser.add_argument("--collector-url", required=True)
    parser.add_argument("--api-token", default=os.environ.get("LAYERTRACE_API_TOKEN", "local-dev-token"))
    parser.add_argument("--customer-id", default=CUSTOMER_ID)
    parser.add_argument("--tenant-id", default=TENANT_ID)
    parser.add_argument("--agent-version", default=AGENT_VERSION)
    parser.add_argument("--payload-version", default=PAYLOAD_VERSION)
    parser.add_argument("--queue-dir", default=str(OUTPUTS_DIR / "agent_queue"))
    parser.add_argument("--include-dns-cache", action="store_true")
    parser.add_argument("--lookback-hours", type=int, default=24)
    parser.add_argument("--max-processes", type=int, default=80)
    parser.add_argument("--max-connections", type=int, default=120)
    parser.add_argument("--timeout-seconds", type=float, default=8.0)
    args = parser.parse_args(argv)

    events, meta = collect_local_events(
        lookback_hours=args.lookback_hours,
        max_processes=args.max_processes,
        max_connections=args.max_connections,
        include_dns_cache=args.include_dns_cache,
    )
    result = ship_events(
        json_objects_from_dicts(events),
        AgentShipConfig(
            collector_url=args.collector_url,
            identity=AgentIdentity(
                customer_id=args.customer_id,
                tenant_id=args.tenant_id,
                agent_version=args.agent_version,
                payload_version=args.payload_version,
                api_token=args.api_token,
            ),
            queue_dir=Path(args.queue_dir),
            timeout_seconds=args.timeout_seconds,
        ),
    )
    print(
        json.dumps(
            {
                "status": result.status,
                "accepted_count": result.accepted_count,
                "task_id": result.task_id,
                "replayed_count": result.replayed_count,
                "queued_count": result.queued_count,
                "error": result.error,
                "collected_count": len(events),
                "source": meta.get("source", "local_windows_collector"),
                "queue_dir": str(Path(args.queue_dir)),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0 if result.status in {"accepted", "queued"} else 1

if __name__ == "__main__":
    raise SystemExit(main())
