"""Capture explicit proxy HTTP metadata for local HTTPS inspection validation."""

from __future__ import annotations

import argparse
import json
import socketserver
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


class InspectionProxyHandler(socketserver.StreamRequestHandler):
    """Handle explicit proxy requests and persist normalized L7 telemetry records."""

    certfile: str = ""
    keyfile: str = ""
    output_path: Path = Path("outputs/l7_proxy/records.jsonl")

    def handle(self) -> None:
        """Process one proxied request, including optional CONNECT TLS inspection."""
        line = self.rfile.readline(65536).decode("iso-8859-1", errors="replace").strip()
        if not line:
            return
        parts = line.split()
        if len(parts) < 2:
            return
        method, target = parts[0].upper(), parts[1]
        headers = self._read_headers(self.rfile)

        if method == "CONNECT":
            host, _, port_text = target.partition(":")
            port = int(port_text or 443)
            if not self.certfile or not self.keyfile:
                self._write_record(
                    {
                        "record_type": "decryption_event",
                        "event_time": _now(),
                        "process_name": "explicit_proxy_client",
                        "sni": host.lower(),
                        "dst_domain": host.lower(),
                        "dst_port": port,
                        "decryption_result": "cert_not_configured",
                        "proxy_mode": "explicit_proxy",
                    }
                )
                self.wfile.write(b"HTTP/1.1 501 MITM certificate not configured\r\nContent-Length: 0\r\n\r\n")
                return
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.certfile, self.keyfile)
            tls_sock = context.wrap_socket(self.connection, server_side=True)
            tls_file = tls_sock.makefile("rwb", buffering=0)
            request_line = tls_file.readline(65536).decode("iso-8859-1", errors="replace").strip()
            tls_headers = self._read_headers(tls_file)
            self._record_http_request(request_line, tls_headers, host.lower(), port, decrypted=True)
            tls_file.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            tls_file.close()
            return

        self._record_http_request(line, headers, "", 80, decrypted=False)
        self.wfile.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")

    def _read_headers(self, stream) -> dict[str, str]:
        """Read HTTP headers from a socket file until the blank line delimiter."""
        headers: dict[str, str] = {}
        while True:
            line = stream.readline(65536).decode("iso-8859-1", errors="replace")
            if line in {"\r\n", "\n", ""}:
                return headers
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()

    def _record_http_request(self, request_line: str, headers: dict[str, str], connect_host: str, connect_port: int, *, decrypted: bool) -> None:
        """Normalize one observed HTTP request into the L7 record schema."""
        parts = request_line.split()
        if len(parts) < 2:
            return
        method, target = parts[0].upper(), parts[1]
        parsed = urlparse(target)
        host = (headers.get("host") or parsed.hostname or connect_host).split(":")[0].lower()
        scheme = "https" if decrypted else parsed.scheme or "http"
        url = target if parsed.scheme else f"{scheme}://{host}{target}"
        self._write_record(
            {
                "record_type": "http_request",
                "event_time": _now(),
                "process_name": "explicit_proxy_client",
                "method": method,
                "url": url,
                "dst_domain": host,
                "dst_port": parsed.port or connect_port,
                "protocol": scheme,
                "decrypted": decrypted,
                "source": "https_inspection_proxy",
            }
        )

    def _write_record(self, record: dict) -> None:
        """Append a JSONL record for later ingestion by the LayerTrace pipeline."""
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """Allow concurrent local proxy clients while keeping shutdown simple."""

    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    """Configure and run the explicit proxy listener."""
    parser = argparse.ArgumentParser(description="Explicit HTTPS inspection proxy PoC")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=8889)
    parser.add_argument("--certfile", default="")
    parser.add_argument("--keyfile", default="")
    parser.add_argument("--output", default="outputs/l7_proxy/records.jsonl")
    args = parser.parse_args()

    InspectionProxyHandler.certfile = args.certfile
    InspectionProxyHandler.keyfile = args.keyfile
    InspectionProxyHandler.output_path = Path(args.output)
    with ThreadingTCPServer((args.listen_host, args.listen_port), InspectionProxyHandler) as server:
        print(f"https inspection proxy listening on {args.listen_host}:{args.listen_port}")
        print(f"records: {InspectionProxyHandler.output_path}")
        server.serve_forever()
    return 0


def _now() -> str:
    """Return an ISO timestamp for proxy-generated telemetry events."""
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
