#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST="$HOME/Library/LaunchAgents/com.security-edr-agent-parser.mac-agent.plist"
LABEL="com.security-edr-agent-parser.mac-agent"
PYTHON_BIN="${PYTHON_BIN:-python3}"
IFACE="${IFACE:-en0}"
PREFLIGHT_DURATION="${PREFLIGHT_DURATION:-3}"
PREFLIGHT_LOG="$ROOT_DIR/outputs/agent/mac_agent_preflight.json"
START_INTERVAL="${START_INTERVAL:-300}"

mkdir -p "$HOME/Library/LaunchAgents" "$ROOT_DIR/outputs/agent"

validate_xml_value() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    echo "error: $name must not be empty" >&2
    exit 1
  fi
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    echo "error: $name contains XML-unsafe control characters" >&2
    exit 1
  fi
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* || "$value" == *$'\t'* ]]; then
    echo "error: $name contains XML-unsafe whitespace" >&2
    exit 1
  fi
}

validate_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "error: $name must be a positive integer" >&2
    exit 1
  fi
}

xml_escape() {
  local name="$1"
  local value="$2"
  validate_xml_value "$name" "$value"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  printf '%s' "$value"
}

PYTHON_BIN_XML="$(xml_escape PYTHON_BIN "$PYTHON_BIN")"
IFACE_XML="$(xml_escape IFACE "$IFACE")"
ROOT_DIR_XML="$(xml_escape ROOT_DIR "$ROOT_DIR")"
OUT_LOG_XML="$(xml_escape StandardOutPath "$ROOT_DIR/outputs/agent/mac_agent.out.log")"
ERR_LOG_XML="$(xml_escape StandardErrorPath "$ROOT_DIR/outputs/agent/mac_agent.err.log")"
validate_positive_integer START_INTERVAL "$START_INTERVAL"
validate_positive_integer PREFLIGHT_DURATION "$PREFLIGHT_DURATION"

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.security-edr-agent-parser.mac-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON_BIN_XML</string>
    <string>-m</string>
    <string>src.mac_agent</string>
    <string>--iface</string>
    <string>$IFACE_XML</string>
    <string>--duration</string>
    <string>60</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$ROOT_DIR_XML</string>
  <key>StandardOutPath</key>
  <string>$OUT_LOG_XML</string>
  <key>StandardErrorPath</key>
  <string>$ERR_LOG_XML</string>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>$START_INTERVAL</integer>
</dict>
</plist>
PLIST

plutil -lint "$PLIST" >/dev/null

if [[ "${SKIP_TCPDUMP_PREFLIGHT:-0}" != "1" ]]; then
  echo "running tcpdump preflight as current user..."
  if ! (cd "$ROOT_DIR" && "$PYTHON_BIN" -m src.mac_agent --iface "$IFACE" --duration "$PREFLIGHT_DURATION" --host-id "mac-agent-preflight") >"$PREFLIGHT_LOG" 2>&1; then
    echo "error: tcpdump preflight failed; see $PREFLIGHT_LOG" >&2
    echo "set SKIP_TCPDUMP_PREFLIGHT=1 only when packet capture permission is already validated elsewhere." >&2
    exit 1
  fi
fi

launchctl unload "$PLIST" >/dev/null 2>&1 || true
launchctl load "$PLIST"
if ! launchctl list "$LABEL" >/dev/null 2>&1; then
  echo "error: launchd did not report loaded job $LABEL" >&2
  exit 1
fi
echo "installed LaunchAgent: $PLIST"
echo "note: real tcpdump capture may require sudo/root packet capture permission on macOS."
