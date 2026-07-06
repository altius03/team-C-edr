#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST="$HOME/Library/LaunchAgents/com.security-edr-agent-parser.mac-agent.plist"
PYTHON_BIN="${PYTHON_BIN:-python3}"
IFACE="${IFACE:-en0}"

mkdir -p "$HOME/Library/LaunchAgents" "$ROOT_DIR/outputs/agent"

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
    <string>$PYTHON_BIN</string>
    <string>-m</string>
    <string>src.mac_agent</string>
    <string>--iface</string>
    <string>$IFACE</string>
    <string>--duration</string>
    <string>60</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$ROOT_DIR</string>
  <key>StandardOutPath</key>
  <string>$ROOT_DIR/outputs/agent/mac_agent.out.log</string>
  <key>StandardErrorPath</key>
  <string>$ROOT_DIR/outputs/agent/mac_agent.err.log</string>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>60</integer>
</dict>
</plist>
PLIST

launchctl unload "$PLIST" >/dev/null 2>&1 || true
launchctl load "$PLIST"
echo "installed LaunchAgent: $PLIST"
echo "note: real tcpdump capture may require sudo/root packet capture permission on macOS."
