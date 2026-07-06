from pathlib import Path

POC_NAME = "layertrace_edr_siem_poc"
PROJECT_NAME = "lightweight_edr_siem"

BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_EVENTS_PATH = BASE_DIR / "samples" / "default_events.json"

OUTPUTS_DIR = BASE_DIR / "outputs"
LATEST_OUTPUT_DIR = OUTPUTS_DIR / "latest"
RUNS_OUTPUT_DIR = OUTPUTS_DIR / "runs"
VERIFICATION_DIR = OUTPUTS_DIR / "verification"
REPORTS_DIR = OUTPUTS_DIR / "reports"
LATEST_REPORT_DIR = REPORTS_DIR / "latest"
REPORT_RUNS_DIR = REPORTS_DIR / "runs"
PIPELINE_DIR = OUTPUTS_DIR / "pipeline"
LATEST_PIPELINE_DIR = PIPELINE_DIR / "latest"
PIPELINE_RUNS_DIR = PIPELINE_DIR / "runs"

DASHBOARD_DIR = BASE_DIR / "dashboard"
DASHBOARD_DATA_DIR = DASHBOARD_DIR / "data"
DASHBOARD_DATA_PATH = DASHBOARD_DATA_DIR / "latest-result.js"
SIGNATURE_DB_PATH = BASE_DIR / "rules" / "threat_signatures.json"

DEFAULT_LIMITATIONS = [
    "PoC는 endpoint metadata, PCAP flow summary, L7 proxy log를 분석하며 OS kernel driver 수준의 EDR은 아닙니다.",
    "HTTPS deep inspection은 로컬 프록시/복호화 로그를 전제로 한 PoC입니다. 임의의 HTTPS를 몰래 복호화하지 않습니다.",
    "threat intelligence는 rules/threat_signatures.json의 small signature set입니다.",
    "AI prediction은 학습된 상용 모델이 아니라 feature 기반 risk scoring PoC입니다.",
    "response action은 기본 dry-run입니다. 실제 차단/격리 적용 전에는 운영 정책 검토가 필요합니다.",
]

CUSTOMER_ID = "techeer-demo"
TENANT_ID = "techeer-demo-lab"
AGENT_VERSION = "0.3.0"
PAYLOAD_VERSION = "1.1"

HOST_DISPLAY_NAMES = {
    "endpoint-01": "황건하-PC",
    "endpoint-02": "박소연-Laptop",
    "endpoint-03": "이혜령-Workstation",
    "endpoint-04": "이주호-Desktop",
    "endpoint-05": "이주호-Lab",
    "endpoint-l7": "이주호-L7-Proxy",
}

REQUIRED_EVENT_FIELDS = {
    "event_id",
    "event_time",
    "received_time",
    "host_id",
    "event_type",
    "source",
    "payload_version",
}

SUPPORTED_EVENT_TYPES = {
    "process_start",
    "process_stop",
    "file_download",
    "dns_query",
    "network_connection",
    "flow_summary",
    "vpn_tunnel",
    "autorun_entry",
    "usb_event",
    "http_request",
    "decryption_event",
    "application_action",
    "signature_match",
    "response_action",
    "ai_prediction",
    "pipeline_delivery",
}

PRIVACY_SENSITIVE_FIELDS = {
    "user_name",
    "user_email",
    "employee_name",
    "phone_number",
    "resident_registration_number",
    "message_content",
    "chat_content",
    "clipboard_text",
    "keystrokes",
    "raw_payload",
    "http_body",
    "document_text",
}

KNOWN_MALICIOUS_DOMAINS = {
    "malware-drop.example",
    "c2.badbeacon.example",
    "phish-login.example",
}

KNOWN_MALICIOUS_IPS = {
    "203.0.113.77",
    "198.51.100.66",
}

KNOWN_MALWARE_HASHES = {
    "badbeef0000000000000000000000000000000000000000000000000000000001",
}

TRUSTED_ASNS = {
    "AS15169",
    "AS8075",
    "AS16509",
    "AS13335",
}

SHELL_PROCESSES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "bash",
    "sh",
    "zsh",
}

LARGE_OUTBOUND_BYTES = 50_000_000
BEACON_MIN_EVENTS = 4
BEACON_INTERVAL_TOLERANCE_SECONDS = 5

MITRE_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]
