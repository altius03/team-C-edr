# LayerTrace Agent Shipping Runbook

이 문서는 현재 구현된 7개 물리 테이블 기반 MVP에서 endpoint agent가 실제 수집 데이터를 REST API로 보내는 흐름을 설명한다.

## Runtime Flow

1. API 서버를 실행한다.

```powershell
uv run python scripts\run_service.py --host 127.0.0.1 --port 8080 --database-url sqlite:///outputs/layertrace-service.sqlite3 --no-seed-latest
```

2. Windows endpoint에서 단발 수집/전송을 실행한다.

```powershell
uv run python scripts\run_agent_once.py --collector-url http://127.0.0.1:8080/v1/telemetry/events --api-token local-dev-token --include-dns-cache
```

3. macOS endpoint에서는 simulate 검증 또는 tcpdump 수집을 같은 ingest API로 보낸다.

```bash
python3 -m src.mac_agent --simulate --collector-url http://127.0.0.1:8080/v1/telemetry/events --api-token local-dev-token
sudo python3 -m src.mac_agent --iface en0 --duration 30 --collector-url http://127.0.0.1:8080/v1/telemetry/events --api-token local-dev-token
```

loopback collector는 로컬 데모 편의를 위해 HTTP와 `local-dev-token` 기본값을
사용할 수 있다. 원격 collector로 전송할 때는 `https://` URL과 `--api-token`
또는 `LAYERTRACE_API_TOKEN`을 반드시 명시한다. 실제 `tcpdump` 캡처 권한이 없으면
macOS agent는 빈 이벤트 성공으로 넘기지 않고 `tcpdump_failed` JSON 에러와
non-zero exit code를 반환한다.

## Cadence

MVP 기본 주기는 5분이다. 상용 EDR처럼 실시간 커널 이벤트를 붙인 구조가 아니므로, 짧은 데모는 1분, 일반 포트폴리오 시연은 5분, 저부하 장시간 실행은 15분을 권장한다.

Windows에서는 Task Scheduler가 `scripts\run_agent_once.py`를 반복 실행하게 둔다. macOS에서는 launchd `StartInterval` 기본값을 300초로 설정하고, 필요하면 `START_INTERVAL=<초>`로 조정한다. 검증 중에는 스케줄러를 자동 등록하지 않는다. macOS LaunchAgent 설치 script는 같은 사용자 권한으로 짧은 `tcpdump` preflight를 실행해 캡처 권한 실패를 먼저 드러낸다. 이미 별도 절차로 BPF 권한을 검증한 환경에서만 `SKIP_TCPDUMP_PREFLIGHT=1`로 건너뛴다.

## Retry Spool

전송 실패 시 batch는 `outputs/agent_queue/` 아래 JSON 파일로 남는다. 다음 실행은 새 batch를 보내기 전에 pending spool을 먼저 replay한다. API가 `202 Accepted`를 반환한 spool 파일만 삭제한다.

`401` 또는 `403`은 인증 실패로 표시된다. 이 경우 batch는 retry spool에 남지만, 토큰을 고치기 전까지는 정상 replay로 보지 않는다.

## Boundaries

- 물리 DB 구현은 현재 `runs`, `events`, `alerts`, `incidents`, `alert_events`, `incident_alerts`, `dlq_events`, `tasks`, `outbox_events` 9개 테이블이다.
- dashboard의 확장 개념은 `runs.payload`와 산출물 JSON 안에 남으며 별도 테이블로 구현된 것은 아니다.
- 수집기는 HTTP body, message content, clipboard, keystrokes를 수집하지 않는다.
