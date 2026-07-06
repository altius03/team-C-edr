# LayerTrace EDR PoC 팀원 도메인 학습서

상태: 팀원 학습서 초안  
작성일: 2026-07-06  
기준 프로젝트: `poc_code/security_edr_siem_poc`  
대상 독자: 컴퓨터공학 신입생 수준의 팀원  
관련 문서: `README.md`, `docs/erd-sa-current.md`

## 읽기 전에

이 문서는 구현 상세를 먼저 설명하는 문서가 아니다.
팀원이 보안 도메인을 거의 모르는 상태에서도 우리 제품이 무엇을 하려는지, 왜 필요한지, 어떤 용어가 나오는지, 발표 때 어떻게 설명해야 하는지를 이해하도록 만든 학습서다.

목표는 하나다.
팀원 모두가 우리 프로젝트를 다음처럼 설명할 수 있어야 한다.

> 이 프로젝트는 사용자의 PC에서 발생하는 process, network, file, DNS 같은 endpoint telemetry와 PCAP/L7 metadata를 모아, 의심스러운 보안 이벤트를 탐지하고 dashboard와 report로 보여주는 EDR/SIEM-style PoC다.

여기서 중요한 점은 `보안 제품 전체를 완성하는 것`이 아니다.
우리의 목표는 Palo Alto, CrowdStrike Falcon, Cortex, SIEM 같은 제품이 공통으로 갖는 흐름을 작게 재현하는 것이다.

```text
수집 -> 정규화 -> 탐지 -> 분석 -> 시각화 -> 보고서
```

현재 결정은 명확하다.
0부터 새로 만들지 않고, 이미 동작하는 `security_edr_siem_poc` 코드를 활용해서 고도화한다.

---

## 1. 우리 제품을 한 문장으로 설명하기

우리 제품의 핵심 문장은 다음이다.

> PC 안에서 발생하는 보안 신호를 모아 위험한 행동인지 판단하고, 어떤 공격 단계인지 분석한 뒤, 대시보드와 보고서로 보여주는 미니 EDR/SIEM 플랫폼.

이 문장에서 중요한 단어는 여섯 개다.

| 단어 | 의미 |
|---|---|
| `PC` / `Endpoint` | 사용자가 쓰는 노트북, 데스크톱, 서버 같은 단말 |
| `Telemetry` | 시스템에서 관측한 행위 데이터 |
| `EDR` | endpoint에서 발생한 행위를 탐지하고 대응하는 보안 기술 |
| `SIEM` | 여러 로그와 이벤트를 모아 분석하는 보안 관제 시스템 |
| `Detection` | 위험하거나 의심스러운 행동을 찾아내는 과정 |
| `Dashboard` / `Report` | 분석 결과를 사람이 이해할 수 있게 보여주는 화면과 문서 |

우리 프로젝트는 백신을 새로 만드는 프로젝트가 아니다.
VPN을 만드는 것도 아니고, 방화벽처럼 트래픽을 직접 차단하는 것도 아니다.

더 정확히 말하면, 이미 발생한 PC 행위와 네트워크 행위를 보안 분석 가능한 이벤트로 바꾸고, 그중 위험한 것을 찾아 보여주는 관제형 PoC다.

---

## 2. 왜 이 프로젝트가 필요한가

기업이나 조직에서는 수많은 PC와 서버가 계속 동작한다.
각 PC에서는 매 순간 여러 일이 일어난다.

- 프로그램이 실행된다.
- 브라우저가 외부 사이트에 접속한다.
- 파일이 다운로드된다.
- DNS로 도메인을 조회한다.
- 어떤 프로세스가 외부 IP와 통신한다.
- 압축 파일이나 실행 파일이 생긴다.

이 중 대부분은 정상이다.
문제는 공격도 비슷한 형태로 숨어 있다는 점이다.

예를 들어 공격자는 다음처럼 움직일 수 있다.

```text
악성 URL 접속
-> 파일 다운로드
-> 실행 파일 실행
-> 외부 C2 서버와 주기적 통신
-> 많은 데이터 외부 전송
```

사람이 모든 PC의 모든 로그를 직접 보면 너무 많아서 중요한 신호를 놓친다.
그래서 보안 제품은 데이터를 모으고, 정리하고, 위험한 패턴을 찾아내고, 분석자가 볼 수 있게 보여준다.

우리 프로젝트는 이 과정을 작게 만든다.

```text
endpoint/network event
-> event schema로 정리
-> rule 기반 탐지
-> MITRE ATT&CK mapping
-> incident 생성
-> dashboard/report 표시
```

---

## 3. 현재 프로젝트의 실제 범위

현재 작업 폴더는 다음이다.

```text
C:\Users\geonh\Desktop\테커 아이디어회의\poc_code\security_edr_siem_poc
```

현재 구현은 단순한 화면 mock이 아니다.
실제로 Python CLI를 실행하면 sample event를 분석하고, dashboard data와 report를 생성한다.

현재 구현된 범위:

| 영역 | 현재 상태 |
|---|---|
| Sample event 분석 | `samples/default_events.json` 기반 실행 가능 |
| Windows local telemetry | process, TCP connection, file metadata, optional DNS cache 수집 |
| PCAP/TCP flow | `.pcap`에서 TCP flow와 평문 HTTP request metadata 추출 |
| L7 metadata | 허가된 decrypted L7 record를 event로 변환 |
| Detection | rule 기반 alert/incident 생성 |
| MITRE mapping | detection 결과를 MITRE ATT&CK tactic/technique로 매핑 |
| SIEM-style analysis | query finding, topology, timeline 분석 |
| AI-style prediction | feature 기반 host risk scoring |
| Response plan | dry-run 대응 계획 생성 |
| Dashboard | 정적 HTML/JS dashboard |
| Report | HTML/Markdown report |
| Validation | `scripts/validate_poc.py`로 전체 검증 |

중요한 표현:

```text
현재는 프로덕션 보안 제품이 아니라, 발표와 포트폴리오를 위한 실행 가능한 로컬 PoC다.
```

---

## 4. 보안 관제란 무엇인가

보안 관제는 조직 내부에서 발생하는 보안 이벤트를 계속 모니터링하고, 위험한 일을 찾아내고, 대응 여부를 판단하는 활동이다.

여기서 `이벤트`는 매우 넓은 뜻이다.

- 로그인 실패
- 이상한 프로세스 실행
- 외부 IP 연결
- 악성 도메인 접속
- 의심 파일 다운로드
- 대용량 외부 전송
- 방화벽 차단 로그
- EDR 탐지 결과

보안 관제의 핵심 질문은 다음이다.

```text
많은 이벤트 중 진짜 위험한 것은 무엇인가?
어떤 PC에서 일어났는가?
언제 시작됐는가?
무슨 근거로 위험하다고 판단하는가?
다음에 무엇을 해야 하는가?
```

우리 dashboard와 report는 이 질문에 답하기 위한 화면과 문서다.

---

## 5. SOC

`SOC`는 Security Operations Center의 약자다.
제품명이라기보다는 보안 관제 조직 또는 운영 체계를 말한다.

SOC에서는 보통 다음 일을 한다.

- 보안 이벤트 모니터링
- alert 확인
- 정탐/오탐 판단
- incident 분석
- 대응 조치 판단
- 보고서 작성
- detection rule 개선

우리 프로젝트의 dashboard는 작은 SOC 화면처럼 동작해야 한다.
단순히 예쁜 그래프가 아니라, 분석자가 판단할 수 있는 정보를 줘야 한다.

예를 들어 alert를 클릭했을 때 분석자는 바로 다음을 보고 싶어 한다.

| 질문 | dashboard가 보여줘야 하는 것 |
|---|---|
| 어떤 PC인가 | 사용자/부서/기기 이름 |
| 어떤 룰인가 | rule id, rule name |
| 얼마나 위험한가 | severity, risk score |
| 근거가 무엇인가 | domain, process, file hash, connection |
| 다음 조치는 무엇인가 | response plan |

---

## 6. EDR

`EDR`은 Endpoint Detection and Response의 약자다.
Endpoint는 사용자의 PC, 노트북, 서버 같은 단말을 뜻한다.

EDR은 endpoint에서 발생하는 행동을 수집하고, 의심스러운 행동을 탐지하고, 필요하면 대응을 돕는 보안 기술이다.

EDR이 보는 데이터는 보통 다음과 같다.

| 데이터 | 예시 |
|---|---|
| process | 어떤 프로그램이 실행됐는지 |
| parent process | 어떤 프로그램이 그 프로그램을 실행했는지 |
| file | 어떤 파일이 생성/수정/다운로드됐는지 |
| network connection | 어떤 프로세스가 어떤 IP/port로 연결했는지 |
| DNS | 어떤 도메인을 조회했는지 |
| hash | 파일이 알려진 악성 파일과 같은지 |

우리 프로젝트에서 EDR 느낌이 강한 부분은 `local_collector.py`다.
이 코드는 Windows PC에서 metadata를 가져와 event로 바꾼다.

현재 수집 가능한 예시:

```text
Get-CimInstance Win32_Process
Get-NetTCPConnection
Get-DnsClientCache
Downloads 폴더 파일 metadata/hash
```

EDR은 백신과 다르다.
백신은 보통 악성 파일을 잡는 이미지가 강하다.
EDR은 파일 하나만 보는 것이 아니라, 행동의 흐름을 본다.

예를 들어 다음 흐름이 더 중요하다.

```text
browser가 suspicious.exe를 다운로드함
-> suspicious.exe가 Downloads에서 실행됨
-> 외부 C2 domain으로 주기적 연결 발생
-> 대용량 outbound transfer 발생
```

---

## 7. SIEM

`SIEM`은 Security Information and Event Management의 약자다.
여러 시스템에서 발생한 로그와 이벤트를 모아 저장하고 분석하는 시스템이다.

SIEM이 필요한 이유는 보안 이벤트가 한 곳에서만 발생하지 않기 때문이다.

- endpoint event
- firewall log
- DNS log
- web server log
- cloud log
- authentication log
- EDR alert
- IDS/IPS log

각각 따로 보면 의미가 약할 수 있다.
하지만 모아서 보면 공격 흐름이 보일 수 있다.

우리 프로젝트는 완전한 SIEM은 아니지만, SIEM-style 분석을 포함한다.

현재 코드에서 SIEM 역할을 하는 파일:

```text
src/siem_analyzer.py
```

이 파일은 alert와 event를 바탕으로 다음을 만든다.

- query finding
- topology summary
- timeline
- 반복 가능한 분석 근거

발표에서는 이렇게 설명하면 좋다.

> 우리 프로젝트는 대규모 SIEM은 아니지만, endpoint/network event를 모아 alert, incident, topology, report로 연결하는 Mini SIEM 흐름을 구현했다.

---

## 8. XDR이라는 말을 조심해야 하는 이유

`XDR`은 Extended Detection and Response의 약자다.
Endpoint뿐 아니라 network, cloud, identity, email 같은 여러 보안 영역의 이벤트를 통합 분석하는 방향이다.

우리 프로젝트는 처음에 XDR/SIEM이라는 표현을 썼지만, 현재 제품의 중심은 EDR + SIEM-style PoC에 가깝다.

왜냐하면 현재 실제로 다루는 중심 데이터는 다음이기 때문이다.

- endpoint process metadata
- endpoint network connection metadata
- DNS metadata
- file metadata/hash
- PCAP/L7 metadata
- detection result
- report/dashboard

Cloud, email, identity, SaaS 로그까지 모두 통합하지는 않는다.

따라서 발표에서는 이렇게 말하는 편이 안전하다.

```text
완전한 XDR 제품은 아니다.
EDR telemetry와 network/L7 metadata를 SIEM-style로 분석하는 PoC다.
장기적으로 XDR처럼 확장할 수 있는 구조를 보여준다.
```

---

## 9. Telemetry

`Telemetry`는 시스템에서 관측한 행위 데이터를 뜻한다.
보안에서는 "어떤 일이 일어났는지 알려주는 신호"라고 이해하면 된다.

Endpoint telemetry 예시:

- process name
- process path
- parent process
- command line 일부
- file path
- file hash
- remote IP
- remote port
- DNS domain

Network telemetry 예시:

- source IP
- destination IP
- port
- protocol
- packet count
- byte count
- duration
- DNS query
- HTTP method/path
- TLS SNI

우리 프로젝트의 원칙은 `원문 내용`이 아니라 `metadata`를 수집하는 것이다.

---

## 10. Metadata와 Payload

보안에서 `metadata`와 `payload`를 구분하는 것은 매우 중요하다.

`Payload`는 실제 내용이다.
예를 들어 다음은 payload에 가깝다.

- 카카오톡 메시지 본문
- 이메일 본문
- 로그인 request body
- 문서 내용
- 다운로드한 파일의 원문 내용
- HTTPS 통신의 실제 body

`Metadata`는 겉정보다.
예를 들어 다음은 metadata다.

- 어떤 프로세스가 실행됐는가
- 어떤 도메인에 접속했는가
- 몇 번 연결했는가
- 몇 byte를 보냈는가
- 어떤 URL path였는가
- 어떤 파일 hash였는가
- 언제 발생했는가

우리 프로젝트는 payload를 수집하지 않는다.

수집하지 않는 것:

| 수집하지 않는 것 | 이유 |
|---|---|
| message body | 개인 대화/메일 원문이 들어갈 수 있음 |
| browser password | credential theft와 구분이 어려움 |
| keystroke | keylogging처럼 보일 수 있음 |
| clipboard | token/password/개인 대화가 섞일 수 있음 |
| document body | 문서 원문은 민감정보일 수 있음 |
| 임의의 HTTPS payload | 무단 감청처럼 보일 수 있음 |

대신 metadata만으로도 탐지가 가능하다.

예를 들어 메시지 본문을 몰라도 다음은 알 수 있다.

```text
어떤 process가
어떤 domain으로
얼마나 자주
얼마나 많은 데이터를
어떤 시간대에 보냈는가
```

보안 탐지는 반드시 내용을 다 봐야만 가능한 것이 아니다.
행동의 패턴만으로도 충분히 의심 이벤트를 만들 수 있다.

---

## 11. Process

`Process`는 실행 중인 프로그램이다.

예를 들어 사용자가 Chrome을 실행하면 `chrome.exe` process가 생긴다.
터미널을 열면 `powershell.exe` process가 생긴다.
Python 스크립트를 실행하면 `python.exe` process가 생긴다.

보안에서는 process가 매우 중요하다.
공격도 결국 어떤 프로그램이 실행되면서 시작되기 때문이다.

EDR이 process를 볼 때 중요한 정보:

| 정보 | 의미 |
|---|---|
| process name | 실행 파일 이름 |
| process path | 파일 위치 |
| parent process | 누가 이 process를 실행했는지 |
| command line | 어떤 인자로 실행됐는지 |
| start time | 언제 실행됐는지 |

예를 들어 다음은 의심스럽다.

```text
winword.exe
-> powershell.exe
-> 외부 IP 연결
```

Word 문서가 PowerShell을 실행하고, PowerShell이 외부로 통신하면 정상 업무보다 공격 흐름에 가까워 보인다.

우리 프로젝트는 process metadata를 event로 바꾸고, detection rule이 이를 분석한다.

---

## 12. Network Connection

`Network connection`은 내 PC가 외부 또는 내부 다른 시스템과 통신하는 연결이다.

예를 들어 브라우저로 웹사이트에 접속하면 PC는 해당 서버 IP와 TCP connection을 만든다.

보안에서 connection이 중요한 이유는 공격자가 외부 서버와 통신하는 경우가 많기 때문이다.

네트워크 연결에서 보는 정보:

| 정보 | 의미 |
|---|---|
| local address | 내 PC 주소 |
| local port | 내 PC 쪽 port |
| remote address | 상대 IP |
| remote port | 상대 port |
| protocol | TCP/UDP 등 |
| state | 연결 상태 |
| owning process | 어떤 process가 만든 연결인지 |

우리 프로젝트는 Windows에서 `Get-NetTCPConnection`을 활용해 connection metadata를 수집한다.

---

## 13. DNS

`DNS`는 domain name을 IP 주소로 바꿔주는 시스템이다.

사람은 `example.com`처럼 domain을 기억하지만, 컴퓨터는 실제 통신할 때 IP 주소가 필요하다.
DNS는 이 변환을 담당한다.

보안에서 DNS가 중요한 이유는 악성코드도 외부 서버와 통신할 때 domain을 쓰기 때문이다.

예를 들어 다음과 같은 domain은 의심 대상이 될 수 있다.

```text
malware-drop.example
c2-beacon.example
phishing-login.example
```

우리 프로젝트는 DNS cache를 optional로 수집할 수 있다.

```powershell
python -m src.run --collect-local --include-dns-cache
```

DNS event는 "어떤 PC가 어떤 domain을 조회했는가"를 보여준다.
이 정보는 malicious domain rule과 연결하기 좋다.

---

## 14. File Hash

`Hash`는 파일 내용을 고정 길이 문자열로 요약한 값이다.
같은 파일이면 같은 hash가 나오고, 파일 내용이 조금만 바뀌어도 hash가 달라진다.

보안에서는 hash를 악성 파일 식별에 자주 쓴다.

예를 들어 어떤 실행 파일의 hash가 알려진 malware hash와 같다면 위험도가 높다.

우리 프로젝트는 Downloads 폴더의 최근 파일을 보고 다음 metadata를 만들 수 있다.

- file name
- file path
- extension
- size
- modified time
- hash

여기서 중요한 점은 파일 내용을 report에 그대로 저장하지 않는다는 것이다.
hash와 metadata만으로도 탐지 근거를 만들 수 있다.

---

## 15. PCAP

`PCAP`은 packet capture의 약자다.
네트워크 packet을 캡처해 파일로 저장한 형식이다.

Wireshark 같은 도구로 PCAP을 열면 packet 목록, protocol, IP, port 등을 볼 수 있다.

우리 프로젝트에서 PCAP은 network telemetry 입력이다.
실제 network packet을 실시간 감청하지 않아도, 이미 저장된 `.pcap` 파일을 분석해서 flow event를 만들 수 있다.

현재 담당 코드:

```text
src/pcap_flow.py
```

PCAP 기반 분석 흐름:

```text
pcap file
-> packet parsing
-> TCP flow summary
-> HTTP request metadata
-> event schema
-> detection rule
```

PCAP은 보안 학습에 좋다.
같은 파일을 반복 분석할 수 있고, 입력과 출력이 명확하기 때문이다.

---

## 16. Packet과 Flow

`Packet`은 네트워크에서 오가는 작은 데이터 조각이다.
웹페이지 하나를 열 때도 실제로는 많은 packet이 오간다.

Packet 하나만 보면 의미가 작을 수 있다.
하지만 여러 packet을 묶으면 하나의 통신 흐름이 보인다.
이것을 `Flow`라고 부른다.

Flow는 보통 다음 정보로 요약된다.

| 정보 | 의미 |
|---|---|
| source IP/port | 출발지 |
| destination IP/port | 목적지 |
| protocol | TCP/UDP 등 |
| start/end time | 통신 시간 |
| bytes in/out | 주고받은 데이터 크기 |
| packet count | packet 수 |

우리 프로젝트는 packet을 그대로 dashboard에 보여주는 것이 아니라, flow와 alert로 요약한다.

```text
packet은 원재료
flow는 요약된 통신 행위
alert는 위험하다고 판단된 결과
```

---

## 17. L7과 Deep Inspection

네트워크 계층을 말할 때 `L4`, `L7` 같은 표현이 나온다.

간단히 말하면 다음과 같다.

| 계층 | 보는 것 |
|---|---|
| L3 | IP 주소 |
| L4 | port, TCP/UDP |
| L7 | HTTP, URL, method, application action 같은 애플리케이션 정보 |

L4만 보면 이런 정도를 알 수 있다.

```text
내 PC가 443 port로 어떤 IP에 연결했다.
```

L7을 보면 더 많은 맥락을 알 수 있다.

```text
GET /payload/invoice.exe 요청을 보냈다.
Content-Type은 application/octet-stream이다.
URL이 malicious URL rule과 매칭됐다.
```

하지만 HTTPS는 암호화되어 있으므로 임의의 payload를 마음대로 복호화하면 안 된다.

우리 프로젝트의 L7 기준은 다음이다.

```text
허가된 local proxy, test app, sample record만 사용한다.
raw body는 저장하지 않는다.
URL, method, status, content-type, byte count 같은 metadata만 사용한다.
```

현재 담당 코드:

```text
src/l7_inspector.py
scripts/https_inspection_proxy.py
```

---

## 18. Detection Rule

`Detection rule`은 위험한 행동을 찾기 위한 조건이다.

예를 들어 다음은 rule이 될 수 있다.

```text
remote domain이 known malicious domain 목록에 있으면 alert 생성
Downloads 폴더에서 unsigned executable이 실행되면 alert 생성
짧은 시간 동안 주기적 외부 연결이 반복되면 alert 생성
대용량 outbound transfer가 발생하면 alert 생성
```

우리 프로젝트의 detection rule은 `src/detection_engine.py`에 구현되어 있고, 일부 signature data는 다음 파일에 있다.

```text
rules/threat_signatures.json
```

README 기준 rule 예시:

| Rule | 탐지 내용 |
|---|---|
| R001 | known malicious domain access |
| R002 | suspicious executable downloaded from browser |
| R003 | unsigned executable started from Downloads |
| R004 | periodic external connection |
| R005 | large outbound transfer |
| R009 | decrypted L7 malicious URL access |
| R011 | known malware hash signature match |

Rule 기반 탐지는 설명하기 좋다.
왜 alert가 생겼는지 사람이 이해할 수 있기 때문이다.

---

## 19. Alert와 Incident

`Alert`는 하나의 탐지 결과다.

예를 들어 다음은 alert다.

```text
김민준 laptop에서 known malicious domain으로 접속함
```

`Incident`는 관련 alert를 묶은 더 큰 사건이다.

예를 들어 다음 여러 alert가 같은 host에서 이어졌다면 하나의 incident로 볼 수 있다.

```text
악성 URL 접속
-> suspicious executable 다운로드
-> Downloads에서 실행
-> 외부 C2 연결
-> 대용량 outbound transfer
```

Alert와 Incident의 차이는 다음이다.

| 구분 | 의미 |
|---|---|
| Alert | 하나의 위험 신호 |
| Incident | 여러 신호를 연결한 사건 |

대시보드는 alert 목록만 보여주면 부족하다.
분석자가 공격 흐름을 이해할 수 있도록 incident 단위로 묶어줘야 한다.

---

## 20. Severity와 Risk Score

`Severity`는 위험도를 등급으로 표현한 것이다.

일반적으로 다음처럼 나눈다.

```text
low
medium
high
critical
```

`Risk score`는 위험도를 숫자로 표현한 것이다.
예를 들어 0부터 100까지 점수를 줄 수 있다.

둘의 차이는 다음이다.

| 구분 | 예시 | 장점 |
|---|---|---|
| severity | high | 사람이 빠르게 이해 |
| risk score | 87 | 정렬과 계산에 유리 |

Dashboard에서는 둘 다 중요하다.
분석자는 `critical`을 먼저 보고 싶고, 같은 critical 안에서도 점수가 높은 host를 먼저 보고 싶다.

---

## 21. MITRE ATT&CK

`MITRE ATT&CK`은 공격자의 행동을 전술과 기법으로 정리한 지식 체계다.

쉽게 말하면 "공격자가 보통 어떤 단계로 움직이는가"를 정리한 표준 분류표다.

예시:

| 전술 | 의미 |
|---|---|
| Initial Access | 처음 침투 |
| Execution | 악성 코드 실행 |
| Persistence | 계속 남아 있으려는 행동 |
| Privilege Escalation | 더 높은 권한 획득 |
| Defense Evasion | 탐지 회피 |
| Command and Control | 외부 C2 서버와 통신 |
| Exfiltration | 데이터 유출 |

우리 프로젝트는 alert를 단순히 "위험"이라고만 표시하지 않고, MITRE ATT&CK 관점으로 매핑한다.

예를 들어:

```text
known malicious domain access -> Command and Control
large outbound transfer -> Exfiltration
unsigned executable from Downloads -> Execution
```

발표에서 MITRE를 언급하면 전문성이 올라간다.
단, "MITRE를 완벽히 구현했다"가 아니라 "탐지 결과를 MITRE 관점으로 분류해 분석자가 이해하기 쉽게 했다"고 말해야 한다.

---

## 22. SIEM Query Finding

SIEM에서는 단순히 alert만 보는 것이 아니라, 반복 가능한 query로 로그를 분석한다.

예를 들어 이런 질문을 query로 만들 수 있다.

```text
최근 24시간 동안 high severity alert가 발생한 host는?
같은 destination으로 반복 연결한 process는?
known malicious domain에 접근한 device는?
DLQ로 빠진 event는 몇 개인가?
```

우리 프로젝트의 `SIEM Analysis`는 이런 분석 결과를 report와 dashboard에 보여주는 역할이다.

중요한 점은 "왜 위험한가"를 설명하는 것이다.

나쁜 설명:

```text
위험합니다.
```

좋은 설명:

```text
같은 endpoint에서 악성 domain 접속, suspicious executable 실행, 외부 C2 연결이 시간순으로 연결되어 incident로 묶였습니다.
```

---

## 23. Dashboard

Dashboard는 분석자가 빠르게 판단할 수 있게 돕는 화면이다.

우리 dashboard가 보여줘야 하는 핵심은 다음이다.

- 전체 alert 수
- incident 수
- 가장 위험한 endpoint
- severity 분포
- MITRE tactic 분포
- timeline
- endpoint risk
- response plan
- report link
- data quality / DLQ

좋은 보안 dashboard는 다음 질문에 빨리 답해야 한다.

```text
지금 가장 위험한 PC는 무엇인가?
무슨 일이 발생했는가?
왜 위험한가?
어떤 근거가 있는가?
다음에 무엇을 해야 하는가?
```

시연할 때는 화면을 예쁘게 설명하기보다, 분석 흐름을 보여주는 것이 중요하다.

예시 시연 흐름:

```text
1. Overview에서 전체 위험 상태 확인
2. 가장 높은 severity incident 클릭
3. alert evidence 확인
4. MITRE mapping 확인
5. endpoint risk 확인
6. report 열기
7. recommended action 설명
```

---

## 24. Report

Report는 dashboard를 보지 않는 사람도 결과를 이해할 수 있게 만든 문서다.

보안 report에는 보통 다음 내용이 필요하다.

| 섹션 | 의미 |
|---|---|
| Executive Summary | 핵심 결론 |
| Endpoint Risk | host별 위험도 |
| Incident Summary | 공격 흐름 |
| Alert Evidence | 탐지 근거 |
| MITRE Mapping | 공격 단계 분류 |
| SIEM Analysis | 반복 가능한 분석 결과 |
| Response Plan | 대응 권고 |
| Limitations | 현재 한계 |

우리 프로젝트는 CLI 실행 시 HTML/Markdown report를 생성한다.

```text
outputs/reports/latest/security_report.html
outputs/reports/latest/security_report.md
```

팀원이 발표할 때 report는 "분석 결과를 외부 사람에게 전달하는 산출물"이라고 설명하면 된다.

---

## 25. Response Plan

`Response`는 탐지 이후의 대응이다.

실제 EDR 제품은 다음 같은 대응을 할 수 있다.

- endpoint 격리
- process kill
- file quarantine
- firewall rule 추가
- ticket 생성
- 담당자 알림

우리 프로젝트는 실제 차단이나 격리를 하지 않는다.
대신 `dry-run response plan`을 만든다.

즉, 실제로 PC를 건드리지는 않고 "이런 대응을 권고한다"고 보여준다.

이 방식이 안전하다.
학습용 PoC에서 실제 process kill, network block, file deletion을 구현하면 위험하고 발표 범위도 커진다.

---

## 26. AI-style Prediction

우리 프로젝트에는 `AI-style host risk scoring`이 있다.
다만 이것은 학습된 대형 ML model이 아니다.

현재는 feature 기반 risk scoring에 가깝다.

예를 들어 다음 feature를 보고 host의 위험도를 예측할 수 있다.

- alert 개수
- severity 분포
- malicious domain 접근 여부
- outbound transfer 크기
- suspicious process 존재 여부
- incident 연결 여부

발표에서는 이렇게 말하면 된다.

```text
현재는 학습된 ML 모델이 아니라 feature 기반 risk scoring입니다.
다만 향후에는 수집된 telemetry와 alert history를 이용해 ML 기반 예측으로 확장할 수 있습니다.
```

과장하면 안 된다.
"AI가 모든 공격을 예측한다"가 아니라 "위험한 host를 우선순위화하는 scoring"이라고 설명하는 것이 정확하다.

---

## 27. Pipeline Bundle

현재 PoC는 분석 결과를 `gzip telemetry bundle`로 묶을 수 있다.

이것은 나중에 collector나 backend로 보낼 수 있는 데이터 묶음이라고 보면 된다.

현재 파일:

```text
outputs/pipeline/latest/telemetry_bundle.json.gz
```

현재 시연 구조는 다음처럼 단순하게 유지한다.

```text
Sample / local endpoint / PCAP / L7 metadata
-> Python CLI
-> Detection/SIEM analysis
-> outputs/latest/result.json
-> Dashboard/Report
```

현재 Python CLI와 static dashboard/report만으로도 동작하는 PoC를 보여줄 수 있다.

---

## 28. 저장소와 backend를 지금 넣지 않는 이유

팀원들이 헷갈리기 쉬운 부분이다.

현재 구현은 local Python CLI 중심이다. 이 단계에서는 DB, queue, streaming backend를 붙이는 것보다 수집, 탐지, SIEM 분석, dashboard/report가 실제로 이어지는지가 더 중요하다.

현재 범위는 다음이다.

| 구성 | 역할 |
|---|---|
| Python CLI | sample/local/PCAP/L7 telemetry를 읽고 분석 실행 |
| JSON artifact | event, alert, incident, report metadata를 저장하는 현재 결과물 |
| Static dashboard | 최신 JSON artifact를 읽어 사용자 화면 표시 |
| HTML/Markdown report | 분석 결과 공유용 산출물 |

중요한 구분:

```text
현재 PoC는 DB 서버 없이 동작한다.
outputs/latest/result.json이 현재 결과 저장소 역할을 한다.
dashboard/data/latest-result.js가 화면용 데이터 주입 역할을 한다.
```

Kafka 계열은 이벤트를 여러 worker에게 전달하고, 병목을 흡수하는 데 강하다.
하지만 dashboard가 조회할 현재 상태, report, incident, device 정보는 PostgreSQL 같은 DB에 두는 것이 맞다.

---

## 29. Event-driven 구조

`Event-driven`은 어떤 일이 발생하면 그 event를 기준으로 다음 처리가 이어지는 구조다.

예를 들어:

```text
telemetry event 수신
-> validation event 생성
-> detection worker가 alert 생성
-> incident worker가 incident 생성
-> report worker가 report 생성
-> dashboard read model 갱신
```

이 구조의 장점은 병목을 줄일 수 있다는 것이다.

Collector가 모든 일을 한 번에 처리하면 느려진다.
대신 Collector는 event를 안전하게 받고 저장한 뒤, 분석은 worker에게 맡긴다.

장기 구조:

```text
Collector
-> PostgreSQL event_outbox
-> Redpanda topic
-> detection consumer
-> SIEM consumer
-> report consumer
-> dashboard projection
```

현재 시연에서는 이 구조를 모두 구현한 것은 아니다.
하지만 제품 확장 방향을 설명할 때 중요한 설계 포인트다.

---

## 30. Data Quality와 DLQ

`Data Quality`는 들어온 데이터가 분석 가능한 품질인지 확인하는 것이다.

예를 들어 event에 필수 field가 없으면 detection rule이 제대로 동작하지 못할 수 있다.

`DLQ`는 Dead Letter Queue의 약자다.
처리하지 못한 event를 버리지 않고 따로 보관하는 공간이다.

DLQ가 필요한 이유:

- event schema가 틀렸을 수 있다.
- 필수 field가 없을 수 있다.
- worker 처리 중 error가 날 수 있다.
- 나중에 원인을 분석해야 할 수 있다.

우리 프로젝트는 invalid event를 그냥 버리지 않고 data quality 영역에서 보여준다.
이것은 보안 제품에서 신뢰성을 보여주는 중요한 요소다.

---

## 31. 현재 PoC 실행 흐름

팀원이 실제로 실행 흐름을 이해하려면 다음 순서를 보면 된다.

```text
python -m src.run
```

내부 흐름:

```text
1. sample event loading
2. optional local/PCAP/L7 event 추가
3. detection engine 실행
4. response plan 생성
5. AI-style prediction 생성
6. pipeline bundle 생성
7. result writer가 outputs와 dashboard data 생성
8. report builder가 HTML/Markdown report 생성
```

관련 파일:

| 단계 | 파일 |
|---|---|
| CLI entry | `src/run.py` |
| sample loading | `src/sample_loader.py` |
| local collection | `src/local_collector.py` |
| PCAP parsing | `src/pcap_flow.py` |
| L7 parsing | `src/l7_inspector.py` |
| detection | `src/detection_engine.py` |
| SIEM analysis | `src/siem_analyzer.py` |
| prediction | `src/ai_predictor.py` |
| response | `src/response_engine.py` |
| pipeline | `src/pipeline.py` |
| report | `src/report_builder.py` |
| output write | `src/result_writer.py` |

---

## 32. 팀원이 직접 해볼 실습

처음 보는 팀원은 아래 순서로 실습하면 된다.

### 실습 1. 기본 실행

```powershell
cd "C:\Users\geonh\Desktop\테커 아이디어회의\poc_code\security_edr_siem_poc"
python -m src.run
```

확인할 파일:

```text
dashboard/data/latest-result.js
outputs/reports/latest/security_report.html
outputs/reports/latest/security_report.md
```

### 실습 2. Dashboard 열기

```powershell
cd "C:\Users\geonh\Desktop\테커 아이디어회의\poc_code\security_edr_siem_poc\dashboard"
python -m http.server 8765 -b 127.0.0.1
```

브라우저:

```text
http://127.0.0.1:8765/
```

### 실습 3. 전체 검증

```powershell
cd "C:\Users\geonh\Desktop\테커 아이디어회의\poc_code\security_edr_siem_poc"
python scripts\validate_poc.py
```

성공하면 다음 decision이 나온다.

```text
local_poc_passed_with_advanced_modules
```

### 실습 4. Local telemetry 수집

```powershell
python -m src.run --collect-local
```

DNS cache까지 포함:

```powershell
python -m src.run --collect-local --include-dns-cache
```

---

## 33. 발표할 때 쓰기 좋은 설명

짧은 설명:

> 사용자의 PC에서 발생한 process, network, file, DNS metadata를 모아 위험한 행동을 탐지하고, MITRE ATT&CK 기준으로 분류한 뒤 dashboard와 report로 보여주는 EDR/SIEM-style PoC입니다.

조금 더 자세한 설명:

> 이 프로젝트는 백신이나 방화벽처럼 직접 차단하는 제품이 아니라, endpoint와 network telemetry를 분석해 보안 이벤트를 탐지하는 관제형 PoC입니다. 현재는 Python 기반 local PoC로 동작하며, sample event, Windows metadata, PCAP, L7 metadata를 입력으로 받아 alert, incident, MITRE mapping, SIEM analysis, report를 생성합니다.

기술 강조:

> 단순 dashboard mock이 아니라, event loading, validation, privacy masking, detection rule, MITRE mapping, SIEM-style analysis, AI-style risk scoring, report generation까지 이어지는 end-to-end flow를 구현했습니다.

안전 범위 강조:

> message body, browser password, keystroke, clipboard, document body, 임의의 HTTPS payload는 수집하지 않고, 탐지에 필요한 metadata만 사용합니다.

---

## 34. 오해하면 안 되는 것

| 오해 | 정확한 설명 |
|---|---|
| VPN을 만드는 프로젝트다 | 아니다. VPN은 핵심이 아니다. |
| 방화벽처럼 트래픽을 차단한다 | 현재는 실제 차단하지 않는다. 분석과 dry-run response 중심이다. |
| 완전한 XDR이다 | 아니다. EDR/SIEM-style PoC이며 XDR로 확장 가능한 구조다. |
| HTTPS 내용을 마음대로 복호화한다 | 아니다. 허가된 L7 metadata/sample만 사용한다. |
| AI가 공격을 예측한다 | 현재는 feature 기반 risk scoring이다. |
| dashboard만 만든 프로젝트다 | 아니다. CLI 분석, detection, report, validation까지 있다. |
| 실제 운영 제품이다 | 아니다. 학습/포트폴리오/발표용 local PoC다. |

---

## 35. 팀원이 알아야 할 파일 우선순위

처음부터 모든 코드를 읽을 필요는 없다.
다음 순서로 보면 된다.

1. `README.md`
2. `docs/erd-sa-current.md`
3. `docs/team-domain-learning-guide.md`
4. `src/run.py`
5. `src/detection_engine.py`
6. `src/local_collector.py`
7. `src/siem_analyzer.py`
8. `src/report_builder.py`
9. `dashboard/app.js`
10. `scripts/validate_poc.py`

처음 읽는 팀원이 가장 먼저 이해해야 하는 것은 코드 문법이 아니라 데이터 흐름이다.

```text
input event
-> analysis
-> alert/incident
-> dashboard/report
```

---

## 36. 최종 요약

우리 프로젝트는 다음 세 가지로 이해하면 된다.

1. `Endpoint telemetry`와 `network/L7 metadata`를 모은다.
2. `Detection rule`, `MITRE ATT&CK`, `SIEM-style analysis`로 위험 흐름을 분석한다.
3. `Dashboard`와 `Report`로 사람이 이해할 수 있게 보여준다.

가장 중요한 발표 메시지는 다음이다.

> LayerTrace EDR PoC는 실제 운영 제품은 아니지만, EDR/SIEM 제품의 핵심 흐름인 수집, 정규화, 탐지, 분석, 시각화, 보고서를 end-to-end로 작게 구현한 보안 분석 PoC다.
