# 📘 `JW-XDR` 실동작 운영 및 6대 메뉴 상세 설명서

본 문서는 장식용/예시용 더미 데이터를 모두 제거하고, **현재 실행 중인 로컬 Windows PC(`os.hostname()`)에서 100% 실제로 수집·탐지·차단·검증되는 기능만으로 구축한 `JW-XDR`**의 전체 운영 매뉴얼입니다.

---

## 1. 실제 작동하는 6대 핵심 엔진 요약

| 메뉴 / 모듈 | 실제 동작 방식 (가짜 더미 데이터 0%) | 실행되는 실제 명령어 / 모듈 |
| :--- | :--- | :--- |
| **① 위협 탐지 & 케이스 관제 (`cases`)** | • 서버(`5280` 포트)로 들어오는 모든 HTTP 요청의 URL 쿼리·헤더를 실시간 검사해 **SQLi, XSS, Log4Shell, 권한상승, 레지스트리 영속성 변조** 페이로드 감지 시 즉시 **`HTTP 403 Forbidden` 차단** 및 `node:sqlite` DB에 케이스 자동 생성<br>• 내 PC 초기 실측(Windows 취약 설정 & `package-lock.json` 취약 패키지) 결과를 바탕으로 실제 케이스만 표시 | [server.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/server.mjs), [detect-engine.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/xdr/detect-engine.mjs), [case-manager.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/xdr/case-manager.mjs) |
| **② 실시간 네트워크 소켓 (`network`)** | • 현재 내 PC에서 `netstat.exe -ano -p TCP`를 실시간 실행하여 **실제 활성 TCP 연결(`ESTABLISHED`), 대기 포트(`LISTENING`), 외부 원격 IP**를 추출하고 `tasklist`의 PID와 매핑해 어느 프로세스(`chrome.exe`, `node.exe` 등)가 외부와 통신 중인지 표시<br>• 원격 IP 옆의 **[🚫 IP 차단 제안]** 클릭 시 게이트웨이 차단 목록에 즉시 등록 | [live-host-collector.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/xdr/live-host-collector.mjs) (`netstat.exe -ano`) |
| **③ 실행 프로세스 & ZTNA (`endpoint`)** | • 현재 내 PC에서 `tasklist.exe /FO CSV /NH`를 실시간 실행하여 **실제 실행 중인 프로세스 전체 목록과 메모리 점유율(MB)**을 실시간 조회<br>• `os.cpus()`, `os.totalmem()`, `os.networkInterfaces()`로 내 PC의 실제 하드웨어/IPv4 인터페이스를 표시하고 **ZTNA 3단(신원·기기·맥락) 4상태(`allow`/`deny`/`challenge`/`unknown`)** 판정 실행 | [live-host-collector.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/xdr/live-host-collector.mjs) (`tasklist.exe`), [decider.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/ztna/decider.mjs) |
| **④ Windows 보안 정책 실측 (`policy`)** | • 현재 내 PC에서 `net accounts` 및 `reg.exe query` (`HKLM\...\Lsa`, `LanmanServer\Parameters`, `RDP-Tcp`)를 실시간 실행(Read-Only)하여 **내 PC의 실제 암호 길이, 잠금 임계값, SMB 서명, RDP NLA 설정값**을 읽어옴<br>• 이를 수동 체크리스트와 1:1 비교해 **인적 오류(불일치)**를 검출하고 평문 토큰을 `[REDACTED]`로 마스킹 | [live-host-collector.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/xdr/live-host-collector.mjs), [win-policy-parser.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/xdr/win-policy-parser.mjs) |
| **⑤ 공급망 취약점 스캔 (`sbom`)** | • 프로젝트의 실제 `package-lock.json`에서 `exact_lock_version`을 추출하고 **실시간 Google OSV API (`https://api.osv.dev/v1/querybatch`)**에 HTTPS POST 쿼리를 수행하여 **`vulnerable` / `none_found` / `unverifiable` 3상태**로 분류 | [sbom-osv-scanner.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/cti/sbom-osv-scanner.mjs) |
| **⑥ 능동 대응(SOAR) · AI 감사 · DB 백업 (`soar`)** | • 4대 능동 대응 조치의 **4단계 인간 승인(`PROPOSED` ➔ `APPROVED` ➔ `PENDING_ACK` ➔ `EFFECT_VERIFIED`)** 전이 및 실제 게이트웨이 IP 차단 적용<br>• **ISO 42001 `eventId` 근거 고정 AI 분석**(가짜 `eventId` 환각 거부 및 월권 차단 실증)<br>• **`node:sqlite` `SQLite format 3\0` 16바이트 헤더 검증 백업** 및 손상 파일 복원 거부 | [active-response.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/soar/active-response.mjs), [soc-triage-agent.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/ai/soc-triage-agent.mjs), [sqlite-store.mjs](file:///c:/Users/User/Desktop/JW-XDR/src/db/sqlite-store.mjs) |

---

## 2. 구동 방법

### 2.1 실행 명령어
`c:\Users\User\Desktop\JW-XDR` 경로에서 아래 명령어를 실행합니다.

```powershell
# 방법 1: 원클릭 배치 파일 실행
.\run-jw-xdr.bat

# 방법 2: npm 명령어로 직접 실행
npm test
npm start
```

### 2.2 접속 주소
- **통합 관제 대시보드 (`JW-XDR`)**: `http://127.0.0.1:5280/dashboard/`
- **엔드포인트 보안 에이전트 (`bankhar-agent`)**: `http://127.0.0.1:5280/agent/`

---

## 3. 대시보드(`/dashboard/`) 6대 메뉴별 사용법

### 메뉴 1: `📈 위협 탐지 & 케이스 관제`
1. **실시간 L7 HTTP 공격 패킷 전송 & 인라인 IPS 403 차단 테스트 패널**:
   - 드롭다운에서 공격 유형(① SQL Injection, ② XSS, ③ Log4Shell JNDI, ④ Windows Run 레지스트리 변조, ⑤ 권한 상승)을 선택하고 **[🚀 실제 공격 HTTP 요청 발사 (403 차단 확인)]** 버튼을 클릭합니다.
   - 브라우저가 서버로 실제 공격 쿼리를 전송하며, 서버의 L7 IPS 미들웨어가 이를 즉시 감지하여 **`HTTP 403 Forbidden` (`XDR_L7_INLINE_IPS_BLOCK`)으로 차단**하고 하단 케이스 테이블 최상단에 신규 케이스를 자동 등록합니다.
2. **케이스 상세 슬라이드오버 드로어 (6개 탭)**:
   - 케이스 행을 클릭하면 우측에서 드로어가 열리며 **`기본 정보 & Kill Chain(14단계)`**, **`관련 원시 이벤트(실제 payload_json)`**, **`대상 호스트 상태(내 PC 실측 사양)`**, **`차단/위협 지표(IOC)`**, **`AI 근거 고정 분석`**, **`능동 대응(SOAR)`** 탭을 조회·조작할 수 있습니다.
   - 드로어 하단의 **[✓ 인지]**, **[⊗ 종결 (MTTR 기록)]**, **[🛡️ 오탐 예외처리 (FP 튜닝)]**, **[🎯 정탐 확정 (TP 튜닝)]** 버튼으로 케이스 상태를 즉시 변경합니다.

### 메뉴 2: `🌐 실시간 네트워크 소켓 (netstat)`
- 현재 내 PC에서 실행된 `netstat -ano -p TCP` 결과와 `tasklist` 프로세스명을 결합하여 **실제 로컬 주소:포트, 원격 주소:포트, 연결 상태(`ESTABLISHED` / `LISTENING`), PID, 프로세스 이름**을 실시간으로 보여줍니다.
- 외부 원격 IP 우측의 **[🚫 IP 차단 제안]** 버튼을 누르면 해당 원격 IP가 SOAR 차단 대기열에 즉시 등록됩니다.

### 메뉴 3: `🖥️ 실행 프로세스 (tasklist) & ZTNA`
- **좌측 상단**: 현재 내 PC(`DESKTOP-OF0CMDB` 등)의 실제 CPU 모델/코어 수, RAM 사용량(`MB` 및 `%`), 실제 활성 IPv4 네트워크 인터페이스와 MAC 주소를 보여줍니다.
- **우측 상단 (ZTNA 판정기)**: 신원, 기기 등록 상태, MFA 2차 인증 여부를 변경하며 **[판정 실행]**을 누르면 `allow` / `deny` / `challenge` / `unknown` 4상태 판정 결과를 즉시 반환합니다.
- **하단 테이블**: 현재 내 PC에서 실행 중인 프로세스(`tasklist /FO CSV`)를 메모리 점유율 순으로 보여주며, 특정 프로세스에 대해 **[⚡ 프로세스 종료 제안 (SOAR)]**을 등록할 수 있습니다.

### 메뉴 4: `📋 Windows 보안 정책 실측 (reg/net)`
- 서버가 내 PC의 `net accounts` 및 `reg query` (`HKLM\...\Lsa`, `LanmanServer\Parameters`, `RDP-Tcp`)를 실제로 조회하여 **내 PC의 실제 설정값(`MinimumPasswordLength`, `LockoutBadCount`, `LockoutDuration` 등)**을 화면에 표시합니다.
- 테이블의 **`수동 점검 판정`** 드롭다운(`양호` / `취약`)을 바꿔가며 **[🔄 내 PC 실시간 재추출 & [REDACTED] 마스킹 검증]** 버튼을 누르면, 수동 체크리스트와 실제 OS 설정값 간의 불일치(인적 오류) 및 평문 토큰 `[REDACTED]` 마스킹 결과를 즉시 확인할 수 있습니다.

### 메뉴 5: `📦 공급망 취약점 스캔 (OSV.dev)`
- **[🌐 실시간 OSV.dev 온라인 스캔 (seq 증가)]**: 프로젝트의 `package-lock.json`을 파싱하여 Google OSV API(`https://api.osv.dev/v1/querybatch`)로 조회하고 `vulnerable` / `none_found` / `unverifiable` 3상태를 갱신합니다.
- **[⚡ 오프라인/통신 장애 시뮬레이션]**: 네트워크 단절 시 `none_found`(취약점 없음)로 거짓 안심시키지 않고 전체 패키지를 정직하게 `unverifiable`(검증 불가)로 분리하는지 실증합니다.

### 메뉴 6: `🛡️ 능동 대응(SOAR) · AI 감사 · DB 백업`
- **좌측 (SOAR 4단계 인간 승인)**: 등록된 조치에 대해 **[1. 승인(Approve)]** ➔ **[2. 미연동 접수(ACK)]** ➔ **[3. 원천 집행 완료]** 버튼을 눌러 단계 전이와 `effectApplied: false/true` 상태 분리를 제어합니다. (`BLOCK_ATTACK_IP`가 승인되면 게이트웨이에서 해당 출발지 IP의 HTTP 요청이 실제로 `403 Forbidden` 차단됩니다.)
- **우측 상단 (ISO 42001 AI 근거 고정 실증)**:
  - **[✓ 정상 eventId 근거 고정 AI 분석 실행]**: 실제 수집된 `eventId`만을 인용하여 1차 판정 및 감사 로그를 남깁니다.
  - **[🚫 가짜 eventId(EVT-999999) 환각 차단 실증]**: 존재하지 않는 이벤트 ID 인용 시 `wrong_event_rejected: true`로 즉시 거부합니다.
  - **[🚫 AI 임의 차단 월권 차단 실증]**: 인간 승인 없이 AI가 이미 차단했다고 주장할 때 `proposal_not_executed: true`로 차단합니다.
- **우측 하단 (SQLite 무결성 백업 & 손상 헤더 복원 거부)**:
  - **[💾 현재 SQLite DB 무결성 백업 생성]**: `backup/` 디렉터리에 실제 `.db` 백업 파일을 생성하고 16바이트 헤더를 검증합니다.
  - **[💥 손상된 헤더 파일 복원 시도]**: 잘못된 헤더 바이트를 주입해 복원이 즉시 거부(`INVALID_SQLITE_HEADER`)되고 기존 DB가 보호(`preservedExistingDb: true`)되는지 확인합니다.
