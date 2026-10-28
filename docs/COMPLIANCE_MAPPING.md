# 📋 컴플라이언스 및 MITRE ATT&CK 통합 매핑 명세 (`COMPLIANCE_MAPPING.md`)

> **문서 목적**:
> **ISMS-P, PCI-DSS, 국정원 주요정보통신기반시설 가이드, ISO 42001(AI 관리체계), MITRE ATT&CK**과 `JW-XDR` 구현 모듈 간의 추적성 매트릭스입니다.

---

## 1. 컴플라이언스 프레임워크 × 모듈 매핑표

| 규제 / 프레임워크 | 핵심 요구사항 | `JW-XDR` 구현 모듈 및 파일 | 실증 방식 (스냅샷 ➔ 상시 실증) |
| :--- | :--- | :--- | :--- |
| **ISMS-P (2.5 인증 및 권한관리)** | 최소 권한 원칙(PoLP), 역할 기반 접근 제어(RBAC), 비인가 접근 통제 | `src/ztna/decider.mjs` | 모든 요청마다 신원·기기·세션 3단 분리 및 4상태(`allow`/`deny`/`challenge`/`unknown`) 상시 판정 |
| **ISMS-P (2.5.3 / 2.5.4) & 주요정보통신기반시설 (W-01~W-04)** | 패스워드 복잡성, 최소 8자, 최대/최소 사용기간, 계정 잠금 임계값, Guest/Admin 계정 관리 | `src/xdr/win-policy-parser.mjs`<br/>`scripts/windows-policy-audit.bat` | `secpol.msc` 수동 점검 체크리스트 vs `secedit /export` · `reg query` 자동 진단 1:1 대조 및 인적 오류 검출 |
| **PCI-DSS v4.0 (Req 8 & Req 10)** | 다중 인증(MFA/Step-Up), 무차별 대입 공격 잠금, 모든 보안 이벤트 및 감사 증적 보존 | `src/ztna/decider.mjs`<br/>`src/db/sqlite-store.mjs` | 민감 경로 접근 시 `challenge`(Step-Up) 강제 및 `node:sqlite` 감사 로그 영속 보관 |
| **ISO/IEC 42001 (인공지능 관리체계)** | AI 의사결정 투명성, 환각(Hallucination) 통제, 인간의 감독(Human-in-the-Loop), 개인정보 가명화 | `src/ai/soc-triage-agent.mjs`<br/>`src/soar/active-response.mjs` | `eventId` 근거 고정(`Evidence Binding`), 미존재 이벤트 인용 거부(`wrong_event_rejected`), 민감정보 익명화 리포트, 인간 최종 승인 강제 |
| **MITRE ATT&CK v15** | 침투 전술(Tactics) 및 기법(Techniques) 단계별 상관분석 및 Kill Chain 시각화 | `src/xdr/detect-engine.mjs`<br/>`public/dashboard/dashboard.mjs` | 6대 위협 시나리오 자동 태깅(`TA0001`~`TA0011`) 및 케이스 상세 14단계 Kill Chain 하이라이트 |

---

## 2. 6대 핵심 위협 × MITRE ATT&CK × 능동 대응 매핑

| 위협 분류 (`category`) | MITRE Tactic | MITRE Technique | Kill Chain 단계 | 기본 권고 능동 대응 (SOAR) |
| :--- | :--- | :--- | :---: | :--- |
| `brute-force` | Credential Access (`TA0006`) | `T1110` (Brute Force) | 자격증명 접근 / 명령·제어 | `BLOCK_ATTACK_IP` (공격 IP 차단) |
| `web-injection` | Initial Access (`TA0001`) | `T1190` (Exploit Public-Facing App) | 초기 접근 | `BLOCK_ATTACK_IP` (WAF/방화벽 IP 차단) |
| `known-cve` | Execution (`TA0002`) | `T1203` (Exploitation for Client Execution) | 실행 | `ISOLATE_HOST` (감염 의심 호스트 격리) |
| `persistence` | Persistence (`TA0003`) | `T1547` (Boot or Logon Autostart) | 지속 | `KILL_MALICIOUS_PROCESS` (비인가 프로세스 종료) |
| `privilege` | Privilege Escalation (`TA0004`) | `T1068` (Exploitation for Privilege Escalation) | 권한 상승 | `DISABLE_OS_ACCOUNT` (이상 징후 계정 비활성화) |
| `exfiltration` | Exfiltration (`TA0010`) | `T1041` (Exfiltration Over C2 Channel) | 유출 | `ISOLATE_HOST` + `BLOCK_ATTACK_IP` |
