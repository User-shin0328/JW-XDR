# 🛡️ 프로젝트 마스터 플랜: 통합 XDR 플랫폼 (`JW-XDR`)

> **프로젝트 정의 및 소개 문구**:
> 본 프로젝트는 **신규 독립 프로젝트(`JW-XDR`)로 설계·구축하는 통합 XDR(Extended Detection and Response) 플랫폼**입니다.

---

## 0. 신규 프로젝트 추진 개요

- **프로젝트 성격**: **독립 프로젝트 저장소(`JW-XDR`)**를 생성하여 이론·실습·아키텍처 원칙을 하나의 완성형 보안 솔루션으로 직접 구현합니다.
- **포트폴리오/README 공식 소개글 (발췌용)**:
  > *"본 시스템은 ① 제로 트러스트 접근 제어(ZTNA), ② SIEM/XDR 로그 상관분석 및 MITRE ATT&CK 매핑, ③ Windows 로컬 보안 정책 수동·자동 상시 실증, ④ ISO 42001 기반 SOC AI 에이전트 1차 정탐/오탐 분석, ⑤ 5중 안전장치 기반 Human-in-the-Loop 능동 대응(Active Response 4대 조치)을 바탕으로 직접 설계·구현한 통합 XDR 플랫폼(`JW-XDR`)입니다."*
- **커리큘럼 2대 축의 결합**:
  1. **SKT ALEPH 실무 특강 커리큘럼 (1~6구간)**: SOC 관제와 MTTD/MTTR 지표, 컴플라이언스(ISMS-P·PCI-DSS·ISO 42001)의 `[스냅샷 심사 ➔ 상시 실증]` 전환, `secpol.msc` 수동 점검 vs 배치(`.bat`) 자동 진단 대조 실습, SKT T-MAC XDR 멀티 테넌트 콘솔 및 능동 대응·AI 에이전트 구조.
  2. **SKT ALEPH 엔지니어링 커리큘럼 (13~22단계)**: 4상태 ZTNA PDP, 6대 위협 탐지, 근거 고정(`eventId`) 기반 AI 환각·월권 차단, 4단계 승인 게이지와 원천 집행(`effectApplied`) 분리, SBOM/OSV 공급망 검증, `node:sqlite` 영속성 및 4자 분리 아키텍처.

---

## 1. 프로젝트 비전 및 핵심 설계 철학

### 1.1 왜 단일 통합 XDR인가? (EDR + NDR + SIEM + SOAR + ZTNA)
기존 보안 환경에서는 엔드포인트(EDR), 네트워크(NDR), 로그 집계(SIEM), 자동화 대응(SOAR), 접근 제어(ZTNA)가 파편화되어 운영 효율이 떨어지고 24/7/365 관제 인력의 알람 피로도(Alert Fatigue)가 극심했습니다. 본 프로젝트는 이를 **멀티 테넌트(Multi-tenant) 클라우드 SaaS 구조의 단일 통합 XDR 플랫폼**으로 통합합니다.

### 1.2 5대 핵심 아키텍처 원칙 (특강 + 방어전 13~22단계 결합)
1. **경계선 보안에서 제로 트러스트(Zero Trust)로의 전환 (13~14단계 + 3구간)**
   - 내부망을 무조건 신뢰하지 않고, 모든 요청마다 신원(Identity)·기기(Device)·세션(Session)·실시간 위험 신호(Signals)를 지속 검증합니다.
   - 최소 권한 원칙(PoLP)과 역할 기반 접근 제어(RBAC)를 적용하며, 판단 근거가 부족할 때는 즉시 차단하거나 통과시키지 않고 `unknown`(확인 불가) 또는 `challenge`(Step-Up 재인증)로 안전하게 분리(Fail-Closed)합니다.
2. **스냅샷 심사에서 상시 실증(Continuous Validation) 체계로의 전환 (16·20단계 + 3·4·5구간)**
   - 연 1~2회 특정 시점의 단면만 확인하던 기존 컴플라이언스(ISMS-P, PCI-DSS, 국정원 감사)의 한계를 넘어, **엔드포인트 OS 보안 정책(`reg query`, `secedit /export`)과 소프트웨어 공급망(SBOM/OSV)을 상시 자동 진단·실증**하고 수동 점검 대비 인적 오류(누락·오해석)를 제거합니다.
3. **정탐·오탐·미탐 정밀 분리와 MTTD / MTTR 단축 (15단계 + 1·4·6구간)**
   - 무분별한 차단으로 인한 가용성 저하(인프라 엔지니어와 보안 엔지니어 간 상충)를 방지하기 위해 **룰 튜닝(Rule Tuning)**과 **MITRE ATT&CK(Tactic/Technique) 매핑**을 적용합니다.
   - 관제 핵심 성과 지표인 **MTTD(평균 탐지 시간)**와 **MTTR(평균 대응 시간)**를 모든 케이스(Case) 단위로 실시간 계측합니다.
4. **ISO 42001 기반 신뢰 가능한 SOC AI 에이전트 (17~18단계 + 1·3·6구간)**
   - 24/7 관제 피로도를 줄이기 위해 LLM 기반 SOC AI 에이전트가 탐지된 케이스의 **1차 정탐(True Positive) / 오탐(False Positive) 자동 분석 및 판단 보류(Hold/Unknown) 라벨링**을 수행합니다.
   - AI의 환각(Hallucination)이나 월권(Overreach)을 막기 위해 **근거 고정(Evidence Binding)**을 강제하고, AI 에이전트의 모든 활동 감사 로그(Audit Trail)를 기록합니다.
5. **부작용(Side Effect)을 통제하는 Human-in-the-Loop 능동 대응 (19단계 + 6구간)**
   - **공격 IP 차단, 호스트 격리, 계정 비활성화, 악성 프로세스 강제 종료**의 4대 능동 대응(Active Response)을 지원하되, 오작동에 따른 업무 중단을 막기 위해 **사람의 최종 승인(Human-in-the-Loop)**과 **4단계 상태 전이(`제안` ➔ `확인` ➔ `접수(ACK)` ➔ `원천 집행 완료`)**를 엄격히 분리합니다.

---

## 2. 강의 구간(1~6구간) × 방어전 단계(13~22단계) 통합 매핑표

| 모듈 영역 | 방어전 단계 | 특강 연계 구간 및 핵심 개념 | 구현할 핵심 기능 요약 |
| :--- | :---: | :--- | :--- |
| **M1. ZTNA 정책 결정기 (PDP)** | **13~14단계** | **[2·3구간]** IAM(PoLP/RBAC), 제로 트러스트, 다층 보안 체계 | 신원·기기·세션 3단 분리, 4상태 판정(`allow`/`deny`/`challenge`/`unknown`), 미검증 기기 및 위험 신호 차단 |
| **M2. 위협 탐지 & MITRE 케이스 엔진** | **15단계** | **[1·2·4·6구간]** SIEM/XDR 상관분석, SQLi, MITRE ATT&CK, 정탐/오탐/미탐, MTTD/MTTR | 6대 공격 시나리오 탐지, 심각도(`Critical`/`High`/`Medium`/`Low`), MITRE 매트릭스 매핑, 케이스 발행 및 룰 튜닝 |
| **M3. 상시 실증 엔드포인트 진단기** | **16단계** | **[3·4·5구간]** 스냅샷 ➔ 상시 실증, `secpol.msc` 수동 vs 배치(`.bat`) 자동 진단 대조 | 브라우저/OS 실측 + Windows 로컬 보안 정책(`reg query`/`secedit`) 자동 파서, 수동 체크리스트 비교 뷰, 민감정보 마스킹 복사 |
| **M4. SOC AI 에이전트 & 게이트웨이** | **17~18단계** | **[1·3·6구간]** 24/7 알람 피로 해소, ISO 42001(AI 관리체계), AI 1차 정탐/오탐/판단보류 | AI 게이트웨이 상태 점검(7종 복구 안내), 케이스 1차 정탐/오탐/판단보류 라벨링, `eventId` 근거 고정, AI 감사 로그 |
| **M5. T-MAC 능동 대응 (SOAR)** | **19단계** | **[2·6구간]** 인프라 가용성 vs 보안 안전성 조율, 능동 대응 4대 조치, 최종 승인 옵션 | 4대 조치(IP 차단·호스트 격리·계정 비활성화·프로세스 종료) + 4단계 승인 게이지 + 원천 집행(`effectApplied`) 분리 |
| **M6. 공급망(SBOM) & 취약점 관리** | **20단계** | **[2·3구간]** CTI(위협 인텔리전스), 취약점 사전 관리, 컴플라이언스 증적 | `package-lock.json` 정확 버전 고정(`exact_lock_version`), OSV 취약점 대조, 시점 불일치(Stale) 차단 |
| **M7. 영속성 저장소 & 무결성 백업** | **21단계** | **[1·2·6구간]** 개인정보 보관/파기 법령, 1년 감사 증적 보존, 차단·AI 감사 이력 | `node:sqlite` 기반 멀티 테넌트 DB, 케이스/이벤트/AI판정/SOAR/실증 이력 영속화, SQLite 헤더 검증 백업/복원 |
| **M8. 클라우드 XDR 대시보드 & 패키징** | **22단계** | **[6구간 & 대시보드 노션]** 멀티 테넌트 SaaS 콘솔, 타임라인·매트릭스 UI, 런북 | 클라우드 XDR 대시보드 + 엔드포인트 에이전트 UI(CSP 100% 준수), 4자 분리 아키텍처 런북, 포터블 배포(`.bat`) |

---

## 3. 전체 시스템 아키텍처 및 디렉토리 구조

### 3.1 4자 분리(4-Plane) 멀티 테넌트 아키텍처 (22단계 규격 반영)
```mermaid
flowchart TB
  subgraph Endpoint["1. 엔드포인트 영역 (Endpoint Agent & Local Audit)"]
    AgentUI["에이전트 UI (bankhar-agent)\n[전체/주의/확인불가 타임라인 & 자원 실측]"]
    WinAudit["Windows 상시 실증 수집기 (Read-Only)\n[reg query / secedit /export 파서]"]
  end

  subgraph ControlPlane["2. XDR 제어 및 분석 영역 (Multi-Tenant Cloud XDR Server)"]
    ZTNA["M1. ZTNA PDP 엔진\n(allow / deny / challenge / unknown)"]
    Detect["M2. SIEM/XDR 상관분석 & 케이스 엔진\n(6대 위협 + MITRE ATT&CK + MTTD/MTTR)"]
    AIGateway["M4. SOC AI 에이전트 (ISO 42001)\n(1차 정탐/오탐/판단보류 + 근거 고정)"]
    SBOM["M6. CTI & SBOM/OSV 취약점 엔진\n(exact_lock_version & Stale 차단)"]
    SQLite[("M7. node:sqlite 영속 저장소\n(테넌트별 Cases / Events / Audits / Receipts)")]
  end

  subgraph Console["3. 관제사 콘솔 영역 (Cloud XDR Dashboard)"]
    DashUI["클라우드 XDR 통합 관제 대시보드\n(심각도 통계 / MITRE 매트릭스 / 케이스 관리 / 룰 튜닝)"]
    Approval["Human-in-the-Loop 승인 워크플로우\n(제안 ➔ 확인 ➔ 접수(ACK) ➔ 원천 확인)"]
  end

  subgraph Enforcer["4. 원천 집행 영역 (Enforcement Plane - Mock / Adapter)"]
    ActiveResp["M5. 능동 대응 4대 조치 집행기\n① 공격 IP 차단  ② 호스트 격리\n③ 계정 비활성화  ④ 악성 프로세스 종료"]
  end

  AgentUI -->|신원·기기·진단 보고| ZTNA
  WinAudit -->|수동 vs 자동 정책 증적| SQLite
  ZTNA -->|접근 로그 & 이상 징후| Detect
  Detect -->|케이스 발행| SQLite
  Detect -->|케이스 분석 요청| AIGateway
  AIGateway -->|정탐/오탐/보류 + 감사로그| SQLite
  SQLite <--> DashUI
  DashUI -->|관제사 최종 승인 (Intent)| Approval
  Approval -->|집행 요청| ActiveResp
  ActiveResp -->|Receipt (effectApplied 여부)| SQLite
```

### 3.2 독립 프로젝트 디렉토리 구조 (`JW-XDR/`)
```text
JW-XDR/
├── README.md                     # JW-XDR 프로젝트 소개 및 실행 가이드
├── package.json
├── package-lock.json
├── run-jw-xdr.bat                # 원클릭 포터블 실행기
├── docs/
│   ├── ARCHITECTURE_RUNBOOK.md   # 22단계: 4자 분리 구조 및 장애 복구 런북
│   └── COMPLIANCE_MAPPING.md     # ISMS-P / PCI-DSS / ISO 42001 / MITRE 매핑 문서
├── scripts/
│   └── windows-policy-audit.bat  # 5구간 실습 반영: 읽기 전용 Windows 보안 정책 진단 스크립트
├── src/
│   ├── server.mjs                # 통합 XDR API & 멀티 테넌트 라우터
│   ├── db/
│   │   ├── sqlite-store.mjs      # 21단계: node:sqlite 영속성 & 백업/복원 엔진
│   │   └── schema.sql            # Cases, Events, AI_Audits, SOAR_Receipts, Policy_Audits
│   ├── ztna/
│   │   └── decider.mjs           # 13~14단계: 4상태 ZTNA PDP & RBAC/PoLP 검증기
│   ├── xdr/
│   │   ├── detect-engine.mjs     # 15단계: 6대 위협 탐지 & MITRE ATT&CK 매핑
│   │   ├── case-manager.mjs      # 1·6구간: 케이스 발행, 정탐/오탐/미탐 튜닝, MTTD/MTTR 계산
│   │   └── win-policy-parser.mjs # 4~5구간: 수동 점검 vs 자동 스크립트(secedit/reg) 비교 엔진
│   ├── ai/
│   │   ├── ai-gateway.mjs        # 17단계: AI 연결 상태 진단 & 7대 오류 복구 안내
│   │   └── soc-triage-agent.mjs  # 18단계+6구간: 1차 정탐/오탐/판단보류 + Evidence Binding
│   ├── soar/
│   │   └── active-response.mjs   # 19단계+6구간: 4대 능동 대응 & 4단계 Human-in-the-Loop
│   └── cti/
│       └── sbom-osv-scanner.mjs  # 20단계: package-lock 정확 버전 & OSV 취약점 대조
├── public/
│   ├── dashboard/                # 클라우드 XDR 콘솔 UI (노션 대시보드 레퍼런스 구현)
│   │   ├── index.html
│   │   ├── dashboard.css         # CSP(style-src 'self') 100% 준수 스타일시트
│   │   └── dashboard.mjs
│   └── agent/                    # 엔드포인트 에이전트 UI (bankhar_b 타임라인형 계승)
│       ├── index.html
│       ├── agent.css             # CSP(style-src 'self') 100% 준수 스타일시트
│       └── agent.mjs
└── test/
    └── self-verification.mjs     # 13~22단계 전체 보안 게이트 자동 검증 스위트
```

---

## 4. 모듈별 상세 기능 및 기술 명세

### 모듈 1. 제로 트러스트 접근 제어 (ZTNA PDP) — *[13~14단계 + 2·3구간]*
- **3단 분리 카드**:
  1. `신원 확인(Identity)`: 발급자(`issuer`), 주체(`sub`), 부서/역할(RBAC), 최소 권한(PoLP) 검증.
  2. `기기 확인(Device)`: 기기 등록 여부(`deviceRegistered`), 엔드포인트 보안 정책 준수 상태.
  3. `세션 확인(Session)`: Step-Up(MFA/생체인증) 완료 여부, 토큰 만료 시각.
- **4상태 판정 계약**:
  - `allow`: 신원·기기·세션 모두 정상이고 위험 신호가 없는 경우.
  - `challenge`: 민감 경로 접근 또는 경미한 이상 징후 감지 시 Step-Up 재인증 요구.
  - `deny`: 미등록 기기, 권한 없는 경로 접근, 명확한 공격 신호 감지 시 즉시 차단.
  - `unknown`: 판단을 위한 원천 신호나 정책 연결이 누락된 경우 통과시키지 않고 `확인 불가`로 격리.

---

### 모듈 2. SIEM/XDR 상관분석·MITRE ATT&CK·케이스 관리 — *[15단계 + 1·2·4·6구간]*
- **6대 핵심 위협 시나리오 탐지 및 MITRE ATT&CK 매핑**:
  | 위협 분류 (`category`) | 세부 공격 기법 | MITRE ATT&CK Tactic | MITRE Technique | 기본 심각도 |
  | :--- | :--- | :--- | :--- | :---: |
  | `brute-force` | 비밀번호 다회 오류 / 크리덴셜 스터핑 | Credential Access (`TA0006`) | `T1110` (Brute Force) | `High` |
  | `web-injection` | 쿼리스트링 SQL Injection / XSS | Initial Access (`TA0001`) | `T1190` (Exploit Public-Facing App) | `Critical` |
  | `known-cve` | 공개 CVE 악용 요청 | Execution (`TA0002`) | `T1203` (Exploitation for Client Execution) | `Critical` |
  | `persistence` | 레지스트리 Run 키 / 스케줄러 변조 | Persistence (`TA0003`) | `T1547` (Boot or Logon Autostart) | `High` |
  | `privilege` | 비인가 관리자 권한 상승 시도 | Privilege Escalation (`TA0004`) | `T1068` (Exploitation for Privilege Escalation) | `Critical` |
  | `exfiltration` | 대량 개인정보/기밀 외부 유출 시도 | Exfiltration (`TA0010`) | `T1041` (Exfiltration Over C2 Channel) | `Critical` |
- **케이스(Case) 생명주기 및 MTTD / MTTR 자동 산출 (1구간 반영)**:
  - $\text{MTTD (평균 탐지 시간)} = T_{\text{case\_created}} - T_{\text{first\_event\_occurred}}$
  - $\text{MTTR (평균 대응 시간)} = T_{\text{response\_completed}} - T_{\text{case\_created}}$
- **정탐 / 오탐 / 미탐 룰 튜닝 워크플로우 (1구간 반영)**:
  - 관제사가 케이스를 `정탐(True Positive)`, `오탐(False Positive)`, `미탐 재분석(False Negative Review)`으로 판정하면 해당 패턴의 예외 조건이나 임계값을 룰셋 버전으로 기록합니다.

---

### 모듈 3. 상시 실증(Continuous Validation) & Windows 로컬 보안 정책 진단 — *[16단계 + 3·4·5구간]*
- **배경 (3~5구간 실습 반영)**:
  - 연 1회 스냅샷 심사의 한계를 극복하고, `secpol.msc` 수동 점검에서 발생하는 인적 오류(누락·잘못된 해석)를 방지하기 위해 **수동 점검 체크리스트와 자동 진단 스크립트 결과를 1:1 대조하는 상시 실증 모듈**을 구현합니다.
- **점검 항목 명세 (읽기 전용 수집, OS 설정 임의 변경 금지)**:
  1. **암호 정책 (Password Policy)**:
     - 패스워드 복잡성 만족 여부 (`PasswordComplexity` = 1 권장)
     - 최소 암호 길이 (`MinimumPasswordLength` $\ge 8$자 권장)
     - 최대/최소 암호 사용 기간 (`MaximumPasswordAge`, `MinimumPasswordAge`)
  2. **계정 잠금 정책 (Account Lockout Policy - Brute Force 방어)**:
     - 계정 잠금 임계값 (`LockoutBadCount`: 로그인 $N$회 실패 시 잠금 설정 여부)
     - 계정 잠금 기간 및 원래대로 설정 시간 (`LockoutDuration`, `ResetLockoutCount`)
  3. **계정 관리 (Account Management)**:
     - 불필요한 기본 관리자(`Administrator`) 및 게스트(`Guest`) 계정 비활성화 여부 (`reg query` / `net user` 읽기 전용 파싱)
  4. **브라우저/에이전트 실시간 자원 및 보안 점검 (16단계)**:
     - 논리 CPU 코어, JS 힙 메모리, 스토리지 쿼터, HTTPS 보안 컨텍스트, CSP 적용 여부.
     - 샌드박스 권한 밖 항목(원천 방화벽 커널 상태, 타 프로세스 목록 등)은 추측하지 않고 `? 확인 불가(unverifiable)`와 사유를 명시.
- **수동 vs 자동 대조 리포트 및 민감정보 마스킹 내보내기**:
  - 사용자가 수동으로 체크한 결과(`양호`/`취약`)와 자동 스크립트(`secedit /export`, `reg query`) 파싱 결과를 비교하여 **불일치(인적 오류 발생 지점)**를 하이라이트 표시합니다.
  - 진단 JSON 복사 시 토큰·쿠키·세션키·개인식별정보는 `[REDACTED]` 처리합니다.

---

### 모듈 4. SOC AI 에이전트 & ISO 42001 거버넌스 — *[17~18단계 + 1·3·6구간]*
- **AI 게이트웨이 연결 진단 및 7종 오류 복구 안내 (17단계)**:
  - API 키, 토큰 등 비밀값은 코드·로그·Git에 절대 저장하지 않으며 설정 화면의 비밀 입력란을 통해서만 주입합니다.
  - 미설정, 인증 실패(401/403), 한도 초과(429), 시간 초과(Timeout), 모델명 불일치(404), 네트워크 단절, 비정상 응답 형식의 7가지 장애 상황에 대해 각각 구체적인 1줄 복구 가이드를 제시합니다.
- **SOC AI 에이전트 1차 자동 분석 및 라벨링 (18단계 + 6구간 라이브 시연 반영)**:
  - 발행된 케이스(Case)에 대해 AI 에이전트가 로그 문맥을 분석하여 3가지 라벨 중 하나를 부여합니다:
    1. `정탐 유력 (Likely True Positive)`
    2. `오탐 유력 (Likely False Positive)`
    3. `판단 보류 (Hold / Unknown — 근거 부족 또는 추가 확인 필요)`
- **환각·월권 차단 가드레일 (ISO 42001 연계)**:
  - **근거 고정(`Evidence Binding`)**: 실제 수집된 이벤트 배열에 존재하는 `eventId`와 로그 원문만 인용할 수 있으며, 존재하지 않는 `eventId`를 인용하면 즉시 거부(`wrong_event_rejected: true`)합니다.
  - **제안과 집행의 분리**: AI 에이전트는 대응 조치를 **제안(Proposal)**만 할 수 있으며, 직접 차단 명령을 실행할 수 없습니다(`proposal_not_executed: true`).
  - **AI 활동 감사 로그**: AI가 언제, 어떤 케이스를, 어떤 근거(`eventId`)로 판정했는지 전수 기록합니다.

---

### 모듈 5. T-MAC 능동 대응(Active Response) & Human-in-the-Loop — *[19단계 + 2·6구간]*
- **4대 능동 대응 조치 카탈로그 (6구간 SKT T-MAC XDR 시연 반영)**:
  1. **공격 IP 차단 (`BLOCK_ATTACK_IP`)**: 위협이 확인된 외부 공격자 IP의 접근을 방화벽/에이전트 단에서 차단.
  2. **호스트 격리 (`ISOLate_HOST`)**: 악성코드 감염이 의심되는 엔드포인트의 네트워크 통신을 격리하여 내부 횡적 이동(Lateral Movement) 방지.
  3. **계정 비활성화 (`DISABLE_OS_ACCOUNT`)**: 비정상 활동이나 탈취 징후가 감지된 계정을 즉시 비활성화.
  4. **악성 프로세스 강제 종료 (`KILL_MALICIOUS_PROCESS`)**: 비인가 스크립트나 악성 프로세스 실행 즉시 종료.
- **부작용(Side Effect) 방지를 위한 4단계 상태 전이 (19단계 규격)**:
  - 인프라 가용성 저하 및 오작동으로 인한 업무 중단을 막기 위해 중요 조치는 반드시 **사람의 최종 승인(Human-in-the-Loop)**을 거치며 아래 4단계를 구분합니다:
    - `[1. 제안 (Proposed)]`: 탐지 룰 또는 SOC AI 에이전트가 대응 조치를 권고한 상태.
    - `[2. 확인 (Approved / Executing)]`: 관제사가 대상(`target`)과 사유를 검토하고 최종 승인을 누른 상태.
    - `[3. 접수 (Pending ACK)]`: 제어 서버가 조치 의도(`Intent`)를 접수하고 접수 번호(`receiptId`)를 발급한 상태.
    - `[4. 원천 확인 (Effect Verified)]`: 실제 방화벽/엔드포인트 집행기에서 차단이 적용(`effectApplied: true`)되었는지 확인된 상태. 원천 집행기가 연결되지 않은 연습 환경에서는 거짓으로 완료 처리하지 않고 **`⚠ 원천 집행 미연동 (접수만 완료)`** 배지를 명확히 표시합니다.

---

### 모듈 6. CTI & 공급망(SBOM/OSV) 취약점 상시 관리 — *[20단계 + 2·3구간]*
- **`package-lock.json` 정확 버전 고정 (`exact_lock_version`)**:
  - `package.json`의 범위 표기(`^`, `~`)가 아닌 `package-lock.json`에 실제 설치된 정확한 버전으로 SBOM 인벤토리를 생성합니다.
- **OSV 취약점 대조 및 3상태 판정**:
  - `vulnerable`(취약점 존재), `none_found`(알려진 취약점 없음), `unverifiable`(오프라인/조회 불가)로 투명하게 분류합니다.
  - 이전 조회 응답이 뒤늦게 도착하여 최신 화면을 덮어쓰는 현상(Stale Response)을 요청 순번(`requestSeq`)으로 완벽히 차단합니다.

---

### 모듈 7. 멀티 테넌트 SQLite 영속성 & 무결성 백업 — *[21단계 + 1·2·6구간]*
- **내장 `node:sqlite` 기반 6대 핵심 테이블**:
  1. `tenants`: 중소·중견기업 멀티 테넌트 격리 정보 (`tenant_id`, `name`, `compliance_tier`)
  2. `security_events`: 수집된 원시 이벤트/로그 (`event_id`, `tenant_id`, `category`, `severity`, `mitre_tactic`, `mitre_technique`, `payload_json`, `occurred_at`)
  3. `xdr_cases`: 상관분석으로 발행된 케이스 (`case_id`, `tenant_id`, `title`, `severity`, `verdict_status`, `mttd_ms`, `mttr_ms`, `created_at`, `resolved_at`)
  4. `ai_audit_logs`: SOC AI 에이전트 1차 판정 및 근거 고정 감사 이력 (`audit_id`, `case_id`, `ai_label`, `cited_event_ids`, `guardrail_status`, `created_at`)
  5. `soar_actions`: 능동 대응 4대 조치 승인·접수·원천 집행 이력 (`action_id`, `case_id`, `action_type`, `target`, `stage`, `approved_by`, `effect_applied`, `updated_at`)
  6. `policy_audits`: Windows 로컬 보안 정책 수동 vs 자동 상시 실증 이력 (`audit_id`, `hostname`, `manual_json`, `auto_json`, `mismatch_count`, `checked_at`)
- **안전한 백업 및 복원**:
  - 파일 헤더(`SQLite format 3\0`) 검증을 통과한 유효한 백업만 복원하며, 손상된 파일 투입 시 기존 DB를 보호하고 즉시 거부합니다.

---

### 모듈 8. 클라우드 XDR 통합 대시보드 & 에이전트 UI 설계 — *[22단계 + 노션 대시보드 레퍼런스]*
- **화면 1: 클라우드 XDR 통합 관제 콘솔 (`/dashboard`) — *노션 클라우드XDR대시보드 구조 반영***
  1. **상단 글로벌 바**: 멀티 테넌트 선택기(`Tenant A`, `Tenant B`), 실시간 MTTD / MTTR 지표 카운터, AI 게이트웨이 상태 배지.
  2. **심각도 & 위협 통계 요약 행**: `Critical` / `High` / `Medium` / `Low` 건수 카드 및 시간대별 이벤트 추이.
  3. **MITRE ATT&CK 매트릭스 히트맵 뷰**: Tactic(전술) 열 × Technique(기법) 셀로 구성된 매트릭스에서 현재 탐지된 공격 기법 하이라이트.
  4. **케이스(Case) & SOC AI 에이전트 분석 패널**:
     - 발행된 케이스 목록, AI 1차 판정 배지(`정탐 유력` / `오탐 유력` / `판단 보류`), 인용된 `eventId` 근거 링크, 관제사 룰 튜닝(정탐/오탐 확정) 버튼.
  5. **능동 대응(Active Response) 컨트롤 & 감사 로그 드로어**:
     - 4대 조치(`공격 IP 차단`, `호스트 격리`, `계정 비활성화`, `악성 프로세스 강제 종료`) 선택, Human-in-the-Loop 최종 승인 버튼, 4단계 상태 게이지(`제안 ➔ 확인 ➔ 접수 ➔ 원천 확인`), AI 및 차단 감사 로그 테이블.
- **화면 2: 엔드포인트 보안 에이전트 (`/agent`) — *`bankhar_b` 기록 타임라인형 계승***
  1. **상단 타원형 알약 필터 칩 (`[전체] [주의] [확인 불가]`) + 시각순 1줄 스택 피드**.
  2. **내 PC 자원·보안 상시 실증 카드** + **Windows 로컬 보안 정책(수동 vs 자동) 비교 탭**.
  3. **CSP(`style-src 'self'`) 100% 준수**: 모든 스타일은 외부 CSS 파일로 일원화하고 인라인 스타일을 완전히 배제.

---

## 5. 단계별 구현 로드맵 (신규 프로젝트 초기화 ~ 패키징)

### Phase 0: 프로젝트 저장소(`JW-XDR`) 초기화 및 아키텍처 매핑 (Day 1 오전)
- 독립 디렉토리(`JW-XDR/`) 및 Git 저장소 초기화 (`git init`, `npm init`).
- `README.md`에 **통합 XDR 프로젝트(`JW-XDR`)**임을 명시하고 아키텍처 다이어그램 수록.

### Phase 1: 코어 스키마 및 ZTNA + SIEM/XDR 탐지 엔진 구축 (Day 1 오후 ~ Day 2)
- `node:sqlite` 6대 테이블 스키마 작성 및 멀티 테넌트 시드 데이터 구성.
- 13~14단계 ZTNA `decide(request)` 4상태 판정기 및 15단계 6대 위협 × MITRE ATT&CK 매핑 엔진 구현.
- 케이스(Case) 자동 발행 및 MTTD/MTTR 산출 로직 구현.

### Phase 2: Windows 상시 실증 진단기 & SBOM/OSV 스캐너 구축 (Day 3)
- 4~5구간 실습을 반영한 읽기 전용 `windows-policy-audit.bat` (`reg query`, `secedit /export`) 및 결과 파서 구현.
- 수동 점검 체크리스트 입력값과 자동 진단 결과를 비교하여 인적 오류(누락·오판)를 검출하는 API 구현.
- 20단계 `package-lock.json` 기반 SBOM 추출 및 OSV 취약점 조회기(Stale 차단 포함) 구현.

### Phase 3: SOC AI 에이전트(ISO 42001) & T-MAC 능동 대응(SOAR) 구축 (Day 4)
- 17~18단계 AI 게이트웨이 7종 복구 안내 및 케이스 1차 정탐/오탐/판단보류 분류 에이전트 구현 (`eventId` 근거 고정 강제).
- 19단계 + 6구간 4대 능동 대응(`IP 차단`, `호스트 격리`, `계정 비활성화`, `프로세스 종료`) 및 Human-in-the-Loop 4단계 승인 전이 구현.

### Phase 4: 클라우드 XDR 대시보드 & 엔드포인트 에이전트 UI 통합 (Day 5)
- 노션 클라우드 XDR 대시보드 레퍼런스를 반영한 관제 콘솔(`/dashboard`)과 기록 타임라인형 에이전트(`/agent`) UI 구축.
- 엄격한 CSP(`style-src 'self'; script-src 'self'`) 준수 및 반응형 2열 레이아웃 적용.

### Phase 5: 자기 점검 스위트, 백업 무결성 검증 및 포터블 패키징 (Day 6)
- 전체 요구사항을 자동 검증하는 `npm test` 스위트 작성.
- 4자 분리 런북(`ARCHITECTURE_RUNBOOK.md`) 및 원클릭 실행기(`run-jw-xdr.bat`) 패키징 완료.
