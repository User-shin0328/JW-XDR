# 🛡️ 통합 보안 관제 및 능동 대응 플랫폼 (`JW-XDR`)

> *"본 시스템은 ① 제로 트러스트 접근 제어(ZTNA), ② SIEM/XDR 실시간 로그 상관분석 및 MITRE ATT&CK 매핑, ③ Windows 로컬 보안 정책 수동·자동 상시 실증, ④ ISO 42001 기반 SOC AI 에이전트 1차 정탐/오탐 분석, ⑤ 5중 안전장치 기반 Human-in-the-Loop 능동 대응(Active Response 4대 조치)을 통합 구현한 로컬 호스트 XDR 플랫폼(`JW-XDR`)입니다."*

---

## 1. 프로젝트 개요 및 아키텍처

파편화된 **EDR(엔드포인트) + NDR(네트워크 소켓) + SIEM(상관분석) + SOAR(능동 대응) + ZTNA(제로 트러스트)**를 단일 **통합 관제 대시보드(`JW-XDR`)**와 **엔드포인트 에이전트(`bankhar-agent`)**로 통합한 독립 프로젝트입니다.

```mermaid
flowchart TB
  subgraph Endpoint["1. 엔드포인트 영역 (Endpoint Agent & Local Audit)"]
    AgentUI["에이전트 UI (/agent)\n[전체/주의/확인불가 타임라인 & 자원 실측]"]
    WinAudit["Windows 상시 실증 수집기 (Read-Only)\n[wevtutil / reg query / net accounts 파서]"]
  end

  subgraph ControlPlane["2. XDR 제어 및 분석 영역 (JW-XDR Server)"]
    ZTNA["M1. ZTNA PDP 엔진\n(allow / deny / challenge / unknown)"]
    Detect["M2. SIEM/XDR 상관분석 & 케이스 엔진\n(6대 위협 + MITRE ATT&CK + MTTD/MTTR)"]
    AIGateway["M4. SOC AI 에이전트 (ISO 42001)\n(1차 정탐/오탐/판단보류 + 근거 고정)"]
    SBOM["M6. CTI & SBOM/OSV 취약점 엔진\n(exact_lock_version & Stale 차단)"]
    SQLite[("M7. node:sqlite 영속 저장소 (jw_xdr.db)\n(Cases / Events / Audits / Receipts)")]
  end

  subgraph Console["3. 관제사 콘솔 영역 (JW-XDR Dashboard /dashboard)"]
    DashUI["JW-XDR 통합 관제 대시보드\n(케이스 & 실시간 로그 / 네트워크 소켓 / 실행 프로세스 / 보안 정책 / 공급망 / SOAR)"]
    Approval["Human-in-the-Loop 승인 워크플로우\n(제안 ➔ 승인 ➔ 실제 원천 집행 ➔ 롤백)"]
  end

  subgraph Enforcer["4. 원천 집행 영역 (5중 안전장치 OS Enforcer)"]
    ActiveResp["M5. 능동 대응 4대 조치 집행기\n① 공격 IP 차단 (netsh + L7)  ② 호스트 안전 격리\n③ 계정 보호 잠금  ④ 프로세스 종료 (taskkill)"]
  end

  AgentUI -->|신원·기기·진단 보고| ZTNA
  WinAudit -->|실시간 이벤트 & 정책 증적| SQLite
  ZTNA -->|접근 로그 & 이상 징후| Detect
  Detect -->|케이스 발행| SQLite
  Detect -->|케이스 분석 요청| AIGateway
  AIGateway -->|정탐/오탐/보류 + 감사로그| SQLite
  SQLite <--> DashUI
  DashUI -->|관제사 최종 승인 (Intent)| Approval
  Approval -->|안전장치 검증 후 집행| ActiveResp
  ActiveResp -->|Receipt (effectApplied 여부)| SQLite
```

---

## 2. 노션 `CloudXDR` 스크린샷 기반 대시보드 구성 (`/dashboard/`)

- **멀티 테넌트 선택기 & 좌측 네비게이션**: `TEST Tenant`, `AppExKr IDC`, `CloudXDR Demo`, `NTMORE`, `System Default` 테넌트 전환 및 `대시보드 (케이스 / 보안 이벤트 / 취약점 / 컴플라이언스 / CSPM / NetFlow / CloudWAN / UEBA)` 메뉴 완벽 구현
- **New 케이스 목록 & 케이스 상세 2단 슬라이드오버 드로어**:
  - `기본 정보` 탭: `SOC Agent 분석 (판단 보류 / 정탐 유력 / 오탐 유력)` 배지, 케이스 메타데이터 그리드, **14단계 공격 단계(Kill Chain)** 하이라이트, **엔터티 관계 그래프**, 하단 고정 액션 바(`[✓ 인지] [⊗ 종결] [🛡️ 예외처리] [👤 할당]`)
  - `관련 이벤트` / `영향받은 자산` / `IOC 정보` 탭: 수집 이벤트(`eventId`), 영향 자산(`appex-svr01`), 침해지표(`SYSTEM_BLACKLIST`, `TLP:AMBER`) 조회
  - `보고서` 탭 & **AI 분석 리포트 생성 모달**: 한국어/영어, 조사/종결 리포트(종결 상태 검증), 민감정보 익명화 토글 및 **ISO 42001 `eventId` 근거 고정(환각·월권 차단)**
  - `활동 로그 · 능동 대응` 탭: **4대 능동 대응 조치(`공격 IP 차단`, `호스트 격리`, `계정 비활성화`, `악성 프로세스 강제 종료`)** 및 **4단계 승인 게이지(`제안 ➔ 확인 ➔ 접수(ACK) ➔ 원천 확인`)**
- **보안 이벤트 / 취약점 / 컴플라이언스 / CSPM / NetFlow / CloudWAN / UEBA 뷰**:
  - 시간별·일별 이벤트 트렌드, 도넛 차트, 취약한 패키지 Top 10 드로어 & `CVE 상세 정보` 모달, `package-lock.json` SBOM/OSV 3상태 대조
  - Windows 로컬 보안 정책(`secpol.msc` 수동 vs `windows-policy-audit.bat` 자동) 1:1 대조 및 인적 오류 검출
  - NetFlow 산키 다이어그램(Sankey) 및 우선순위 위협 IP 차단 제안, CloudWAN 대한민국 권역별 클러스터 맵
- **시스템 관리 > 테넌트 상세정보 드로어**:
  - `AI 서비스 연동` 탭(LightChat, 도메인, API Key 암호화 입력, 모델 38개 연결 테스트, 17단계 7종 장애 복구 안내, SOC Agent 폴링/긴급정지, 자산 중요도 문턱 기반 자동차단 vs 사람 승인 설정), `SOC Agent 활동` 탭, `차단 현황` 탭

---

## 3. 빠른 실행 및 검증 방법

```powershell
# 1. 전체 보안 게이트 자동 테스트 (M1 ~ M8)
npm test

# 2. 서버 실행 (http://127.0.0.1:5280)
npm start
# 또는 Windows 탐색기에서 run-jw-xdr.bat 실행
```
