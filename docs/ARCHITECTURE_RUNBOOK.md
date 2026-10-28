# 🏛️ 4자 분리(4-Plane) 아키텍처 및 운영·복구 런북 (`ARCHITECTURE_RUNBOOK.md`)

> **문서 목적**:
> 본 문서는 `JW-XDR` 플랫폼의 4자 분리 구조, 실행 환경, 장애 복구 가이드 및 `node:sqlite` 무결성 백업·복원 절차를 정의합니다.

---

## 1. 실행 환경 사양 및 재현 절차

- **운영체제**: Windows 11 (24H2 권장) / 크로스 플랫폼 호환
- **런타임**: Node.js `v22.5.0` 이상 (`v24.19.0` 권장 — 내장 `node:sqlite`, `node:http` 사용, 외부 npm 의존성 0개)
- **기본 포트**: `5280` (`PORT` 환경 변수로 변경 가능)

### 1.1 실행 및 자동 검증 명령어
```powershell
# 1. 전체 보안 게이트 자동 검증 (M1 ~ M8)
npm test

# 2. 문법 및 정적 무결성 점검
npm run check

# 3. 통합 XDR 서버 기동 (JW-XDR 대시보드 + 엔드포인트 에이전트)
npm start
# 또는 run-jw-xdr.bat 더블클릭
```

- **관제사 콘솔 (JW-XDR 대시보드)**: `http://127.0.0.1:5280/dashboard/`
- **엔드포인트 에이전트 (bankhar-agent)**: `http://127.0.0.1:5280/agent/`

---

## 2. 4자 분리(4-Plane) 멀티 테넌트 아키텍처

1. **Plane 1 — 엔드포인트 영역 (`/agent` & `scripts/windows-policy-audit.bat`)**:
   - 브라우저 일반 권한으로 측정 가능한 지표(논리 CPU 코어, JS 힙, 스토리지 쿼터)와 샌드박스 제한으로 조회 불가능한 항목(`? 확인 불가`)을 엄격히 분리합니다.
   - `reg query` 및 `secedit /export` 읽기 전용 파서를 통해 `secpol.msc` 수동 점검 대비 인적 오류(불일치)를 상시 실증합니다.
2. **Plane 2 — XDR 제어 및 상관분석 서버 (`src/server.mjs`, `src/ztna/`, `src/xdr/`)**:
   - 4상태 ZTNA PDP(`allow`/`deny`/`challenge`/`unknown`) 및 6대 공격 시나리오 × MITRE ATT&CK 매핑, 케이스(Case) 상관분석 발행, MTTD/MTTR 자동 계측을 수행합니다.
3. **Plane 3 — ISO 42001 SOC AI 게이트웨이 (`src/ai/`)**:
   - 발행된 케이스의 1차 `정탐 유력` / `오탐 유력` / `판단 보류` 라벨링을 수행합니다.
   - 실제 수집된 `eventId`만 인용하도록 강제(`Evidence Binding`)하며, 존재하지 않는 이벤트 인용(`wrong_event_rejected`)이나 AI의 직접 실행 주장(`proposal_not_executed`)을 즉시 차단합니다.
4. **Plane 4 — 원천 집행 영역 (`src/soar/active-response.mjs`)**:
   - 4대 능동 대응(`BLOCK_ATTACK_IP`, `ISOLATE_HOST`, `DISABLE_OS_ACCOUNT`, `KILL_MALICIOUS_PROCESS`)의 4단계 상태(`제안 ➔ 확인 ➔ 접수(ACK) ➔ 원천 확인`)를 분리합니다.
   - 실제 원천 방화벽/호스트 집행기가 미연결된 상태에서는 거짓으로 완료 처리하지 않고 **`⚠ 원천 집행 미연동 (접수만 완료)`** 배지를 표시합니다.

---

## 3. SQLite 무결성 백업 및 복원 절차

- **대상 데이터베이스**: `data/jw_xdr.db` (`tenants`, `security_events`, `xdr_cases`, `ai_audit_logs`, `soar_actions`, `policy_audits` 6대 테이블)
- **백업 저장 위치**: `backup/jw_xdr_<label>_<timestamp>.db`
- **복원 무결성 검증 규칙**:
  1. 일반 정규 파일 여부 확인 (심볼릭 링크 거부)
  2. 첫 16바이트가 `SQLite format 3\0` 시그니처와 정확히 일치하는지 검증
  3. 손상된 헤더 파일 투입 시 기존 DB 연결을 보존하고 즉시 거부(`INVALID_SQLITE_HEADER`)
