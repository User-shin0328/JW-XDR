/**
 * JW-XDR Automated Self-Verification Suite (M1 ~ M8)
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { XdrSqliteStore } from '../src/db/sqlite-store.mjs';
import { decide } from '../src/ztna/decider.mjs';
import { evaluateAlert, THREAT_CATALOG } from '../src/xdr/detect-engine.mjs';
import { computeMttdMttrMetrics, ingestEventAndCorrelateCase, updateCaseVerdictAndTuneRule } from '../src/xdr/case-manager.mjs';
import { compareManualVsAutoPolicy, redactSensitiveDiagnostics } from '../src/xdr/win-policy-parser.mjs';
import { checkAiGatewayHealth, AI_RECOVERY_GUIDES } from '../src/ai/ai-gateway.mjs';
import { analyzeCaseWithSocAgent } from '../src/ai/soc-triage-agent.mjs';
import { proposeActiveResponse, transitionSoarActionStage } from '../src/soar/active-response.mjs';
import { scanLockfileSbom } from '../src/cti/sbom-osv-scanner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');
const TEST_DB_PATH = path.join(ROOT_DIR, 'data', 'test_verification.db');

if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);
const store = new XdrSqliteStore(TEST_DB_PATH);

console.log('======================================================================');
console.log(' 🧪 [JW-XDR] 전체 보안 게이트 통합 자동 검증 스위트 (M1 ~ M8)');
console.log('======================================================================');

// 1. M1 (13~14단계 + 2·3구간): ZTNA 4상태 판정 (allow / deny / challenge / unknown)
{
  const allowRes = decide({ sub: 'analyst@skt.kr', deviceRegistered: true, stepUp: true, path: '/dashboard', signals: [] });
  assert.equal(allowRes.decision, 'allow');

  const denyDevRes = decide({ sub: 'user@skt.kr', deviceRegistered: false, stepUp: true, path: '/dashboard' });
  assert.equal(denyDevRes.decision, 'deny');

  const challengeRes = decide({ sub: 'user@skt.kr', deviceRegistered: true, stepUp: false, path: '/soar/execute' });
  assert.equal(challengeRes.decision, 'challenge');

  const unknownRes = decide({ sub: 'user@skt.kr', deviceRegistered: null, telemetryUnavailable: true });
  assert.equal(unknownRes.decision, 'unknown');
  assert.notEqual(unknownRes.decision, 'allow', '원천 신호 누락 시 절대 allow로 통과되면 안 됨');

  console.log(' [PASS] M1 (13~14단계): ZTNA 3단 분리 및 4상태(allow/deny/challenge/unknown) 판정 검증 완료');
}

// 2. M2 (15단계 + 1·4·6구간): 6대 위협 시나리오 × MITRE ATT&CK 매핑 및 MTTD/MTTR 산출
{
  const categories = Object.keys(THREAT_CATALOG);
  assert.equal(categories.length, 6);
  for (const cat of categories) {
    const res = evaluateAlert({ category: cat, failCount: 15, query: 'UNION SELECT', exploit: 'CVE-2026-74705', reg: 'CurrentVersion\\Run', cmd: 'pkexec', bytesOut: 250000 });
    assert.equal(res.action, 'block');
    assert.ok(res.mitreTactic.includes('TA00'));
  }

  const newCase = ingestEventAndCorrelateCase(store, {
    category: 'web-injection',
    query: "1' OR 1=1--",
    srcIp: '203.0.113.55'
  });
  assert.ok(newCase.case_id);
  assert.ok(newCase.mttd_ms > 0);

  const tuned = updateCaseVerdictAndTuneRule(store, newCase.case_id, {
    verdictStatus: 'TRUE_POSITIVE',
    status: 'Acknowledged',
    ruleTuningNote: 'SQLi 정탐 확정'
  });
  assert.equal(tuned.verdict_status, 'TRUE_POSITIVE');
  assert.ok(tuned.mttr_ms > 0);

  const metrics = computeMttdMttrMetrics(store.getCases());
  assert.ok(metrics.avgMttdMs > 0 && metrics.avgMttrMs > 0);
  console.log(' [PASS] M2 (15단계 + 1·6구간): 6대 위협 MITRE 매핑, 케이스 발행, 룰 튜닝 및 MTTD/MTTR 산출 완료');
}

// 3. M3 (16단계 + 3·4·5구간): Windows 로컬 보안 정책 수동 vs 자동 비교 및 민감정보 마스킹
{
  const policyComp = compareManualVsAutoPolicy();
  assert.equal(policyComp.totalItems, 8);
  assert.ok(policyComp.mismatchCount >= 1, '수동 점검 인적 오류(불일치) 검출 작동 확인');

  const redacted = redactSensitiveDiagnostics({
    hostname: 'WIN11-PC',
    apiKey: 'sk-secret-key-123456789',
    authHeader: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
  });
  assert.equal(redacted.apiKey, '[REDACTED]');
  assert.equal(redacted.authHeader, 'Bearer [REDACTED]');
  console.log(' [PASS] M3 (16단계 + 4·5구간): Windows 보안 정책(secpol vs secedit/reg) 비교 및 [REDACTED] 마스킹 완료');
}

// 4. M4 (17~18단계 + 1·3·6구간): AI 게이트웨이 7종 복구 안내 & ISO 42001 근거 고정(Evidence Binding)
{
  const guideKeys = Object.keys(AI_RECOVERY_GUIDES);
  assert.equal(guideKeys.length, 7);
  for (const key of guideKeys) {
    const h = checkAiGatewayHealth({ scenario: key });
    assert.equal(h.ok, false);
    assert.ok(h.error.recoveryGuide.startsWith('복구 안내:'));
  }

  const validTriage = analyzeCaseWithSocAgent(store, { caseId: 'CASE-HOST-POLICY-01', anonymize: true });
  assert.equal(validTriage.ok, true);
  assert.equal(validTriage.wrong_event_rejected, false);
  assert.equal(validTriage.proposal_not_executed, true);

  const hallucinatedTriage = analyzeCaseWithSocAgent(store, { caseId: 'CASE-HOST-POLICY-01', simulateHallucinatedEventId: true });
  assert.equal(hallucinatedTriage.ok, false);
  assert.equal(hallucinatedTriage.wrong_event_rejected, true);

  const overreachTriage = analyzeCaseWithSocAgent(store, { caseId: 'CASE-HOST-POLICY-01', simulateAlreadyExecutedClaim: true });
  assert.equal(overreachTriage.ok, false);
  assert.equal(overreachTriage.proposal_not_executed, true);
  console.log(' [PASS] M4 (17~18단계 + ISO 42001): 7종 AI 장애 복구 안내, eventId 근거 고정 및 환각·월권 차단 완료');
}

// 5. M5 (19단계 + 2·6구간): 4대 능동 대응 및 Human-in-the-Loop 4단계 전이 (원천 집행 분리)
{
  const prop = proposeActiveResponse(store, {
    caseId: 'CASE-SBOM-LOCK-01',
    actionType: 'BLOCK_ATTACK_IP',
    target: '198.51.100.77'
  });
  assert.equal(prop.ok, true);
  assert.equal(prop.action.stage, 'PROPOSED');

  // 원천 집행기 미연결(enforcerConnected: false) 상태에서 EFFECT_VERIFIED 요청 시 거짓 성공 금지!
  const transUnlinked = transitionSoarActionStage(store, {
    actionId: prop.action.action_id,
    nextStage: 'EFFECT_VERIFIED',
    enforcerConnected: false
  });
  assert.equal(transUnlinked.effectApplied, false);
  assert.equal(transUnlinked.action.stage, 'PENDING_ACK');
  assert.ok(transUnlinked.badgeText.includes('원천 집행 미연동'));
  console.log(' [PASS] M5 (19단계 + 6구간): 4대 능동 대응, 인간 승인 전이 및 원천 집행 미연동 정직 분리 완료');
}

// 6. M6 (20단계): package-lock.json 정확 버전(exact_lock_version) 및 OSV 3상태 분리
{
  const sbom = scanLockfileSbom({ requestSeq: 7 });
  assert.equal(sbom.exactLockVersionVerified, true);
  assert.equal(sbom.requestSeq, 7);
  assert.ok(sbom.counts.vulnerable >= 1);
  assert.ok(sbom.counts.none_found >= 1);
  assert.ok(sbom.counts.unverifiable >= 1);
  console.log(' [PASS] M6 (20단계): package-lock.json 정확 버전 고정 및 OSV 3상태(vulnerable/none_found/unverifiable) 완료');
}

// 7. M7 (21단계): SQLite 헤더 검증 백업 및 손상된 파일 복원 거부
{
  const backupRes = store.createBackup('unit_test');
  assert.equal(backupRes.ok, true);
  assert.equal(backupRes.headerVerified, true);
  const fullBackupPath = path.join(ROOT_DIR, 'backup', backupRes.backupFile);
  if (fs.existsSync(fullBackupPath)) fs.unlinkSync(fullBackupPath);

  const corruptRes = store.restoreFromBackup(Buffer.from('INVALID_HEADER_NOT_SQLITE_3_0000000000000000000000000000000000000000000000000000000000000000000000000'));
  assert.equal(corruptRes.ok, false);
  assert.equal(corruptRes.preservedExistingDb, true);
  console.log(' [PASS] M7 (21단계): node:sqlite 무결성 백업 및 손상 헤더 복원 거부(기존 DB 보호) 완료');
}

// 8. M8 (22단계): CSP(style-src 'self') 준수 — HTML/MJS 내 인라인 style="" 속성 제로 검증
{
  const filesToCheck = [
    path.join(ROOT_DIR, 'public/dashboard/index.html'),
    path.join(ROOT_DIR, 'public/dashboard/dashboard.mjs'),
    path.join(ROOT_DIR, 'public/agent/index.html'),
    path.join(ROOT_DIR, 'public/agent/agent.mjs')
  ];
  for (const f of filesToCheck) {
    const content = fs.readFileSync(f, 'utf8');
    assert.equal(/\sstyle\s*=\s*["']/i.test(content), false, `인라인 style 속성이 발견되었습니다: ${f}`);
  }
  console.log(' [PASS] M8 (22단계): 대시보드(/dashboard) 및 에이전트(/agent) CSP(style-src \'self\') 100% 준수 완료');
}

store.db.close();
if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);

console.log('======================================================================');
console.log(' 🎉 모든 보안 게이트(M1 ~ M8) 자동 검증을 100% 통과했습니다!');
console.log('======================================================================');
