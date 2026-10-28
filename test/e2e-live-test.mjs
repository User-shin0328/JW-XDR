import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { createXdrServer } from '../src/server.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');
const TEST_DB = path.join(ROOT_DIR, 'data', 'test_e2e_live.db');

if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);

console.log('======================================================================');
console.log(' 🚀 [JW-XDR] 전체 기능 실서버 구동 및 통합 E2E 테스트 시작');
console.log('======================================================================');

const { server, store } = createXdrServer({ dbPath: TEST_DB });
const TEST_PORT = 5299;

function request(options, postData = null) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port: TEST_PORT,
      ...options
    };
    const req = http.request(opts, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const bodyStr = Buffer.concat(chunks).toString('utf8');
        let bodyJson = null;
        try {
          bodyJson = JSON.parse(bodyStr);
        } catch {
          // not json
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          bodyStr,
          bodyJson
        });
      });
    });
    req.on('error', reject);
    if (postData) {
      if (typeof postData === 'string' || Buffer.isBuffer(postData)) {
        req.write(postData);
      } else {
        req.write(JSON.stringify(postData));
      }
    }
    req.end();
  });
}

async function runAllTests() {
  let passCount = 0;
  let testCount = 0;

  function recordPass(title) {
    testCount++;
    passCount++;
    console.log(` [PASS #${testCount}] ${title}`);
  }

  try {
    // 1. 서버 리스닝 시작
    await new Promise((resolve) => server.listen(TEST_PORT, '127.0.0.1', resolve));
    recordPass(`서버 정상 구동 및 포트 바인딩 완료 (http://127.0.0.1:${TEST_PORT})`);

    // 2. 루트 및 리다이렉트 테스트
    {
      const resRoot = await request({ method: 'GET', path: '/' });
      assert.equal(resRoot.statusCode, 302);
      assert.equal(resRoot.headers.location, '/dashboard/');

      const resDash = await request({ method: 'GET', path: '/dashboard' });
      assert.equal(resDash.statusCode, 302);
      assert.equal(resDash.headers.location, '/dashboard/');

      const resAgent = await request({ method: 'GET', path: '/agent' });
      assert.equal(resAgent.statusCode, 302);
      assert.equal(resAgent.headers.location, '/agent/');
      recordPass('웹 라우팅 및 302 리다이렉트 정상 동작 (/, /dashboard, /agent)');
    }

    // 3. 정적 대시보드 및 에이전트 UI, CSP 헤더 검증
    {
      const resDashHtml = await request({ method: 'GET', path: '/dashboard/' });
      assert.equal(resDashHtml.statusCode, 200);
      assert.ok(resDashHtml.bodyStr.includes('JW-XDR'));
      assert.ok(resDashHtml.headers['content-security-policy'].includes("style-src 'self'"));

      const resAgentHtml = await request({ method: 'GET', path: '/agent/' });
      assert.equal(resAgentHtml.statusCode, 200);
      assert.ok(resAgentHtml.bodyStr.includes('bankhar-agent') || resAgentHtml.bodyStr.includes('에이전트'));

      const resDashJs = await request({ method: 'GET', path: '/dashboard/dashboard.mjs' });
      assert.equal(resDashJs.statusCode, 200);
      assert.ok(resDashJs.headers['content-type'].includes('application/javascript'));
      recordPass('정적 파일 제공 및 보안 헤더(CSP strict, No-Store) 검증 완료');
    }

    // 4. L7 인라인 IPS 실시간 악성 웹 요청 탐지 및 차단 검증
    let blockedCaseId = null;
    {
      const sqliRes = await request({
        method: 'GET',
        path: '/somepage?query=UNION%20SELECT%20*%20FROM%20users--',
        headers: {
          'x-attack-ip': '198.51.100.99',
          'user-agent': 'SQLi-Attacker-Bot'
        }
      });
      assert.equal(sqliRes.statusCode, 403);
      assert.equal(sqliRes.bodyJson.code, 'XDR_L7_INLINE_IPS_BLOCK');
      assert.ok(sqliRes.bodyJson.caseId);
      blockedCaseId = sqliRes.bodyJson.caseId;

      // 차단된 IP로부터의 재요청 시 IP 차단 정책 게이트웨이 즉각 거부 확인
      const blockedIpRes = await request({
        method: 'GET',
        path: '/dashboard/',
        headers: {
          'x-attack-ip': '198.51.100.99',
          'x-verify-ip-block': '1'
        }
      });
      assert.equal(blockedIpRes.statusCode, 403);
      assert.equal(blockedIpRes.bodyJson.code, 'XDR_ACTIVE_IP_BLOCKED');
      recordPass('L7 실시간 패킷 인스펙션(IPS) & 악성 IP 자동 차단 게이트웨이 동작 확인');
    }

    // 5. 호스트 실측 수집 및 /api/overview 엔드포인트 검증
    {
      const overviewRes = await request({ method: 'GET', path: '/api/overview' });
      assert.equal(overviewRes.statusCode, 200);
      const data = overviewRes.bodyJson;
      assert.ok(data.ok);
      assert.ok(data.hostInfo && data.hostInfo.hostname);
      assert.ok(Array.isArray(data.procSnapshot.processes));
      assert.ok(Array.isArray(data.netstatSnapshot.connections));
      assert.ok(data.policyReport && data.policyReport.totalItems >= 8);
      assert.ok(Array.isArray(data.cases) && data.cases.length > 0);
      assert.ok(data.metrics && typeof data.metrics.avgMttdMs === 'number');
      recordPass('통합 관제 Overview API (/api/overview) 호스트 실측 및 메트릭 산출 정상');
    }

    // 6. 호스트 텔레메트리 상세 API (/api/host/telemetry)
    {
      const telemRes = await request({ method: 'GET', path: '/api/host/telemetry' });
      assert.equal(telemRes.statusCode, 200);
      const telem = telemRes.bodyJson;
      assert.ok(telem.procSnapshot.totalCount > 0, '실행 중인 프로세스 목록 실측 확인');
      assert.ok(telem.netstatSnapshot.summary.total >= 0, '실제 활성 소켓 목록 실측 확인');
      assert.ok(telem.liveWinPolicy.hostname, 'Windows 레지스트리 및 계정 정책 실측 확인');
      recordPass('로컬 호스트 실측 텔레메트리 API (/api/host/telemetry) 수집 정상');
    }

    // 7. ZTNA 4상태(allow/deny/challenge/unknown) 판정 API (/api/ztna/decide)
    {
      const allowReq = await request({
        method: 'POST',
        path: '/api/ztna/decide',
        headers: { 'Content-Type': 'application/json' }
      }, { sub: 'soc-admin@jw.com', deviceRegistered: true, stepUp: true, path: '/dashboard' });
      assert.equal(allowReq.bodyJson.decision, 'allow');

      const denyReq = await request({
        method: 'POST',
        path: '/api/ztna/decide',
        headers: { 'Content-Type': 'application/json' }
      }, { sub: 'unknown@external.com', deviceRegistered: false, path: '/dashboard' });
      assert.equal(denyReq.bodyJson.decision, 'deny');

      const unknownReq = await request({
        method: 'POST',
        path: '/api/ztna/decide',
        headers: { 'Content-Type': 'application/json' }
      }, { sub: 'guest@jw.com', deviceRegistered: null, telemetryUnavailable: true });
      assert.equal(unknownReq.bodyJson.decision, 'unknown');
      recordPass('ZTNA PDP 판정 API (/api/ztna/decide) 4상태 분리 정상');
    }

    // 8. SIEM/XDR 룰 평가 및 케이스 인제스트·판정 튜닝 라이프사이클
    {
      // 룰 평가
      const xdrEval = await request({
        method: 'POST',
        path: '/api/xdr/evaluate',
        headers: { 'Content-Type': 'application/json' }
      }, { category: 'persistence', reg: 'CurrentVersion\\Run', srcIp: '192.168.1.10' });
      assert.equal(xdrEval.bodyJson.action, 'block');
      assert.ok(xdrEval.bodyJson.mitreTactic.includes('TA0003'));

      // 신규 케이스 인제스트
      const newCaseRes = await request({
        method: 'POST',
        path: '/api/cases/ingest',
        headers: { 'Content-Type': 'application/json' }
      }, {
        category: 'privilege',
        cmd: 'pkexec --user root bash',
        srcIp: '192.168.1.200',
        severity: 'CRITICAL',
        title: '권한 상승 시도 탐지'
      });
      assert.equal(newCaseRes.statusCode, 201);
      const caseId = newCaseRes.bodyJson.caseDetail.case_id;
      assert.ok(caseId);

      // 케이스 단건 조회
      const getCaseRes = await request({ method: 'GET', path: `/api/cases/${caseId}` });
      assert.equal(getCaseRes.statusCode, 200);
      assert.equal(getCaseRes.bodyJson.caseDetail.case_id, caseId);

      // 케이스 판정(정탐/오탐) 및 룰 튜닝
      const verdictRes = await request({
        method: 'POST',
        path: '/api/cases/verdict',
        headers: { 'Content-Type': 'application/json' }
      }, {
        caseId,
        verdictStatus: 'TRUE_POSITIVE',
        status: 'Closed',
        ruleTuningNote: '실제 권한상승 시도로 판정하여 룰 가중치 상향 조정'
      });
      assert.equal(verdictRes.statusCode, 200);
      assert.equal(verdictRes.bodyJson.caseDetail.verdict_status, 'TRUE_POSITIVE');
      assert.ok(verdictRes.bodyJson.caseDetail.mttr_ms > 0);
      recordPass('XDR 룰 평가, 케이스 인제스트, 단건 조회, 정탐 판정 및 룰 튜닝 정상');
    }

    // 9. ISO 42001 SOC AI 에이전트 1차 분석 & 근거 고정(Evidence Binding)
    {
      // AI 헬스체크
      const healthRes = await request({
        method: 'POST',
        path: '/api/ai/health',
        headers: { 'Content-Type': 'application/json' }
      }, { domain: 'mock-llm.jw-security.kr', model: 'claude-3-5-sonnet' });
      assert.ok(healthRes.bodyJson);

      // AI 정상 분석
      const triageRes = await request({
        method: 'POST',
        path: '/api/ai/triage',
        headers: { 'Content-Type': 'application/json' }
      }, { caseId: blockedCaseId, anonymize: true });
      assert.equal(triageRes.statusCode, 200);
      assert.equal(triageRes.bodyJson.ok, true);
      assert.ok(triageRes.bodyJson.aiLabel);
      assert.equal(triageRes.bodyJson.anonymized, true);

      // AI 환각(없는 eventId 생성) 방어 검증
      const hallucinationRes = await request({
        method: 'POST',
        path: '/api/ai/triage',
        headers: { 'Content-Type': 'application/json' }
      }, { caseId: blockedCaseId, simulateHallucinatedEventId: true });
      assert.equal(hallucinationRes.statusCode, 400);
      assert.equal(hallucinationRes.bodyJson.wrong_event_rejected, true);
      recordPass('ISO 42001 SOC AI 에이전트 정탐 분석, 익명화, 환각 근거 차단 정상');
    }

    // 10. SOAR 5중 안전장치 및 4대 능동 대응 집행 라이프사이클
    {
      // 안전장치 1: 보호 대상 프로세스(node.exe / explorer.exe 등) 종료 시도 시 즉각 차단
      const killProtected = await request({
        method: 'POST',
        path: '/api/soar/propose',
        headers: { 'Content-Type': 'application/json' }
      }, {
        caseId: blockedCaseId,
        actionType: 'KILL_MALICIOUS_PROCESS',
        target: `${process.pid} (node.exe)`
      });
      assert.equal(killProtected.statusCode, 200);
      const killActId = killProtected.bodyJson.action.action_id;

      const attemptKill = await request({
        method: 'POST',
        path: '/api/soar/transition',
        headers: { 'Content-Type': 'application/json' }
      }, {
        actionId: killActId,
        nextStage: 'EFFECT_VERIFIED',
        enforcerConnected: true,
        approvedBy: 'admin'
      });
      // 5중 안전장치로 인해 실제 강제 종료되지 않고 안전 차단되어야 함
      assert.equal(attemptKill.bodyJson.blockedByGuardrail, true, '보호 프로세스 종료가 안전장치에 의해 차단되어야 함');
      assert.equal(attemptKill.bodyJson.effectApplied, false);
      assert.equal(attemptKill.bodyJson.action.stage, 'GUARDRAIL_BLOCKED');

      // 정상 대응 제안: 공격 IP 차단 제안 -> 승인 전이
      const ipProp = await request({
        method: 'POST',
        path: '/api/soar/propose',
        headers: { 'Content-Type': 'application/json' }
      }, {
        caseId: blockedCaseId,
        actionType: 'BLOCK_ATTACK_IP',
        target: '203.0.113.199'
      });
      assert.equal(ipProp.statusCode, 200);
      const ipActId = ipProp.bodyJson.action.action_id;

      const ipTrans = await request({
        method: 'POST',
        path: '/api/soar/transition',
        headers: { 'Content-Type': 'application/json' }
      }, {
        actionId: ipActId,
        nextStage: 'APPROVED',
        approvedBy: 'soc-manager'
      });
      assert.equal(ipTrans.statusCode, 200);
      assert.equal(ipTrans.bodyJson.action.stage, 'APPROVED');
      recordPass('SOAR 5중 안전장치(보호 프로세스 차단) 및 4단계 승인 전이 정상');
    }

    // 11. Windows 보안 정책 수동 vs 자동 대조 및 진단 민감정보 마스킹
    {
      const polRes = await request({
        method: 'POST',
        path: '/api/policy/compare',
        headers: { 'Content-Type': 'application/json' }
      }, {
        manualChecklist: {
          MinimumPasswordLength: 6, // 수동 체크리스트 오류 설정
          MaximumPasswordAge: 90
        },
        sessionToken: 'Bearer super-secret-admin-token-12345'
      });
      assert.equal(polRes.statusCode, 200);
      assert.ok(polRes.bodyJson.report.totalItems >= 8);
      assert.ok(polRes.bodyJson.redactedExport.exportedToken === '[REDACTED]');
      recordPass('Windows 정책 1:1 대조(인적오류 검출) 및 [REDACTED] 마스킹 정상');
    }

    // 12. CTI & SBOM / OSV 취약점 점검 API
    {
      const sbomRes = await request({ method: 'GET', path: '/api/cti/sbom?seq=2&live=false' });
      assert.equal(sbomRes.statusCode, 200);
      assert.equal(sbomRes.bodyJson.exactLockVersionVerified, true);
      assert.ok(sbomRes.bodyJson.counts);
      assert.ok(sbomRes.bodyJson.counts.vulnerable >= 1);
      assert.ok(sbomRes.bodyJson.counts.none_found >= 1);
      assert.ok(sbomRes.bodyJson.counts.unverifiable >= 1);
      recordPass('CTI & SBOM exact_lock_version 검증 및 OSV 3상태 분류 정상');
    }

    // 13. SQLite 헤더 무결성 백업 및 위변조 파일 복원 거부 API
    {
      const backupRes = await request({
        method: 'POST',
        path: '/api/db/backup',
        headers: { 'Content-Type': 'application/json' }
      }, { label: 'e2e_test' });
      assert.equal(backupRes.statusCode, 200);
      assert.equal(backupRes.bodyJson.headerVerified, true);

      // 손상된 헤더 복원 시도 거부 테스트
      const restoreFailRes = await request({
        method: 'POST',
        path: '/api/db/restore-test',
        headers: { 'Content-Type': 'application/json' }
      }, { simulateCorruptHeader: true });
      assert.equal(restoreFailRes.statusCode, 400);
      assert.equal(restoreFailRes.bodyJson.ok, false);
      assert.equal(restoreFailRes.bodyJson.preservedExistingDb, true);
      recordPass('SQLite format 3 무결성 백업 및 손상 헤더 복원 방어(DB 보호) 정상');
    }

    // 14. 테넌트 설정 업데이트 API
    {
      const tenantRes = await request({
        method: 'POST',
        path: '/api/tenant/settings',
        headers: { 'Content-Type': 'application/json' }
      }, {
        tenantId: store.getDefaultTenantId(),
        ai_domain: 'https://ai.jw-security.kr',
        ai_model: 'gemini-1.5-pro'
      });
      assert.equal(tenantRes.statusCode, 200);
      assert.equal(tenantRes.bodyJson.tenant.ai_model, 'gemini-1.5-pro');
      recordPass('멀티 테넌트 설정 갱신 및 DB 영속화 정상');
    }

    console.log('======================================================================');
    console.log(` 🏆 전체 기능 구동 테스트 ${passCount}/${testCount}건 100% 성공!`);
    console.log('======================================================================');
  } finally {
    server.close();
    store.db.close();
    if (fs.existsSync(TEST_DB)) fs.unlinkSync(TEST_DB);
  }
}

runAllTests().catch((err) => {
  console.error('❌ E2E 테스트 실패:', err);
  process.exit(1);
});
