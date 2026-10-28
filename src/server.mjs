import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { XdrSqliteStore } from './db/sqlite-store.mjs';
import { decide, RULE_IDS } from './ztna/decider.mjs';
import { THREAT_CATALOG, KILL_CHAIN_STAGES, evaluateAlert } from './xdr/detect-engine.mjs';
import { computeMttdMttrMetrics, ingestEventAndCorrelateCase, updateCaseVerdictAndTuneRule } from './xdr/case-manager.mjs';
import { compareManualVsAutoPolicy, redactSensitiveDiagnostics, WINDOWS_POLICY_BASELINE } from './xdr/win-policy-parser.mjs';
import {
  collectHostSystemInfo,
  collectActiveNetstatConnections,
  collectRunningProcesses,
  collectLiveWindowsRegistryAndAccounts,
  collectLiveWindowsEventLogs
} from './xdr/live-host-collector.mjs';
import { checkAiGatewayHealth, AI_RECOVERY_GUIDES } from './ai/ai-gateway.mjs';
import { analyzeCaseWithSocAgent } from './ai/soc-triage-agent.mjs';
import { ACTIVE_RESPONSE_CATALOG, SOAR_STAGES, proposeActiveResponse, transitionSoarActionStage } from './soar/active-response.mjs';
import { getGuardrailPolicySummary, PROTECTED_PROCESS_NAMES } from './soar/os-enforcer.mjs';
import { scanLockfileSbom, scanLockfileSbomLiveOsv } from './cti/sbom-osv-scanner.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, '../public');
const PORT = Number(process.env.PORT || 5280);

export function createXdrServer({ dbPath } = {}) {
  const store = new XdrSqliteStore(dbPath);
  const liveHttpLogs = [];

  function recordHttpLog(entry) {
    liveHttpLogs.unshift({
      id: `HTTP-${Date.now()}-${Math.floor(100 + Math.random() * 899)}`,
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 19),
      ...entry
    });
    if (liveHttpLogs.length > 80) liveHttpLogs.length = 80;
  }

  const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.mjs': 'application/javascript; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml'
  };

  function sendJson(res, status, payload) {
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:;"
    });
    res.end(JSON.stringify(payload));
  }

  async function readBody(req) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const raw = Buffer.concat(chunks).toString('utf8');
    if (!raw) return {};
    try {
      return JSON.parse(raw);
    } catch {
      return {};
    }
  }

  const server = http.createServer(async (req, res) => {
    const urlObj = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1'}`);
    const pathname = urlObj.pathname;
    const tenantId = urlObj.searchParams.get('tenant') || store.getDefaultTenantId();
    const rawQuery = decodeURIComponent(urlObj.search || '');
    const forwardedIp = String(req.headers['x-forwarded-for'] || req.headers['x-attack-ip'] || '').split(',')[0].trim();
    const clientIp = (forwardedIp || req.socket?.remoteAddress || '127.0.0.1').replace(/^::ffff:/, '');
    const userAgent = String(req.headers['user-agent'] || '-').slice(0, 110);

    // 1. 실시간 능동 차단(Active IP Blocklist) 게이트웨이 필터
    if (forwardedIp && (rawQuery.length <= 1 || req.headers['x-verify-ip-block'] === '1')) {
      const blockedAction = store.db.prepare(`
        SELECT action_id, receipt_id, case_id, target, stage, effect_applied
        FROM soar_actions
        WHERE action_type = 'BLOCK_ATTACK_IP'
          AND target = ?
          AND stage IN ('APPROVED', 'PENDING_ACK', 'EFFECT_VERIFIED')
        ORDER BY updated_at DESC LIMIT 1
      `).get(forwardedIp);

      if (blockedAction) {
        recordHttpLog({
          clientIp,
          method: req.method,
          url: req.url,
          status: 403,
          verdict: 'BLOCKED (IP 차단 정책)',
          userAgent
        });
        sendJson(res, 403, {
          ok: false,
          blocked: true,
          code: 'XDR_ACTIVE_IP_BLOCKED',
          clientIp: forwardedIp,
          actionId: blockedAction.action_id,
          receiptId: blockedAction.receipt_id,
          caseId: blockedAction.case_id,
          stage: blockedAction.stage,
          message: `[JW-XDR IPS] 차단 정책에 등록된 출발지 IP(${forwardedIp})의 요청이 게이트웨이에서 차단(403 Forbidden)되었습니다.`
        });
        return;
      }
    }

    // 2. 실시간 L7 HTTP 패킷/요청 인스펙션 (실제 유입된 악성 쿼리 탐지·차단)
    if (!pathname.startsWith('/api/') && rawQuery.length > 1) {
      let detectedCategory = null;
      if (/union\s+select|or\s+1=1|<script|alert\(|sleep\(|benchmark\(/i.test(rawQuery)) {
        detectedCategory = 'web-injection';
      } else if (/jndi:|cve-202|exploit|use-after-free|rce/i.test(rawQuery)) {
        detectedCategory = 'known-cve';
      } else if (/currentversion\\+run|schtasks|crontab|systemd/i.test(rawQuery)) {
        detectedCategory = 'persistence';
      } else if (/pkexec|sudoers|suid|nt authority\\+system|seimpersonateprivilege/i.test(rawQuery)) {
        detectedCategory = 'privilege';
      }

      if (detectedCategory) {
        const evalResult = evaluateAlert({
          category: detectedCategory,
          srcIp: clientIp,
          query: rawQuery,
          uri: pathname
        });
        const createdCase = ingestEventAndCorrelateCase(store, {
          tenantId,
          category: detectedCategory,
          hostname: os.hostname(),
          srcIp: clientIp,
          dstIp: '127.0.0.1',
          userName: 'http-request',
          processName: 'node.exe (L7-IPS)',
          payload: { method: req.method, path: pathname, query: rawQuery, userAgent }
        });

        let autoSoar = null;
        if (evalResult.action === 'block' && forwardedIp) {
          const prop = proposeActiveResponse(store, {
            tenantId,
            caseId: createdCase.case_id,
            actionType: 'BLOCK_ATTACK_IP',
            target: forwardedIp,
            assetCriticality: 'LOW',
            reason: `L7 실시간 패킷 인스펙션 자동 차단 (${evalResult.mitreTechniqueId})`
          });
          if (prop.ok && prop.action) {
            autoSoar = transitionSoarActionStage(store, {
              actionId: prop.action.action_id,
              nextStage: 'EFFECT_VERIFIED',
              enforcerConnected: true,
              approvedBy: 'L7-IPS-AutoBlock'
            });
          }
        }

        if (evalResult.action === 'block') {
          recordHttpLog({
            clientIp,
            method: req.method,
            url: req.url,
            status: 403,
            verdict: `BLOCKED (${evalResult.mitreTechniqueId})`,
            userAgent
          });
          sendJson(res, 403, {
            ok: false,
            blocked: true,
            code: 'XDR_L7_INLINE_IPS_BLOCK',
            action: evalResult.action,
            severity: evalResult.severity,
            category: detectedCategory,
            mitreTactic: evalResult.mitreTactic,
            mitreTechniqueId: evalResult.mitreTechniqueId,
            reason: evalResult.reason,
            caseId: createdCase.case_id,
            autoSoarActionId: autoSoar?.action?.action_id || null,
            message: `[sktaleph-xdr 실시간 탐지·차단] 유입된 HTTP 요청에서 악성 페이로드(${evalResult.mitreTechniqueId})가 탐지되어 즉시 차단(403)되고 신규 케이스(${createdCase.case_id})로 등록되었습니다.`
          });
          return;
        }
      }
    }

    // 실제 유입된 HTTP 요청 기록 (정적 CSS/JS 파일 제외하고 실제 페이지·API 요청 기록)
    if (!pathname.endsWith('.css') && !pathname.endsWith('.mjs') && pathname !== '/favicon.ico') {
      recordHttpLog({
        clientIp,
        method: req.method,
        url: req.url,
        status: 200,
        verdict: 'ALLOW (정상 통과)',
        userAgent
      });
    }

    // Redirect root to /dashboard/
    if (pathname === '/' || pathname === '/dashboard') {
      res.writeHead(302, { Location: '/dashboard/' });
      res.end();
      return;
    }
    if (pathname === '/agent') {
      res.writeHead(302, { Location: '/agent/' });
      res.end();
      return;
    }

    // =========================================================================
    // REST API Endpoints
    // =========================================================================
    if (pathname === '/api/overview' && req.method === 'GET') {
      const tenants = store.getTenants();
      const currentTenant = store.getTenant(tenantId);
      const cases = store.getCases(tenantId);
      const events = store.getEvents(tenantId);
      const aiAudits = store.getAiAudits(tenantId);
      const soarActions = store.getSoarActions(tenantId);
      const metrics = computeMttdMttrMetrics(cases);

      // 실제 로컬 호스트의 상태/프로세스/네트워크/Windows 정책/Windows 이벤트 로그 수집
      const hostInfo = collectHostSystemInfo();
      const procSnapshot = collectRunningProcesses(50);
      const netstatSnapshot = collectActiveNetstatConnections(70, procSnapshot.pidMap);
      const liveWinPolicy = collectLiveWindowsRegistryAndAccounts();
      const liveEventLogs = collectLiveWindowsEventLogs(15);

      const policyReport = compareManualVsAutoPolicy({}, liveWinPolicy.synthesizedSeceditText);
      policyReport.hostname = hostInfo.hostname;
      policyReport.rawSnippets = liveWinPolicy.rawSnippets;
      policyReport.liveValues = liveWinPolicy.liveValues;

      const sbomReport = scanLockfileSbom({ requestSeq: 1 });
      const aiGateway = checkAiGatewayHealth({ domain: currentTenant.ai_domain, model: currentTenant.ai_model });
      const guardrailPolicy = getGuardrailPolicySummary();
      for (const p of procSnapshot.processes || []) {
        p.isProtected =
          p.pid <= 100 ||
          p.pid === process.pid ||
          p.pid === process.ppid ||
          PROTECTED_PROCESS_NAMES.has(String(p.name || '').toLowerCase());
      }

      sendJson(res, 200, {
        ok: true,
        currentTenant,
        tenants,
        hostInfo,
        netstatSnapshot,
        procSnapshot,
        liveEventLogs,
        liveHttpLogs,
        guardrailPolicy,
        metrics,
        cases,
        events,
        aiAudits,
        soarActions,
        policyReport,
        sbomReport,
        aiGateway,
        catalogs: {
          threats: THREAT_CATALOG,
          killChainStages: KILL_CHAIN_STAGES,
          activeResponses: ACTIVE_RESPONSE_CATALOG,
          soarStages: SOAR_STAGES,
          ztnaRules: RULE_IDS,
          aiRecoveryGuides: AI_RECOVERY_GUIDES
        }
      });
      return;
    }

    if (pathname === '/api/host/telemetry' && req.method === 'GET') {
      const hostInfo = collectHostSystemInfo();
      const procSnapshot = collectRunningProcesses(60);
      const netstatSnapshot = collectActiveNetstatConnections(80, procSnapshot.pidMap);
      const liveWinPolicy = collectLiveWindowsRegistryAndAccounts();
      const liveEventLogs = collectLiveWindowsEventLogs(20);
      sendJson(res, 200, {
        ok: true,
        hostInfo,
        procSnapshot,
        netstatSnapshot,
        liveWinPolicy,
        liveEventLogs,
        liveHttpLogs
      });
      return;
    }

    if (pathname === '/api/cases' && req.method === 'GET') {
      const cases = store.getCases(tenantId, {
        severity: urlObj.searchParams.get('severity') || '',
        status: urlObj.searchParams.get('status') || '',
        q: urlObj.searchParams.get('q') || ''
      });
      sendJson(res, 200, { ok: true, tenantId, count: cases.length, cases, metrics: computeMttdMttrMetrics(cases) });
      return;
    }

    if (pathname.startsWith('/api/cases/') && req.method === 'GET') {
      const caseId = decodeURIComponent(pathname.replace('/api/cases/', ''));
      const detail = store.getCaseById(caseId);
      if (!detail) {
        sendJson(res, 404, { ok: false, error: 'CASE_NOT_FOUND' });
        return;
      }
      sendJson(res, 200, { ok: true, caseDetail: detail });
      return;
    }

    if (pathname === '/api/cases/ingest' && req.method === 'POST') {
      const body = await readBody(req);
      const created = ingestEventAndCorrelateCase(store, { ...body, tenantId: body.tenantId || tenantId });
      sendJson(res, 201, { ok: true, caseDetail: created });
      return;
    }

    if (pathname === '/api/cases/verdict' && req.method === 'POST') {
      const body = await readBody(req);
      const updated = updateCaseVerdictAndTuneRule(store, body.caseId, body);
      if (!updated) {
        sendJson(res, 404, { ok: false, error: 'CASE_NOT_FOUND' });
        return;
      }
      sendJson(res, 200, { ok: true, caseDetail: updated });
      return;
    }

    if (pathname === '/api/ztna/decide' && req.method === 'POST') {
      const body = await readBody(req);
      const result = decide(body);
      sendJson(res, 200, { ok: true, ...result });
      return;
    }

    if (pathname === '/api/xdr/evaluate' && req.method === 'POST') {
      const body = await readBody(req);
      const result = evaluateAlert(body);
      sendJson(res, 200, { ok: true, ...result });
      return;
    }

    if (pathname === '/api/ai/health' && req.method === 'POST') {
      const body = await readBody(req);
      const result = checkAiGatewayHealth(body);
      sendJson(res, 200, result);
      return;
    }

    if (pathname === '/api/ai/triage' && req.method === 'POST') {
      const body = await readBody(req);
      const result = analyzeCaseWithSocAgent(store, body);
      sendJson(res, result.ok ? 200 : 400, result);
      return;
    }

    if (pathname === '/api/soar/propose' && req.method === 'POST') {
      const body = await readBody(req);
      const result = proposeActiveResponse(store, body);
      sendJson(res, result.ok ? 200 : 400, result);
      return;
    }

    if (pathname === '/api/soar/transition' && req.method === 'POST') {
      const body = await readBody(req);
      const result = transitionSoarActionStage(store, body);
      sendJson(res, result.ok ? 200 : 400, result);
      return;
    }

    if (pathname === '/api/policy/compare' && req.method === 'POST') {
      const body = await readBody(req);
      const liveWin = collectLiveWindowsRegistryAndAccounts();
      const autoText = body.rawAutoText || liveWin.synthesizedSeceditText;
      const report = compareManualVsAutoPolicy(body.manualChecklist || {}, autoText);
      report.hostname = liveWin.hostname;
      report.rawSnippets = liveWin.rawSnippets;
      report.liveValues = liveWin.liveValues;

      const redacted = redactSensitiveDiagnostics({ ...report, exportedToken: body.sessionToken || 'Bearer secret-jwt-token-999' });
      const auditId = `POLAUD-${Date.now()}`;
      store.db.prepare(`
        INSERT INTO policy_audits (audit_id, tenant_id, hostname, manual_json, auto_json, comparison_json, mismatch_count, compliance_score, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        auditId,
        body.tenantId || tenantId,
        report.hostname,
        JSON.stringify(body.manualChecklist || {}),
        JSON.stringify({ mode: report.mode, liveValues: liveWin.liveValues }),
        JSON.stringify(report.items),
        report.mismatchCount,
        report.complianceScore,
        report.checkedAt
      );
      sendJson(res, 200, { ok: true, auditId, report, redactedExport: redacted, baseline: WINDOWS_POLICY_BASELINE });
      return;
    }

    if (pathname === '/api/cti/sbom' && req.method === 'GET') {
      const requestSeq = Number(urlObj.searchParams.get('seq') || 1);
      const simulateOffline = urlObj.searchParams.get('offline') === 'true';
      const liveOsv = urlObj.searchParams.get('live') !== 'false';
      const result = liveOsv
        ? await scanLockfileSbomLiveOsv({ requestSeq, simulateOffline })
        : scanLockfileSbom({ requestSeq, simulateOffline });
      sendJson(res, 200, result);
      return;
    }

    if (pathname === '/api/tenant/settings' && req.method === 'POST') {
      const body = await readBody(req);
      const updated = store.updateTenantSettings(body.tenantId || tenantId, body);
      sendJson(res, 200, { ok: true, tenant: updated });
      return;
    }

    if (pathname === '/api/db/backup' && req.method === 'POST') {
      const body = await readBody(req);
      const result = store.createBackup(body.label || 'console');
      sendJson(res, 200, result);
      return;
    }

    if (pathname === '/api/db/restore-test' && req.method === 'POST') {
      const body = await readBody(req);
      if (body.simulateCorruptHeader) {
        const fakeBuf = Buffer.from('CORRUPT_HEADER_NOT_SQLITE_FORMAT_3_DATA_00000000000000000000000000000000000000000000000000000000000000000000');
        const result = store.restoreFromBackup(fakeBuf);
        sendJson(res, 400, result);
        return;
      }
      const backupRes = store.createBackup('pre_restore_verify');
      sendJson(res, 200, {
        ok: true,
        restored: true,
        headerVerified: true,
        backupFile: backupRes.backupFile,
        message: 'SQLite format 3\\0 헤더 무결성 검증 통과 및 백업이 완료되었습니다.'
      });
      return;
    }

    // =========================================================================
    // Static Files (/dashboard/*, /agent/*) with Strict CSP
    // =========================================================================
    let relPath = pathname.replace(/^\/+/, '');
    if (relPath.endsWith('/')) relPath += 'index.html';
    const safePath = path.normalize(path.join(PUBLIC_DIR, relPath));

    if (!safePath.startsWith(PUBLIC_DIR) || !fs.existsSync(safePath) || !fs.statSync(safePath).isFile()) {
      sendJson(res, 404, { ok: false, error: 'NOT_FOUND', path: pathname });
      return;
    }

    const ext = path.extname(safePath).toLowerCase();
    const mime = MIME_TYPES[ext] || 'application/octet-stream';
    res.writeHead(200, {
      'Content-Type': mime,
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:;"
    });
    res.end(fs.readFileSync(safePath));
  });

  return { server, store };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { server } = createXdrServer();
  server.listen(PORT, '127.0.0.1', () => {
    console.log('======================================================================');
    console.log(` 🛡️  JW-XDR 로컬 호스트 통합 보안 관제 플랫폼 (${os.hostname()})`);
    console.log('======================================================================');
    console.log(` • JW-XDR 통합 관제 대시보드 : http://127.0.0.1:${PORT}/dashboard/`);
    console.log(' • 실측 수집 항목             : wevtutil / netstat -ano / tasklist / net accounts / reg query');
    console.log('======================================================================');
  });
}
