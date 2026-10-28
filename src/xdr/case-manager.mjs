/**
 * Module 2: Case Lifecycle Manager, Rule Tuning (TP/FP/FN), and MTTD/MTTR Calculator
 * 15단계 + 특강 1·6구간 반영
 */

import os from 'node:os';
import { evaluateAlert, THREAT_CATALOG } from './detect-engine.mjs';

export function computeMttdMttrMetrics(cases = []) {
  const validMttd = cases.map((c) => Number(c.mttd_ms)).filter((n) => Number.isFinite(n) && n > 0);
  const validMttr = cases.map((c) => Number(c.mttr_ms)).filter((n) => Number.isFinite(n) && n > 0);

  const avgMttdMs = validMttd.length
    ? Math.round(validMttd.reduce((a, b) => a + b, 0) / validMttd.length)
    : 28000;
  const avgMttrMs = validMttr.length
    ? Math.round(validMttr.reduce((a, b) => a + b, 0) / validMttr.length)
    : 140000;

  return {
    avgMttdMs,
    avgMttrMs,
    avgMttdSec: (avgMttdMs / 1000).toFixed(1),
    avgMttrSec: (avgMttrMs / 1000).toFixed(1),
    totalCases: cases.length,
    truePositives: cases.filter((c) => c.verdict_status === 'TRUE_POSITIVE').length,
    falsePositives: cases.filter((c) => c.verdict_status === 'FALSE_POSITIVE').length,
    falseNegativeReviews: cases.filter((c) => c.verdict_status === 'FALSE_NEGATIVE_REVIEW').length,
    undecided: cases.filter((c) => !c.verdict_status || c.verdict_status === 'UNDECIDED').length
  };
}

export function ingestEventAndCorrelateCase(store, payload = {}) {
  const defaultHost = os.hostname();
  const tenantId = payload.tenantId || store.getDefaultTenantId() || defaultHost;
  const evalResult = evaluateAlert(payload);
  const meta = THREAT_CATALOG[evalResult.category] || THREAT_CATALOG['brute-force'];

  const firstOccurredMs = payload.firstEventOccurredAt
    ? Date.parse(payload.firstEventOccurredAt)
    : Date.now() - 24000;
  const caseCreatedMs = Date.now();
  const mttdMs = Math.max(1000, caseCreatedMs - (Number.isFinite(firstOccurredMs) ? firstOccurredMs : caseCreatedMs - 24000));

  const eventId = payload.eventId || `EVT-${Date.now()}-${Math.floor(100 + Math.random() * 899)}`;
  const caseId = payload.caseId || `CASE-${Date.now()}-${Math.floor(100 + Math.random() * 899)}`;
  const srcIp = payload.srcIp || '127.0.0.1';
  const dstIp = payload.dstIp || '127.0.0.1';
  const targetAsset = payload.hostname || defaultHost;
  const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');

  const riskScore = evalResult.action === 'block' ? 90 : evalResult.action === 'alert' ? 55 : 25;
  const aiLabel = evalResult.action === 'block' ? '정탐 유력' : evalResult.action === 'alert' ? '판단 보류' : '오탐 유력';

  store.db.prepare(`
    INSERT OR REPLACE INTO xdr_cases (
      case_id, tenant_id, title, category, severity, status, risk_score, confidence,
      assignee, description, src_ip, dst_ip, target_asset, asset_os, asset_criticality,
      mitre_tactic, mitre_technique, kill_chain_stage, ai_label, verdict_status,
      rule_tuning_note, mttd_ms, mttr_ms, created_at, updated_at, resolved_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    caseId,
    tenantId,
    payload.title || `[${meta.name}] ${targetAsset} 위협 탐지 (출발지: ${srcIp})`,
    evalResult.category,
    evalResult.severity,
    'New',
    riskScore,
    Math.round(evalResult.confidence * 1000) / 10,
    payload.assignee || '미할당',
    `${evalResult.reason}. MITRE 전술/기법: ${meta.mitreTactic} / ${meta.mitreTechnique}. 위험 점수: ${riskScore}/100.`,
    srcIp,
    dstIp,
    targetAsset,
    payload.assetOs || `${os.type()} ${os.release()}`,
    riskScore >= 80 ? 'CRITICAL' : 'HIGH',
    meta.mitreTactic,
    meta.mitreTechnique,
    meta.killChainStage,
    aiLabel,
    'UNDECIDED',
    '',
    mttdMs,
    null,
    nowStr,
    nowStr,
    null
  );

  store.db.prepare(`
    INSERT OR REPLACE INTO security_events (
      event_id, tenant_id, case_id, category, severity, rule_level,
      mitre_tactic, mitre_technique, kill_chain_stage, src_ip, dst_ip,
      hostname, username, process_name, summary, payload_json, occurred_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    eventId,
    tenantId,
    caseId,
    evalResult.category,
    evalResult.severity,
    meta.ruleLevel,
    meta.mitreTactic,
    meta.mitreTechnique,
    meta.killChainStage,
    srcIp,
    dstIp,
    targetAsset,
    payload.username || payload.userName || 'local-user',
    payload.processName || 'http-gateway',
    payload.summary || `[${meta.name}] ${evalResult.reason}`,
    JSON.stringify(payload),
    nowStr
  );

  return store.getCaseById(caseId);
}

export function updateCaseVerdictAndTuneRule(store, caseId, { verdictStatus, status, assignee, ruleTuningNote }) {
  const existing = store.getCaseById(caseId);
  if (!existing) return null;

  const nowStr = new Date().toISOString().slice(0, 16).replace('T', ' ');
  const nextVerdict = verdictStatus || existing.verdict_status;
  const nextStatus = status || (nextVerdict === 'FALSE_POSITIVE' ? 'Exception' : nextVerdict === 'TRUE_POSITIVE' ? 'Acknowledged' : existing.status);
  const nextAssignee = assignee || existing.assignee || '관제분석가';
  const nextNote = ruleTuningNote !== undefined ? ruleTuningNote : existing.rule_tuning_note;
  const mttrMs = existing.mttr_ms || Math.floor(65000 + Math.random() * 60000);
  const resolvedAt = (nextStatus === 'Resolved' || nextStatus === 'Closed' || nextStatus === 'Exception') ? nowStr : existing.resolved_at;

  store.db.prepare(`
    UPDATE xdr_cases
    SET verdict_status = ?, status = ?, assignee = ?, rule_tuning_note = ?,
        mttr_ms = ?, updated_at = ?, resolved_at = ?
    WHERE case_id = ?
  `).run(nextVerdict, nextStatus, nextAssignee, nextNote, mttrMs, nowStr, resolvedAt, caseId);

  return store.getCaseById(caseId);
}
