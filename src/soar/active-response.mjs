/**
 * Module 5: T-MAC Active Response (SOAR) & 5-Layer Safe OS Enforcement
 */

import { executeSafeOsEnforcement, rollbackSafeOsEnforcement } from './os-enforcer.mjs';

export const ACTIVE_RESPONSE_CATALOG = {
  BLOCK_ATTACK_IP: {
    type: 'BLOCK_ATTACK_IP',
    label: '공격 IP 차단',
    description: '위협이 확인된 외부 공격자 IP로부터의 접근을 L7 게이트웨이 및 Windows 방화벽(netsh)에서 차단합니다.'
  },
  ISOLATE_HOST: {
    type: 'ISOLATE_HOST',
    label: '호스트 안전 격리',
    description: '로컬 PC의 인터넷 단절 사고를 방지하면서 외부 비인가 접근만 차단하는 게이트웨이 보호 격리를 적용합니다.'
  },
  DISABLE_OS_ACCOUNT: {
    type: 'DISABLE_OS_ACCOUNT',
    label: '계정 비활성화 (잠금 보호)',
    description: '현재 로그인된 계정 및 필수 관리자 계정은 잠금 방지 안전장치로 보호하며 비인가 계정만 제어합니다.'
  },
  KILL_MALICIOUS_PROCESS: {
    type: 'KILL_MALICIOUS_PROCESS',
    label: '프로세스 강제 종료 (taskkill)',
    description: 'OS 커널 및 사용자 핵심 작업 프로세스(Safe-List)를 보호하면서 대상 PID 프로세스를 실제 종료(taskkill /F)합니다.'
  }
};

export const SOAR_STAGES = [
  { id: 'PROPOSED', step: 1, label: '제안 (Proposed)', desc: '대응 조치가 대기열에 등록된 상태 (미집행)' },
  { id: 'APPROVED', step: 2, label: '승인 (Approved)', desc: '관리자가 대상과 안전장치를 검토 후 승인한 상태' },
  { id: 'PENDING_ACK', step: 3, label: '접수 (Pending ACK)', desc: '제어 서버가 조치 의도를 접수하고 영수증(receiptId)을 발급한 상태' },
  { id: 'EFFECT_VERIFIED', step: 4, label: '원천 집행 완료 (Effect Verified)', desc: '5중 안전장치 통과 후 실제 OS(taskkill/netsh) 및 게이트웨이에 집행이 완료된 상태' }
];

export function proposeActiveResponse(store, {
  tenantId,
  caseId = 'CASE-HOST-POLICY-01',
  actionType = 'BLOCK_ATTACK_IP',
  target = '203.0.113.88',
  reason = '관제 분석에 따른 능동 대응 조치 제안'
} = {}) {
  const effectiveTenantId = tenantId || store.getDefaultTenantId();
  if (!ACTIVE_RESPONSE_CATALOG[actionType]) {
    return { ok: false, code: 'UNSUPPORTED_ACTION_TYPE', message: `지원하지 않는 조치 유형입니다: ${actionType}` };
  }

  const existing = store.db.prepare(
    'SELECT * FROM soar_actions WHERE case_id = ? AND action_type = ? AND target = ? AND stage NOT IN (?, ?)'
  ).get(caseId, actionType, target, 'REJECTED', 'ROLLED_BACK');

  if (existing) {
    return {
      ok: true,
      duplicatePrevented: true,
      action: existing,
      message: `동일한 대상(${target})에 대한 [${ACTIVE_RESPONSE_CATALOG[actionType].label}] 티켓(${existing.action_id})이 이미 존재하여 중복 생성을 방지했습니다.`
    };
  }

  const actionId = `ACT-${Date.now()}-${Math.floor(100 + Math.random() * 899)}`;
  const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');

  store.db.prepare(`
    INSERT INTO soar_actions (
      action_id, receipt_id, tenant_id, case_id, action_type, target,
      reason, stage, approved_by, effect_applied, enforcement_note, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    actionId,
    null,
    effectiveTenantId,
    caseId,
    actionType,
    target,
    reason,
    'PROPOSED',
    null,
    0,
    '[제안(Proposed)]: 오작동 방지를 위해 관리자의 승인을 대기 중입니다.',
    nowStr,
    nowStr
  );

  return {
    ok: true,
    duplicatePrevented: false,
    action: store.db.prepare('SELECT * FROM soar_actions WHERE action_id = ?').get(actionId)
  };
}

export function transitionSoarActionStage(store, {
  actionId,
  nextStage,
  approvedBy = 'soc-analyst-01',
  enforcerConnected = false
} = {}) {
  const row = store.db.prepare('SELECT * FROM soar_actions WHERE action_id = ?').get(actionId);
  if (!row) {
    return { ok: false, code: 'ACTION_NOT_FOUND', message: `조치 티켓(${actionId})을 찾을 수 없습니다.` };
  }

  const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');
  let receiptId = row.receipt_id;
  let effectApplied = 0;
  let enforcementNote = row.enforcement_note;
  let targetStage = nextStage;
  let blockedByGuardrail = false;

  if (targetStage === 'APPROVED') {
    enforcementNote = `[승인(Approved)]: 관리자(${approvedBy}) 승인 완료 — 5중 안전장치 검증 후 원천 집행 가능`;
  } else if (targetStage === 'PENDING_ACK') {
    receiptId = receiptId || `RCPT-${Date.now().toString().slice(-6)}`;
    enforcementNote = `[접수(Pending ACK)]: 서버 접수 완료 (영수증: ${receiptId}) — ⚠ 원천 집행 미연동 (접수만 완료)`;
  } else if (targetStage === 'ROLLED_BACK') {
    const rb = rollbackSafeOsEnforcement(row);
    targetStage = 'ROLLED_BACK';
    effectApplied = 0;
    enforcementNote = rb.note;
  } else if (targetStage === 'EFFECT_VERIFIED') {
    receiptId = receiptId || `RCPT-${Date.now().toString().slice(-6)}`;
    if (enforcerConnected === true) {
      const execRes = executeSafeOsEnforcement(row);
      blockedByGuardrail = Boolean(execRes.blockedByGuardrail);
      if (execRes.effectApplied) {
        targetStage = 'EFFECT_VERIFIED';
        effectApplied = 1;
        enforcementNote = `${execRes.note} (영수증: ${receiptId})`;
      } else if (execRes.blockedByGuardrail) {
        targetStage = 'GUARDRAIL_BLOCKED';
        effectApplied = 0;
        enforcementNote = execRes.note;
      } else {
        targetStage = 'APPROVED';
        effectApplied = 0;
        enforcementNote = execRes.note;
      }
    } else {
      targetStage = 'PENDING_ACK';
      effectApplied = 0;
      enforcementNote = `⚠ 원천 집행 미연동 (접수만 완료): 제어 서버 영수증(${receiptId})은 발급되었으나 원천 집행기를 실행하지 않고 접수 상태로 분리 기록했습니다.`;
    }
  }

  store.db.prepare(`
    UPDATE soar_actions
    SET stage = ?, receipt_id = ?, approved_by = ?, effect_applied = ?, enforcement_note = ?, updated_at = ?
    WHERE action_id = ?
  `).run(targetStage, receiptId, approvedBy, effectApplied, enforcementNote, nowStr, actionId);

  let badgeText = '⚠ 원천 집행 미연동 (접수만 완료)';
  if (effectApplied) {
    badgeText = `✓ 실제 원천 집행 완료 (${row.target})`;
  } else if (blockedByGuardrail) {
    badgeText = `🛡️ 안전장치 작동 — 보호 대상이므로 집행이 차단되었습니다`;
  } else if (targetStage === 'ROLLED_BACK') {
    badgeText = `🔄 원상복구(차단 해제) 완료 (${row.target})`;
  } else if (targetStage === 'APPROVED') {
    badgeText = enforcementNote;
  }

  return {
    ok: true,
    action: store.db.prepare('SELECT * FROM soar_actions WHERE action_id = ?').get(actionId),
    enforcerConnected: Boolean(enforcerConnected),
    effectApplied: Boolean(effectApplied),
    blockedByGuardrail,
    badgeText
  };
}
