/**
 * Module 4-B: ISO 42001 SOC AI Triage Agent & Evidence Binding Guardrail
 * 18단계 + 특강 1·3·6구간 (1차 정탐/오탐/판단보류 분류, eventId 근거 고정, 환각·월권 차단, 민감정보 익명화 리포트)
 */

export function analyzeCaseWithSocAgent(store, {
  caseId,
  requestedEventIds = null,
  simulateHallucinatedEventId = false,
  simulateAlreadyExecutedClaim = false,
  anonymize = true,
  reportType = '조사 리포트',
  language = '한국어'
} = {}) {
  const targetCase = store.getCaseById(caseId);
  if (!targetCase) {
    return {
      ok: false,
      status: 'error',
      error: { code: 'CASE_NOT_FOUND', message: `케이스(${caseId})를 찾을 수 없습니다.` }
    };
  }

  // 종결 리포트는 Resolved 또는 Closed 상태일 때만 허용 (ISMS-P / SOC 표준 규격)
  if (reportType === '종결 리포트' && !['Resolved', 'Closed', 'Exception'].includes(targetCase.status)) {
    return {
      ok: false,
      status: 'error',
      error: {
        code: 'REPORT_REQUIRES_RESOLVED_CASE',
        message: '종결 리포트는 케이스가 Resolved 또는 Closed 상태일 때만 생성할 수 있습니다.'
      }
    };
  }

  const validEvents = Array.isArray(targetCase.events) ? targetCase.events : [];
  const validEventIds = new Set(validEvents.map((e) => e.event_id));

  const citedIds = simulateHallucinatedEventId
    ? ['EVT-9999-HALLUCINATED']
    : Array.isArray(requestedEventIds) && requestedEventIds.length > 0
      ? requestedEventIds
      : validEvents.map((e) => e.event_id);

  // 18단계: 근거 부족(이벤트 0건) 시 추정 금지 -> 판단 보류(insufficient_evidence)
  if (citedIds.length === 0 || validEvents.length === 0) {
    return {
      ok: false,
      status: 'insufficient_evidence',
      aiLabel: '판단 보류',
      wrong_event_rejected: false,
      proposal_not_executed: true,
      guardrailStatus: 'INSUFFICIENT_EVIDENCE (수집된 원시 이벤트 근거 부족으로 추측 설명 거부)',
      message: '연결된 수집 이벤트(eventId) 근거가 부족하여 AI 에이전트가 임의 추측하지 않고 [판단 보류]로 처리했습니다.'
    };
  }

  // 18단계: 존재하지 않는 eventId 인용 시 즉시 거부 (wrong_event_rejected: true)
  const invalidIds = citedIds.filter((id) => !validEventIds.has(id));
  if (invalidIds.length > 0) {
    const auditId = `AIAUD-${Date.now()}`;
    store.db.prepare(`
      INSERT INTO ai_audit_logs (
        audit_id, tenant_id, case_id, ai_label, confidence, cited_event_ids,
        guardrail_status, wrong_event_rejected, proposal_not_executed,
        anonymized, report_type, summary, recommended_action, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      auditId,
      targetCase.tenant_id,
      caseId,
      '판단 보류',
      0,
      JSON.stringify(citedIds),
      `REJECTED_WRONG_EVENT_ID (${invalidIds.join(', ')})`,
      1,
      1,
      anonymize ? 1 : 0,
      reportType,
      `[환각 차단] 케이스에 존재하지 않는 이벤트 ID(${invalidIds.join(', ')})를 인용한 AI 응답을 거부했습니다.`,
      'NONE (가드레일 차단)',
      new Date().toISOString().slice(0, 19).replace('T', ' ')
    );

    return {
      ok: false,
      status: 'error',
      wrong_event_rejected: true,
      proposal_not_executed: true,
      rejectedEventIds: invalidIds,
      error: {
        code: 'WRONG_EVENT_ID_REJECTED',
        message: `실제 수집 로그에 존재하지 않는 eventId(${invalidIds.join(', ')}) 인용이 감지되어 ISO 42001 가드레일에 의해 즉시 거부되었습니다.`
      }
    };
  }

  // 18단계: AI가 이미 차단을 직접 실행했다고 주장하면 월권으로 거부 (proposal_not_executed)
  if (simulateAlreadyExecutedClaim) {
    return {
      ok: false,
      status: 'error',
      wrong_event_rejected: false,
      proposal_not_executed: true,
      error: {
        code: 'ALREADY_EXECUTED_CLAIM_REJECTED',
        message: 'AI가 차단 조치를 이미 직접 실행했다고 답한 설명은 월권(Overreach)이므로 사용할 수 없습니다. AI는 제안(Proposal)만 수행합니다.'
      }
    };
  }

  // 정상 근거 고정 분석
  let aiLabel = '판단 보류';
  if (targetCase.risk_score >= 70 || ['크리티컬', '높음'].includes(targetCase.severity)) {
    aiLabel = targetCase.verdict_status === 'FALSE_POSITIVE' ? '오탐 유력' : '정탐 유력';
  } else if (targetCase.verdict_status === 'FALSE_POSITIVE') {
    aiLabel = '오탐 유력';
  }

  const hostDisplay = anonymize ? `HOST_ANON_${targetCase.target_asset.slice(0, 4).toUpperCase()}` : targetCase.target_asset;
  const dstIpDisplay = anonymize ? targetCase.dst_ip.replace(/\.\d+\.\d+$/, '.xxx.xxx') : targetCase.dst_ip;

  const recommendedActionMap = {
    'brute-force': `BLOCK_ATTACK_IP (${targetCase.src_ip} 방화벽 접근 차단 제안)`,
    'web-injection': `BLOCK_ATTACK_IP (${targetCase.src_ip} WAF/방화벽 즉시 차단 제안)`,
    'known-cve': `ISOLATE_HOST (${hostDisplay} 네트워크 격리 및 커널 패치 권고)`,
    'persistence': `KILL_MALICIOUS_PROCESS (${hostDisplay} 비인가 자동실행 프로세스 강제 종료 제안)`,
    'privilege': `DISABLE_OS_ACCOUNT (${hostDisplay} :: user01 계정 임시 비활성화 제안)`,
    'exfiltration': `ISOLATE_HOST (${hostDisplay} 아웃바운드 통신 격리 및 C2 IP ${targetCase.src_ip} 차단 제안)`
  };
  const recommendedAction = recommendedActionMap[targetCase.category] || `BLOCK_ATTACK_IP (${targetCase.src_ip})`;

  const summary = [
    `[ISO 42001 근거 고정 분석 (${language} / ${reportType})]`,
    `• 인용된 실제 이벤트 증거: ${citedIds.join(', ')}`,
    `• 대상 자산(${anonymize ? '익명화 적용' : '원문'}): ${hostDisplay} (${dstIpDisplay}) / 출발지 위협 IP: ${targetCase.src_ip}`,
    `• MITRE ATT&CK 매핑: ${targetCase.mitre_tactic} — ${targetCase.mitre_technique} (Kill Chain: ${targetCase.kill_chain_stage})`,
    `• AI 1차 판정 결과: [${aiLabel}] (위험도 ${targetCase.risk_score}/100, 신뢰도 ${targetCase.confidence}%)`,
    `• 권고 조치(제안만 수행, 미실행): ${recommendedAction} — 실제 적용은 관제사(Human-in-the-Loop) 최종 승인이 필요합니다.`
  ].join('\n');

  const auditId = `AIAUD-2026-${Math.floor(100 + Math.random() * 900)}`;
  const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');

  store.db.prepare(`
    INSERT INTO ai_audit_logs (
      audit_id, tenant_id, case_id, ai_label, confidence, cited_event_ids,
      guardrail_status, wrong_event_rejected, proposal_not_executed,
      anonymized, report_type, summary, recommended_action, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    auditId,
    targetCase.tenant_id,
    caseId,
    aiLabel,
    targetCase.confidence,
    JSON.stringify(citedIds),
    'BOUND_OK (근거 고정 검증 통과)',
    0,
    1,
    anonymize ? 1 : 0,
    reportType,
    summary,
    recommendedAction,
    nowStr
  );

  store.db.prepare('UPDATE xdr_cases SET ai_label = ?, updated_at = ? WHERE case_id = ?').run(aiLabel, nowStr, caseId);

  return {
    ok: true,
    status: 'ready',
    auditId,
    caseId,
    aiLabel,
    confidence: targetCase.confidence,
    citedEventIds: citedIds,
    wrong_event_rejected: false,
    proposal_not_executed: true,
    anonymized: Boolean(anonymize),
    reportType,
    summary,
    recommendedAction,
    createdAt: nowStr
  };
}
