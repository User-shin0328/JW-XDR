/**
 * Module 1: ZTNA Policy Decision Point (PDP)
 * 13~14단계 + 특강 2·3구간 (IAM PoLP/RBAC, 신원·기기·세션 3단 분리, 4상태 판정 allow/deny/challenge/unknown)
 */

export const RULE_IDS = [
  'ZTNA-01-UNKNOWN-TELEMETRY',
  'ZTNA-02-UNREGISTERED-DEVICE',
  'ZTNA-03-THREAT-SIGNAL-DENY',
  'ZTNA-04-RBAC-POLP-DENY',
  'ZTNA-05-STEPUP-CHALLENGE',
  'ZTNA-06-VERIFIED-ALLOW'
];

export function decide(request = {}) {
  const checkedAt = new Date().toISOString();

  // 1. 판단 근거 부족 / 신호 누락 시 통과시키지 않고 unknown(확인 불가)으로 격리 (Fail-Closed)
  if (
    !request ||
    typeof request !== 'object' ||
    request.deviceRegistered === undefined ||
    request.deviceRegistered === null ||
    request.issuer === 'unknown' ||
    request.telemetryUnavailable === true
  ) {
    return {
      decision: 'unknown',
      ruleId: 'ZTNA-01-UNKNOWN-TELEMETRY',
      reason: '원천 신원·기기·세션 판단 근거(Telemetry)가 누락되었거나 확인 불가 상태이므로 자동 허용하지 않고 격리합니다.',
      stepUpRequired: false,
      checkedAt,
      cards: buildThreePillarCards(request, 'unknown')
    };
  }

  const signals = Array.isArray(request.signals) ? request.signals : [];
  const pathStr = String(request.path || '/dashboard');
  const role = String(request.role || 'analyst');

  // 2. 미등록 기기 즉시 차단
  if (request.deviceRegistered === false) {
    return {
      decision: 'deny',
      ruleId: 'ZTNA-02-UNREGISTERED-DEVICE',
      reason: '미등록 기기(deviceRegistered: false)에서의 접근 요청이므로 제로 트러스트 기기 준수 정책에 따라 차단합니다.',
      stepUpRequired: false,
      checkedAt,
      cards: buildThreePillarCards(request, 'deny')
    };
  }

  // 3. 명확한 침해/위협 신호 감지 시 즉시 차단
  const highRiskSignals = ['compromised_session', 'impossible_travel', 'malware_detected', 'sql_injection_attempt', 'blacklisted_ip'];
  const hitSignal = signals.find((s) => highRiskSignals.includes(s));
  if (hitSignal) {
    return {
      decision: 'deny',
      ruleId: 'ZTNA-03-THREAT-SIGNAL-DENY',
      reason: `실시간 위협 신호(${hitSignal})가 감지되어 세션 접근을 즉시 차단합니다.`,
      stepUpRequired: false,
      checkedAt,
      cards: buildThreePillarCards(request, 'deny')
    };
  }

  // 4. 최소 권한 원칙(PoLP) 및 역할 기반 접근 제어(RBAC) 위반 차단
  if (pathStr.startsWith('/admin/soar-override') && role !== 'soc-admin') {
    return {
      decision: 'deny',
      ruleId: 'ZTNA-04-RBAC-POLP-DENY',
      reason: `최소 권한 원칙(PoLP/RBAC)에 따라 현재 역할(${role})은 민감 통제 경로(${pathStr})에 접근할 수 없습니다.`,
      stepUpRequired: false,
      checkedAt,
      cards: buildThreePillarCards(request, 'deny')
    };
  }

  // 5. 민감 경로 접근 또는 경미한 이상 징후 시 Step-Up(MFA/생체인증) 재인증 요구 (challenge)
  const isSensitivePath = pathStr.startsWith('/soar/execute') || pathStr.startsWith('/tenant/policy') || pathStr.startsWith('/vault');
  const hasAnomalySignal = signals.includes('new_location') || signals.includes('unusual_hour') || signals.includes('elevated_action');
  if ((isSensitivePath || hasAnomalySignal) && request.stepUp !== true) {
    return {
      decision: 'challenge',
      ruleId: 'ZTNA-05-STEPUP-CHALLENGE',
      reason: '민감 통제 경로 접근 또는 비일상적 접속 징후가 감지되어 Step-Up(MFA/생체인증) 추가 검증을 요구합니다.',
      stepUpRequired: true,
      checkedAt,
      cards: buildThreePillarCards(request, 'challenge')
    };
  }

  // 6. 신원·기기·세션 모두 정상 검증 완료
  return {
    decision: 'allow',
    ruleId: 'ZTNA-06-VERIFIED-ALLOW',
    reason: '신원(Identity)·등록 기기(Device)·세션(Session) 및 최소 권한(PoLP) 검증을 모두 통과했습니다.',
    stepUpRequired: false,
    checkedAt,
    cards: buildThreePillarCards(request, 'allow')
  };
}

export function buildThreePillarCards(request = {}, decision = 'unknown') {
  const userSub = request.sub || 'analyst-01@jw-xdr.local';
  const issuer = request.issuer || 'https://auth.jw-xdr.internal';
  const role = request.role || 'soc-analyst';
  const devReg = request.deviceRegistered;
  const stepUp = request.stepUp;

  return {
    identity: {
      section: 'identity',
      status: decision === 'unknown' ? 'unknown' : 'verified',
      subject: userSub,
      issuer,
      role,
      polpStatus: decision === 'deny' && role !== 'soc-admin' ? '권한 초과 차단' : '최소 권한(PoLP) 준수'
    },
    device: {
      section: 'device',
      status: devReg === true ? 'compliant' : devReg === false ? 'unregistered' : 'unknown',
      deviceRegistered: Boolean(devReg),
      label: devReg === true ? '등록 기기 · 보안 정책 준수' : devReg === false ? '미등록 기기 (차단 대상)' : '기기 상태 확인 불가'
    },
    session: {
      section: 'session',
      status: stepUp === true ? 'step_up_verified' : decision === 'challenge' ? 'challenge_required' : 'standard_active',
      stepUp: Boolean(stepUp),
      label: stepUp === true ? 'Step-Up(MFA) 완료 세션' : decision === 'challenge' ? 'Step-Up 재인증 필요' : '일반 활성 세션'
    }
  };
}
