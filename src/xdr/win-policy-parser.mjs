/**
 * Module 3: Continuous Validation & Windows Local Security Policy Parser
 * 16단계 + 특강 3·4·5구간 (스냅샷 심사 ➔ 상시 실증 전환, secpol.msc 수동 vs 배치 자동 진단 1:1 비교, 민감정보 마스킹)
 */

export const WINDOWS_POLICY_BASELINE = [
  {
    id: 'POL-PWD-01',
    category: '암호 정책 (Password Policy)',
    key: 'PasswordComplexity',
    title: '패스워드 복잡성 만족 여부',
    recommended: '사용 (1)',
    expectedValue: 1,
    comparator: 'eq',
    mitreRef: 'T1110 (Brute Force 예방)',
    ismsRef: 'ISMS-P 2.5.4 비밀번호 관리'
  },
  {
    id: 'POL-PWD-02',
    category: '암호 정책 (Password Policy)',
    key: 'MinimumPasswordLength',
    title: '최소 암호 길이 (8자 이상 권장)',
    recommended: '8자 이상 (>= 8)',
    expectedValue: 8,
    comparator: 'gte',
    mitreRef: 'T1110.001 (Password Guessing 방어)',
    ismsRef: 'ISMS-P 2.5.4 / 주요정보통신기반시설 W-02'
  },
  {
    id: 'POL-PWD-03',
    category: '암호 정책 (Password Policy)',
    key: 'MaximumPasswordAge',
    title: '최대 암호 사용 기간 (90일 이하 권장)',
    recommended: '90일 이하 (1~90)',
    expectedValue: 90,
    comparator: 'lte_positive',
    mitreRef: 'T1078 (Valid Accounts 악용 완화)',
    ismsRef: 'ISMS-P 2.5.4 최대 사용기간 제한'
  },
  {
    id: 'POL-PWD-04',
    category: '암호 정책 (Password Policy)',
    key: 'MinimumPasswordAge',
    title: '최소 암호 사용 기간 (1일 이상 권장)',
    recommended: '1일 이상 (>= 1)',
    expectedValue: 1,
    comparator: 'gte',
    mitreRef: 'T1098 (즉시 재변경 우회 방지)',
    ismsRef: '주요정보통신기반시설 W-04'
  },
  {
    id: 'POL-LOCK-01',
    category: '계정 잠금 정책 (Account Lockout Policy)',
    key: 'LockoutBadCount',
    title: '계정 잠금 임계값 (로그인 실패 시 잠금)',
    recommended: '5회 이하 (1~5)',
    expectedValue: 5,
    comparator: 'lte_positive',
    mitreRef: 'TA0006 / T1110 (무차별 대입 공격 차단)',
    ismsRef: 'ISMS-P 2.5.3 사용자 인증 / PCI-DSS 8.3.4'
  },
  {
    id: 'POL-LOCK-02',
    category: '계정 잠금 정책 (Account Lockout Policy)',
    key: 'LockoutDuration',
    title: '계정 잠금 기간 및 원래대로 설정 시간',
    recommended: '30분 이상 (>= 30)',
    expectedValue: 30,
    comparator: 'gte',
    mitreRef: 'T1110 (자동화된 스터핑 지연)',
    ismsRef: '주요정보통신기반시설 W-03'
  },
  {
    id: 'POL-ACCT-01',
    category: '계정 관리 (Account Management)',
    key: 'EnableGuestAccount',
    title: '불필요한 게스트(Guest) 계정 비활성화 여부',
    recommended: '사용 안 함 (0)',
    expectedValue: 0,
    comparator: 'eq',
    mitreRef: 'T1078.003 (Local Accounts 오남용 차단)',
    ismsRef: 'ISMS-P 2.5.1 사용자 계정 관리'
  },
  {
    id: 'POL-ACCT-02',
    category: '계정 관리 (Account Management)',
    key: 'DefaultAdminRestricted',
    title: '기본 관리자(Administrator) 계정 이름 변경 또는 제한 여부',
    recommended: '적용 (1)',
    expectedValue: 1,
    comparator: 'eq',
    mitreRef: 'T1078 (기본 관리자 타겟팅 방어)',
    ismsRef: '주요정보통신기반시설 W-01'
  }
];

export const DEFAULT_AUTO_SCRIPT_DUMP = `
[System Access]
MinimumPasswordAge = 0
MaximumPasswordAge = 90
MinimumPasswordLength = 8
PasswordComplexity = 0
LockoutBadCount = 0
LockoutDuration = 0
ResetLockoutCount = 0
EnableAdminAccount = 1
EnableGuestAccount = 0
NewAdministratorName = "Administrator"
`.trim();

export function parseSeceditDump(rawText = DEFAULT_AUTO_SCRIPT_DUMP) {
  const parsed = {};
  const lines = String(rawText).split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$/);
    if (!m) continue;
    const key = m[1];
    const valRaw = m[2].replace(/^"|"$/g, '');
    const numVal = Number(valRaw);
    parsed[key] = Number.isNaN(numVal) ? valRaw : numVal;
  }
  const adminName = String(parsed.NewAdministratorName || 'Administrator');
  parsed.DefaultAdminRestricted = adminName.toLowerCase() !== 'administrator' ? 1 : 0;
  return parsed;
}

export function evaluatePolicyValue(rule, actualVal) {
  const v = Number(actualVal);
  if (Number.isNaN(v)) return '취약';
  if (rule.comparator === 'eq') return v === rule.expectedValue ? '양호' : '취약';
  if (rule.comparator === 'gte') return v >= rule.expectedValue ? '양호' : '취약';
  if (rule.comparator === 'lte_positive') return v >= 1 && v <= rule.expectedValue ? '양호' : '취약';
  return '취약';
}

export function compareManualVsAutoPolicy(manualChecklist = {}, rawAutoText = DEFAULT_AUTO_SCRIPT_DUMP) {
  const autoMap = parseSeceditDump(rawAutoText);

  // 기본 수동 점검 시나리오: 수강생이 secpol.msc에서 육안 점검 중 일부 항목(PasswordComplexity, LockoutBadCount)을 '양호'로 잘못 체크한 인적 오류 재현
  const defaultManual = {
    PasswordComplexity: '양호',      // 실제 자동 파싱은 0(취약) -> 인적 오류(불일치) 검출!
    MinimumPasswordLength: '양호',   // 실제 8(양호) -> 일치
    MaximumPasswordAge: '양호',      // 실제 90(양호) -> 일치
    MinimumPasswordAge: '취약',      // 실제 0(취약) -> 일치
    LockoutBadCount: '양호',         // 실제 0(설정안됨=취약)을 0회=안전으로 오해석 -> 인적 오류(불일치) 검출!
    LockoutDuration: '취약',         // 실제 0(취약) -> 일치
    EnableGuestAccount: '양호',      // 실제 0(비활성=양호) -> 일치
    DefaultAdminRestricted: '취약'   // 실제 Administrator 기본명 유지(취약) -> 일치
  };

  const mergedManual = { ...defaultManual, ...manualChecklist };
  const items = [];
  let mismatchCount = 0;
  let passCount = 0;

  for (const rule of WINDOWS_POLICY_BASELINE) {
    const rawVal = autoMap[rule.key] ?? 0;
    const autoVerdict = evaluatePolicyValue(rule, rawVal);
    const manualVerdict = mergedManual[rule.key] || autoVerdict;
    const isMismatch = manualVerdict !== autoVerdict;
    if (isMismatch) mismatchCount++;
    if (autoVerdict === '양호') passCount++;

    items.push({
      id: rule.id,
      category: rule.category,
      key: rule.key,
      title: rule.title,
      recommended: rule.recommended,
      actualRawValue: rawVal,
      manualVerdict,
      autoVerdict,
      isMismatch,
      humanErrorReason: isMismatch
        ? `수동 점검에서는 [${manualVerdict}]로 판정했으나, secedit/reg 자동 실측값(${rule.key}=${rawVal})은 [${autoVerdict}]입니다. (수동 점검 시 누락·오해석 인적 오류 검출)`
        : '수동 점검 결과와 자동 스크립트 실증 결과가 일치합니다.',
      mitreRef: rule.mitreRef,
      ismsRef: rule.ismsRef
    });
  }

  const complianceScore = Number(((passCount / WINDOWS_POLICY_BASELINE.length) * 100).toFixed(1));
  return {
    checkedAt: new Date().toISOString(),
    hostname: 'WIN11-SEC-ENDPOINT',
    mode: 'READ_ONLY_CONTINUOUS_VALIDATION',
    totalItems: WINDOWS_POLICY_BASELINE.length,
    passCount,
    failCount: WINDOWS_POLICY_BASELINE.length - passCount,
    mismatchCount,
    complianceScore,
    items,
    unverifiableSandboxItems: [
      {
        key: 'KernelFirewallDriverState',
        label: '원천 커널 방화벽 필터 드라이버 내부 상태',
        status: 'unverifiable',
        reason: '브라우저/일반 권한 샌드박스에서는 OS 커널 영역 필터 드라이버 직접 조회가 차단되어 있으므로 추측하지 않고 [? 확인 불가]로 분리합니다.'
      },
      {
        key: 'OtherUsersProcessMemory',
        label: '타 세션 프로세스 메모리 덤프',
        status: 'unverifiable',
        reason: '최소 권한(Read-Only) 원칙 및 OS 보안 정책상 타 계정 프로세스 핸들 접근은 금지됩니다.'
      }
    ]
  };
}

// 16단계: 민감정보 마스킹([REDACTED]) 내보내기
export function redactSensitiveDiagnostics(inputObj = {}) {
  const sensitiveKeys = /token|secret|password|passwd|apikey|api_key|cookie|sessionkey|session_id|privatekey|authorization|ssn|phone|resident/i;
  function walk(val) {
    if (val === null || val === undefined) return val;
    if (Array.isArray(val)) return val.map(walk);
    if (typeof val === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(val)) {
        if (sensitiveKeys.test(k)) {
          out[k] = '[REDACTED]';
        } else {
          out[k] = walk(v);
        }
      }
      return out;
    }
    if (typeof val === 'string') {
      return val
        .replace(/(Bearer\s+)[A-Za-z0-9._-]+/gi, '$1[REDACTED]')
        .replace(/(sk-[A-Za-z0-9_-]{8,})/g, '[REDACTED]');
    }
    return val;
  }
  return walk(inputObj);
}
