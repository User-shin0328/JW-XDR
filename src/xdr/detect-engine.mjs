/**
 * Module 2: SIEM/XDR Threat Detection & MITRE ATT&CK Mapping Engine
 * 15단계 + 특강 1·2·4·6구간 (6대 핵심 위협 시나리오 탐지, MITRE ATT&CK 매핑, 심각도 분류)
 */

export const THREAT_CATALOG = {
  'brute-force': {
    category: 'brute-force',
    name: '비밀번호 다회 오류 / 크리덴셜 스터핑',
    mitreTactic: 'Credential Access (TA0006)',
    mitreTechnique: 'T1110 (Brute Force)',
    killChainStage: '자격증명 접근',
    defaultSeverity: '높음',
    ruleLevel: 8
  },
  'web-injection': {
    category: 'web-injection',
    name: '쿼리스트링 SQL Injection / XSS 공격',
    mitreTactic: 'Initial Access (TA0001)',
    mitreTechnique: 'T1190 (Exploit Public-Facing App)',
    killChainStage: '초기 접근',
    defaultSeverity: '크리티컬',
    ruleLevel: 12
  },
  'known-cve': {
    category: 'known-cve',
    name: '공개 CVE 취약점 악용 요청',
    mitreTactic: 'Execution (TA0002)',
    mitreTechnique: 'T1203 (Exploitation for Client Execution)',
    killChainStage: '실행',
    defaultSeverity: '크리티컬',
    ruleLevel: 12
  },
  'persistence': {
    category: 'persistence',
    name: '레지스트리 Run 키 / 예약 작업 영속성 변조',
    mitreTactic: 'Persistence (TA0003)',
    mitreTechnique: 'T1547 (Boot or Logon Autostart)',
    killChainStage: '지속',
    defaultSeverity: '높음',
    ruleLevel: 10
  },
  'privilege': {
    category: 'privilege',
    name: '비인가 관리자 권한 상승(Privilege Escalation) 시도',
    mitreTactic: 'Privilege Escalation (TA0004)',
    mitreTechnique: 'T1068 (Exploitation for Privilege Escalation)',
    killChainStage: '권한 상승',
    defaultSeverity: '크리티컬',
    ruleLevel: 11
  },
  'exfiltration': {
    category: 'exfiltration',
    name: '대량 개인정보/기밀 외부 유출 시도',
    mitreTactic: 'Exfiltration (TA0010)',
    mitreTechnique: 'T1041 (Exfiltration Over C2 Channel)',
    killChainStage: '유출',
    defaultSeverity: '크리티컬',
    ruleLevel: 12
  }
};

export const KILL_CHAIN_STAGES = [
  '정찰', '자원 개발', '초기 접근', '실행', '지속', '권한 상승', '방어 회피',
  '자격증명 접근', '탐색', '측면 이동', '수집', '명령·제어', '유출', '영향'
];

export function evaluateAlert(alert = {}) {
  const category = alert.category || inferCategory(alert);
  const meta = THREAT_CATALOG[category] || THREAT_CATALOG['brute-force'];
  const rawText = JSON.stringify(alert).toLowerCase();

  let action = 'record';
  let confidence = 0.35;
  let reason = '정상 범위의 시스템 활동으로 기록(record)합니다.';

  if (category === 'brute-force') {
    const failCount = Number(alert.failCount ?? alert.attempts ?? 0);
    if (failCount >= 10 || rawText.includes('credential_stuffing') || rawText.includes('blacklist')) {
      action = 'block';
      confidence = 0.92;
      reason = `짧은 시간 내 ${failCount || 15}회 연속 인증 실패 및 위협 IP 접촉이 확인되어 즉시 차단(block) 권고`;
    } else if (failCount >= 4) {
      action = 'alert';
      confidence = 0.68;
      reason = `반복된 로그인 오류(${failCount}회)가 감지되어 관제 주의 경보(alert) 발행`;
    }
  } else if (category === 'web-injection') {
    if (/union\s+select|or\s+1=1|<script|sleep\(|benchmark\(/i.test(rawText)) {
      action = 'block';
      confidence = 0.96;
      reason = '쿼리스트링 파라미터 내 명확한 SQL Injection / XSS 공격 구문이 탐지되어 차단(block) 권고';
    } else if (/select\s+|script|alert\(/i.test(rawText)) {
      action = 'alert';
      confidence = 0.72;
      reason = '웹 요청 내 비정상 특수문자 패턴이 포함되어 경보(alert) 발행';
    }
  } else if (category === 'known-cve') {
    if (/jndi:|cve-202|exploit|use-after-free|rce/i.test(rawText)) {
      action = 'block';
      confidence = 0.97;
      reason = '공개 CVE 취약점 악용 시그니처가 명확히 일치하여 즉시 차단(block) 권고';
    } else {
      action = 'alert';
      confidence = 0.75;
      reason = '취약 버전 패키지 대상 비정상 프로빙 요청 감지';
    }
  } else if (category === 'persistence') {
    if (/currentversion\\+run|schtasks\s+\/create|crontab|systemd/i.test(rawText)) {
      action = 'block';
      confidence = 0.91;
      reason = '재부팅 후 자동 실행을 위한 레지스트리 Run 키/스케줄러 영속성 변조가 확인되어 차단(block) 권고';
    } else {
      action = 'alert';
      confidence = 0.69;
      reason = '시작 프로그램 설정 영역 접근 감지';
    }
  } else if (category === 'privilege') {
    if (/pkexec|sudoers|suid|nt authority\\+system|seimpersonateprivilege/i.test(rawText)) {
      action = 'block';
      confidence = 0.93;
      reason = '일반 계정의 비인가 관리자/루트 권한 상승 시도가 탐지되어 차단(block) 권고';
    } else {
      action = 'alert';
      confidence = 0.74;
      reason = '비일상적인 관리자 권한 명령 호출 감지';
    }
  } else if (category === 'exfiltration') {
    const bytesOut = Number(alert.bytesOut ?? 0);
    if (bytesOut >= 100000 || /c2|exfil|external_dump/i.test(rawText)) {
      action = 'block';
      confidence = 0.95;
      reason = '미식별 외부 목적지로의 대용량 데이터 유출 전송이 포착되어 즉시 차단(block) 권고';
    } else {
      action = 'alert';
      confidence = 0.71;
      reason = '외부 대역으로의 비정상 아웃바운드 세션 증가 감지';
    }
  }

  return {
    action,
    confidence,
    reason,
    category: meta.category,
    mitreTactic: meta.mitreTactic,
    mitreTechnique: meta.mitreTechnique,
    killChainStage: meta.killChainStage,
    severity: action === 'block' ? meta.defaultSeverity : action === 'alert' ? '중간' : '낮음',
    ruleLevel: meta.ruleLevel
  };
}

function inferCategory(alert = {}) {
  const s = JSON.stringify(alert).toLowerCase();
  if (s.includes('union select') || s.includes('sqli') || s.includes('xss')) return 'web-injection';
  if (s.includes('cve-') || s.includes('jndi')) return 'known-cve';
  if (s.includes('currentversion\\run') || s.includes('schtasks')) return 'persistence';
  if (s.includes('pkexec') || s.includes('privilege') || s.includes('sudo')) return 'privilege';
  if (s.includes('exfil') || s.includes('bytesout')) return 'exfiltration';
  return 'brute-force';
}
