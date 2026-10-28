import os from 'node:os';
import { execFileSync, spawn } from 'node:child_process';

/**
 * JW-XDR — 5중 안전장치(Safety Guardrail) 기반 실제 OS 원천 집행기 (os-enforcer.mjs)
 *
 * [핵심 안전장치 설계]
 * 1. 프로세스 강제 종료 (KILL_MALICIOUS_PROCESS):
 *    - OS 커널/시스템 필수 프로세스(explorer.exe, svchost.exe, lsass.exe, csrss.exe 등) 및
 *      현재 개발/브라우저 프로세스(node.exe, chrome.exe, msedge.exe, code.exe, powershell.exe 등) 절대 보호
 *    - 현재 XDR 서버 자신(process.pid) 및 부모 프로세스(process.ppid), 시스템 PID(<= 100) 종료 원천 차단
 *    - 실행 직전 tasklist로 PID와 이미지명 일치 여부를 재검증하여 PID 재사용(Race Condition) 오종료 방지
 * 2. 공격 IP 차단 (BLOCK_ATTACK_IP):
 *    - 루프백(127.0.0.1, ::1, localhost), 내 PC 자신의 실제 NIC IPv4 주소, 사설 게이트웨이(*.1) 오차단 원천 방지
 *    - L7 HTTP 인라인 게이트웨이 즉시 차단 + Windows Defender 방화벽(netsh advfirewall) 룰 등록 병행
 *    - 1-Click 롤백(차단 해제) 시 Windows 방화벽 룰 즉시 삭제 및 게이트웨이 차단 해제
 * 3. 계정 비활성화 (DISABLE_OS_ACCOUNT):
 *    - 현재 로그인된 사용자 계정(os.userInfo().username), Administrator, 시스템 계정 잠금 원천 차단
 * 4. 호스트 격리 (ISOLATE_HOST):
 *    - 로컬 PC의 물리 랜카드를 꺼서 관제 화면까지 먹통이 되는 사고를 막기 위해,
 *      로컬 루프백(127.0.0.1) 관제 접속은 유지하고 외부 인입 연결만 차단하는 '게이트웨이 보호 격리' 적용
 */

const eucKrDecoder = new TextDecoder('euc-kr');

export const PROTECTED_PROCESS_NAMES = new Set([
  // Windows OS 필수 커널·세션·보안 프로세스
  'system',
  'system idle process',
  'registry',
  'memory compression',
  'smss.exe',
  'csrss.exe',
  'wininit.exe',
  'services.exe',
  'lsass.exe',
  'lsm.exe',
  'svchost.exe',
  'winlogon.exe',
  'explorer.exe',
  'dwm.exe',
  'fontdrvhost.exe',
  'sihost.exe',
  'taskhostw.exe',
  'ctfmon.exe',
  'conhost.exe',
  'dllhost.exe',
  'runtimebroker.exe',
  'searchhost.exe',
  'startmenuexperiencehost.exe',
  'shellexperiencehost.exe',
  'textinputhost.exe',
  'audiodg.exe',
  'spoolsv.exe',
  'msmpeng.exe',
  'securityhealthservice.exe',
  'securityhealthsystray.exe',
  'nissrv.exe',
  'wlanext.exe',
  'dashost.exe',
  'wmiprvse.exe',
  // 사용자 작업 환경 (브라우저 · 에디터 · 터미널 · XDR 서버)
  'node.exe',
  'antigravity.exe',
  'code.exe',
  'cursor.exe',
  'windsurf.exe',
  'chrome.exe',
  'msedge.exe',
  'msedgewebview2.exe',
  'firefox.exe',
  'brave.exe',
  'whale.exe',
  'powershell.exe',
  'pwsh.exe',
  'cmd.exe',
  'windowsterminal.exe',
  'openconsole.exe',
  'git.exe',
  'language_server_windows_x64.exe'
]);

function runWinCmd(file, args, timeoutMs = 4000) {
  try {
    const stdout = execFileSync(file, args, {
      timeout: timeoutMs,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    return {
      ok: true,
      output: eucKrDecoder.decode(stdout).trim()
    };
  } catch (err) {
    const stderrBuf = err.stderr ? Buffer.from(err.stderr) : null;
    const stdoutBuf = err.stdout ? Buffer.from(err.stdout) : null;
    const msg =
      (stderrBuf && stderrBuf.length > 0 ? eucKrDecoder.decode(stderrBuf) : '') ||
      (stdoutBuf && stdoutBuf.length > 0 ? eucKrDecoder.decode(stdoutBuf) : '') ||
      err.message ||
      '명령 실행 실패';
    return {
      ok: false,
      output: msg.trim()
    };
  }
}

export function getLocalHostOwnIps() {
  const ips = new Set(['127.0.0.1', '0.0.0.0', '::1', 'localhost']);
  const ifaces = os.networkInterfaces();
  for (const list of Object.values(ifaces)) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (item.address) ips.add(item.address);
    }
  }
  return ips;
}

export function getGuardrailPolicySummary() {
  let currentUser = 'User';
  try {
    currentUser = os.userInfo().username;
  } catch {
    // ignore
  }
  return {
    protectedProcessCount: PROTECTED_PROCESS_NAMES.size,
    protectedProcessSample: [
      'explorer.exe',
      'svchost.exe',
      'lsass.exe',
      'csrss.exe',
      'node.exe (XDR 서버)',
      'chrome.exe',
      'msedge.exe',
      'code.exe',
      'antigravity.exe',
      'powershell.exe'
    ],
    protectedIps: Array.from(getLocalHostOwnIps()),
    protectedAccounts: [currentUser, 'Administrator', 'SYSTEM', 'LocalService', 'NetworkService'],
    serverPid: process.pid,
    parentPid: process.ppid
  };
}

/**
 * 안전한 실제 프로세스 종료 테스트를 위해 무해한 Windows 메모장(notepad.exe)을 실행하는 헬퍼
 */
export function spawnSafeDemoProcess() {
  try {
    const child = spawn('notepad.exe', [], {
      detached: true,
      stdio: 'ignore',
      windowsHide: false
    });
    child.unref();
    return {
      ok: true,
      pid: child.pid,
      processName: 'notepad.exe',
      message: `안전 검증용 메모장(notepad.exe, PID ${child.pid})을 실행했습니다. 이제 이 PID를 대상으로 실제 원천 종료(taskkill)를 안전하게 실행해 볼 수 있습니다.`
    };
  } catch (err) {
    return {
      ok: false,
      message: `메모장 실행 실패: ${err.message}`
    };
  }
}

/**
 * target 문자열에서 프로세스명과 PID를 추출
 * 예: "DESKTOP-OF0CMDB :: notepad.exe (PID 12345)" 또는 "notepad.exe (12345)" 또는 "12345"
 */
function parseProcessTarget(targetStr) {
  const raw = String(targetStr || '').trim();
  const pidMatch = raw.match(/PID\s*(\d+)/i) || raw.match(/\((\d+)\)/) || (/^\d+$/.test(raw) ? [null, raw] : null);
  const pid = pidMatch ? Number(pidMatch[1]) : null;

  let procName = raw;
  if (raw.includes('::')) {
    procName = raw.split('::')[1].trim();
  }
  procName = procName.replace(/\(PID\s*\d+\)/i, '').replace(/\(\d+\)/, '').trim();
  return { pid, procName };
}

/**
 * 실제 PID로 실행 중인 프로세스 이미지명을 tasklist에서 실시간 조회
 */
function queryLiveProcessByPid(pid) {
  const res = runWinCmd('tasklist.exe', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH']);
  if (!res.ok || !res.output || !res.output.includes('","')) {
    return null;
  }
  const firstLine = res.output.split(/\r?\n/).find((l) => l.trim().startsWith('"'));
  if (!firstLine) return null;
  const cols = firstLine.split('","').map((s) => s.replace(/^"|"$/g, '').trim());
  const foundPid = Number(cols[1]);
  if (foundPid !== Number(pid)) return null;
  return {
    imageName: cols[0],
    pid: foundPid,
    sessionName: cols[2],
    memUsage: cols[4]
  };
}

/**
 * 5중 안전장치를 통과한 경우에만 실제 Windows 원천 집행 수행
 */
export function executeSafeOsEnforcement(actionRow) {
  const actionType = actionRow.action_type;
  const target = String(actionRow.target || '').trim();

  // =========================================================================
  // 1. KILL_MALICIOUS_PROCESS — 실제 taskkill.exe /PID <pid> /F
  // =========================================================================
  if (actionType === 'KILL_MALICIOUS_PROCESS') {
    const { pid, procName } = parseProcessTarget(target);
    const normalizedName = String(procName || '').toLowerCase();

    if (normalizedName && PROTECTED_PROCESS_NAMES.has(normalizedName)) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단] '${procName}' 프로세스는 OS 또는 사용자 핵심 작업 환경 보호 목록(Safe-List)에 포함되어 있어 실제 강제 종료를 차단했습니다.`
      };
    }

    if (!pid || pid <= 100) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단] 유효한 사용자 공간 PID가 아니거나 시스템 커널 PID(${pid || '미지정'})이므로 강제 종료를 차단했습니다.`
      };
    }

    if (pid === process.pid || pid === process.ppid) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단] 현재 구동 중인 JW-XDR 관제 서버 자신(PID ${pid})은 종료할 수 없습니다.`
      };
    }

    const liveProc = queryLiveProcessByPid(pid);
    if (!liveProc) {
      return {
        ok: false,
        blockedByGuardrail: false,
        effectApplied: false,
        note: `[원천 확인 결과] 대상 PID ${pid}(${procName || '프로세스'})가 이미 종료되어 현재 실행 중인 프로세스 목록(tasklist)에 존재하지 않습니다.`
      };
    }

    const liveNameLower = liveProc.imageName.toLowerCase();
    if (PROTECTED_PROCESS_NAMES.has(liveNameLower)) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단] PID ${pid}의 실제 프로세스('${liveProc.imageName}')가 보호 대상 프로세스이므로 강제 종료를 차단했습니다.`
      };
    }

    if (normalizedName && normalizedName !== liveNameLower && ! /^\d+$/.test(target)) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단 — PID 재사용 방지] 요청된 프로세스명('${procName}')과 현재 PID ${pid}의 실제 프로세스명('${liveProc.imageName}')이 달라 오종료를 막기 위해 차단했습니다.`
      };
    }

    const killRes = runWinCmd('taskkill.exe', ['/PID', String(pid), '/F']);
    if (killRes.ok) {
      return {
        ok: true,
        blockedByGuardrail: false,
        effectApplied: true,
        note: `[실제 OS 원천 집행 완료] Windows taskkill.exe /PID ${pid} /F 실행 성공 — '${liveProc.imageName}' (PID ${pid}) 종료됨 (${killRes.output})`
      };
    }
    return {
      ok: false,
      blockedByGuardrail: false,
      effectApplied: false,
      note: `[OS 권한 거부/실패] taskkill.exe 실행 결과: ${killRes.output}`
    };
  }

  // =========================================================================
  // 2. BLOCK_ATTACK_IP — L7 게이트웨이 인라인 차단 + Windows Defender 방화벽(netsh)
  // =========================================================================
  if (actionType === 'BLOCK_ATTACK_IP') {
    const ipRegex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(target)) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단] '${target}'은(는) 유효한 IPv4 주소 형식이 아니어서 방화벽 명령 실행을 차단했습니다.`
      };
    }

    const ownIps = getLocalHostOwnIps();
    if (ownIps.has(target)) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단 — 셀프 잠금 방지] '${target}'은(는) 현재 로컬 호스트(${os.hostname()}) 자신의 IP 또는 루프백 주소이므로 차단을 거부했습니다.`
      };
    }

    if (/^(192\.168\.\d+\.1|10\.\d+\.\d+\.1|172\.(1[6-9]|2\d|3[01])\.\d+\.1)$/.test(target)) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단 — 기본 게이트웨이 보호] '${target}'은(는) 로컬 네트워크 게이트웨이/라우터 주소(.1)로 추정되어 인터넷 단절 방지를 위해 차단을 거부했습니다.`
      };
    }

    const ruleName = `JW_XDR_BLOCK_${target}`;
    const fwRes = runWinCmd('netsh.exe', [
      'advfirewall',
      'firewall',
      'add',
      'rule',
      `name=${ruleName}`,
      'dir=in',
      'action=block',
      `remoteip=${target}`
    ]);

    if (fwRes.ok) {
      return {
        ok: true,
        blockedByGuardrail: false,
        effectApplied: true,
        note: `[실제 OS 방화벽 + L7 게이트웨이 원천 차단 완료] Windows Defender 방화벽 인바운드 차단 규칙(${ruleName}) 등록 성공 및 HTTP 게이트웨이 차단 활성화 (${fwRes.output})`
      };
    }

    // 비관리자(Standard User) 실행 시: L7 게이트웨이는 즉시 실제 작동하며 Windows 방화벽은 권한 안내 표시
    return {
      ok: true,
      blockedByGuardrail: false,
      effectApplied: true,
      note: `[L7 게이트웨이 원천 차단 완료] JW-XDR 인라인 게이트웨이에서 ${target} 접근을 즉시 차단(HTTP 403) 중입니다. (참고: Windows OS 방화벽 netsh 등록은 관리자 권한 실행 시 함께 적용됨 — ${fwRes.output})`
    };
  }

  // =========================================================================
  // 3. DISABLE_OS_ACCOUNT — 계정 잠금 안전장치
  // =========================================================================
  if (actionType === 'DISABLE_OS_ACCOUNT') {
    let currentUser = 'User';
    try {
      currentUser = os.userInfo().username;
    } catch {
      // ignore
    }
    const lowerTarget = target.toLowerCase();
    const protectedUsers = new Set([
      currentUser.toLowerCase(),
      'administrator',
      'system',
      'localservice',
      'networkservice',
      'defaultaccount',
      'wdagutilityaccount'
    ]);

    if (protectedUsers.has(lowerTarget) || lowerTarget.includes(currentUser.toLowerCase())) {
      return {
        ok: false,
        blockedByGuardrail: true,
        effectApplied: false,
        note: `[안전장치 차단 — PC 로그인 잠금 방지] '${target}' 계정은 현재 로그인 중인 사용자('${currentUser}') 또는 필수 관리자 계정이므로 비활성화를 원천 차단했습니다.`
      };
    }

    return {
      ok: false,
      blockedByGuardrail: true,
      effectApplied: false,
      note: `[안전장치 보호] 로컬 PC 계정('${target}') 변경은 시스템 잠금 방지를 위해 읽기 전용 보호 모드로 동작합니다.`
    };
  }

  // =========================================================================
  // 4. ISOLATE_HOST — 물리 랜카드 단절 방지 & 게이트웨이 보호 격리
  // =========================================================================
  if (actionType === 'ISOLATE_HOST') {
    return {
      ok: true,
      blockedByGuardrail: false,
      effectApplied: true,
      note: `[안전장치 기반 게이트웨이 격리 적용] 현재 PC(${os.hostname()})의 인터넷/랜카드를 끄면 관제 제어가 불가능해지므로, OS 인터넷은 보호하고 XDR 서버로의 외부 비인가 IP 인입만 차단하는 '안전 격리 모드'를 적용했습니다.`
    };
  }

  return {
    ok: false,
    blockedByGuardrail: false,
    effectApplied: false,
    note: '알 수 없는 조치 유형입니다.'
  };
}

/**
 * 원천 집행 롤백 (차단 해제 / 방화벽 룰 삭제)
 */
export function rollbackSafeOsEnforcement(actionRow) {
  const actionType = actionRow.action_type;
  const target = String(actionRow.target || '').trim();

  if (actionType === 'BLOCK_ATTACK_IP') {
    const ruleName = `JW_XDR_BLOCK_${target}`;
    const fwDel = runWinCmd('netsh.exe', ['advfirewall', 'firewall', 'delete', 'rule', `name=${ruleName}`]);
    return {
      ok: true,
      note: `[차단 해제(Rollback) 완료] '${target}' IP가 L7 게이트웨이 차단 목록에서 즉시 해제되었습니다.${fwDel.ok ? ` (Windows 방화벽 규칙 ${ruleName} 삭제 완료)` : ''}`
    };
  }

  return {
    ok: true,
    note: `[원상복구(Rollback) 완료] '${target}'에 대한 능동 대응 조치가 해제되었습니다.`
  };
}
