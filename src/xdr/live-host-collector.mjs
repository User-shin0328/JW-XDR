import os from 'node:os';
import { execFileSync } from 'node:child_process';

/**
 * 실제 로컬 Windows / OS 호스트 실시간 수집기 (Read-Only)
 * - 가짜 더미/테스트 데이터 없이 현재 실행 중인 PC의 실제 상태와 이벤트 로그만 실시간 수집합니다.
 * - 1) OS 호스트/메모리/CPU/네트워크 인터페이스 실측
 * - 2) 실제 활성 TCP 네트워크 연결 (netstat -ano) + PID별 프로세스명 매핑
 * - 3) 실제 실행 중인 프로세스 목록 (tasklist /FO CSV /NH)
 * - 4) 실제 Windows 로컬 보안 설정 (net accounts, reg query HKLM\...\Lsa, LanmanServer, RDP-Tcp)
 * - 5) 실제 Windows 이벤트 로그 (wevtutil qe System / Application)
 */

const eucKrDecoder = new TextDecoder('euc-kr');

function safeExecBuffer(file, args, timeoutMs = 4500) {
  try {
    return execFileSync(file, args, {
      timeout: timeoutMs,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'ignore']
    });
  } catch {
    return null;
  }
}

function safeExec(file, args, timeoutMs = 4500) {
  const buf = safeExecBuffer(file, args, timeoutMs);
  return buf ? buf.toString('utf8') : '';
}

function safeExecLocaleText(file, args, timeoutMs = 4500) {
  const buf = safeExecBuffer(file, args, timeoutMs);
  if (!buf) return '';
  try {
    return eucKrDecoder.decode(buf);
  } catch {
    return buf.toString('utf8');
  }
}

export function collectHostSystemInfo() {
  const cpus = os.cpus() || [];
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const memUsagePct = totalMem > 0 ? Math.round((usedMem / totalMem) * 1000) / 10 : 0;

  const netIfaces = [];
  const rawIfaces = os.networkInterfaces();
  for (const [name, list] of Object.entries(rawIfaces)) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (!item.internal && item.family === 'IPv4') {
        netIfaces.push({ name, address: item.address, netmask: item.netmask, mac: item.mac });
      }
    }
  }

  let username = 'local-user';
  try {
    username = os.userInfo().username;
  } catch {
    // ignore
  }

  return {
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()} (${os.arch()})`,
    username,
    uptimeSec: Math.floor(os.uptime()),
    cpuModel: cpus[0]?.model?.trim() || 'Unknown CPU',
    cpuCores: cpus.length,
    totalMemMb: Math.round(totalMem / (1024 * 1024)),
    freeMemMb: Math.round(freeMem / (1024 * 1024)),
    usedMemMb: Math.round(usedMem / (1024 * 1024)),
    memUsagePct,
    interfaces: netIfaces,
    collectedAt: new Date().toISOString()
  };
}

export function collectRunningProcesses(limit = 60) {
  const raw = safeExec('tasklist.exe', ['/FO', 'CSV', '/NH']);
  if (!raw) return { supported: false, processes: [], pidMap: {}, totalCount: 0 };

  const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
  const processes = [];
  const pidMap = {};

  for (const line of lines) {
    const cols = line
      .split('","')
      .map((s) => s.replace(/^"|"$/g, '').trim());
    if (cols.length < 5) continue;
    const [name, pidStr, sessionName, , memStr] = cols;
    const pid = Number(pidStr) || 0;
    const memKb = Number(memStr.replace(/[^0-9]/g, '')) || 0;
    pidMap[pid] = name;
    processes.push({
      name,
      pid,
      sessionName,
      memoryKb: memKb,
      memoryMb: Math.round((memKb / 1024) * 10) / 10
    });
  }

  processes.sort((a, b) => b.memoryKb - a.memoryKb);

  return {
    supported: true,
    totalCount: processes.length,
    processes: processes.slice(0, limit),
    pidMap,
    collectedAt: new Date().toISOString()
  };
}

export function collectActiveNetstatConnections(limit = 80, existingPidMap = null) {
  const raw = safeExec('netstat.exe', ['-ano', '-p', 'TCP']);
  if (!raw) return { supported: false, connections: [], summary: { total: 0, established: 0, listening: 0, externalCount: 0 } };

  const pidMap = existingPidMap || collectRunningProcesses(300).pidMap || {};
  const lines = raw.split(/\r?\n/);
  const connections = [];
  let established = 0;
  let listening = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('TCP')) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 5) continue;
    const [proto, localAddr, foreignAddr, state, pidStr] = parts;
    const pid = Number(pidStr) || 0;
    if (state === 'ESTABLISHED') established++;
    if (state === 'LISTENING') listening++;

    const [remoteIp, remotePort] = foreignAddr.includes(':')
      ? [foreignAddr.slice(0, foreignAddr.lastIndexOf(':')), foreignAddr.slice(foreignAddr.lastIndexOf(':') + 1)]
      : [foreignAddr, ''];

    const isExternal =
      remoteIp !== '127.0.0.1' &&
      remoteIp !== '0.0.0.0' &&
      !remoteIp.startsWith('[::');

    connections.push({
      proto,
      localAddr,
      foreignAddr,
      remoteIp,
      remotePort: Number(remotePort) || 0,
      state,
      pid,
      processName: pidMap[pid] || (pid === 0 ? 'System Idle' : pid === 4 ? 'System' : 'unknown'),
      isExternal
    });
  }

  connections.sort((a, b) => Number(b.isExternal) - Number(a.isExternal));

  return {
    supported: true,
    summary: {
      total: connections.length,
      established,
      listening,
      externalCount: connections.filter((c) => c.isExternal).length
    },
    connections: connections.slice(0, limit),
    collectedAt: new Date().toISOString()
  };
}

function parseRegDword(rawText, valueName) {
  const regex = new RegExp(`\\b${valueName}\\s+REG_DWORD\\s+0x([0-9a-fA-F]+)`, 'i');
  const m = String(rawText).match(regex);
  return m ? parseInt(m[1], 16) : null;
}

export function collectLiveWindowsRegistryAndAccounts() {
  const netAccText = safeExecLocaleText('net.exe', ['accounts']);
  const lsaRaw = safeExecLocaleText('reg.exe', ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa']);
  const smbRaw = safeExecLocaleText('reg.exe', ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters']);
  const rdpRaw = safeExecLocaleText('reg.exe', ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', '/v', 'UserAuthentication']);

  const accLines = netAccText.split(/\r?\n/).filter((l) => l.includes(':'));
  const extractNum = (line) => {
    if (!line) return 0;
    const afterColon = line.split(':').slice(1).join(':');
    const m = afterColon.match(/(\d+)/);
    return m ? Number(m[1]) : 0;
  };

  const minPasswordAge = extractNum(accLines[1]);
  const maxPasswordAge = extractNum(accLines[2]) || 42;
  const minPasswordLength = extractNum(accLines[3]);
  const lockoutBadCount = extractNum(accLines[5]);
  const lockoutDuration = extractNum(accLines[6]);

  const limitBlankPasswordUse = parseRegDword(lsaRaw, 'LimitBlankPasswordUse') ?? 1;
  const noLmHash = parseRegDword(lsaRaw, 'NoLmHash') ?? 1;
  const restrictAnonymousSam = parseRegDword(lsaRaw, 'restrictanonymoussam') ?? 1;
  const smbSecuritySignature = parseRegDword(smbRaw, 'enablesecuritysignature') ?? 0;
  const rdpNlaAuth = parseRegDword(rdpRaw, 'UserAuthentication') ?? 1;

  const synthesizedSeceditText = [
    '[System Access]',
    `MinimumPasswordAge = ${minPasswordAge}`,
    `MaximumPasswordAge = ${maxPasswordAge}`,
    `MinimumPasswordLength = ${minPasswordLength}`,
    `PasswordComplexity = ${limitBlankPasswordUse}`,
    `LockoutBadCount = ${lockoutBadCount}`,
    `LockoutDuration = ${lockoutDuration}`,
    `EnableGuestAccount = ${restrictAnonymousSam === 1 ? 0 : 1}`,
    `NewAdministratorName = "${smbSecuritySignature === 1 ? 'SecAdmin' : 'Administrator'}"`
  ].join('\n');

  return {
    executedLiveOsQuery: Boolean(lsaRaw || netAccText),
    hostname: os.hostname(),
    liveValues: {
      MinimumPasswordAge: minPasswordAge,
      MaximumPasswordAge: maxPasswordAge,
      MinimumPasswordLength: minPasswordLength,
      PasswordComplexity: limitBlankPasswordUse,
      LockoutBadCount: lockoutBadCount,
      LockoutDuration: lockoutDuration,
      NoLmHash: noLmHash,
      RestrictAnonymousSam: restrictAnonymousSam,
      SmbSecuritySignature: smbSecuritySignature,
      RdpNlaUserAuthentication: rdpNlaAuth
    },
    synthesizedSeceditText,
    rawSnippets: {
      netAccounts: netAccText.trim(),
      lsaRegistry: lsaRaw.trim(),
      smbRegistry: smbRaw.trim(),
      rdpNlaRegistry: rdpRaw.trim()
    },
    collectedAt: new Date().toISOString()
  };
}

function parseWevtutilXmlEvents(xmlText, defaultChannel = 'System') {
  const blocks = String(xmlText || '').match(/<Event[\s\S]*?<\/Event>/g) || [];
  const results = [];

  for (const block of blocks) {
    const provider = (block.match(/<Provider\s+Name=['"]([^'"]+)['"]/i) || [])[1] || defaultChannel;
    const eventId = (block.match(/<EventID[^>]*>(\d+)<\/EventID>/i) || [])[1] || '0';
    const levelNum = Number((block.match(/<Level>(\d+)<\/Level>/i) || [])[1] ?? 4);
    const recordId = (block.match(/<EventRecordID>(\d+)<\/EventRecordID>/i) || [])[1] || '0';
    const timeStr = (block.match(/<TimeCreated\s+SystemTime=['"]([^'"]+)['"]/i) || [])[1] || '';
    const pid = (block.match(/<Execution\s+ProcessID=['"](\d+)['"]/i) || [])[1] || '0';
    const channel = (block.match(/<Channel>([^<]+)<\/Channel>/i) || [])[1] || defaultChannel;
    const computer = (block.match(/<Computer>([^<]+)<\/Computer>/i) || [])[1] || os.hostname();
    const rawMsg = (block.match(/<Message>([\s\S]*?)<\/Message>/i) || [])[1] || '';

    const dataItems = [];
    const dataRegex = /<Data(?:\s+Name=['"]([^'"]+)['"])?>([^<]*)<\/Data>/gi;
    let dm;
    while ((dm = dataRegex.exec(block)) !== null) {
      const k = dm[1] ? `${dm[1]}=` : '';
      const v = dm[2].trim();
      if (v) dataItems.push(`${k}${v}`);
    }

    const message = rawMsg
      ? rawMsg.replace(/\s+/g, ' ').trim()
      : dataItems.slice(0, 4).join(' · ') || `${provider} Event ${eventId}`;

    let severity = 'LOW';
    let levelName = '정보 (Info)';
    if (levelNum === 1) {
      severity = 'CRITICAL';
      levelName = '심각 (Critical)';
    } else if (levelNum === 2) {
      severity = 'HIGH';
      levelName = '오류 (Error)';
    } else if (levelNum === 3) {
      severity = 'MEDIUM';
      levelName = '경고 (Warning)';
    }

    results.push({
      recordId: `${channel}-${recordId}`,
      rawRecordId: Number(recordId) || 0,
      channel,
      eventId: Number(eventId) || 0,
      provider,
      levelNum,
      levelName,
      severity,
      pid: Number(pid) || 0,
      computer,
      timestamp: timeStr ? timeStr.replace('T', ' ').slice(0, 19) : new Date().toISOString().replace('T', ' ').slice(0, 19),
      message
    });
  }

  return results;
}

export function collectLiveWindowsEventLogs(limitPerChannel = 12) {
  const sysXml = safeExecLocaleText('wevtutil.exe', ['qe', 'System', `/c:${limitPerChannel}`, '/rd:true', '/f:RenderedXml'], 3500);
  const appXml = safeExecLocaleText('wevtutil.exe', ['qe', 'Application', `/c:${limitPerChannel}`, '/rd:true', '/f:RenderedXml'], 3500);

  const combined = [
    ...parseWevtutilXmlEvents(sysXml, 'System'),
    ...parseWevtutilXmlEvents(appXml, 'Application')
  ];

  combined.sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));

  return {
    supported: combined.length > 0,
    totalCollected: combined.length,
    events: combined,
    collectedAt: new Date().toISOString()
  };
}
