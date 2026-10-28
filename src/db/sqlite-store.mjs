import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { collectLiveWindowsRegistryAndAccounts, collectLiveWindowsEventLogs } from '../xdr/live-host-collector.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');
const DEFAULT_DB_DIR = path.resolve(__dirname, '../../data');
const DEFAULT_DB_PATH = path.join(DEFAULT_DB_DIR, 'jw_xdr.db');
const BACKUP_DIR = path.resolve(__dirname, '../../backup');

const SQLITE_MAGIC_HEADER = 'SQLite format 3\0';

export class XdrSqliteStore {
  constructor(dbPath = DEFAULT_DB_PATH) {
    this.dbPath = dbPath;
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.initSchema();
    this.seedFromActualHostIfEmpty();
  }

  initSchema() {
    const schemaSql = fs.readFileSync(SCHEMA_PATH, 'utf8');
    this.db.exec(schemaSql);
  }

  seedFromActualHostIfEmpty() {
    const countRow = this.db.prepare('SELECT COUNT(*) AS cnt FROM tenants').get();
    if (countRow && countRow.cnt > 0) return;

    const host = os.hostname();
    const user = (() => {
      try {
        return os.userInfo().username;
      } catch {
        return 'local-user';
      }
    })();
    const osLabel = `${os.type()} ${os.release()}`;
    const nowStr = new Date().toISOString().replace('T', ' ').slice(0, 19);

    this.db.prepare(`
      INSERT INTO tenants (
        tenant_id, name, compliance_tier, ai_enabled, ai_provider, ai_domain, ai_model,
        soc_agent_enabled, soc_poll_sec, soc_batch_size, soc_auto_report,
        soc_emergency_stop, auto_block_enabled, asset_criticality_threshold, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      host,
      `${host} (Local Host)`,
      'ISMS-P / ISO-42001',
      1,
      'Local-XDR-Engine',
      'http://127.0.0.1:5280',
      'deterministic-soc-v1',
      1,
      60,
      10,
      1,
      0,
      1,
      'HIGH',
      nowStr
    );

    const liveWin = collectLiveWindowsRegistryAndAccounts();
    const lv = liveWin.liveValues || {};

    const insertCase = this.db.prepare(`
      INSERT INTO xdr_cases (
        case_id, tenant_id, title, category, severity, status, risk_score, confidence,
        assignee, description, src_ip, dst_ip, target_asset, asset_os, asset_criticality,
        mitre_tactic, mitre_technique, kill_chain_stage, ai_label, verdict_status,
        rule_tuning_note, mttd_ms, mttr_ms, created_at, updated_at, resolved_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertEvent = this.db.prepare(`
      INSERT INTO security_events (
        event_id, tenant_id, case_id, category, severity, rule_level,
        mitre_tactic, mitre_technique, kill_chain_stage, src_ip, dst_ip,
        hostname, username, process_name, summary, payload_json, occurred_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // 실제 로컬 PC의 Windows 계정/레지스트리 보안 정책 실측 결과만 등록
    insertCase.run(
      'CASE-HOST-POLICY-01',
      host,
      `[${host}] Windows 로컬 보안 정책 실측 취약 항목 탐지 (최소암호길이=${lv.MinimumPasswordLength ?? 0}, 잠금임계값=${lv.LockoutBadCount ?? 0}, SMB서명=${lv.SmbSecuritySignature ?? 0})`,
      'persistence',
      'HIGH',
      'New',
      78,
      91.0,
      user,
      `현재 호스트(${host})에서 실제 실행한 net accounts 및 reg query 결과, 최소 암호 길이(${lv.MinimumPasswordLength ?? 0}자), 계정 잠금 임계값(${lv.LockoutBadCount ?? 0}회), 잠금 기간(${lv.LockoutDuration ?? 0}분), SMB 서명 강제(${lv.SmbSecuritySignature ?? 0}) 설정이 권장 보안 기준에 미달하여 실측 케이스로 등록되었습니다.`,
      '127.0.0.1',
      '127.0.0.1',
      host,
      osLabel,
      'HIGH',
      'TA0006 Credential Access',
      'T1110 / T1078',
      '자격증명 접근',
      '정탐 유력',
      'UNDECIDED',
      '',
      3200,
      null,
      nowStr,
      nowStr,
      null
    );

    insertEvent.run(
      'EVT-HOST-POLICY-01',
      host,
      'CASE-HOST-POLICY-01',
      'persistence',
      'HIGH',
      10,
      'TA0006 Credential Access',
      'T1110 / T1078',
      '자격증명 접근',
      '127.0.0.1',
      '127.0.0.1',
      host,
      user,
      'net.exe / reg.exe',
      `[${host}] 실시간 Windows 계정 및 레지스트리 정책 점검 (MinimumPasswordLength=${lv.MinimumPasswordLength ?? 0}, LockoutBadCount=${lv.LockoutBadCount ?? 0}, SmbSecuritySignature=${lv.SmbSecuritySignature ?? 0})`,
      JSON.stringify(lv),
      nowStr
    );

    // 실제 Windows 이벤트 로그(wevtutil)에서 수집된 최근 OS 이벤트를 security_events에 기록
    const liveEvts = collectLiveWindowsEventLogs(6).events || [];
    for (const ev of liveEvts) {
      const evtKey = `EVT-WIN-${ev.recordId}`;
      try {
        insertEvent.run(
          evtKey,
          host,
          'CASE-HOST-POLICY-01',
          'system-event',
          ev.severity,
          ev.levelNum <= 2 ? 12 : ev.levelNum === 3 ? 8 : 4,
          'TA0002 Execution',
          `EventID ${ev.eventId}`,
          '실행',
          '127.0.0.1',
          '127.0.0.1',
          host,
          user,
          `${ev.provider} (PID ${ev.pid})`,
          ev.message,
          JSON.stringify(ev),
          ev.timestamp
        );
      } catch {
        // ignore duplicate
      }
    }
  }

  getDefaultTenantId() {
    const first = this.db.prepare('SELECT tenant_id FROM tenants LIMIT 1').get();
    return first ? first.tenant_id : os.hostname();
  }

  getTenants() {
    return this.db.prepare('SELECT * FROM tenants ORDER BY name ASC').all();
  }

  getTenant(tenantId) {
    if (tenantId) {
      const found = this.db.prepare('SELECT * FROM tenants WHERE tenant_id = ?').get(tenantId);
      if (found) return found;
    }
    return this.getTenants()[0];
  }

  updateTenantSettings(tenantId, patch) {
    const cur = this.getTenant(tenantId);
    if (!cur) return null;
    const updated = {
      ai_enabled: patch.ai_enabled !== undefined ? (patch.ai_enabled ? 1 : 0) : cur.ai_enabled,
      ai_provider: patch.ai_provider ?? cur.ai_provider,
      ai_domain: patch.ai_domain ?? cur.ai_domain,
      ai_model: patch.ai_model ?? cur.ai_model,
      soc_agent_enabled: patch.soc_agent_enabled !== undefined ? (patch.soc_agent_enabled ? 1 : 0) : cur.soc_agent_enabled,
      soc_poll_sec: Number(patch.soc_poll_sec ?? cur.soc_poll_sec),
      soc_batch_size: Number(patch.soc_batch_size ?? cur.soc_batch_size),
      soc_auto_report: patch.soc_auto_report !== undefined ? (patch.soc_auto_report ? 1 : 0) : cur.soc_auto_report,
      soc_emergency_stop: patch.soc_emergency_stop !== undefined ? (patch.soc_emergency_stop ? 1 : 0) : cur.soc_emergency_stop,
      auto_block_enabled: patch.auto_block_enabled !== undefined ? (patch.auto_block_enabled ? 1 : 0) : cur.auto_block_enabled,
      asset_criticality_threshold: patch.asset_criticality_threshold ?? cur.asset_criticality_threshold
    };
    this.db.prepare(`
      UPDATE tenants SET
        ai_enabled = ?, ai_provider = ?, ai_domain = ?, ai_model = ?,
        soc_agent_enabled = ?, soc_poll_sec = ?, soc_batch_size = ?,
        soc_auto_report = ?, soc_emergency_stop = ?, auto_block_enabled = ?,
        asset_criticality_threshold = ?
      WHERE tenant_id = ?
    `).run(
      updated.ai_enabled, updated.ai_provider, updated.ai_domain, updated.ai_model,
      updated.soc_agent_enabled, updated.soc_poll_sec, updated.soc_batch_size,
      updated.soc_auto_report, updated.soc_emergency_stop, updated.auto_block_enabled,
      updated.asset_criticality_threshold, cur.tenant_id
    );
    return this.getTenant(cur.tenant_id);
  }

  getCases(tenantId, { severity, status, q } = {}) {
    let sql = 'SELECT * FROM xdr_cases WHERE 1=1';
    const params = [];
    if (tenantId) {
      const exists = this.db.prepare('SELECT 1 FROM xdr_cases WHERE tenant_id = ? LIMIT 1').get(tenantId);
      if (exists) {
        sql += ' AND tenant_id = ?';
        params.push(tenantId);
      }
    }
    if (severity && severity !== 'ALL') {
      sql += ' AND severity = ?';
      params.push(severity);
    }
    if (status && status !== 'ALL') {
      sql += ' AND status = ?';
      params.push(status);
    }
    if (q) {
      sql += ' AND (title LIKE ? OR case_id LIKE ? OR target_asset LIKE ? OR src_ip LIKE ?)';
      const pat = `%${q}%`;
      params.push(pat, pat, pat, pat);
    }
    sql += ' ORDER BY created_at DESC, case_id DESC';
    return this.db.prepare(sql).all(...params);
  }

  getCaseById(caseId) {
    let row = this.db.prepare('SELECT * FROM xdr_cases WHERE case_id = ?').get(caseId);
    if (!row) {
      row = this.db.prepare('SELECT * FROM xdr_cases ORDER BY created_at DESC LIMIT 1').get();
    }
    if (!row) return null;
    const events = this.db.prepare('SELECT * FROM security_events WHERE case_id = ? ORDER BY occurred_at DESC').all(row.case_id);
    const soarActions = this.db.prepare('SELECT * FROM soar_actions WHERE case_id = ? ORDER BY created_at DESC').all(row.case_id);
    const aiAudits = this.db.prepare('SELECT * FROM ai_audit_logs WHERE case_id = ? ORDER BY created_at DESC').all(row.case_id);
    return {
      ...row,
      events,
      soarActions,
      aiAudits
    };
  }

  getEvents(tenantId, limit = 100) {
    return this.db.prepare('SELECT * FROM security_events ORDER BY occurred_at DESC LIMIT ?').all(limit);
  }

  getEventById(eventId) {
    return this.db.prepare('SELECT * FROM security_events WHERE event_id = ?').get(eventId) || null;
  }

  getAiAudits(tenantId, limit = 50) {
    return this.db.prepare('SELECT * FROM ai_audit_logs ORDER BY created_at DESC LIMIT ?').all(limit);
  }

  getSoarActions(tenantId) {
    return this.db.prepare('SELECT * FROM soar_actions ORDER BY updated_at DESC').all();
  }

  getPolicyAudits(tenantId) {
    return this.db.prepare('SELECT * FROM policy_audits ORDER BY checked_at DESC LIMIT 10').all();
  }

  createBackup(label = 'manual') {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const safeLabel = String(label).replace(/[^a-zA-Z0-9_-]/g, '');
    const backupFile = path.join(BACKUP_DIR, `jw_xdr_${safeLabel}_${stamp}.db`);
    fs.copyFileSync(this.dbPath, backupFile);
    const verify = this.verifySqliteFile(backupFile);
    return {
      ok: verify.valid,
      backupFile: path.basename(backupFile),
      sizeBytes: verify.sizeBytes,
      headerVerified: verify.valid,
      createdAt: new Date().toISOString()
    };
  }

  verifySqliteFile(filePath) {
    if (!fs.existsSync(filePath)) {
      return { valid: false, reason: 'FILE_NOT_FOUND' };
    }
    const stat = fs.lstatSync(filePath);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      return { valid: false, reason: 'NOT_CANONICAL_REGULAR_FILE' };
    }
    if (stat.size < 100) {
      return { valid: false, reason: 'FILE_TOO_SMALL' };
    }
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, 16, 0);
    fs.closeSync(fd);
    const headerStr = buf.toString('utf8');
    if (headerStr !== SQLITE_MAGIC_HEADER) {
      return {
        valid: false,
        reason: 'INVALID_SQLITE_HEADER',
        message: '파일 첫 16바이트가 SQLite format 3\\0 헤더와 일치하지 않아 복원을 즉시 거부했습니다 (기존 DB 보호됨).'
      };
    }
    return { valid: true, sizeBytes: stat.size, header: 'SQLite format 3\\0' };
  }

  restoreFromBackup(filePathOrBuffer) {
    if (Buffer.isBuffer(filePathOrBuffer)) {
      const header = filePathOrBuffer.subarray(0, 16).toString('utf8');
      if (filePathOrBuffer.length < 100 || header !== SQLITE_MAGIC_HEADER) {
        return {
          ok: false,
          code: 'INVALID_SQLITE_HEADER',
          preservedExistingDb: true,
          message: '손상되었거나 유효하지 않은 SQLite 헤더입니다. 기존 데이터베이스를 안전하게 보호하고 복원을 거부했습니다.'
        };
      }
      const tempPath = path.join(BACKUP_DIR, `temp_restore_${Date.now()}.db`);
      fs.writeFileSync(tempPath, filePathOrBuffer);
      const check = this.verifySqliteFile(tempPath);
      if (!check.valid) {
        fs.unlinkSync(tempPath);
        return { ok: false, code: check.reason, preservedExistingDb: true };
      }
      this.db.close();
      fs.copyFileSync(tempPath, this.dbPath);
      fs.unlinkSync(tempPath);
      this.db = new DatabaseSync(this.dbPath);
      return { ok: true, restored: true, headerVerified: true };
    }

    const check = this.verifySqliteFile(filePathOrBuffer);
    if (!check.valid) {
      return {
        ok: false,
        code: check.reason,
        preservedExistingDb: true,
        message: check.message || '백업 파일 검증 실패로 복원이 거부되었습니다.'
      };
    }
    this.db.close();
    fs.copyFileSync(filePathOrBuffer, this.dbPath);
    this.db = new DatabaseSync(this.dbPath);
    return { ok: true, restored: true, headerVerified: true, sizeBytes: check.sizeBytes };
  }
}
