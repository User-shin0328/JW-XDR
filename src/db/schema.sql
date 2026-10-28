-- JW-XDR Multi-Tenant Persistence Schema (node:sqlite)
-- 6대 핵심 테이블 (tenants, security_events, xdr_cases, ai_audit_logs, soar_actions, policy_audits)

CREATE TABLE IF NOT EXISTS tenants (
  tenant_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  compliance_tier TEXT NOT NULL DEFAULT 'ISMS-P / ISO-42001',
  ai_enabled INTEGER NOT NULL DEFAULT 1,
  ai_provider TEXT NOT NULL DEFAULT 'LightChat (전역 기본)',
  ai_domain TEXT NOT NULL DEFAULT 'https://xdr-mf.appexnetworks.co.kr',
  ai_model TEXT NOT NULL DEFAULT 'claude-sonnet-4-5-20250929',
  soc_agent_enabled INTEGER NOT NULL DEFAULT 1,
  soc_poll_sec INTEGER NOT NULL DEFAULT 60,
  soc_batch_size INTEGER NOT NULL DEFAULT 25,
  soc_auto_report INTEGER NOT NULL DEFAULT 1,
  soc_emergency_stop INTEGER NOT NULL DEFAULT 0,
  auto_block_enabled INTEGER NOT NULL DEFAULT 1,
  asset_criticality_threshold TEXT NOT NULL DEFAULT 'MEDIUM',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
  event_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  case_id TEXT,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  rule_level INTEGER NOT NULL DEFAULT 5,
  mitre_tactic TEXT NOT NULL,
  mitre_technique TEXT NOT NULL,
  kill_chain_stage TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  hostname TEXT NOT NULL,
  username TEXT,
  process_name TEXT,
  summary TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS xdr_cases (
  case_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'New',
  risk_score INTEGER NOT NULL DEFAULT 25,
  confidence REAL NOT NULL DEFAULT 67.0,
  assignee TEXT NOT NULL DEFAULT '미할당',
  description TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  target_asset TEXT NOT NULL,
  asset_os TEXT NOT NULL DEFAULT 'Ubuntu',
  asset_criticality TEXT NOT NULL DEFAULT 'HIGH',
  mitre_tactic TEXT NOT NULL,
  mitre_technique TEXT NOT NULL,
  kill_chain_stage TEXT NOT NULL,
  ai_label TEXT NOT NULL DEFAULT '판단 보류',
  verdict_status TEXT NOT NULL DEFAULT 'UNDECIDED',
  rule_tuning_note TEXT DEFAULT '',
  mttd_ms INTEGER NOT NULL DEFAULT 42000,
  mttr_ms INTEGER DEFAULT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  resolved_at TEXT DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS ai_audit_logs (
  audit_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  ai_label TEXT NOT NULL,
  confidence REAL NOT NULL,
  cited_event_ids TEXT NOT NULL,
  guardrail_status TEXT NOT NULL,
  wrong_event_rejected INTEGER NOT NULL DEFAULT 0,
  proposal_not_executed INTEGER NOT NULL DEFAULT 1,
  anonymized INTEGER NOT NULL DEFAULT 1,
  report_type TEXT NOT NULL DEFAULT '조사 리포트',
  summary TEXT NOT NULL,
  recommended_action TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS soar_actions (
  action_id TEXT PRIMARY KEY,
  receipt_id TEXT,
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  action_type TEXT NOT NULL,
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  stage TEXT NOT NULL,
  approved_by TEXT,
  effect_applied INTEGER NOT NULL DEFAULT 0,
  enforcement_note TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_audits (
  audit_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  hostname TEXT NOT NULL,
  manual_json TEXT NOT NULL,
  auto_json TEXT NOT NULL,
  comparison_json TEXT NOT NULL,
  mismatch_count INTEGER NOT NULL DEFAULT 0,
  compliance_score REAL NOT NULL DEFAULT 64.6,
  checked_at TEXT NOT NULL
);
