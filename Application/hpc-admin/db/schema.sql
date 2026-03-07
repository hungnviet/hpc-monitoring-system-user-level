-- ═══════════════════════════════════════════════════════════════════════
-- HPC Admin Web App — TimescaleDB Schema
-- Run with: psql $TIMESCALE_URL -f db/schema.sql
-- ═══════════════════════════════════════════════════════════════════════

-- ═══════════════════════════════════════════════════════
-- 1. COMPUTE NODE REGISTRY
--    Mirrored from etcd. Admin can also edit via UI.
--    Real-time status (active/idle/down) is derived at query time:
--      active = nodeId seen in InfluxDB in last 10s
--      idle   = seen in last 5 min but not last 10s
--      down   = not seen in last 5 min
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS nodes (
  id            TEXT PRIMARY KEY,          -- matches nodeId in all measurements
  name          TEXT NOT NULL,             -- human-readable name e.g. "compute-01"
  ip            TEXT NOT NULL,
  group_name    TEXT NOT NULL,             -- e.g. "gpu-cluster", "cpu-cluster"
  collect_agent TEXT NOT NULL,             -- collectAgentId from NodeStatusDto
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- 2. HPC USER REGISTRY
--    Admin registers users manually.
--    uid must match ProcessStatusDto.uid / UserAppHourlyDto.uid
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS hpc_users (
  uid        INT  PRIMARY KEY,             -- Linux UID — joins with UserAppHourlyDto.uid
  username   TEXT NOT NULL UNIQUE,         -- human-readable login name
  email      TEXT,
  group_name TEXT                          -- e.g. "research-a", "ml-team"
);

-- ═══════════════════════════════════════════════════════
-- 3. COLLECTION SETTINGS
--    Per-node configuration pushed to collect agents via etcd.
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS collection_settings (
  node_id          TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  interval_seconds INT  NOT NULL DEFAULT 10,
  window_seconds   INT  NOT NULL DEFAULT 60,
  collect_agent    TEXT NOT NULL,
  updated_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- 4. PIPELINE PREPROCESSING RULES
--    Rules executed at collect agents (filter / aggregate / derive).
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS pipeline_rules (
  id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name       TEXT NOT NULL,
  type       TEXT NOT NULL CHECK (type IN ('filter','aggregate','derive')),
  resource   TEXT NOT NULL CHECK (resource IN ('cpu','gpu','mem','disk','net')),
  condition  TEXT NOT NULL,               -- e.g. "value == 0", "avg over 60s"
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- 5. ALERT THRESHOLD RULES
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS alert_rules (
  id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name       TEXT NOT NULL,
  node_group TEXT NOT NULL,               -- "gpu-cluster" | "cpu-cluster" | "all" | etc.
  resource   TEXT NOT NULL CHECK (resource IN ('cpu','gpu','mem','disk','net')),
  operator   TEXT NOT NULL CHECK (operator IN ('>','<','>=','<=')),
  threshold  DOUBLE PRECISION NOT NULL,
  severity   TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- 6. IN-APP NOTIFICATIONS
--    Fired when a metric crosses an alert_rule threshold.
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS notifications (
  id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  rule_id      TEXT REFERENCES alert_rules(id) ON DELETE SET NULL,
  severity     TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  message      TEXT NOT NULL,
  node_id      TEXT REFERENCES nodes(id) ON DELETE SET NULL,
  acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- 7. CONFIGURATION VERSION HISTORY
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS config_versions (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  version         TEXT NOT NULL,          -- semver e.g. "1.5.0"
  author          TEXT NOT NULL DEFAULT 'admin',
  description     TEXT,
  config_snapshot JSONB,                  -- full snapshot of all settings at that time
  active          BOOLEAN NOT NULL DEFAULT FALSE,
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- 8. AUDIT LOG
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS audit_logs (
  id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  actor      TEXT NOT NULL DEFAULT 'admin',
  action     TEXT NOT NULL CHECK (action IN ('CREATE','UPDATE','DELETE','ROLLOUT','LOGIN')),
  target     TEXT NOT NULL,               -- e.g. "alert_rule", "collection_setting"
  detail     TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════
-- 9. SAVED CUSTOM DASHBOARD PANELS
-- ═══════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS custom_dashboards (
  id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  title      TEXT NOT NULL,
  user_uids  INT[],                       -- array of uid (matches hpc_users.uid)
  resource   TEXT NOT NULL CHECK (resource IN ('cpu','gpu','mem','disk','net')),
  chart_type TEXT NOT NULL CHECK (chart_type IN ('line','bar','stacked')),
  pinned     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
