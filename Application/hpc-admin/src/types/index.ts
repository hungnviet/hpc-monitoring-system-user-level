// ── Node & Cluster ────────────────────────────────────────────────────
export type NodeStatus = "active" | "idle" | "down"

export interface ComputeNode {
  id: string
  name: string
  ip: string
  status: NodeStatus
  collectAgent: string
  group: string
  cpuUsage: number
  gpuUsage: number
  memUsage: number
  diskUsage: number
}

// ── Analytics ─────────────────────────────────────────────────────────
export type ResourceType = "cpu" | "gpu" | "mem" | "disk" | "net"

export interface MetricPoint {
  timestamp: string
  value: number
}

export interface UserUsage {
  userId: string
  username: string
  resource: ResourceType
  data: MetricPoint[]
}

export interface ChartPanel {
  id: string
  title: string
  userIds: string[]
  resource: ResourceType
  chartType: "line" | "bar" | "stacked"
  pinned: boolean
}

// ── Config ────────────────────────────────────────────────────────────
export interface CollectionSetting {
  nodeId: string
  nodeName: string
  group: string
  intervalSeconds: number
  windowSeconds: number
  collectAgent: string
}

export type PipelineRuleType = "filter" | "aggregate" | "derive"

export interface PipelineRule {
  id: string
  name: string
  type: PipelineRuleType
  resource: ResourceType
  condition: string
  enabled: boolean
}

export type AlertSeverity = "info" | "warning" | "critical"

export interface AlertRule {
  id: string
  name: string
  nodeGroup: string
  resource: ResourceType
  operator: ">" | "<" | ">=" | "<="
  threshold: number
  severity: AlertSeverity
  enabled: boolean
}

// ── Governance ────────────────────────────────────────────────────────
export interface ConfigVersion {
  id: string
  version: string
  author: string
  description: string
  createdAt: string
  active: boolean
}

export interface AuditLog {
  id: string
  actor: string
  action: string
  target: string
  detail: string
  createdAt: string
}

// ── Notifications ─────────────────────────────────────────────────────
export interface Notification {
  id: string
  severity: AlertSeverity
  message: string
  nodeId: string
  nodeName: string
  acknowledged: boolean
  createdAt: string
}

// ── Chat ──────────────────────────────────────────────────────────────
export interface ChatMessage {
  id: string
  role: "user" | "assistant"
  content: string
  timestamp: string
}

// ── Users (for analytics selectors) ──────────────────────────────────
export interface HpcUser {
  id: string
  username: string
  email: string
  group: string
}
