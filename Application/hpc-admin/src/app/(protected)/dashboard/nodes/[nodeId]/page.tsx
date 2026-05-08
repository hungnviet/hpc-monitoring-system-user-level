"use client"
import { use, useState, useEffect, useCallback, useMemo } from "react"
import Link from "next/link"
import {
  LineChart, Line, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Legend,
} from "recharts"
import { GrafanaPanel } from "@/components/dashboard/GrafanaPanel"
import { NodeStatusBadge } from "@/components/dashboard/NodeStatusBadge"
import { Button } from "@/components/ui/Button"
import { Select } from "@/components/ui/Select"
import { DateRangePicker } from "@/components/ui/DateRangePicker"
import type { NodeStatus } from "@/types"

// ── Types ─────────────────────────────────────────────────────────────────────

interface DbNode {
  id: string
  name: string
  ip: string
  group_name: string
  collect_agent: string
  created_at: string
}

interface EtcdNode {
  nodeId: string
  status?: "running" | "stopped"
  window?: string
  heartbeat_interval?: string
  target_collect_agent?: string
}

interface MergedNode {
  id: string
  name: string
  ip: string
  group: string
  collectAgent: string
  createdAt: string
  status: NodeStatus
  etcdStatus: "running" | "stopped" | "unknown"
  etcdLoaded: boolean
  window?: string
  heartbeat?: string
  targetAgent?: string
}

interface HourlyRow {
  bucket_time: string
  avg_cpu_usage_percent: number | null
  max_cpu_usage_percent: number | null
  avg_mem_usage_percent: number | null
  max_mem_used_bytes: number | null
  avg_gpu_utilization: number | null
  max_gpu_temperature: number | null
  total_gpu_power_watts: number | null
  total_disk_read_bytes: number | null
  total_disk_write_bytes: number | null
  total_net_rx_bytes: number | null
  total_net_tx_bytes: number | null
  is_active: boolean | null
}

// ── Field definitions ─────────────────────────────────────────────────────────

interface FieldDef {
  label: string
  key: keyof HourlyRow
  unit: string
  color: string
  divisor?: number
}

const FIELDS: FieldDef[] = [
  { label: "Avg CPU %",        key: "avg_cpu_usage_percent",   unit: "%",  color: "#58a6ff" },
  { label: "Max CPU %",        key: "max_cpu_usage_percent",   unit: "%",  color: "#79c0ff" },
  { label: "Avg Memory %",     key: "avg_mem_usage_percent",   unit: "%",  color: "#3fb950" },
  { label: "Max Memory (MB)",  key: "max_mem_used_bytes",      unit: "MB", color: "#56d364", divisor: 1_048_576 },
  { label: "Avg GPU Util %",   key: "avg_gpu_utilization",     unit: "%",  color: "#bc8cff" },
  { label: "Max GPU Temp",     key: "max_gpu_temperature",     unit: "°C", color: "#d2a8ff" },
  { label: "Total GPU Power",  key: "total_gpu_power_watts",   unit: "W",  color: "#f0883e" },
  { label: "Disk Read (MB)",   key: "total_disk_read_bytes",   unit: "MB", color: "#d29922", divisor: 1_048_576 },
  { label: "Disk Write (MB)",  key: "total_disk_write_bytes",  unit: "MB", color: "#e3b341", divisor: 1_048_576 },
  { label: "Net RX (MB)",      key: "total_net_rx_bytes",      unit: "MB", color: "#f85149", divisor: 1_048_576 },
  { label: "Net TX (MB)",      key: "total_net_tx_bytes",      unit: "MB", color: "#ffa198", divisor: 1_048_576 },
]

type RangeKey = "1d" | "2d" | "7d" | "custom"

const timeRangeOptions = [
  { value: "1d",     label: "Last 1 day" },
  { value: "2d",     label: "Last 2 days" },
  { value: "7d",     label: "Last 7 days" },
  { value: "custom", label: "Custom Range" },
]

const RANGE_MS: Record<Exclude<RangeKey, "custom">, number> = {
  "1d": 86_400_000,
  "2d": 172_800_000,
  "7d": 604_800_000,
}

// System-level (current status) Grafana dashboard.
// `var-node_id` is bound to the route's nodeId; no time range is forwarded
// so the panels render with their default "now" window.
const SYSTEM_GRAFANA_BASE = "http://localhost:3000/d-solo/ad2h9fx/system-level?orgId=1&timezone=browser&refresh=10s&__feature.dashboardSceneSolo=true"

function systemPanelUrl(nodeId: string, panelId: string) {
  return `${SYSTEM_GRAFANA_BASE}&var-node_id=${encodeURIComponent(nodeId)}&panelId=${panelId}`
}

const SYSTEM_PANELS: Array<{ title: string; panelId: string }> = [
  { title: "Current CPU Usage",              panelId: "panel-16" },
  { title: "Current CPU Memory Usage",       panelId: "panel-26" },
  { title: "Current GPU Utilization",        panelId: "panel-19" },
  { title: "Current GPU Memory Utilization", panelId: "panel-24" },
  { title: "Current GPU Temperature",        panelId: "panel-21" },
  { title: "Current GPU Power",              panelId: "panel-22" },
]

// ── Helpers ───────────────────────────────────────────────────────────────────

function deriveStatus(s: "running" | "stopped" | "unknown"): NodeStatus {
  if (s === "running") return "active"
  if (s === "stopped") return "down"
  return "idle"
}

function rangeSpanMs(range: RangeKey, customFrom: string, customTo: string): number {
  if (range === "custom") {
    const span = new Date(customTo).getTime() - new Date(customFrom).getTime()
    return Number.isFinite(span) && span > 0 ? span : RANGE_MS["1d"]
  }
  return RANGE_MS[range]
}

function formatBucketTime(iso: string, spanMs: number) {
  const d = new Date(iso)
  // Use date+hour format when the range spans more than ~2 days
  if (spanMs > 2 * 86_400_000) {
    return `${(d.getMonth() + 1).toString().padStart(2, "0")}-${d.getDate().toString().padStart(2, "0")} ${d.getHours().toString().padStart(2, "0")}:00`
  }
  return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`
}

function getFieldValue(row: HourlyRow, field: FieldDef): number | null {
  const raw = row[field.key] as number | null
  if (raw === null || raw === undefined) return null
  return field.divisor ? Math.round((Number(raw) / field.divisor) * 100) / 100 : Math.round(Number(raw) * 10) / 10
}

// ── Sub-components ────────────────────────────────────────────────────────────

function MetricRow({ label, value, unit = "%", color }: {
  label: string; value: number | null; unit?: string; color: string
}) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-[#21262d] last:border-0">
      <span className="text-sm text-[#8b949e]">{label}</span>
      <div className="flex items-center gap-3">
        {value === null ? (
          <span className="text-xs text-[#6e7681]">—</span>
        ) : (
          <>
            {unit === "%" && (
              <div className="w-24 h-1.5 bg-[#21262d] rounded-full overflow-hidden">
                <div className="h-full rounded-full" style={{ width: `${Math.min(value, 100)}%`, backgroundColor: color }} />
              </div>
            )}
            <span className="text-sm font-medium text-[#e6edf3] w-16 text-right">{value}{unit}</span>
          </>
        )}
      </div>
    </div>
  )
}

function InfoBadge({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-4 py-2.5">
      <p className="text-xs text-[#6e7681] mb-0.5">{label}</p>
      <p className="text-sm font-medium text-[#e6edf3] font-mono">{value}</p>
    </div>
  )
}

const tooltipStyle = {
  backgroundColor: "#1c2128",
  border: "1px solid #30363d",
  borderRadius: "6px",
  color: "#e6edf3",
  fontSize: "12px",
}

const FIELD_BY_KEY = new Map(FIELDS.map(f => [f.key as string, f]))

// ── Page ──────────────────────────────────────────────────────────────────────

export default function NodeDetailPage({ params }: { params: Promise<{ nodeId: string }> }) {
  const { nodeId } = use(params)

  const [node, setNode] = useState<MergedNode | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)
  const [toggling, setToggling] = useState(false)

  // Hourly chart state
  const [hourly, setHourly] = useState<HourlyRow[]>([])
  const [range, setRange] = useState<RangeKey>("1d")
  const [customFrom, setCustomFrom] = useState(() => new Date(Date.now() - 86_400_000).toISOString())
  const [customTo, setCustomTo]     = useState(() => new Date().toISOString())
  const [selectedFields, setSelectedFields] = useState<string[]>(["avg_cpu_usage_percent", "avg_mem_usage_percent"])
  const [chartLoading, setChartLoading] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [dbRes, etcdRes] = await Promise.all([
        fetch(`/api/nodes/${nodeId}`),
        fetch(`/api/etcd/nodes/${nodeId}`),
      ])

      if (dbRes.status === 404) { setNotFound(true); return }
      if (!dbRes.ok) throw new Error("Failed to load node")

      const db: DbNode = await dbRes.json()
      const etcd: EtcdNode | null = etcdRes.ok ? await etcdRes.json() : null
      const etcdStatus = etcd?.status ?? "unknown"

      setNode({
        id:           db.id,
        name:         db.name,
        ip:           db.ip,
        group:        db.group_name,
        collectAgent: db.collect_agent,
        createdAt:    db.created_at,
        status:       deriveStatus(etcdStatus),
        etcdStatus,
        etcdLoaded:   !!etcd,
        window:       etcd?.window,
        heartbeat:    etcd?.heartbeat_interval,
        targetAgent:  etcd?.target_collect_agent,
      })
    } catch {
      setNotFound(true)
    } finally {
      setLoading(false)
    }
  }, [nodeId])

  const loadHourly = useCallback(async () => {
    setChartLoading(true)
    try {
      const qs = new URLSearchParams({ range })
      if (range === "custom") {
        if (!customFrom || !customTo) { setHourly([]); return }
        qs.set("from", customFrom)
        qs.set("to", customTo)
      }
      const res = await fetch(`/api/nodes/${nodeId}/hourly?${qs.toString()}`)
      if (res.ok) setHourly(await res.json())
    } finally {
      setChartLoading(false)
    }
  }, [nodeId, range, customFrom, customTo])

  useEffect(() => { load() }, [load])
  useEffect(() => { loadHourly() }, [loadHourly])

  async function toggleStatus() {
    if (!node) return
    const next = node.etcdStatus === "running" ? "stopped" : "running"
    setToggling(true)
    try {
      const res = await fetch(`/api/etcd/nodes/${nodeId}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: next }),
      })
      if (res.ok) {
        setNode(n => n ? { ...n, etcdStatus: next, status: deriveStatus(next) } : n)
      }
    } finally {
      setToggling(false)
    }
  }

  function toggleField(key: string) {
    setSelectedFields(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    )
  }

  // ── Derived chart data ──────────────────────────────────────────────────────


  const selectedSet = useMemo(() => new Set(selectedFields), [selectedFields])

  const activeFields = useMemo(
    () => FIELDS.filter(f => selectedSet.has(f.key as string)),
    [selectedSet],
  )

  const spanMs = useMemo(() => rangeSpanMs(range, customFrom, customTo), [range, customFrom, customTo])

  const chartData = useMemo(() => hourly.map(row => {
    const obj: Record<string, string | number | null> = {
      time: formatBucketTime(row.bucket_time, spanMs),
    }
    for (const f of activeFields) {
      obj[f.key as string] = getFieldValue(row, f)
    }
    return obj
  }), [hourly, spanMs, activeFields])

  // ── Render ─────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="p-6 space-y-4">
        <div className="h-8 w-48 rounded bg-[#1c2128] animate-pulse" />
        <div className="h-40 rounded-xl bg-[#1c2128] animate-pulse" />
        <div className="h-24 rounded-xl bg-[#1c2128] animate-pulse" />
      </div>
    )
  }

  if (notFound || !node) {
    return (
      <div className="p-6">
        <p className="text-[#f85149]">Node not found.</p>
        <Link href="/dashboard/nodes" className="text-[#58a6ff] hover:underline text-sm mt-2 inline-block">
          ← Back to nodes
        </Link>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <Link href="/dashboard/nodes" className="text-[#8b949e] hover:text-[#e6edf3] transition-colors">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <div>
            <h1 className="text-lg font-semibold text-[#e6edf3]">{node.name}</h1>
            <p className="text-sm text-[#8b949e] font-mono">{node.ip} · {node.group}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <NodeStatusBadge status={node.status} />
          {node.etcdLoaded && (
            <Button
              size="sm"
              variant={node.etcdStatus === "running" ? "danger" : "primary"}
              loading={toggling}
              onClick={toggleStatus}
            >
              {toggling ? "…" : node.etcdStatus === "running" ? "Stop Collection" : "Start Collection"}
            </Button>
          )}
        </div>
      </div>

      {/* etcd config strip */}
      {node.etcdLoaded && (
        <div className="flex items-center gap-4 rounded-lg border border-[#30363d] bg-[#161b22] px-4 py-3 text-xs text-[#8b949e] flex-wrap">
          <span className="text-[#6e7681] font-medium">etcd config</span>
          <span>window <span className="text-[#e6edf3] font-mono">{node.window ?? "—"}s</span></span>
          <span>heartbeat <span className="text-[#e6edf3] font-mono">{node.heartbeat ?? "—"}s</span></span>
          <span>target agent <span className="text-[#e6edf3] font-mono">{node.targetAgent ?? "—"}</span></span>
          <Link href="/config/collection" className="ml-auto text-[#58a6ff] hover:underline">
            Edit in Collection Settings →
          </Link>
        </div>
      )}
      {!node.etcdLoaded && (
        <div className="rounded-lg border border-[#d29922]/30 bg-[#d29922]/5 px-4 py-3 text-xs text-[#d29922]">
          Node is registered in the database but has no etcd config entry. Push configuration from{" "}
          <Link href="/config/collection" className="underline">Collection Settings</Link> to register it.
        </div>
      )}
      
      {/* Info badges */}
      <div className="flex flex-wrap gap-3">
        <InfoBadge label="Collect Agent" value={node.collectAgent} />
        <InfoBadge label="Group"         value={node.group} />
        <InfoBadge label="Node ID"       value={node.id} />
        {node.createdAt && (
          <InfoBadge
            label="Registered"
            value={new Date(node.createdAt).toLocaleDateString()}
          />
        )}
      </div>

      {/* Historical chart */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <h2 className="text-xs font-semibold text-[#8b949e] uppercase tracking-wide">Historical Metrics</h2>
          <div className="w-48">
            <Select
              options={timeRangeOptions}
              value={range}
              onChange={e => setRange(e.target.value as RangeKey)}
            />
          </div>
        </div>

        {/* Custom date pickers */}
        {range === "custom" && (
          <DateRangePicker
            from={customFrom}
            to={customTo}
            onFromChange={setCustomFrom}
            onToChange={setCustomTo}
          />
        )}

        {/* Field selector */}
        <div className="flex flex-wrap gap-2">
          {FIELDS.map(f => {
            const active = selectedFields.includes(f.key as string)
            return (
              <button
                key={f.key as string}
                onClick={() => toggleField(f.key as string)}
                className={`px-2.5 py-1 text-xs rounded-full border transition-colors cursor-pointer ${
                  active
                    ? "border-transparent text-[#0d1117]"
                    : "border-[#30363d] text-[#6e7681] hover:text-[#e6edf3]"
                }`}
                style={active ? { backgroundColor: f.color } : {}}
              >
                {f.label}
              </button>
            )
          })}
        </div>

        {/* Chart */}
        {chartLoading ? (
          <div className="h-64 rounded bg-[#1c2128] animate-pulse" />
        ) : chartData.length === 0 ? (
          <div className="h-64 flex items-center justify-center text-sm text-[#6e7681]">
            No data available for this node in the selected range
          </div>
        ) : activeFields.length === 0 ? (
          <div className="h-64 flex items-center justify-center text-sm text-[#6e7681]">
            Select at least one field to display
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={280}>
            <LineChart
              data={chartData}
              margin={{ top: 5, right: 10, left: -10, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
              <XAxis
                dataKey="time"
                tick={{ fill: "#6e7681", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                interval="preserveStartEnd"
              />
              <YAxis
                tick={{ fill: "#6e7681", fontSize: 11 }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip
                contentStyle={tooltipStyle}
                formatter={(value, name) => {
                  const field = FIELD_BY_KEY.get(String(name))
                  if (value == null) return ["—", field?.label ?? String(name)]
                  return [`${value}${field?.unit ?? ""}`, field?.label ?? String(name)]
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: 12, color: "#8b949e" }}
                formatter={(value: string) => FIELD_BY_KEY.get(value)?.label ?? value}
              />
              {activeFields.map(f => (
                <Line
                  key={f.key as string}
                  type="monotone"
                  dataKey={f.key as string}
                  stroke={f.color}
                  dot={false}
                  strokeWidth={2}
                  connectNulls={false}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Grafana panels */}
      <div>
        <h2 className="text-sm font-semibold text-[#8b949e] mb-3 uppercase tracking-wide">Current status of node</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {SYSTEM_PANELS.map(p => (
            <GrafanaPanel
              key={p.panelId}
              title={p.title}
              src={systemPanelUrl(nodeId, p.panelId)}
              height={220}
            />
          ))}
        </div>
      </div>
    </div>
  )
}
