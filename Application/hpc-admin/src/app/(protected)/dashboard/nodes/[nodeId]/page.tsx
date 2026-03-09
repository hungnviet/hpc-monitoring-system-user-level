"use client"
import { use, useState, useEffect, useCallback } from "react"
import Link from "next/link"
import {
  LineChart, Line, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Legend,
} from "recharts"
import { GrafanaPanel } from "@/components/dashboard/GrafanaPanel"
import { NodeStatusBadge } from "@/components/dashboard/NodeStatusBadge"
import { Button } from "@/components/ui/Button"
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

type RangeKey = "24h" | "48h" | "7d" | "30d"

// ── Helpers ───────────────────────────────────────────────────────────────────

function deriveStatus(s: "running" | "stopped" | "unknown"): NodeStatus {
  if (s === "running") return "active"
  if (s === "stopped") return "down"
  return "idle"
}

function formatBucketTime(iso: string, range: RangeKey) {
  const d = new Date(iso)
  if (range === "7d" || range === "30d") {
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

// ── Page ──────────────────────────────────────────────────────────────────────

export default function NodeDetailPage({ params }: { params: Promise<{ nodeId: string }> }) {
  const { nodeId } = use(params)

  const [node, setNode] = useState<MergedNode | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)
  const [toggling, setToggling] = useState(false)

  // Hourly chart state
  const [hourly, setHourly] = useState<HourlyRow[]>([])
  const [range, setRange] = useState<RangeKey>("24h")
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
      const res = await fetch(`/api/nodes/${nodeId}/hourly?range=${range}`)
      if (res.ok) setHourly(await res.json())
    } finally {
      setChartLoading(false)
    }
  }, [nodeId, range])

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

  const latest = hourly.length > 0 ? hourly[hourly.length - 1] : null

  const chartData = hourly.map(row => {
    const obj: Record<string, string | number | null> = {
      time: formatBucketTime(row.bucket_time, range),
    }
    for (const f of FIELDS) {
      if (selectedFields.includes(f.key as string)) {
        obj[f.key as string] = getFieldValue(row, f)
      }
    }
    return obj
  })

  const activeFields = FIELDS.filter(f => selectedFields.includes(f.key as string))

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

      {/* Current metrics */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
        <h2 className="text-xs font-semibold text-[#8b949e] uppercase tracking-wide mb-4">
          Current Metrics
          {latest && (
            <span className="ml-2 normal-case font-normal text-[#6e7681]">
              (last snapshot: {new Date(latest.bucket_time).toLocaleString()})
            </span>
          )}
        </h2>
        <MetricRow
          label="CPU Utilization"
          value={latest ? (latest.avg_cpu_usage_percent !== null ? Math.round(Number(latest.avg_cpu_usage_percent) * 10) / 10 : null) : null}
          color="#58a6ff"
        />
        <MetricRow
          label="GPU Usage"
          value={latest ? (latest.avg_gpu_utilization !== null ? Math.round(Number(latest.avg_gpu_utilization) * 10) / 10 : null) : null}
          color="#bc8cff"
        />
        <MetricRow
          label="Memory Usage"
          value={latest ? (latest.avg_mem_usage_percent !== null ? Math.round(Number(latest.avg_mem_usage_percent) * 10) / 10 : null) : null}
          color="#3fb950"
        />
        <MetricRow
          label="GPU Temperature"
          value={latest?.max_gpu_temperature !== null && latest?.max_gpu_temperature !== undefined
            ? Math.round(Number(latest.max_gpu_temperature)) : null}
          unit="°C"
          color="#d29922"
        />
      </div>

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
          {/* Time range pills */}
          <div className="flex rounded-lg border border-[#30363d] overflow-hidden">
            {(["24h", "48h", "7d", "30d"] as RangeKey[]).map(r => (
              <button
                key={r}
                onClick={() => setRange(r)}
                className={`px-3 py-1 text-xs transition-colors cursor-pointer ${range === r ? "bg-[#1f6feb] text-white" : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#21262d]"}`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>

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
                  const field = FIELDS.find(f => (f.key as string) === name)
                  if (value == null) return ["—", field?.label ?? String(name)]
                  return [`${value}${field?.unit ?? ""}`, field?.label ?? String(name)]
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: 12, color: "#8b949e" }}
                formatter={(value: string) => {
                  const field = FIELDS.find(f => (f.key as string) === value)
                  return field?.label ?? value
                }}
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
        <h2 className="text-sm font-semibold text-[#8b949e] mb-3 uppercase tracking-wide">Grafana Panels</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <GrafanaPanel title="CPU Utilization + Load"     height={220} />
          <GrafanaPanel title="GPU Usage + Temperature"    height={220} />
          <GrafanaPanel title="GPU Power Draw"             height={220} />
          <GrafanaPanel title="Memory Usage + Bandwidth"  height={220} />
          <GrafanaPanel title="Disk Throughput + Latency" height={220} />
        </div>
      </div>
    </div>
  )
}
