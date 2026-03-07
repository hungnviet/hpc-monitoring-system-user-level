"use client"
import { useState, useEffect, useCallback } from "react"
import { GrafanaPanel } from "@/components/dashboard/GrafanaPanel"
import { HealthIndicator } from "@/components/dashboard/HealthIndicator"

// ── Types ─────────────────────────────────────────────────────────────────────

interface DbNode { id: string; name: string; ip: string; group_name: string; collect_agent: string }
interface EtcdNode { nodeId: string; status?: "running" | "stopped" }

interface ClusterSummary {
  totalNodes: number
  activeNodes: number   // running in etcd
  idleNodes: number     // in DB but not registered in etcd
  downNodes: number     // stopped in etcd
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildSummary(dbNodes: DbNode[], etcdNodes: EtcdNode[]): ClusterSummary {
  const etcdMap = new Map(etcdNodes.map(n => [n.nodeId, n]))
  let active = 0, idle = 0, down = 0
  for (const db of dbNodes) {
    const e = etcdMap.get(db.id)
    if (!e)                         idle++
    else if (e.status === "running") active++
    else                             down++
  }
  return { totalNodes: dbNodes.length, activeNodes: active, idleNodes: idle, downNodes: down }
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ label, value, unit = "%", color = "#58a6ff" }: {
  label: string; value: string | number; unit?: string; color?: string
}) {
  const pct = typeof value === "number" ? value : 0
  const isNA = value === "—"
  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
      <p className="text-xs text-[#8b949e] mb-1 uppercase tracking-wide font-medium">{label}</p>
      <p className="text-2xl font-bold" style={{ color: isNA ? "#6e7681" : color }}>
        {value}{!isNA && unit}
      </p>
      {!isNA && typeof value === "number" && (
        <div className="mt-3 h-1.5 bg-[#21262d] rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
        </div>
      )}
    </div>
  )
}

type TimeRange = "now" | "1h" | "6h" | "24h"

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>("now")
  const [summary, setSummary] = useState<ClusterSummary>({ totalNodes: 0, activeNodes: 0, idleNodes: 0, downNodes: 0 })
  const [loading, setLoading] = useState(true)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)

  const load = useCallback(async () => {
    try {
      const [dbRes, etcdRes] = await Promise.all([
        fetch("/api/nodes"),
        fetch("/api/etcd/nodes"),
      ])
      const dbNodes: DbNode[] = dbRes.ok ? await dbRes.json() : []
      const etcdNodes: EtcdNode[] = etcdRes.ok ? await etcdRes.json() : []
      setSummary(buildSummary(dbNodes, etcdNodes))
      setLastRefresh(new Date())
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial load + auto-refresh every 30 s
  useEffect(() => {
    load()
    const id = setInterval(load, 30_000)
    return () => clearInterval(id)
  }, [load])

  const s = summary

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Cluster Overview</h1>
          <p className="text-sm text-[#8b949e] mt-0.5">Real-time cluster health and resource utilization</p>
        </div>
        <div className="flex items-center gap-3">
          {loading ? (
            <div className="h-8 w-36 rounded-full bg-[#1c2128] animate-pulse" />
          ) : (
            <HealthIndicator activeNodes={s.activeNodes} totalNodes={s.totalNodes} />
          )}
          <div className="flex rounded-lg border border-[#30363d] overflow-hidden">
            {(["now", "1h", "6h", "24h"] as TimeRange[]).map(t => (
              <button
                key={t}
                onClick={() => setTimeRange(t)}
                className={`px-3 py-1.5 text-xs transition-colors cursor-pointer ${timeRange === t ? "bg-[#1f6feb] text-white" : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"}`}
              >
                {t === "now" ? "Live" : t}
              </button>
            ))}
          </div>
          {lastRefresh && (
            <span className="text-xs text-[#6e7681]">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Node status row */}
      {loading ? (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-24 rounded-xl bg-[#1c2128] animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex flex-col items-center">
            <span className="text-3xl font-bold text-[#e6edf3]">{s.activeNodes}</span>
            <span className="text-xs text-[#3fb950] mt-1 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#3fb950] animate-pulse inline-block" />
              Active
            </span>
          </div>
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex flex-col items-center">
            <span className="text-3xl font-bold text-[#e6edf3]">{s.idleNodes}</span>
            <span className="text-xs text-[#d29922] mt-1">Idle</span>
          </div>
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex flex-col items-center">
            <span className="text-3xl font-bold text-[#e6edf3]">{s.downNodes}</span>
            <span className="text-xs text-[#f85149] mt-1">Down</span>
          </div>
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex flex-col items-center">
            <span className="text-3xl font-bold text-[#e6edf3]">{s.totalNodes}</span>
            <span className="text-xs text-[#8b949e] mt-1">Total</span>
          </div>
        </div>
      )}

      {/* Resource stats — require InfluxDB (Phase 3) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Avg CPU"    value="—" unit="" color="#58a6ff" />
        <StatCard label="Avg GPU"    value="—" unit="" color="#bc8cff" />
        <StatCard label="Avg Memory" value="—" unit="" color="#3fb950" />
        <StatCard label="Avg Disk"   value="—" unit="" color="#d29922" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <StatCard label="Network In"  value="—" unit="" color="#79c0ff" />
        <StatCard label="Network Out" value="—" unit="" color="#56d364" />
      </div>
      <p className="text-xs text-[#6e7681] -mt-2">
        Resource metrics require InfluxDB integration (Phase 3).
      </p>

      {/* Grafana panels */}
      <div>
        <h2 className="text-sm font-semibold text-[#8b949e] mb-3 uppercase tracking-wide">Grafana Panels</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <GrafanaPanel title="CPU Usage"            height={220} />
          <GrafanaPanel title="GPU Usage"            height={220} />
          <GrafanaPanel title="Memory Consumption"  height={220} />
          <GrafanaPanel title="Disk Utilization"    height={220} />
          <GrafanaPanel title="Network Throughput"  height={220} />
          <GrafanaPanel title="Node Status"         height={220} />
        </div>
      </div>
    </div>
  )
}
