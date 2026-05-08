"use client"
import { useState, useEffect, useCallback, useMemo } from "react"
import { GrafanaPanel } from "@/components/dashboard/GrafanaPanel"
import { HealthIndicator } from "@/components/dashboard/HealthIndicator"

// ── Types ─────────────────────────────────────────────────────────────────────

interface EtcdNode { nodeId: string; status?: "running" | "stopped" }

interface ClusterSummary {
  totalNodes: number
  activeNodes: number
  idleNodes: number
  downNodes: number
}

interface ClusterStats {
  avg_cpu_pct: number | null
  avg_gpu_pct: number | null
  avg_mem_pct: number | null
  total_disk_mb: number | null
  net_rx_mb: number | null
  net_tx_mb: number | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function buildSummary(etcdNodes: EtcdNode[]): ClusterSummary {
  let active = 0, down = 0
  for (const n of etcdNodes) {
    if (n.status === "running") active++
    else if (n.status === "stopped") down++
  }
  return { totalNodes: etcdNodes.length, activeNodes: active, idleNodes: 0, downNodes: down }
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatCard({ label, value, unit = "%", color = "#58a6ff" }: {
  label: string; value: string | number; unit?: string; color?: string
}) {
  const pct = typeof value === "number" ? value : 0
  const isNA = value === "—"
  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-3 py-2.5">
      <p className="text-[10px] text-[#8b949e] mb-0.5 uppercase tracking-wide font-medium">{label}</p>
      <p className="text-lg font-semibold leading-tight" style={{ color: isNA ? "#6e7681" : color }}>
        {value}{!isNA && unit}
      </p>
      {!isNA && typeof value === "number" && (
        <div className="mt-2 h-1 bg-[#21262d] rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
        </div>
      )}
    </div>
  )
}

type TimeRange = "1h" | "6h" | "24h"

// System-level dashboard: cluster-wide gauges, bars, and node-rank stat panels.
// `var-node_id` is required by the dashboard variable but is unused for cluster-level panels.
const GRAFANA_BASE =
  "http://localhost:3000/d-solo/ad2h9fx/system-level?orgId=1&timezone=browser&refresh=10s&__feature.dashboardSceneSolo=true"

// ── Page ──────────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>("1h")
  const [summary, setSummary] = useState<ClusterSummary>({ totalNodes: 0, activeNodes: 0, idleNodes: 0, downNodes: 0 })
  const [stats, setStats] = useState<ClusterStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)

  const load = useCallback(async (range: TimeRange) => {
    try {
      const [etcdRes, statsRes] = await Promise.all([
        fetch("/api/etcd/nodes"),
        fetch(`/api/analytics/cluster-stats?range=${range}`),
      ])
      const etcdNodes: EtcdNode[] = etcdRes.ok ? await etcdRes.json() : []
      const clusterStats: ClusterStats = statsRes.ok ? await statsRes.json() : null
      setSummary(buildSummary(etcdNodes))
      setStats(clusterStats)
      setLastRefresh(new Date())
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial load + auto-refresh every 30 s
  useEffect(() => {
    load(timeRange)
    const id = setInterval(() => load(timeRange), 30_000)
    return () => clearInterval(id)
  }, [load, timeRange])

  const s = summary
  const panels = useMemo(() => {
    const range = `&from=now-${timeRange}&to=now`
    const url = (panelId: string) => `${GRAFANA_BASE}&panelId=${panelId}${range}`
    return {
      totalActive:    url("panel-1"),
      activeUsers:    url("panel-8"),
      avgCpu:         url("panel-2"),
      avgMem:         url("panel-3"),
      maxCpuNode:     url("panel-12"),
      maxCpuMemNode:  url("panel-13"),
      avgGpuUtil:     url("panel-4"),
      maxGpuNode:     url("panel-14"),
      avgGpuMem:      url("panel-5"),
      avgGpuTemp:     url("panel-6"),
      avgGpuPower:    url("panel-7"),
      maxGpuMemNode:  url("panel-9"),
      maxGpuTempNode: url("panel-10"),
      maxEnergyGpu:   url("panel-11"),
      freeNodes:      url("panel-15"),
    }
  }, [timeRange])



  return (
    <div className="p-5 space-y-4">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-base font-semibold text-[#e6edf3]">Cluster Overview</h1>
          <p className="text-xs text-[#8b949e] mt-0.5">Overall cluster resource utilization</p>
        </div>
        <div className="flex items-center gap-2.5">
          {loading ? (
            <div className="h-7 w-32 rounded-full bg-[#1c2128] animate-pulse" />
          ) : (
            <HealthIndicator activeNodes={s.activeNodes} totalNodes={s.totalNodes} />
          )}
          <div className="flex rounded-md border border-[#30363d] overflow-hidden">
            {(["1h", "6h", "24h"] as TimeRange[]).map(t => (
              <button
                key={t}
                onClick={() => setTimeRange(t)}
                className={`px-2.5 py-1 text-[11px] transition-colors cursor-pointer ${timeRange === t ? "bg-[#1f6feb] text-white" : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"}`}
              >
                {t}
              </button>
            ))}
          </div>
          {lastRefresh && (
            <span className="text-[11px] text-[#6e7681]">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
        </div>
      </div>

      {/* Node status row */}
      {loading ? (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-14 rounded-lg bg-[#1c2128] animate-pulse" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-3 py-2.5 flex items-center justify-between">
            <span className="text-[11px] text-[#3fb950] flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#3fb950] animate-pulse inline-block" />
              Active
            </span>
            <span className="text-xl font-semibold text-[#e6edf3] leading-none">{s.activeNodes}</span>
          </div>
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-3 py-2.5 flex items-center justify-between">
            <span className="text-[11px] text-[#d29922]">Idle</span>
            <span className="text-xl font-semibold text-[#e6edf3] leading-none">{s.idleNodes}</span>
          </div>
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-3 py-2.5 flex items-center justify-between">
            <span className="text-[11px] text-[#f85149]">Down</span>
            <span className="text-xl font-semibold text-[#e6edf3] leading-none">{s.downNodes}</span>
          </div>
          <div className="bg-[#161b22] border border-[#30363d] rounded-lg px-3 py-2.5 flex items-center justify-between">
            <span className="text-[11px] text-[#8b949e]">Total</span>
            <span className="text-xl font-semibold text-[#e6edf3] leading-none">{s.totalNodes}</span>
          </div>
        </div>
      )}

      {/* Resource + network stats — single dense row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
        <StatCard label="Avg CPU"    value={stats ? `${stats.avg_cpu_pct ?? "—"}%`     : "—"} unit="" color="#58a6ff" />
        <StatCard label="Avg GPU"    value={stats ? `${stats.avg_gpu_pct ?? "—"}%`     : "—"} unit="" color="#bc8cff" />
        <StatCard label="Avg Memory" value={stats ? `${stats.avg_mem_pct ?? "—"}%`     : "—"} unit="" color="#3fb950" />
        <StatCard label="Avg Disk"   value={stats ? `${stats.total_disk_mb ?? "—"} MB` : "—"} unit="" color="#d29922" />
        <StatCard label="Net In"     value={stats ? `${stats.net_rx_mb ?? "—"} MB`     : "—"} unit="" color="#79c0ff" />
        <StatCard label="Net Out"    value={stats ? `${stats.net_tx_mb ?? "—"} MB`     : "—"} unit="" color="#56d364" />
      </div>

      {/* Grafana panels */}
      <div>
        <h2 className="text-sm font-semibold text-[#8b949e] mb-3 uppercase tracking-wide">Curent Cluster Status</h2>

        <div className="grid grid-cols-7 grid-rows-[100px_100px_72px_72px_72px] gap-3">
          {/* ── Row 1 ──────────────────────────────────────────────── */}
          <GrafanaPanel src={panels.totalActive}    className="col-start-1 row-start-1" />
          <GrafanaPanel src={panels.activeUsers}    className="col-start-2 row-start-1" />
          <GrafanaPanel src={panels.avgCpu}         className="col-start-3 col-span-2 row-start-1 row-span-2" />
          <GrafanaPanel src={panels.avgMem}         className="col-start-5 col-span-2 row-start-1 row-span-2" />
          <GrafanaPanel src={panels.maxCpuNode}     className="col-start-7 row-start-1" />

          {/* ── Row 2 ──────────────────────────────────────────────── */}
          <GrafanaPanel src={panels.avgGpuUtil}     className="col-start-1 col-span-2 row-start-2 row-span-2" />
          <GrafanaPanel src={panels.maxCpuMemNode}  className="col-start-7 row-start-2" />

          {/* ── Row 3 ──────────────────────────────────────────────── */}
          <GrafanaPanel src={panels.avgGpuMem}      className="col-start-3 col-span-4 row-start-3" />
          <GrafanaPanel src={panels.maxGpuMemNode}  className="col-start-7 row-start-3" />

          {/* ── Row 4 ──────────────────────────────────────────────── */}
          <GrafanaPanel src={panels.maxGpuNode}     className="col-start-1 col-span-2 row-start-4" />
          <GrafanaPanel src={panels.avgGpuTemp}     className="col-start-3 col-span-4 row-start-4" />
          <GrafanaPanel src={panels.maxGpuTempNode} className="col-start-7 row-start-4" />

          {/* ── Row 5 ──────────────────────────────────────────────── */}
          <GrafanaPanel src={panels.avgGpuPower}    className="col-start-3 col-span-4 row-start-5" />
          <GrafanaPanel src={panels.maxEnergyGpu}   className="col-start-7 row-start-5" />
        </div>

        {/* List of free nodes — full-width table panel */}
        <div className="mt-3">
          <GrafanaPanel src={panels.freeNodes} height={320} />
        </div>
      </div>
    </div>
  )
}
