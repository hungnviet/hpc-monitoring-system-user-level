"use client"
import { useState, useEffect, useCallback } from "react"
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
  const active = etcdNodes.filter(n => n.status === "running").length
  const down   = etcdNodes.filter(n => n.status === "stopped").length
  return { totalNodes: etcdNodes.length, activeNodes: active, idleNodes: 0, downNodes: down }
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

type TimeRange = "1h" | "6h" | "24h"

const GRAFANA_BASE = "http://10.1.8.155:3000/d-solo/adtfbh4/h6-monitoring?orgId=1&timezone=browser&__feature.dashboardSceneSolo=true"

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
  const cpuPanelSrc = `${GRAFANA_BASE}&panelId=panel-6&from=now-${timeRange}&to=now`
  const memPanelSrc = `${GRAFANA_BASE}&panelId=panel-8&from=now-${timeRange}&to=now`

  const gpuTempPanelSrc = `${GRAFANA_BASE}&panelId=panel-4&from=now-${timeRange}&to=now`
  const gpuPowerPanelSrc = `${GRAFANA_BASE}&panelId=panel-11&from=now-${timeRange}&to=now`
  const gpuPanelSrc = `${GRAFANA_BASE}&panelId=panel-10&from=now-${timeRange}&to=now`
  const gpuMemPanelSrc = `${GRAFANA_BASE}&panelId=panel-13&from=now-${timeRange}&to=now`



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
            {(["1h", "6h", "24h"] as TimeRange[]).map(t => (
              <button
                key={t}
                onClick={() => setTimeRange(t)}
                className={`px-3 py-1.5 text-xs transition-colors cursor-pointer ${timeRange === t ? "bg-[#1f6feb] text-white" : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"}`}
              >
                {t}
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

      {/* Resource stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Avg CPU"    value={stats ? `${stats.avg_cpu_pct ?? "—"}%`      : "—"} unit="" color="#58a6ff" />
        <StatCard label="Avg GPU"    value={stats ? `${stats.avg_gpu_pct ?? "—"}%`      : "—"} unit="" color="#bc8cff" />
        <StatCard label="Avg Memory" value={stats ? `${stats.avg_mem_pct ?? "—"}%`      : "—"} unit="" color="#3fb950" />
        <StatCard label="Avg Disk"   value={stats ? `${stats.total_disk_mb ?? "—"} MB`  : "—"} unit="" color="#d29922" />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <StatCard label="Network In"  value={stats ? `${stats.net_rx_mb ?? "—"} MB`          : "—"} unit="" color="#79c0ff" />
        <StatCard label="Network Out" value={stats ? `${stats.net_tx_mb ?? "—"} MB`          : "—"} unit="" color="#56d364" />
      </div>

      {/* Grafana panels */}
      <div>
        <h2 className="text-sm font-semibold text-[#8b949e] mb-3 uppercase tracking-wide">Cluster Resource Usage</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <GrafanaPanel         src={cpuPanelSrc} height={220} />
          <GrafanaPanel         src={memPanelSrc} height={220} />
           <GrafanaPanel    src={gpuPanelSrc} height={220} />
          <GrafanaPanel    src={gpuMemPanelSrc} height={220} />
          <GrafanaPanel    src={gpuTempPanelSrc} height={220} />
          <GrafanaPanel   src={gpuPowerPanelSrc} height={220} />
        </div>
      </div>
    </div>
  )
}
