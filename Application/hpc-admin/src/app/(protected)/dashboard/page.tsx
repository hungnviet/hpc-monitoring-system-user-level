"use client"
import { useState } from "react"
import { GrafanaPanel } from "@/components/dashboard/GrafanaPanel"
import { HealthIndicator } from "@/components/dashboard/HealthIndicator"
import { clusterSummary } from "@/lib/mockData/nodes"

interface StatCardProps {
  label: string
  value: string | number
  unit?: string
  color?: string
}

function StatCard({ label, value, unit = "%", color = "#58a6ff" }: StatCardProps) {
  const pct = typeof value === "number" ? value : 0
  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
      <p className="text-xs text-[#8b949e] mb-1 uppercase tracking-wide font-medium">{label}</p>
      <p className="text-2xl font-bold" style={{ color }}>{value}{unit}</p>
      {typeof value === "number" && (
        <div className="mt-3 h-1.5 bg-[#21262d] rounded-full overflow-hidden">
          <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
        </div>
      )}
    </div>
  )
}

type TimeRange = "now" | "1h" | "6h" | "24h"

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>("now")
  const s = clusterSummary

  return (
    <div className="p-6 space-y-6">
      {/* Header row */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Cluster Overview</h1>
          <p className="text-sm text-[#8b949e] mt-0.5">Real-time cluster health and resource utilization</p>
        </div>
        <div className="flex items-center gap-3">
          <HealthIndicator activeNodes={s.activeNodes} totalNodes={s.totalNodes} />
          <div className="flex rounded-lg border border-[#30363d] overflow-hidden">
            {(["now", "1h", "6h", "24h"] as TimeRange[]).map(t => (
              <button
                key={t}
                onClick={() => setTimeRange(t)}
                className={`px-3 py-1.5 text-xs transition-colors ${timeRange === t ? "bg-[#1f6feb] text-white" : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"}`}
              >
                {t === "now" ? "Live" : t}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Node status row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4 flex flex-col items-center">
          <span className="text-3xl font-bold text-[#e6edf3]">{s.activeNodes}</span>
          <span className="text-xs text-[#3fb950] mt-1 flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-[#3fb950] animate-pulse inline-block" />Active</span>
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

      {/* Resource stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="Avg CPU" value={s.avgCpuUsage} color="#58a6ff" />
        <StatCard label="Avg GPU" value={s.avgGpuUsage} color="#bc8cff" />
        <StatCard label="Avg Memory" value={s.avgMemUsage} color="#3fb950" />
        <StatCard label="Avg Disk" value={s.avgDiskUsage} color="#d29922" />
      </div>

      {/* Network */}
      <div className="grid grid-cols-2 gap-3">
        <StatCard label="Network In" value={`${s.networkThroughputIn} GB/s`} unit="" color="#79c0ff" />
        <StatCard label="Network Out" value={`${s.networkThroughputOut} GB/s`} unit="" color="#56d364" />
      </div>

      {/* Grafana panels */}
      <div>
        <h2 className="text-sm font-semibold text-[#8b949e] mb-3 uppercase tracking-wide">Grafana Panels</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <GrafanaPanel title="CPU Usage" height={220} />
          <GrafanaPanel title="GPU Usage" height={220} />
          <GrafanaPanel title="Memory Consumption" height={220} />
          <GrafanaPanel title="Disk Utilization" height={220} />
          <GrafanaPanel title="Network Throughput" height={220} />
          <GrafanaPanel title="Node Status" height={220} />
        </div>
      </div>
    </div>
  )
}
