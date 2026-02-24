"use client"
import { use } from "react"
import Link from "next/link"
import { mockNodes } from "@/lib/mockData/nodes"
import { GrafanaPanel } from "@/components/dashboard/GrafanaPanel"
import { NodeStatusBadge } from "@/components/dashboard/NodeStatusBadge"

function MetricRow({ label, value, unit = "%", color }: { label: string; value: number; unit?: string; color: string }) {
  return (
    <div className="flex items-center justify-between py-2 border-b border-[#21262d] last:border-0">
      <span className="text-sm text-[#8b949e]">{label}</span>
      <div className="flex items-center gap-3">
        <div className="w-24 h-1.5 bg-[#21262d] rounded-full overflow-hidden">
          <div className="h-full rounded-full" style={{ width: `${value}%`, backgroundColor: color }} />
        </div>
        <span className="text-sm font-medium text-[#e6edf3] w-12 text-right">{value}{unit}</span>
      </div>
    </div>
  )
}

export default function NodeDetailPage({ params }: { params: Promise<{ nodeId: string }> }) {
  const { nodeId } = use(params)
  const node = mockNodes.find(n => n.id === nodeId)

  if (!node) return (
    <div className="p-6">
      <p className="text-[#f85149]">Node not found.</p>
      <Link href="/dashboard/nodes" className="text-[#58a6ff] hover:underline text-sm mt-2 inline-block">← Back to nodes</Link>
    </div>
  )

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
        <NodeStatusBadge status={node.status} />
      </div>

      {/* Info card */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
        <h2 className="text-xs font-semibold text-[#8b949e] uppercase tracking-wide mb-4">Current Metrics</h2>
        <MetricRow label="CPU Utilization" value={node.cpuUsage} color="#58a6ff" />
        <MetricRow label="GPU Usage"       value={node.gpuUsage} color="#bc8cff" />
        <MetricRow label="Memory Usage"    value={node.memUsage} color="#3fb950" />
        <MetricRow label="Disk Usage"      value={node.diskUsage} color="#d29922" />
      </div>

      {/* Info badges */}
      <div className="flex flex-wrap gap-3">
        {[
          { label: "Collect Agent", value: node.collectAgent },
          { label: "Group",         value: node.group },
          { label: "Node ID",       value: node.id },
        ].map(item => (
          <div key={item.label} className="bg-[#161b22] border border-[#30363d] rounded-lg px-4 py-2.5">
            <p className="text-xs text-[#6e7681] mb-0.5">{item.label}</p>
            <p className="text-sm font-medium text-[#e6edf3]">{item.value}</p>
          </div>
        ))}
      </div>

      {/* Grafana panels */}
      <div>
        <h2 className="text-sm font-semibold text-[#8b949e] mb-3 uppercase tracking-wide">Grafana Panels</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <GrafanaPanel title="CPU Utilization + Load" height={220} />
          <GrafanaPanel title="GPU Usage + Temperature" height={220} />
          <GrafanaPanel title="GPU Power Draw" height={220} />
          <GrafanaPanel title="Memory Usage + Bandwidth" height={220} />
          <GrafanaPanel title="Disk Throughput + Latency" height={220} />
        </div>
      </div>
    </div>
  )
}
