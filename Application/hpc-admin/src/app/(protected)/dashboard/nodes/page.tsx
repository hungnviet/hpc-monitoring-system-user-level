"use client"
import { useState } from "react"
import Link from "next/link"
import { mockNodes } from "@/lib/mockData/nodes"
import { NodeStatusBadge } from "@/components/dashboard/NodeStatusBadge"
import { Table } from "@/components/ui/Table"
import type { ComputeNode, NodeStatus } from "@/types"

function UsageBar({ value, color }: { value: number; color: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-[#21262d] rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${value}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs text-[#8b949e] w-8">{value}%</span>
    </div>
  )
}

export default function NodesPage() {
  const [statusFilter, setStatusFilter] = useState<NodeStatus | "all">("all")
  const [search, setSearch] = useState("")

  const filtered = mockNodes.filter(n => {
    if (statusFilter !== "all" && n.status !== statusFilter) return false
    if (search && !n.name.includes(search) && !n.ip.includes(search)) return false
    return true
  })

  const columns = [
    { key: "name",   header: "Node",         render: (n: ComputeNode) => (
      <Link href={`/dashboard/nodes/${n.id}`} className="text-[#58a6ff] hover:underline font-medium">{n.name}</Link>
    )},
    { key: "ip",     header: "IP",           render: (n: ComputeNode) => <span className="font-mono text-xs text-[#8b949e]">{n.ip}</span> },
    { key: "status", header: "Status",       render: (n: ComputeNode) => <NodeStatusBadge status={n.status} /> },
    { key: "group",  header: "Group",        render: (n: ComputeNode) => <span className="text-xs text-[#8b949e]">{n.group}</span> },
    { key: "agent",  header: "Collect Agent",render: (n: ComputeNode) => <span className="text-xs text-[#8b949e]">{n.collectAgent}</span> },
    { key: "cpu",    header: "CPU",          render: (n: ComputeNode) => <UsageBar value={n.cpuUsage} color="#58a6ff" /> },
    { key: "gpu",    header: "GPU",          render: (n: ComputeNode) => <UsageBar value={n.gpuUsage} color="#bc8cff" /> },
    { key: "mem",    header: "Memory",       render: (n: ComputeNode) => <UsageBar value={n.memUsage} color="#3fb950" /> },
    { key: "disk",   header: "Disk",         render: (n: ComputeNode) => <UsageBar value={n.diskUsage} color="#d29922" /> },
    { key: "detail", header: "",             render: (n: ComputeNode) => (
      <Link href={`/dashboard/nodes/${n.id}`} className="text-xs text-[#8b949e] hover:text-[#58a6ff] transition-colors">View →</Link>
    )},
  ]

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Compute Nodes</h1>
          <p className="text-sm text-[#8b949e]">{mockNodes.length} nodes in cluster</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <input
          placeholder="Search node or IP…"
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-[#0d1117] border border-[#30363d] rounded-md px-3 py-2 text-sm text-[#e6edf3] placeholder-[#6e7681] focus:outline-none focus:ring-1 focus:ring-[#58a6ff]"
        />
        <div className="flex rounded-lg border border-[#30363d] overflow-hidden">
          {(["all", "active", "idle", "down"] as const).map(s => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3 py-1.5 text-xs capitalize transition-colors ${statusFilter === s ? "bg-[#1f6feb] text-white" : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"}`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <Table columns={columns} data={filtered} keyExtractor={n => n.id} emptyMessage="No nodes match the filter" />
    </div>
  )
}
