"use client"
import { useState, useEffect, useCallback } from "react"
import Link from "next/link"
import { NodeStatusBadge } from "@/components/dashboard/NodeStatusBadge"
import { Table } from "@/components/ui/Table"
import type { NodeStatus } from "@/types"

// ── Types ─────────────────────────────────────────────────────────────────────

interface DbNode {
  id: string
  name: string
  ip: string
  group_name: string
  collect_agent: string
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
  status: NodeStatus
  etcdStatus: "running" | "stopped" | "unknown"
  etcdLoaded: boolean
  window?: string
  heartbeat?: string
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function deriveStatus(etcdStatus: "running" | "stopped" | "unknown"): NodeStatus {
  if (etcdStatus === "running") return "active"
  if (etcdStatus === "stopped") return "down"
  return "idle" // in DB registry but not yet in etcd
}

function merge(dbNodes: DbNode[], etcdNodes: EtcdNode[]): MergedNode[] {
  const etcdMap = new Map(etcdNodes.map(n => [n.nodeId, n]))
  return dbNodes.map(db => {
    const e = etcdMap.get(db.id)
    const etcdStatus = e?.status ?? "unknown"
    return {
      id:           db.id,
      name:         db.name,
      ip:           db.ip,
      group:        db.group_name,
      collectAgent: db.collect_agent,
      status:       deriveStatus(etcdStatus),
      etcdStatus,
      etcdLoaded:   !!e,
      window:       e?.window,
      heartbeat:    e?.heartbeat_interval,
    }
  })
}

// ── Sub-components ────────────────────────────────────────────────────────────

function UsageBar({ value, color }: { value: number | null; color: string }) {
  if (value === null)
    return <span className="text-xs text-[#6e7681]">—</span>
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-[#21262d] rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${value}%`, backgroundColor: color }} />
      </div>
      <span className="text-xs text-[#8b949e] w-8">{value}%</span>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function NodesPage() {
  const [nodes, setNodes] = useState<MergedNode[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [statusFilter, setStatusFilter] = useState<NodeStatus | "all">("all")
  const [search, setSearch] = useState("")
  // Per-row toggling state
  const [toggling, setToggling] = useState<Record<string, boolean>>({})

  const load = useCallback(async () => {
    try {
      const [dbRes, etcdRes] = await Promise.all([
        fetch("/api/nodes"),
        fetch("/api/etcd/nodes"),
      ])
      if (!dbRes.ok) throw new Error("Failed to load nodes")
      const dbNodes: DbNode[] = await dbRes.json()
      const etcdNodes: EtcdNode[] = etcdRes.ok ? await etcdRes.json() : []
      setNodes(merge(dbNodes, etcdNodes))
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function toggleStatus(node: MergedNode) {
    const next = node.etcdStatus === "running" ? "stopped" : "running"
    setToggling(t => ({ ...t, [node.id]: true }))
    try {
      await fetch(`/api/etcd/nodes/${node.id}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: next }),
      })
      setNodes(prev => prev.map(n =>
        n.id === node.id
          ? { ...n, etcdStatus: next, status: deriveStatus(next) }
          : n
      ))
    } finally {
      setToggling(t => ({ ...t, [node.id]: false }))
    }
  }

  const filtered = nodes.filter(n => {
    if (statusFilter !== "all" && n.status !== statusFilter) return false
    if (search && !n.name.toLowerCase().includes(search.toLowerCase()) && !n.ip.includes(search)) return false
    return true
  })

  const columns = [
    {
      key: "name",
      header: "Node",
      render: (n: MergedNode) => (
        <Link href={`/dashboard/nodes/${n.id}`} className="text-[#58a6ff] hover:underline font-medium">
          {n.name}
        </Link>
      ),
    },
    {
      key: "ip",
      header: "IP",
      render: (n: MergedNode) => <span className="font-mono text-xs text-[#8b949e]">{n.ip}</span>,
    },
    {
      key: "status",
      header: "Status",
      render: (n: MergedNode) => <NodeStatusBadge status={n.status} />,
    },
    {
      key: "group",
      header: "Group",
      render: (n: MergedNode) => <span className="text-xs text-[#8b949e]">{n.group}</span>,
    },
    {
      key: "agent",
      header: "Collect Agent",
      render: (n: MergedNode) => (
        <span className="text-xs font-mono text-[#8b949e]">{n.collectAgent}</span>
      ),
    },
    {
      key: "window",
      header: "Window",
      render: (n: MergedNode) => (
        <span className="text-xs text-[#8b949e]">
          {n.window ? `${n.window}s` : <span className="text-[#6e7681]">—</span>}
        </span>
      ),
    },
    {
      key: "cpu",
      header: "CPU",
      render: () => <UsageBar value={null} color="#58a6ff" />,
    },
    {
      key: "gpu",
      header: "GPU",
      render: () => <UsageBar value={null} color="#bc8cff" />,
    },
    {
      key: "mem",
      header: "Memory",
      render: () => <UsageBar value={null} color="#3fb950" />,
    },
    {
      key: "actions",
      header: "",
      render: (n: MergedNode) => {
        const isToggling = toggling[n.id]
        return (
          <div className="flex items-center gap-2">
            {n.etcdLoaded && (
              <button
                disabled={isToggling}
                onClick={() => toggleStatus(n)}
                className={[
                  "text-xs px-2 py-1 rounded border transition-colors",
                  n.etcdStatus === "running"
                    ? "border-[#f85149]/50 text-[#f85149] hover:bg-[#f85149]/10"
                    : "border-[#3fb950]/50 text-[#3fb950] hover:bg-[#3fb950]/10",
                  isToggling ? "opacity-50 cursor-not-allowed" : "cursor-pointer",
                ].join(" ")}
              >
                {isToggling ? "…" : n.etcdStatus === "running" ? "Stop" : "Start"}
              </button>
            )}
            <Link
              href={`/dashboard/nodes/${n.id}`}
              className="text-xs text-[#8b949e] hover:text-[#58a6ff] transition-colors"
            >
              View →
            </Link>
          </div>
        )
      },
    },
  ]

  if (loading) {
    return (
      <div className="p-6 space-y-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="h-10 rounded bg-[#1c2128] animate-pulse" />
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-[#f85149]/40 bg-[#f85149]/10 px-4 py-3 text-sm text-[#f85149]">
          {error}
          <button onClick={load} className="ml-3 underline cursor-pointer">Retry</button>
        </div>
      </div>
    )
  }

  const active = nodes.filter(n => n.status === "active").length
  const down   = nodes.filter(n => n.status === "down").length
  const idle   = nodes.filter(n => n.status === "idle").length

  return (
    <div className="p-6 space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Compute Nodes</h1>
          <p className="text-sm text-[#8b949e]">{nodes.length} nodes in registry</p>
        </div>
        <button
          onClick={load}
          className="text-xs text-[#8b949e] hover:text-[#e6edf3] border border-[#30363d] rounded px-3 py-1.5 transition-colors cursor-pointer"
        >
          Refresh
        </button>
      </div>

      {/* Status summary */}
      <div className="flex items-center gap-5 text-sm">
        <span className="text-[#3fb950]">● {active} active</span>
        <span className="text-[#d29922]">● {idle} idle</span>
        <span className="text-[#f85149]">● {down} down</span>
        <span className="text-xs text-[#6e7681] ml-auto">
          Usage metrics available in Phase 3 (InfluxDB)
        </span>
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
              className={`px-3 py-1.5 text-xs capitalize transition-colors cursor-pointer ${statusFilter === s ? "bg-[#1f6feb] text-white" : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"}`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <Table
        columns={columns}
        data={filtered}
        keyExtractor={n => n.id}
        emptyMessage="No nodes match the filter"
      />
    </div>
  )
}
