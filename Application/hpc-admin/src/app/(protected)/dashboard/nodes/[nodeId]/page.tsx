"use client"
import { use, useState, useEffect, useCallback } from "react"
import Link from "next/link"
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

// ── Helpers ───────────────────────────────────────────────────────────────────

function deriveStatus(s: "running" | "stopped" | "unknown"): NodeStatus {
  if (s === "running") return "active"
  if (s === "stopped") return "down"
  return "idle"
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
          <span className="text-xs text-[#6e7681]">— (Phase 3)</span>
        ) : (
          <>
            <div className="w-24 h-1.5 bg-[#21262d] rounded-full overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${value}%`, backgroundColor: color }} />
            </div>
            <span className="text-sm font-medium text-[#e6edf3] w-12 text-right">{value}{unit}</span>
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

// ── Page ──────────────────────────────────────────────────────────────────────

export default function NodeDetailPage({ params }: { params: Promise<{ nodeId: string }> }) {
  const { nodeId } = use(params)

  const [node, setNode] = useState<MergedNode | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)
  const [toggling, setToggling] = useState(false)

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

  useEffect(() => { load() }, [load])

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
          <Link
            href={`/config/collection`}
            className="ml-auto text-[#58a6ff] hover:underline"
          >
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
        <h2 className="text-xs font-semibold text-[#8b949e] uppercase tracking-wide mb-4">Current Metrics</h2>
        <MetricRow label="CPU Utilization" value={null} color="#58a6ff" />
        <MetricRow label="GPU Usage"       value={null} color="#bc8cff" />
        <MetricRow label="Memory Usage"    value={null} color="#3fb950" />
        <MetricRow label="Disk Usage"      value={null} color="#d29922" />
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
