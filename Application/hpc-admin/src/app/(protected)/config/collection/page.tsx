"use client"
import { useState, useEffect, useCallback } from "react"
import { Table } from "@/components/ui/Table"
import { Modal } from "@/components/ui/Modal"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Button } from "@/components/ui/Button"
import { Badge } from "@/components/ui/Badge"

// ── Types ─────────────────────────────────────────────────────────────────────

interface DbRow {
  id: string
  name: string
  group_name: string
  collect_agent: string
  interval_seconds: number
  window_seconds: number
  updated_at: string | null
}

interface EtcdNodeRow {
  nodeId: string
  target_collect_agent?: string
  window?: string
  heartbeat_interval?: string
  status?: "running" | "stopped"
}

interface EtcdAgent {
  agentId: string
}

interface MergedRow {
  nodeId: string
  nodeName: string
  group: string
  intervalSeconds: number
  windowSeconds: number
  collectAgent: string
  updatedAt: string | null
  // etcd
  etcdStatus: "running" | "stopped" | "unknown"
  etcdLoaded: boolean
  etcdSynced: boolean // false = DB values differ from what's live in etcd
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function isSynced(db: DbRow, etcd: EtcdNodeRow): boolean {
  const windowMatch =
    etcd.window === undefined ||
    parseFloat(etcd.window) === db.window_seconds
  const intervalMatch =
    etcd.heartbeat_interval === undefined ||
    parseFloat(etcd.heartbeat_interval) === db.interval_seconds
  const agentMatch =
    etcd.target_collect_agent === undefined ||
    etcd.target_collect_agent === db.collect_agent
  return windowMatch && intervalMatch && agentMatch
}

function mergeRows(dbRows: DbRow[], etcdRows: EtcdNodeRow[]): MergedRow[] {
  const etcdMap = new Map(etcdRows.map(r => [r.nodeId, r]))
  return dbRows.map(db => {
    const etcd = etcdMap.get(db.id)
    return {
      nodeId: db.id,
      nodeName: db.name,
      group: db.group_name,
      intervalSeconds: db.interval_seconds,
      windowSeconds: db.window_seconds,
      collectAgent: db.collect_agent,
      updatedAt: db.updated_at,
      etcdStatus: etcd?.status ?? "unknown",
      etcdLoaded: !!etcd,
      etcdSynced: etcd ? isSynced(db, etcd) : false,
    }
  })
}

// ── Status badge ──────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: MergedRow["etcdStatus"] }) {
  if (status === "running")
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#3fb950]">
        <span className="h-1.5 w-1.5 rounded-full bg-[#3fb950] animate-pulse" />
        running
      </span>
    )
  if (status === "stopped")
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#8b949e]">
        <span className="h-1.5 w-1.5 rounded-full bg-[#8b949e]" />
        stopped
      </span>
    )
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-[#6e7681]">
      <span className="h-1.5 w-1.5 rounded-full bg-[#6e7681]" />
      no etcd
    </span>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function CollectionPage() {
  const [rows, setRows] = useState<MergedRow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [agentOptions, setAgentOptions] = useState<{ value: string; label: string }[]>([])

  // Edit modal state
  const [editTarget, setEditTarget] = useState<MergedRow | null>(null)
  const [form, setForm] = useState({ intervalSeconds: 10, windowSeconds: 60, collectAgent: "" })
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Per-row action feedback: nodeId → "toggling" | "pushing" | "saved" | null
  const [rowState, setRowState] = useState<Record<string, string | null>>({})

  // ── Load ───────────────────────────────────────────────────────────────────

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [dbRes, etcdRes, agentsRes] = await Promise.all([
        fetch("/api/config/collection"),
        fetch("/api/etcd/nodes"),
        fetch("/api/etcd/agents"),
      ])

      if (!dbRes.ok) throw new Error("Failed to load collection settings")

      const dbRows: DbRow[] = await dbRes.json()
      const etcdRows: EtcdNodeRow[] = etcdRes.ok ? await etcdRes.json() : []
      const agents: EtcdAgent[] = agentsRes.ok ? await agentsRes.json() : []

      setRows(mergeRows(dbRows, etcdRows))
      setAgentOptions(
        agents.length > 0
          ? agents.map(a => ({ value: a.agentId, label: a.agentId }))
          : [{ value: "collect_agent_1", label: "collect_agent_1" }]
      )
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // ── Edit & save ────────────────────────────────────────────────────────────

  function openEdit(row: MergedRow) {
    setEditTarget(row)
    setSaveError(null)
    setForm({
      intervalSeconds: row.intervalSeconds,
      windowSeconds: row.windowSeconds,
      collectAgent: row.collectAgent,
    })
  }

  async function saveEdit() {
    if (!editTarget) return
    setSaving(true)
    setSaveError(null)
    try {
      const res = await fetch(`/api/config/collection/${editTarget.nodeId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          interval_seconds: form.intervalSeconds,
          window_seconds: form.windowSeconds,
          collect_agent: form.collectAgent,
        }),
      })
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error ?? "Save failed")
      }
      setEditTarget(null)
      await load() // re-fetch to reflect both DB and etcd state
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Save failed")
    } finally {
      setSaving(false)
    }
  }

  // ── Start / Stop ───────────────────────────────────────────────────────────

  async function toggleStatus(row: MergedRow) {
    const next = row.etcdStatus === "running" ? "stopped" : "running"
    setRowState(s => ({ ...s, [row.nodeId]: "toggling" }))
    try {
      const res = await fetch(`/api/etcd/nodes/${row.nodeId}/status`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: next }),
      })
      if (!res.ok) throw new Error()
      setRows(prev =>
        prev.map(r => r.nodeId === row.nodeId ? { ...r, etcdStatus: next } : r)
      )
    } finally {
      setRowState(s => ({ ...s, [row.nodeId]: null }))
    }
  }

  // ── Push to etcd (re-sync) ─────────────────────────────────────────────────

  async function pushToEtcd(row: MergedRow) {
    setRowState(s => ({ ...s, [row.nodeId]: "pushing" }))
    try {
      const res = await fetch(`/api/config/collection/${row.nodeId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          interval_seconds: row.intervalSeconds,
          window_seconds: row.windowSeconds,
          collect_agent: row.collectAgent,
        }),
      })
      if (!res.ok) throw new Error()
      setRows(prev =>
        prev.map(r => r.nodeId === row.nodeId ? { ...r, etcdSynced: true } : r)
      )
      setRowState(s => ({ ...s, [row.nodeId]: "saved" }))
      setTimeout(() => setRowState(s => ({ ...s, [row.nodeId]: null })), 2000)
    } catch {
      setRowState(s => ({ ...s, [row.nodeId]: null }))
    }
  }

  // ── Table columns ──────────────────────────────────────────────────────────

  const columns = [
    {
      key: "node",
      header: "Node",
      render: (r: MergedRow) => (
        <span className="font-medium text-[#e6edf3]">{r.nodeName}</span>
      ),
    },
    {
      key: "group",
      header: "Group",
      render: (r: MergedRow) => <Badge variant="info">{r.group}</Badge>,
    },
    {
      key: "status",
      header: "Status",
      render: (r: MergedRow) => <StatusBadge status={r.etcdStatus} />,
    },
    {
      key: "interval",
      header: "Interval",
      render: (r: MergedRow) => (
        <span className="text-sm text-[#e6edf3]">{r.intervalSeconds}s</span>
      ),
    },
    {
      key: "window",
      header: "Window",
      render: (r: MergedRow) => (
        <span className="text-sm text-[#e6edf3]">{r.windowSeconds}s</span>
      ),
    },
    {
      key: "agent",
      header: "Collect Agent",
      render: (r: MergedRow) => (
        <span className="text-xs font-mono text-[#8b949e]">{r.collectAgent}</span>
      ),
    },
    {
      key: "sync",
      header: "etcd",
      render: (r: MergedRow) => {
        const state = rowState[r.nodeId]
        if (!r.etcdLoaded)
          return <span className="text-xs text-[#6e7681]">—</span>
        if (state === "pushing")
          return <span className="text-xs text-[#8b949e]">pushing…</span>
        if (state === "saved")
          return <span className="text-xs text-[#3fb950]">✓ synced</span>
        if (r.etcdSynced)
          return <span className="text-xs text-[#3fb950]">✓ synced</span>
        return (
          <button
            onClick={() => pushToEtcd(r)}
            className="text-xs text-[#f0883e] underline underline-offset-2 hover:text-[#ffa657] cursor-pointer"
          >
            out of sync — push
          </button>
        )
      },
    },
    {
      key: "actions",
      header: "",
      render: (r: MergedRow) => {
        const state = rowState[r.nodeId]
        const isToggling = state === "toggling"
        const canToggle = r.etcdLoaded
        return (
          <div className="flex items-center gap-2">
            {canToggle && (
              <button
                disabled={isToggling}
                onClick={() => toggleStatus(r)}
                className={[
                  "text-xs px-2 py-1 rounded border transition-colors",
                  r.etcdStatus === "running"
                    ? "border-[#f85149]/50 text-[#f85149] hover:bg-[#f85149]/10"
                    : "border-[#3fb950]/50 text-[#3fb950] hover:bg-[#3fb950]/10",
                  isToggling ? "opacity-50 cursor-not-allowed" : "cursor-pointer",
                ].join(" ")}
              >
                {isToggling ? "…" : r.etcdStatus === "running" ? "Stop" : "Start"}
              </button>
            )}
            <Button size="sm" variant="secondary" onClick={() => openEdit(r)}>
              Edit
            </Button>
          </div>
        )
      },
    },
  ]

  // ── Render ─────────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="p-6 space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
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
          <button onClick={load} className="ml-3 underline text-[#f85149] cursor-pointer">
            Retry
          </button>
        </div>
      </div>
    )
  }

  const runningCount = rows.filter(r => r.etcdStatus === "running").length
  const outOfSyncCount = rows.filter(r => r.etcdLoaded && !r.etcdSynced).length

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Collection Settings</h1>
          <p className="text-sm text-[#8b949e]">
            Configure per-node intervals — changes are saved to the database and pushed live to etcd.
          </p>
        </div>
        <button
          onClick={load}
          className="text-xs text-[#8b949e] hover:text-[#e6edf3] border border-[#30363d] rounded px-3 py-1.5 transition-colors cursor-pointer"
        >
          Refresh
        </button>
      </div>

      {/* Summary bar */}
      <div className="flex items-center gap-6 rounded-lg border border-[#30363d] bg-[#161b22] px-4 py-3">
        <div className="text-sm">
          <span className="text-[#8b949e]">Nodes: </span>
          <span className="text-[#e6edf3] font-medium">{rows.length}</span>
        </div>
        <div className="text-sm">
          <span className="text-[#8b949e]">Running: </span>
          <span className="text-[#3fb950] font-medium">{runningCount}</span>
        </div>
        <div className="text-sm">
          <span className="text-[#8b949e]">Stopped: </span>
          <span className="text-[#e6edf3] font-medium">
            {rows.filter(r => r.etcdStatus === "stopped").length}
          </span>
        </div>
        {outOfSyncCount > 0 && (
          <div className="text-sm">
            <span className="text-[#f0883e] font-medium">{outOfSyncCount} out of sync</span>
            <span className="text-[#8b949e]"> — click "out of sync — push" to re-sync</span>
          </div>
        )}
      </div>

      <Table columns={columns} data={rows} keyExtractor={r => r.nodeId} />

      {/* Edit modal */}
      <Modal
        open={!!editTarget}
        onClose={() => { setEditTarget(null); setSaveError(null) }}
        title={`Edit — ${editTarget?.nodeName}`}
      >
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Interval (seconds)"
              type="number"
              min={1}
              value={form.intervalSeconds}
              onChange={e =>
                setForm(f => ({ ...f, intervalSeconds: parseInt(e.target.value) || 10 }))
              }
            />
            <Input
              label="Window (seconds)"
              type="number"
              min={1}
              value={form.windowSeconds}
              onChange={e =>
                setForm(f => ({ ...f, windowSeconds: parseInt(e.target.value) || 60 }))
              }
            />
          </div>
          <Select
            label="Collect Agent"
            options={agentOptions}
            value={form.collectAgent}
            onChange={e => setForm(f => ({ ...f, collectAgent: e.target.value }))}
          />

          {/* etcd live values hint */}
          {editTarget?.etcdLoaded && (
            <div className="rounded border border-[#30363d] bg-[#0d1117] px-3 py-2 text-xs text-[#8b949e] space-y-1">
              <p className="text-[#6e7681] font-medium mb-1">Current etcd values</p>
              <p>
                window:{" "}
                <span className="text-[#e6edf3] font-mono">
                  {editTarget.windowSeconds}s
                </span>
                {"  "}heartbeat:{" "}
                <span className="text-[#e6edf3] font-mono">
                  {editTarget.intervalSeconds}s
                </span>
                {"  "}agent:{" "}
                <span className="text-[#e6edf3] font-mono">
                  {editTarget.collectAgent}
                </span>
              </p>
              <p className="text-[#6e7681]">
                Saving will write to DB and push the new values to etcd immediately.
              </p>
            </div>
          )}

          {saveError && (
            <p className="text-xs text-[#f85149]">{saveError}</p>
          )}

          <div className="flex gap-2 pt-2">
            <Button onClick={saveEdit} disabled={saving}>
              {saving ? "Saving…" : "Save & Push to etcd"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => { setEditTarget(null); setSaveError(null) }}
              disabled={saving}
            >
              Cancel
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
