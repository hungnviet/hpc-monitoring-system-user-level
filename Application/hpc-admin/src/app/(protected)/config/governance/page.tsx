"use client"
import { useState, useEffect, useCallback } from "react"
import { Button } from "@/components/ui/Button"
import { Badge } from "@/components/ui/Badge"
import { Modal } from "@/components/ui/Modal"
import { Input } from "@/components/ui/Input"
import type { ConfigVersion, AuditLog } from "@/types"

// ── Helpers ───────────────────────────────────────────────────────────────────

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60)    return `${diff}s ago`
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

const actionColors: Record<string, string> = {
  CREATE:  "text-[#3fb950]",
  UPDATE:  "text-[#58a6ff]",
  DELETE:  "text-[#f85149]",
  ROLLOUT: "text-[#d29922]",
  LOGIN:   "text-[#8b949e]",
}

// DB returns snake_case
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapVersion(row: any): ConfigVersion {
  return {
    id:          row.id,
    version:     row.version,
    author:      row.author,
    description: row.description ?? "",
    createdAt:   row.created_at,
    active:      row.active,
  }
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapAuditLog(row: any): AuditLog {
  return {
    id:        row.id,
    actor:     row.actor,
    action:    row.action,
    target:    row.target,
    detail:    row.detail ?? "",
    createdAt: row.created_at,
  }
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface SnapshotResult {
  version: { version: string }
  node_count: number
  agent_count: number
  rule_count: number
  threshold_count: number
  etcd_errors: string[]
}

interface ActivateResult {
  version: string
  etcd: { pushed_to_nodes: string[]; pushed_to_agents: string[]; error: string | null }
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function GovernancePage() {
  const [tab, setTab] = useState<"versions" | "audit">("versions")

  // Data
  const [versions, setVersions] = useState<ConfigVersion[]>([])
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])
  const [loadingVersions, setLoadingVersions] = useState(true)
  const [loadingAudit, setLoadingAudit] = useState(true)
  const [dataError, setDataError] = useState<string | null>(null)

  // Push-to-nodes modal
  const [pushModalOpen, setPushModalOpen] = useState(false)
  const [pushDescription, setPushDescription] = useState("")
  const [pushing, setPushing] = useState(false)
  const [pushResult, setPushResult] = useState<SnapshotResult | null>(null)
  const [pushError, setPushError] = useState<string | null>(null)

  // Activate (rollout) existing version
  const [activateTarget, setActivateTarget] = useState<ConfigVersion | null>(null)
  const [activating, setActivating] = useState(false)
  const [activateResult, setActivateResult] = useState<ActivateResult | null>(null)
  const [activateError, setActivateError] = useState<string | null>(null)

  // ── Load ───────────────────────────────────────────────────────────────────

  const loadVersions = useCallback(async () => {
    setLoadingVersions(true)
    try {
      const res = await fetch("/api/config/governance/versions")
      if (!res.ok) throw new Error("Failed to load versions")
      const rows = await res.json()
      setVersions(rows.map(mapVersion))
    } catch (e) {
      setDataError(e instanceof Error ? e.message : "Error")
    } finally {
      setLoadingVersions(false)
    }
  }, [])

  const loadAudit = useCallback(async () => {
    setLoadingAudit(true)
    try {
      const res = await fetch("/api/config/governance/audit")
      if (!res.ok) throw new Error("Failed to load audit log")
      const rows = await res.json()
      setAuditLogs(rows.map(mapAuditLog))
    } catch (e) {
      setDataError(e instanceof Error ? e.message : "Error")
    } finally {
      setLoadingAudit(false)
    }
  }, [])

  useEffect(() => { loadVersions() }, [loadVersions])
  useEffect(() => { if (tab === "audit") loadAudit() }, [tab, loadAudit])

  // ── Push to Nodes (snapshot + push) ───────────────────────────────────────

  function openPushModal() {
    setPushDescription("")
    setPushError(null)
    setPushResult(null)
    setPushModalOpen(true)
  }

  async function doSnapshotAndPush() {
    if (!pushDescription.trim()) return
    setPushing(true)
    setPushError(null)
    try {
      const res = await fetch("/api/config/governance/snapshot-and-push", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ description: pushDescription }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error ?? "Push failed")
      setPushResult(data as SnapshotResult)
      await loadVersions()
      await loadAudit()
    } catch (e) {
      setPushError(e instanceof Error ? e.message : "Push failed")
    } finally {
      setPushing(false)
    }
  }

  // ── Activate existing version ──────────────────────────────────────────────

  function openActivate(v: ConfigVersion) {
    setActivateTarget(v)
    setActivateError(null)
    setActivateResult(null)
  }

  async function doActivate() {
    if (!activateTarget) return
    setActivating(true)
    setActivateError(null)
    try {
      const res = await fetch("/api/config/governance/rollout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ versionId: activateTarget.id }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error ?? "Activation failed")
      setActivateResult({
        version: data.version,
        etcd: data.etcd ?? { pushed_to_nodes: [], pushed_to_agents: [], error: null },
      })
      setActivateTarget(null)
      await loadVersions()
      await loadAudit()
    } catch (e) {
      setActivateError(e instanceof Error ? e.message : "Activation failed")
    } finally {
      setActivating(false)
    }
  }

  // ── Derived ────────────────────────────────────────────────────────────────

  const activeVersion = versions.find(v => v.active)

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">System Governance</h1>
          <p className="text-sm text-[#8b949e]">Configuration versioning, audit logs, and live rollout</p>
        </div>
        <div className="flex items-center gap-3">
          {activateResult && (
            <span className="text-sm text-[#3fb950]">
              ✓ v{activateResult.version} activated
              {activateResult.etcd.pushed_to_nodes.length > 0 &&
                ` — pushed to ${activateResult.etcd.pushed_to_nodes.length} node${activateResult.etcd.pushed_to_nodes.length !== 1 ? "s" : ""}`}
            </span>
          )}
          <Button onClick={openPushModal}>
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Push to Nodes
          </Button>
        </div>
      </div>

      {/* Active version banner */}
      {activeVersion && (
        <div className="flex items-center gap-3 rounded-lg border border-[#238636]/40 bg-[#238636]/10 px-4 py-3">
          <span className="text-xs text-[#3fb950] font-semibold uppercase tracking-wider">Active</span>
          <span className="text-sm font-mono text-[#e6edf3] font-semibold">v{activeVersion.version}</span>
          <span className="text-sm text-[#8b949e]">{activeVersion.description}</span>
          <span className="text-xs text-[#6e7681] ml-auto">{timeAgo(activeVersion.createdAt)} · by {activeVersion.author}</span>
        </div>
      )}

      {dataError && (
        <div className="rounded-lg border border-[#f85149]/40 bg-[#f85149]/10 px-4 py-3 text-sm text-[#f85149]">
          {dataError}
        </div>
      )}

      {/* Tabs */}
      <div className="flex rounded-lg border border-[#30363d] w-fit overflow-hidden">
        {(["versions", "audit"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-5 py-2 text-sm capitalize transition-colors cursor-pointer ${
              tab === t
                ? "bg-[#1f6feb] text-white"
                : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"
            }`}
          >
            {t === "versions" ? "Version History" : "Audit Log"}
          </button>
        ))}
      </div>

      {/* Versions tab */}
      {tab === "versions" && (
        loadingVersions ? (
          <div className="space-y-2">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-16 rounded-xl bg-[#1c2128] animate-pulse" />
            ))}
          </div>
        ) : versions.length === 0 ? (
          <p className="text-sm text-[#8b949e] text-center py-10">
            No versions yet. Click "Push to Nodes" to create the first snapshot.
          </p>
        ) : (
          <div className="space-y-2">
            {versions.map(v => (
              <div
                key={v.id}
                className={`bg-[#161b22] border rounded-xl px-5 py-4 flex items-center gap-4 ${
                  v.active ? "border-[#238636]" : "border-[#30363d]"
                }`}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-sm font-semibold text-[#e6edf3] font-mono">v{v.version}</span>
                    {v.active && <Badge variant="success">Active</Badge>}
                  </div>
                  <p className="text-xs text-[#8b949e] truncate">{v.description}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <div className="text-right">
                    <p className="text-xs text-[#6e7681]">{timeAgo(v.createdAt)}</p>
                    <p className="text-xs text-[#8b949e] mt-0.5">by {v.author}</p>
                  </div>
                  {!v.active && (
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => openActivate(v)}
                    >
                      Activate
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )
      )}

      {/* Audit tab */}
      {tab === "audit" && (
        loadingAudit ? (
          <div className="space-y-1">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="h-10 rounded bg-[#1c2128] animate-pulse" />
            ))}
          </div>
        ) : (
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
            <div className="flex items-center justify-between px-4 py-2 border-b border-[#30363d]">
              <span className="text-xs text-[#8b949e]">Last {auditLogs.length} entries</span>
              <button
                onClick={loadAudit}
                className="text-xs text-[#8b949e] hover:text-[#e6edf3] cursor-pointer"
              >
                Refresh
              </button>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#30363d]">
                  {["Time", "Actor", "Action", "Target", "Detail"].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#8b949e] uppercase tracking-wider">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {auditLogs.map(log => (
                  <tr key={log.id} className="border-b border-[#21262d] last:border-0 hover:bg-[#1c2128] transition-colors">
                    <td className="px-4 py-3 text-xs text-[#6e7681] whitespace-nowrap">{timeAgo(log.createdAt)}</td>
                    <td className="px-4 py-3 text-xs text-[#e6edf3]">{log.actor}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs font-mono font-semibold ${actionColors[log.action] ?? "text-[#8b949e]"}`}>
                        {log.action}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-[#8b949e]">{log.target}</td>
                    <td className="px-4 py-3 text-xs text-[#8b949e]">{log.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Push to Nodes modal */}
      <Modal
        open={pushModalOpen}
        onClose={() => !pushing && setPushModalOpen(false)}
        title="Push Configuration to Nodes"
      >
        {pushResult ? (
          <div className="space-y-4">
            <div className="rounded-lg border border-[#238636]/40 bg-[#238636]/10 px-4 py-3 space-y-2">
              <p className="text-sm font-semibold text-[#3fb950]">
                ✓ Snapshot v{pushResult.version.version} saved and pushed
              </p>
              <div className="text-xs text-[#8b949e] space-y-1">
                <p>Nodes updated: <span className="text-[#e6edf3]">{pushResult.node_count}</span></p>
                <p>Agents updated: <span className="text-[#e6edf3]">{pushResult.agent_count}</span></p>
                <p>Pipeline rules pushed: <span className="text-[#e6edf3]">{pushResult.rule_count}</span></p>
                <p>Alert thresholds pushed: <span className="text-[#e6edf3]">{pushResult.threshold_count}</span></p>
                {pushResult.etcd_errors.length > 0 && (
                  <p className="text-[#f0883e]">etcd warning: {pushResult.etcd_errors.join(", ")}</p>
                )}
              </div>
            </div>
            <Button variant="secondary" onClick={() => setPushModalOpen(false)}>Close</Button>
          </div>
        ) : (
          <div className="space-y-4">
            <p className="text-sm text-[#e6edf3]">
              Takes a snapshot of all current settings (collection, pipeline rules, alert thresholds),
              saves it as a new version, and pushes everything live to all registered nodes and collect agents via etcd.
            </p>
            {activeVersion && (
              <p className="text-xs text-[#8b949e]">
                Current active version:{" "}
                <span className="font-mono text-[#58a6ff]">v{activeVersion.version}</span>
                {" — "}a new version will be created.
              </p>
            )}
            <Input
              label="Version description"
              value={pushDescription}
              onChange={e => setPushDescription(e.target.value)}
              placeholder="e.g. Reduce GPU interval to 5s"
            />
            {pushError && <p className="text-xs text-[#f85149]">{pushError}</p>}
            <div className="flex gap-2 pt-1">
              <Button onClick={doSnapshotAndPush} loading={pushing} disabled={!pushDescription.trim()}>
                {pushing ? "Pushing…" : "Save & Push to All Nodes"}
              </Button>
              <Button variant="secondary" onClick={() => setPushModalOpen(false)} disabled={pushing}>
                Cancel
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Activate existing version modal */}
      <Modal
        open={!!activateTarget}
        onClose={() => !activating && setActivateTarget(null)}
        title={`Activate v${activateTarget?.version}`}
      >
        <div className="space-y-4">
          <p className="text-sm text-[#e6edf3]">
            This will mark <span className="font-mono text-[#58a6ff]">v{activateTarget?.version}</span> as
            the active configuration and replay its stored snapshot to all nodes and agents in etcd.
          </p>
          <p className="text-xs text-[#8b949e]">{activateTarget?.description}</p>
          {activateTarget && !activateTarget.id.includes("mock") && (
            <div className="rounded border border-[#d29922]/30 bg-[#d29922]/5 px-3 py-2 text-xs text-[#d29922]">
              Only versions created by "Push to Nodes" carry a config snapshot. Older versions
              without a snapshot will be marked active in the DB only.
            </div>
          )}
          {activateError && <p className="text-xs text-[#f85149]">{activateError}</p>}
          <div className="flex gap-2">
            <Button onClick={doActivate} loading={activating}>
              {activating ? "Activating…" : "Activate & Push"}
            </Button>
            <Button variant="secondary" onClick={() => setActivateTarget(null)} disabled={activating}>
              Cancel
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
