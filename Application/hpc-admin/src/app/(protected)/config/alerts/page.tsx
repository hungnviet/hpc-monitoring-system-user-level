"use client"
import { useState, useEffect, useCallback } from "react"
import { Button } from "@/components/ui/Button"
import { Modal } from "@/components/ui/Modal"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Badge } from "@/components/ui/Badge"
import type { AlertRule, AlertSeverity, ResourceType } from "@/types"

// ── Constants ─────────────────────────────────────────────────────────────────

const severityOptions = [
  { value: "info",     label: "Info"     },
  { value: "warning",  label: "Warning"  },
  { value: "critical", label: "Critical" },
]
const resourceOptions = [
  { value: "cpu",  label: "CPU"     },
  { value: "gpu",  label: "GPU"     },
  { value: "mem",  label: "Memory"  },
  { value: "disk", label: "Disk"    },
  { value: "net",  label: "Network" },
]
const operatorOptions = [
  { value: ">",  label: ">" },
  { value: "<",  label: "<" },
  { value: ">=", label: ">=" },
  { value: "<=", label: "<=" },
]
const groupOptions = [
  { value: "gpu-cluster", label: "gpu-cluster" },
  { value: "cpu-cluster", label: "cpu-cluster" },
  { value: "storage",     label: "storage" },
  { value: "all",         label: "all" },
]

const severityVariant: Record<AlertSeverity, "danger" | "warning" | "info"> = {
  critical: "danger", warning: "warning", info: "info",
}

// Resources whose > / >= rules map to etcd threshold_rules keys
const SYNCABLE_RESOURCES = new Set(["cpu", "mem", "gpu", "disk"])

function emptyForm(): Omit<AlertRule, "id"> {
  return { name: "", nodeGroup: "all", resource: "cpu", operator: ">", threshold: 80, severity: "warning", enabled: true }
}

// DB returns snake_case — map to the TypeScript type
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function mapRow(row: any): AlertRule {
  return {
    id:        row.id,
    name:      row.name,
    nodeGroup: row.node_group,
    resource:  row.resource,
    operator:  row.operator,
    threshold: Number(row.threshold),
    severity:  row.severity,
    enabled:   row.enabled,
  }
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface PushResult {
  pushed_to: string[]
  thresholds: Record<string, { max: number }>
  skipped: string[]
  pushed_at: string
}

// Whether a rule contributes to the etcd threshold_rules push
function isSyncable(r: AlertRule) {
  return (r.operator === ">" || r.operator === ">=") && SYNCABLE_RESOURCES.has(r.resource)
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AlertsPage() {
  const [rules, setRules] = useState<AlertRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Add/Edit modal
  const [modalOpen, setModalOpen] = useState(false)
  const [editRule, setEditRule] = useState<AlertRule | null>(null)
  const [form, setForm] = useState(emptyForm())
  const [saving, setSaving] = useState(false)
  const [saveError, setSaveError] = useState<string | null>(null)

  // Delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  // etcd push state
  const [pushing, setPushing] = useState(false)
  const [lastPush, setLastPush] = useState<PushResult | null>(null)
  const [pushError, setPushError] = useState<string | null>(null)
  const [dirtyAfterPush, setDirtyAfterPush] = useState(false)

  // ── Load ───────────────────────────────────────────────────────────────────

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch("/api/config/alerts")
      if (!res.ok) throw new Error("Failed to load alert rules")
      const rows = await res.json()
      setRules(rows.map(mapRow))
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // ── CRUD ───────────────────────────────────────────────────────────────────

  function openAdd() {
    setEditRule(null)
    setForm(emptyForm())
    setSaveError(null)
    setModalOpen(true)
  }
  function openEdit(r: AlertRule) {
    setEditRule(r)
    setForm({ name: r.name, nodeGroup: r.nodeGroup, resource: r.resource, operator: r.operator, threshold: r.threshold, severity: r.severity, enabled: r.enabled })
    setSaveError(null)
    setModalOpen(true)
  }

  async function save() {
    if (!form.name.trim()) return
    setSaving(true)
    setSaveError(null)
    try {
      const payload = {
        name:       form.name,
        node_group: form.nodeGroup,
        resource:   form.resource,
        operator:   form.operator,
        threshold:  form.threshold,
        severity:   form.severity,
        enabled:    form.enabled,
      }
      let res: Response
      if (editRule) {
        res = await fetch(`/api/config/alerts/${editRule.id}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        })
      } else {
        res = await fetch("/api/config/alerts", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        })
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error ?? "Save failed")
      }
      setModalOpen(false)
      setDirtyAfterPush(true)
      await load()
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Save failed")
    } finally {
      setSaving(false)
    }
  }

  async function toggleEnabled(rule: AlertRule) {
    try {
      await fetch(`/api/config/alerts/${rule.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name:       rule.name,
          node_group: rule.nodeGroup,
          resource:   rule.resource,
          operator:   rule.operator,
          threshold:  rule.threshold,
          severity:   rule.severity,
          enabled:    !rule.enabled,
        }),
      })
      setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))
      setDirtyAfterPush(true)
    } catch { /* silent optimistic update */ }
  }

  async function confirmDelete() {
    if (!deleteId) return
    setDeleting(true)
    try {
      await fetch(`/api/config/alerts/${deleteId}`, { method: "DELETE" })
      setRules(prev => prev.filter(r => r.id !== deleteId))
      setDeleteId(null)
      setDirtyAfterPush(true)
    } finally {
      setDeleting(false)
    }
  }

  // ── etcd push ──────────────────────────────────────────────────────────────

  async function pushToEtcd() {
    setPushing(true)
    setPushError(null)
    try {
      const res = await fetch("/api/config/alerts/push-to-etcd", { method: "POST" })
      const body = await res.json()
      if (!res.ok) throw new Error(body.error ?? "Push failed")
      setLastPush(body as PushResult)
      setDirtyAfterPush(false)
    } catch (e) {
      setPushError(e instanceof Error ? e.message : "Push failed")
    } finally {
      setPushing(false)
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  const syncableCount = rules.filter(r => r.enabled && isSyncable(r)).length

  if (loading) {
    return (
      <div className="p-6 space-y-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-16 rounded-xl bg-[#1c2128] animate-pulse" />
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

  return (
    <div className="p-6 space-y-5">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Alert Management</h1>
          <p className="text-sm text-[#8b949e]">Define resource thresholds and in-app alert rules</p>
        </div>
        <Button onClick={openAdd}>
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Add Rule
        </Button>
      </div>

      {/* etcd sync banner */}
      <div className="flex items-center justify-between rounded-lg border border-[#30363d] bg-[#161b22] px-4 py-3">
        <div className="text-sm space-y-0.5">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-[#8b949e]">
              {syncableCount} rule{syncableCount !== 1 ? "s" : ""} sync to collect-agent threshold_rules
            </span>
            {dirtyAfterPush && (
              <span className="text-xs text-[#f0883e] font-medium">
                ● changes not pushed — agents still using old thresholds
              </span>
            )}
            {!dirtyAfterPush && lastPush && (
              <span className="text-xs text-[#3fb950]">
                ✓ synced to {lastPush.pushed_to.length} agent{lastPush.pushed_to.length !== 1 ? "s" : ""} at{" "}
                {new Date(lastPush.pushed_at).toLocaleTimeString()}
              </span>
            )}
          </div>
          {lastPush && (
            <div className="text-xs text-[#6e7681] space-y-0.5">
              <p>
                Pushed thresholds:{" "}
                {Object.entries(lastPush.thresholds)
                  .map(([k, v]) => `${k} ≤ ${v.max}`)
                  .join(" · ")}
              </p>
              {lastPush.skipped.length > 0 && (
                <p>Skipped (no etcd mapping): {lastPush.skipped.join(", ")}</p>
              )}
            </div>
          )}
          {pushError && <p className="text-xs text-[#f85149]">{pushError}</p>}
        </div>
        <Button
          variant="secondary"
          onClick={pushToEtcd}
          disabled={pushing || syncableCount === 0}
        >
          {pushing ? "Syncing…" : "Sync to etcd"}
        </Button>
      </div>

      {/* Rule cards */}
      {rules.length === 0 ? (
        <p className="text-sm text-[#8b949e] text-center py-10">
          No alert rules yet. Add one to get started.
        </p>
      ) : (
        <div className="space-y-2">
          {rules.map(r => (
            <div
              key={r.id}
              className={`bg-[#161b22] border rounded-xl px-5 py-4 flex items-center gap-4 transition-opacity ${
                r.enabled ? "border-[#30363d]" : "border-[#21262d] opacity-55"
              }`}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap mb-1">
                  <Badge variant={severityVariant[r.severity]}>{r.severity}</Badge>
                  <span className="text-sm font-semibold text-[#e6edf3]">{r.name}</span>
                  {isSyncable(r) && r.enabled && (
                    <span className="text-xs text-[#58a6ff] border border-[#58a6ff]/30 rounded px-1.5 py-0.5">
                      etcd
                    </span>
                  )}
                </div>
                <p className="text-xs text-[#8b949e]">
                  <span className="text-[#e6edf3]">{r.nodeGroup}</span>
                  {" · "}
                  {r.resource.toUpperCase()} {r.operator}{" "}
                  <span className="text-[#58a6ff]">{r.threshold}%</span>
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={() => toggleEnabled(r)}
                  className={`relative w-10 h-5 rounded-full transition-colors cursor-pointer ${
                    r.enabled ? "bg-[#238636]" : "bg-[#30363d]"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${
                      r.enabled ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <Button size="sm" variant="secondary" onClick={() => openEdit(r)}>Edit</Button>
                <Button size="sm" variant="danger" onClick={() => setDeleteId(r.id)}>Delete</Button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Add / Edit modal */}
      <Modal
        open={modalOpen}
        onClose={() => { setModalOpen(false); setSaveError(null) }}
        title={editRule ? "Edit Alert Rule" : "Add Alert Rule"}
      >
        <div className="space-y-4">
          <Input
            label="Rule Name"
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="e.g. GPU Overload"
          />
          <div className="grid grid-cols-2 gap-4">
            <Select
              label="Node Group"
              options={groupOptions}
              value={form.nodeGroup}
              onChange={e => setForm(f => ({ ...f, nodeGroup: e.target.value }))}
            />
            <Select
              label="Resource"
              options={resourceOptions}
              value={form.resource}
              onChange={e => setForm(f => ({ ...f, resource: e.target.value as ResourceType }))}
            />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <Select
              label="Operator"
              options={operatorOptions}
              value={form.operator}
              onChange={e => setForm(f => ({ ...f, operator: e.target.value as AlertRule["operator"] }))}
            />
            <Input
              label="Threshold (%)"
              type="number"
              min={0}
              max={100}
              value={form.threshold}
              onChange={e => setForm(f => ({ ...f, threshold: parseInt(e.target.value) || 0 }))}
            />
            <Select
              label="Severity"
              options={severityOptions}
              value={form.severity}
              onChange={e => setForm(f => ({ ...f, severity: e.target.value as AlertSeverity }))}
            />
          </div>

          {/* etcd eligibility hint in modal */}
          {(form.operator === ">" || form.operator === ">=") && SYNCABLE_RESOURCES.has(form.resource) && (
            <div className="rounded border border-[#58a6ff]/20 bg-[#58a6ff]/5 px-3 py-2 text-xs text-[#79c0ff]">
              This rule will contribute to <code className="font-mono">threshold_rules</code> in etcd
              when you click "Sync to etcd".
            </div>
          )}

          {saveError && <p className="text-xs text-[#f85149]">{saveError}</p>}
          <div className="flex gap-2 pt-2">
            <Button onClick={save} disabled={saving || !form.name.trim()}>
              {saving ? "Saving…" : editRule ? "Save Changes" : "Add Rule"}
            </Button>
            <Button variant="secondary" onClick={() => { setModalOpen(false); setSaveError(null) }} disabled={saving}>
              Cancel
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete confirm */}
      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete Alert Rule">
        <p className="text-sm text-[#e6edf3] mb-5">
          Are you sure you want to delete this alert rule?
        </p>
        <div className="flex gap-2">
          <Button variant="danger" onClick={confirmDelete} disabled={deleting}>
            {deleting ? "Deleting…" : "Delete"}
          </Button>
          <Button variant="secondary" onClick={() => setDeleteId(null)} disabled={deleting}>
            Cancel
          </Button>
        </div>
      </Modal>
    </div>
  )
}
