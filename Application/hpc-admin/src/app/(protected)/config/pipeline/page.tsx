"use client"
import { useState, useEffect, useCallback } from "react"
import { Button } from "@/components/ui/Button"
import { Modal } from "@/components/ui/Modal"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Badge } from "@/components/ui/Badge"
import type { PipelineRule, PipelineRuleType, ResourceType } from "@/types"

// ── Constants ─────────────────────────────────────────────────────────────────

const ruleTypeOptions = [
  { value: "filter",    label: "Filter" },
  { value: "aggregate", label: "Aggregate" },
  { value: "derive",    label: "Derive" },
]
const resourceOptions = [
  { value: "cpu",  label: "CPU"     },
  { value: "gpu",  label: "GPU"     },
  { value: "mem",  label: "Memory"  },
  { value: "disk", label: "Disk"    },
  { value: "net",  label: "Network" },
]
const ruleTypeBadge: Record<PipelineRuleType, "info" | "warning" | "muted"> = {
  filter: "info", aggregate: "warning", derive: "muted",
}

function emptyForm() {
  return { name: "", type: "filter" as PipelineRuleType, resource: "cpu" as ResourceType, condition: "", enabled: true }
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface PushResult {
  pushed_to: string[]
  rule_count: number
  pushed_at: string
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function PipelinePage() {
  const [rules, setRules] = useState<PipelineRule[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Add/Edit modal
  const [modalOpen, setModalOpen] = useState(false)
  const [editRule, setEditRule] = useState<PipelineRule | null>(null)
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
  // true after any CRUD change that hasn't been pushed yet
  const [dirtyAfterPush, setDirtyAfterPush] = useState(false)

  // ── Load ───────────────────────────────────────────────────────────────────

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch("/api/config/pipeline")
      if (!res.ok) throw new Error("Failed to load pipeline rules")
      setRules(await res.json())
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
  function openEdit(r: PipelineRule) {
    setEditRule(r)
    setForm({ name: r.name, type: r.type, resource: r.resource, condition: r.condition, enabled: r.enabled })
    setSaveError(null)
    setModalOpen(true)
  }

  async function save() {
    if (!form.name.trim()) return
    setSaving(true)
    setSaveError(null)
    try {
      let res: Response
      if (editRule) {
        res = await fetch(`/api/config/pipeline/${editRule.id}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(form),
        })
      } else {
        res = await fetch("/api/config/pipeline", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(form),
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

  async function toggleEnabled(rule: PipelineRule) {
    try {
      await fetch(`/api/config/pipeline/${rule.id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...rule, enabled: !rule.enabled }),
      })
      setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))
      setDirtyAfterPush(true)
    } catch { /* silent — optimistic update already applied */ }
  }

  async function confirmDelete() {
    if (!deleteId) return
    setDeleting(true)
    try {
      await fetch(`/api/config/pipeline/${deleteId}`, { method: "DELETE" })
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
      const res = await fetch("/api/config/pipeline/push-to-etcd", { method: "POST" })
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

  const enabledCount = rules.filter(r => r.enabled).length

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
          <h1 className="text-lg font-semibold text-[#e6edf3]">Pipeline Management</h1>
          <p className="text-sm text-[#8b949e]">
            Configure preprocessing rules executed at collect agents
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button onClick={openAdd}>
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Add Rule
          </Button>
        </div>
      </div>

      {/* etcd push banner */}
      <div className="flex items-center justify-between rounded-lg border border-[#30363d] bg-[#161b22] px-4 py-3">
        <div className="text-sm space-y-0.5">
          <div className="flex items-center gap-3">
            <span className="text-[#8b949e]">
              {enabledCount} of {rules.length} rules enabled
            </span>
            {dirtyAfterPush && (
              <span className="text-xs text-[#f0883e] font-medium">
                ● unsaved changes — push to apply
              </span>
            )}
            {!dirtyAfterPush && lastPush && (
              <span className="text-xs text-[#3fb950]">
                ✓ pushed to {lastPush.pushed_to.length} agent{lastPush.pushed_to.length !== 1 ? "s" : ""} at{" "}
                {new Date(lastPush.pushed_at).toLocaleTimeString()}
              </span>
            )}
          </div>
          {lastPush && (
            <p className="text-xs text-[#6e7681]">
              Agents: {lastPush.pushed_to.join(", ")}
            </p>
          )}
          {pushError && (
            <p className="text-xs text-[#f85149]">{pushError}</p>
          )}
        </div>
        <Button
          variant="secondary"
          onClick={pushToEtcd}
          disabled={pushing || rules.length === 0}
        >
          {pushing ? "Pushing…" : "Push to Agents"}
        </Button>
      </div>

      {/* Rule cards */}
      {rules.length === 0 ? (
        <p className="text-sm text-[#8b949e] text-center py-10">
          No pipeline rules yet. Add one to get started.
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
                <div className="flex items-center gap-2 mb-1">
                  <Badge variant={ruleTypeBadge[r.type]}>{r.type}</Badge>
                  <span className="text-sm font-semibold text-[#e6edf3]">{r.name}</span>
                  <span className="text-xs text-[#6e7681]">· {r.resource.toUpperCase()}</span>
                </div>
                <code className="text-xs text-[#8b949e] font-mono">{r.condition}</code>
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
        title={editRule ? "Edit Rule" : "Add Rule"}
      >
        <div className="space-y-4">
          <Input
            label="Rule Name"
            value={form.name}
            onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="e.g. Drop zero-value GPU"
          />
          <div className="grid grid-cols-2 gap-4">
            <Select
              label="Type"
              options={ruleTypeOptions}
              value={form.type}
              onChange={e => setForm(f => ({ ...f, type: e.target.value as PipelineRuleType }))}
            />
            <Select
              label="Resource"
              options={resourceOptions}
              value={form.resource}
              onChange={e => setForm(f => ({ ...f, resource: e.target.value as ResourceType }))}
            />
          </div>
          <Input
            label="Condition"
            value={form.condition}
            onChange={e => setForm(f => ({ ...f, condition: e.target.value }))}
            placeholder="e.g. value == 0"
          />
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
      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete Rule">
        <p className="text-sm text-[#e6edf3] mb-5">
          Are you sure you want to delete this rule? This cannot be undone.
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
