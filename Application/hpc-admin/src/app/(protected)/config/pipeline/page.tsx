"use client"
import { useState } from "react"
import { mockPipelineRules } from "@/lib/mockData/alerts"
import { Button } from "@/components/ui/Button"
import { Modal } from "@/components/ui/Modal"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Badge } from "@/components/ui/Badge"
import type { PipelineRule, PipelineRuleType, ResourceType } from "@/types"

const ruleTypeOptions = [
  { value: "filter",    label: "Filter" },
  { value: "aggregate", label: "Aggregate" },
  { value: "derive",    label: "Derive" },
]
const resourceOptions = [
  { value: "cpu", label: "CPU" }, { value: "gpu", label: "GPU" },
  { value: "mem", label: "Memory" }, { value: "disk", label: "Disk" }, { value: "net", label: "Network" },
]
const ruleTypeBadge: Record<PipelineRuleType, "info" | "warning" | "muted"> = {
  filter: "info", aggregate: "warning", derive: "muted"
}

function emptyForm() {
  return { name: "", type: "filter" as PipelineRuleType, resource: "cpu" as ResourceType, condition: "", enabled: true }
}

export default function PipelinePage() {
  const [rules, setRules] = useState(mockPipelineRules)
  const [modalOpen, setModalOpen] = useState(false)
  const [editRule, setEditRule] = useState<PipelineRule | null>(null)
  const [form, setForm] = useState(emptyForm())
  const [deleteId, setDeleteId] = useState<string | null>(null)

  function openAdd() { setEditRule(null); setForm(emptyForm()); setModalOpen(true) }
  function openEdit(r: PipelineRule) { setEditRule(r); setForm({ name: r.name, type: r.type, resource: r.resource, condition: r.condition, enabled: r.enabled }); setModalOpen(true) }
  function save() {
    if (!form.name) return
    if (editRule) {
      setRules(prev => prev.map(r => r.id === editRule.id ? { ...r, ...form } : r))
    } else {
      setRules(prev => [...prev, { id: `pr${Date.now()}`, ...form }])
    }
    setModalOpen(false)
  }
  function toggleEnabled(id: string) { setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r)) }
  function deleteRule(id: string) { setRules(prev => prev.filter(r => r.id !== id)); setDeleteId(null) }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Pipeline Management</h1>
          <p className="text-sm text-[#8b949e]">Configure preprocessing rules executed at collect agents</p>
        </div>
        <Button onClick={openAdd}>
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
          Add Rule
        </Button>
      </div>

      <div className="space-y-2">
        {rules.map(r => (
          <div key={r.id} className={`bg-[#161b22] border rounded-xl px-5 py-4 flex items-center gap-4 ${r.enabled ? "border-[#30363d]" : "border-[#21262d] opacity-60"}`}>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Badge variant={ruleTypeBadge[r.type]}>{r.type}</Badge>
                <span className="text-sm font-semibold text-[#e6edf3]">{r.name}</span>
                <span className="text-xs text-[#6e7681]">· {r.resource.toUpperCase()}</span>
              </div>
              <code className="text-xs text-[#8b949e] font-mono">{r.condition}</code>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {/* Toggle */}
              <button onClick={() => toggleEnabled(r.id)} className={`relative w-10 h-5 rounded-full transition-colors ${r.enabled ? "bg-[#238636]" : "bg-[#30363d]"}`}>
                <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${r.enabled ? "translate-x-5" : ""}`} />
              </button>
              <Button size="sm" variant="secondary" onClick={() => openEdit(r)}>Edit</Button>
              <Button size="sm" variant="danger" onClick={() => setDeleteId(r.id)}>Delete</Button>
            </div>
          </div>
        ))}
      </div>

      {/* Add/Edit modal */}
      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editRule ? "Edit Rule" : "Add Rule"}>
        <div className="space-y-4">
          <Input label="Rule Name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. Drop zero-value GPU" />
          <div className="grid grid-cols-2 gap-4">
            <Select label="Type" options={ruleTypeOptions} value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value as PipelineRuleType }))} />
            <Select label="Resource" options={resourceOptions} value={form.resource} onChange={e => setForm(f => ({ ...f, resource: e.target.value as ResourceType }))} />
          </div>
          <Input label="Condition" value={form.condition} onChange={e => setForm(f => ({ ...f, condition: e.target.value }))} placeholder="e.g. value == 0" />
          <div className="flex gap-2 pt-2">
            <Button onClick={save} disabled={!form.name}>{editRule ? "Save Changes" : "Add Rule"}</Button>
            <Button variant="secondary" onClick={() => setModalOpen(false)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      {/* Delete confirm */}
      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete Rule">
        <p className="text-sm text-[#e6edf3] mb-5">Are you sure you want to delete this rule? This cannot be undone.</p>
        <div className="flex gap-2">
          <Button variant="danger" onClick={() => deleteRule(deleteId!)}>Delete</Button>
          <Button variant="secondary" onClick={() => setDeleteId(null)}>Cancel</Button>
        </div>
      </Modal>
    </div>
  )
}
