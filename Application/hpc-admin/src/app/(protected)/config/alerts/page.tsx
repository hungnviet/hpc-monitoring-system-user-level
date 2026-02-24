"use client"
import { useState } from "react"
import { mockAlertRules } from "@/lib/mockData/alerts"
import { Button } from "@/components/ui/Button"
import { Modal } from "@/components/ui/Modal"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Badge } from "@/components/ui/Badge"
import type { AlertRule, AlertSeverity, ResourceType } from "@/types"

const severityOptions = [
  { value: "info",     label: "Info"     },
  { value: "warning",  label: "Warning"  },
  { value: "critical", label: "Critical" },
]
const resourceOptions = [
  { value: "cpu", label: "CPU" }, { value: "gpu", label: "GPU" },
  { value: "mem", label: "Memory" }, { value: "disk", label: "Disk" }, { value: "net", label: "Network" },
]
const operatorOptions = [
  { value: ">",  label: ">" }, { value: "<",  label: "<" },
  { value: ">=", label: ">=" }, { value: "<=", label: "<=" },
]
const groupOptions = [
  { value: "gpu-cluster", label: "gpu-cluster" },
  { value: "cpu-cluster", label: "cpu-cluster" },
  { value: "storage",     label: "storage" },
  { value: "all",         label: "all" },
]

const severityVariant: Record<AlertSeverity, "danger" | "warning" | "info"> = {
  critical: "danger", warning: "warning", info: "info"
}

function emptyForm(): Omit<AlertRule, "id"> {
  return { name: "", nodeGroup: "all", resource: "cpu", operator: ">", threshold: 80, severity: "warning", enabled: true }
}

export default function AlertsPage() {
  const [rules, setRules] = useState(mockAlertRules)
  const [modalOpen, setModalOpen] = useState(false)
  const [editRule, setEditRule] = useState<AlertRule | null>(null)
  const [form, setForm] = useState(emptyForm())
  const [deleteId, setDeleteId] = useState<string | null>(null)

  function openAdd() { setEditRule(null); setForm(emptyForm()); setModalOpen(true) }
  function openEdit(r: AlertRule) { setEditRule(r); setForm({ name: r.name, nodeGroup: r.nodeGroup, resource: r.resource, operator: r.operator, threshold: r.threshold, severity: r.severity, enabled: r.enabled }); setModalOpen(true) }
  function save() {
    if (!form.name) return
    if (editRule) {
      setRules(prev => prev.map(r => r.id === editRule.id ? { ...r, ...form } : r))
    } else {
      setRules(prev => [...prev, { id: `ar${Date.now()}`, ...form }])
    }
    setModalOpen(false)
  }
  function toggleEnabled(id: string) { setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r)) }
  function deleteRule(id: string) { setRules(prev => prev.filter(r => r.id !== id)); setDeleteId(null) }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Alert Management</h1>
          <p className="text-sm text-[#8b949e]">Define resource thresholds and in-app alert rules</p>
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
              <div className="flex items-center gap-2 flex-wrap mb-1">
                <Badge variant={severityVariant[r.severity]}>{r.severity}</Badge>
                <span className="text-sm font-semibold text-[#e6edf3]">{r.name}</span>
              </div>
              <p className="text-xs text-[#8b949e]">
                <span className="text-[#e6edf3]">{r.nodeGroup}</span> ·{" "}
                {r.resource.toUpperCase()} {r.operator} <span className="text-[#58a6ff]">{r.threshold}%</span>
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button onClick={() => toggleEnabled(r.id)} className={`relative w-10 h-5 rounded-full transition-colors ${r.enabled ? "bg-[#238636]" : "bg-[#30363d]"}`}>
                <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${r.enabled ? "translate-x-5" : ""}`} />
              </button>
              <Button size="sm" variant="secondary" onClick={() => openEdit(r)}>Edit</Button>
              <Button size="sm" variant="danger" onClick={() => setDeleteId(r.id)}>Delete</Button>
            </div>
          </div>
        ))}
      </div>

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title={editRule ? "Edit Alert Rule" : "Add Alert Rule"}>
        <div className="space-y-4">
          <Input label="Rule Name" value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="e.g. GPU Overload" />
          <div className="grid grid-cols-2 gap-4">
            <Select label="Node Group" options={groupOptions} value={form.nodeGroup} onChange={e => setForm(f => ({ ...f, nodeGroup: e.target.value }))} />
            <Select label="Resource" options={resourceOptions} value={form.resource} onChange={e => setForm(f => ({ ...f, resource: e.target.value as ResourceType }))} />
          </div>
          <div className="grid grid-cols-3 gap-4">
            <Select label="Operator" options={operatorOptions} value={form.operator} onChange={e => setForm(f => ({ ...f, operator: e.target.value as AlertRule["operator"] }))} />
            <Input label="Threshold (%)" type="number" min={0} max={100} value={form.threshold} onChange={e => setForm(f => ({ ...f, threshold: parseInt(e.target.value) || 0 }))} />
            <Select label="Severity" options={severityOptions} value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value as AlertSeverity }))} />
          </div>
          <div className="flex gap-2 pt-2">
            <Button onClick={save} disabled={!form.name}>{editRule ? "Save Changes" : "Add Rule"}</Button>
            <Button variant="secondary" onClick={() => setModalOpen(false)}>Cancel</Button>
          </div>
        </div>
      </Modal>

      <Modal open={!!deleteId} onClose={() => setDeleteId(null)} title="Delete Alert Rule">
        <p className="text-sm text-[#e6edf3] mb-5">Are you sure you want to delete this alert rule?</p>
        <div className="flex gap-2">
          <Button variant="danger" onClick={() => deleteRule(deleteId!)}>Delete</Button>
          <Button variant="secondary" onClick={() => setDeleteId(null)}>Cancel</Button>
        </div>
      </Modal>
    </div>
  )
}
