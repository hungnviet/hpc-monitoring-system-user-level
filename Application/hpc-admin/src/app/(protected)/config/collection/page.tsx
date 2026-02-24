"use client"
import { useState } from "react"
import { mockCollectionSettings } from "@/lib/mockData/alerts"
import { Table } from "@/components/ui/Table"
import { Modal } from "@/components/ui/Modal"
import { Input } from "@/components/ui/Input"
import { Select } from "@/components/ui/Select"
import { Button } from "@/components/ui/Button"
import { Badge } from "@/components/ui/Badge"
import type { CollectionSetting } from "@/types"

const agentOptions = [
  { value: "agent-a", label: "agent-a" },
  { value: "agent-b", label: "agent-b" },
  { value: "agent-c", label: "agent-c" },
]

export default function CollectionPage() {
  const [settings, setSettings] = useState(mockCollectionSettings)
  const [editTarget, setEditTarget] = useState<CollectionSetting | null>(null)
  const [form, setForm] = useState({ intervalSeconds: 10, windowSeconds: 60, collectAgent: "agent-a" })
  const [saved, setSaved] = useState(false)

  function openEdit(s: CollectionSetting) {
    setEditTarget(s)
    setForm({ intervalSeconds: s.intervalSeconds, windowSeconds: s.windowSeconds, collectAgent: s.collectAgent })
  }

  function saveEdit() {
    if (!editTarget) return
    setSettings(prev => prev.map(s => s.nodeId === editTarget.nodeId ? { ...s, ...form } : s))
    setEditTarget(null)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const columns = [
    { key: "node",     header: "Node",          render: (s: CollectionSetting) => <span className="font-medium text-[#e6edf3]">{s.nodeName}</span> },
    { key: "group",    header: "Group",          render: (s: CollectionSetting) => <Badge variant="info">{s.group}</Badge> },
    { key: "interval", header: "Interval",       render: (s: CollectionSetting) => <span className="text-sm text-[#e6edf3]">{s.intervalSeconds}s</span> },
    { key: "window",   header: "Window",         render: (s: CollectionSetting) => <span className="text-sm text-[#e6edf3]">{s.windowSeconds}s</span> },
    { key: "agent",    header: "Collect Agent",  render: (s: CollectionSetting) => <span className="text-xs font-mono text-[#8b949e]">{s.collectAgent}</span> },
    { key: "actions",  header: "",               render: (s: CollectionSetting) => (
      <Button size="sm" variant="secondary" onClick={() => openEdit(s)}>Edit</Button>
    )},
  ]

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Collection Settings</h1>
          <p className="text-sm text-[#8b949e]">Configure collection interval and agent assignment per node</p>
        </div>
        {saved && <span className="text-sm text-[#3fb950]">✓ Changes saved</span>}
      </div>

      {/* Group bulk config hint */}
      <div className="bg-[#1a2a3c] border border-[#1f3a5f] rounded-lg px-4 py-3 text-sm text-[#79c0ff]">
        Tip: Edit nodes individually below, or configure groups via the Pipeline rules to apply batch changes.
      </div>

      <Table columns={columns} data={settings} keyExtractor={s => s.nodeId} />

      <Modal open={!!editTarget} onClose={() => setEditTarget(null)} title={`Edit — ${editTarget?.nodeName}`}>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Interval (seconds)"
              type="number"
              min={1}
              value={form.intervalSeconds}
              onChange={e => setForm(f => ({ ...f, intervalSeconds: parseInt(e.target.value) || 10 }))}
            />
            <Input
              label="Window (seconds)"
              type="number"
              min={1}
              value={form.windowSeconds}
              onChange={e => setForm(f => ({ ...f, windowSeconds: parseInt(e.target.value) || 60 }))}
            />
          </div>
          <Select
            label="Collect Agent"
            options={agentOptions}
            value={form.collectAgent}
            onChange={e => setForm(f => ({ ...f, collectAgent: e.target.value }))}
          />
          <div className="flex gap-2 pt-2">
            <Button onClick={saveEdit}>Save Changes</Button>
            <Button variant="secondary" onClick={() => setEditTarget(null)}>Cancel</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
