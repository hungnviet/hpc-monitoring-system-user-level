"use client"
import { useState } from "react"
import { mockSavedPanels, mockUserUsage } from "@/lib/mockData/analytics"
import { mockUsers } from "@/lib/mockData/nodes"
import { UsageChart } from "@/components/analytics/UsageChart"
import { Button } from "@/components/ui/Button"
import { Modal } from "@/components/ui/Modal"
import { Select } from "@/components/ui/Select"
import { Input } from "@/components/ui/Input"
import { Badge } from "@/components/ui/Badge"
import type { ChartPanel, ResourceType } from "@/types"

const resourceOptions = [
  { value: "cpu", label: "CPU" }, { value: "gpu", label: "GPU" },
  { value: "mem", label: "Memory" }, { value: "disk", label: "Disk" }, { value: "net", label: "Network" },
]
const chartTypeOptions = [
  { value: "line", label: "Line" }, { value: "bar", label: "Bar" }, { value: "stacked", label: "Stacked" },
]

function PanelCard({ panel, onRemove, onPin }: { panel: ChartPanel; onRemove: () => void; onPin: () => void }) {
  const series = mockUserUsage
    .filter(u => panel.userIds.includes(u.userId) && u.resource === panel.resource)
    .map(u => ({ name: u.username, data: u.data }))

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[#21262d]">
        <div className="flex items-center gap-2">
          {panel.pinned && <span className="text-[#d29922] text-xs">📌</span>}
          <span className="text-sm font-semibold text-[#e6edf3]">{panel.title}</span>
          <Badge variant="info">{panel.resource.toUpperCase()}</Badge>
        </div>
        <div className="flex items-center gap-1">
          <button onClick={onPin} className="p-1.5 rounded text-[#8b949e] hover:text-[#d29922] transition-colors text-xs" title={panel.pinned ? "Unpin" : "Pin"}>
            {panel.pinned ? "📌" : "📍"}
          </button>
          <button onClick={onRemove} className="p-1.5 rounded text-[#8b949e] hover:text-[#f85149] transition-colors">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
      </div>
      <div className="p-4">
        {series.length > 0 ? (
          <UsageChart series={series} chartType={panel.chartType} height={200} />
        ) : (
          <div className="h-48 flex items-center justify-center text-[#6e7681] text-sm">No data for selection</div>
        )}
      </div>
    </div>
  )
}

export default function CustomDashboardPage() {
  const [panels, setPanels] = useState<ChartPanel[]>(mockSavedPanels)
  const [addOpen, setAddOpen] = useState(false)
  const [title, setTitle] = useState("")
  const [resource, setResource] = useState<ResourceType>("cpu")
  const [chartType, setChartType] = useState<"line" | "bar" | "stacked">("line")
  const [selectedUsers, setSelectedUsers] = useState<string[]>([])

  function addPanel() {
    if (!title) return
    const newPanel: ChartPanel = {
      id: `p${Date.now()}`, title, userIds: selectedUsers, resource, chartType, pinned: false,
    }
    setPanels(prev => [...prev, newPanel])
    setAddOpen(false)
    setTitle(""); setSelectedUsers([])
  }

  function removePanel(id: string) { setPanels(prev => prev.filter(p => p.id !== id)) }
  function togglePin(id: string)   { setPanels(prev => prev.map(p => p.id === id ? { ...p, pinned: !p.pinned } : p)) }

  const sorted = [...panels].sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0))

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">Custom Dashboard Builder</h1>
          <p className="text-sm text-[#8b949e]">Build, save, and pin personalized chart panels</p>
        </div>
        <Button onClick={() => setAddOpen(true)}>
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
          Add Panel
        </Button>
      </div>

      {sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 gap-3">
          <p className="text-[#6e7681]">No panels yet. Add your first panel.</p>
          <Button variant="secondary" onClick={() => setAddOpen(true)}>Add Panel</Button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {sorted.map(p => <PanelCard key={p.id} panel={p} onRemove={() => removePanel(p.id)} onPin={() => togglePin(p.id)} />)}
        </div>
      )}

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title="Add Chart Panel">
        <div className="space-y-4">
          <Input label="Panel Title" value={title} onChange={e => setTitle(e.target.value)} placeholder="e.g. GPU Usage — ML Team" />
          <Select label="Resource" options={resourceOptions} value={resource} onChange={e => setResource(e.target.value as ResourceType)} />
          <Select label="Chart Type" options={chartTypeOptions} value={chartType} onChange={e => setChartType(e.target.value as typeof chartType)} />
          <div>
            <p className="text-xs font-medium text-[#8b949e] mb-2">Users</p>
            <div className="flex flex-wrap gap-2">
              {mockUsers.map(u => (
                <button key={u.id} onClick={() => setSelectedUsers(prev => prev.includes(u.id) ? prev.filter(x => x !== u.id) : [...prev, u.id])}
                  className={`px-3 py-1.5 text-xs rounded-full border transition-colors ${selectedUsers.includes(u.id) ? "bg-[#1f6feb] border-[#1f6feb] text-white" : "border-[#30363d] text-[#8b949e]"}`}>
                  {u.username}
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-2 pt-2">
            <Button onClick={addPanel} disabled={!title}>Add Panel</Button>
            <Button variant="secondary" onClick={() => setAddOpen(false)}>Cancel</Button>
          </div>
        </div>
      </Modal>
    </div>
  )
}
