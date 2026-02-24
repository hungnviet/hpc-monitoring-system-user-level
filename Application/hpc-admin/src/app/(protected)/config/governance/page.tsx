"use client"
import { useState } from "react"
import { mockConfigVersions, mockAuditLogs } from "@/lib/mockData/governance"
import { Button } from "@/components/ui/Button"
import { Badge } from "@/components/ui/Badge"
import { Modal } from "@/components/ui/Modal"
import type { AuditLog } from "@/types"

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60)    return `${diff}s ago`
  if (diff < 3600)  return `${Math.floor(diff/60)}m ago`
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`
  return `${Math.floor(diff/86400)}d ago`
}

const actionColors: Record<string, string> = {
  CREATE:  "text-[#3fb950]",
  UPDATE:  "text-[#58a6ff]",
  DELETE:  "text-[#f85149]",
  ROLLOUT: "text-[#d29922]",
  LOGIN:   "text-[#8b949e]",
}

export default function GovernancePage() {
  const [tab, setTab] = useState<"versions" | "audit">("versions")
  const [rolloutOpen, setRolloutOpen] = useState(false)
  const [rolling, setRolling] = useState(false)
  const [rolloutDone, setRolloutDone] = useState(false)

  async function doRollout() {
    setRolling(true)
    await new Promise(r => setTimeout(r, 2000))
    setRolling(false)
    setRolloutDone(true)
    setRolloutOpen(false)
    setTimeout(() => setRolloutDone(false), 3000)
  }

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[#e6edf3]">System Governance</h1>
          <p className="text-sm text-[#8b949e]">Configuration versioning, audit logs, and live rollout</p>
        </div>
        <div className="flex items-center gap-2">
          {rolloutDone && <span className="text-sm text-[#3fb950]">✓ Config pushed to all nodes</span>}
          <Button onClick={() => setRolloutOpen(true)}>
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Push to Nodes
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex rounded-lg border border-[#30363d] w-fit overflow-hidden">
        {(["versions", "audit"] as const).map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-5 py-2 text-sm capitalize transition-colors ${tab === t ? "bg-[#1f6feb] text-white" : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22]"}`}>
            {t === "versions" ? "Version History" : "Audit Log"}
          </button>
        ))}
      </div>

      {tab === "versions" ? (
        <div className="space-y-2">
          {mockConfigVersions.map(v => (
            <div key={v.id} className={`bg-[#161b22] border rounded-xl px-5 py-4 flex items-center gap-4 ${v.active ? "border-[#238636]" : "border-[#30363d]"}`}>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-sm font-semibold text-[#e6edf3] font-mono">v{v.version}</span>
                  {v.active && <Badge variant="success">Active</Badge>}
                </div>
                <p className="text-xs text-[#8b949e]">{v.description}</p>
              </div>
              <div className="text-right shrink-0">
                <p className="text-xs text-[#6e7681]">{timeAgo(v.createdAt)}</p>
                <p className="text-xs text-[#8b949e] mt-0.5">by {v.author}</p>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#30363d]">
                {["Time", "Actor", "Action", "Target", "Detail"].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-medium text-[#8b949e] uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {mockAuditLogs.map((log: AuditLog) => (
                <tr key={log.id} className="border-b border-[#21262d] last:border-0 hover:bg-[#1c2128] transition-colors">
                  <td className="px-4 py-3 text-xs text-[#6e7681] whitespace-nowrap">{timeAgo(log.createdAt)}</td>
                  <td className="px-4 py-3 text-xs text-[#e6edf3]">{log.actor}</td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-mono font-semibold ${actionColors[log.action] ?? "text-[#8b949e]"}`}>{log.action}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-[#8b949e]">{log.target}</td>
                  <td className="px-4 py-3 text-xs text-[#8b949e]">{log.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Rollout confirm modal */}
      <Modal open={rolloutOpen} onClose={() => !rolling && setRolloutOpen(false)} title="Push Configuration to Nodes">
        <p className="text-sm text-[#e6edf3] mb-2">This will push the current active configuration to all registered compute nodes.</p>
        <p className="text-xs text-[#8b949e] mb-5">Active version: <span className="font-mono text-[#58a6ff]">v{mockConfigVersions.find(v => v.active)?.version}</span></p>
        <div className="flex gap-2">
          <Button onClick={doRollout} loading={rolling}>{rolling ? "Pushing…" : "Confirm Push"}</Button>
          <Button variant="secondary" onClick={() => setRolloutOpen(false)} disabled={rolling}>Cancel</Button>
        </div>
      </Modal>
    </div>
  )
}
