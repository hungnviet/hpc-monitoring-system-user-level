"use client"
import { useState } from "react"
import { mockNotifications } from "@/lib/mockData/alerts"
import { Badge } from "@/components/ui/Badge"
import type { AlertSeverity } from "@/types"

function severityVariant(s: AlertSeverity) {
  return s === "critical" ? "danger" : s === "warning" ? "warning" : "info"
}

function timeAgo(iso: string) {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60)   return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`
  if (diff < 86400)return `${Math.floor(diff/3600)}h ago`
  return `${Math.floor(diff/86400)}d ago`
}

export function NotificationsPanel({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [notifications, setNotifications] = useState(mockNotifications)

  const ack = (id: string) => setNotifications(prev => prev.map(n => n.id === id ? { ...n, acknowledged: true } : n))
  const ackAll = () => setNotifications(prev => prev.map(n => ({ ...n, acknowledged: true })))

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative z-10 w-96 h-full bg-[#161b22] border-l border-[#30363d] flex flex-col shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#30363d]">
          <div>
            <h2 className="text-sm font-semibold text-[#e6edf3]">Notifications</h2>
            <p className="text-xs text-[#8b949e]">{notifications.filter(n => !n.acknowledged).length} unread</p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={ackAll} className="text-xs text-[#58a6ff] hover:underline">Mark all read</button>
            <button onClick={onClose} className="text-[#6e7681] hover:text-[#e6edf3]">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto divide-y divide-[#21262d]">
          {notifications.map(n => (
            <div key={n.id} className={`px-5 py-4 ${n.acknowledged ? "opacity-50" : ""}`}>
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant={severityVariant(n.severity)}>{n.severity}</Badge>
                    <span className="text-xs text-[#6e7681]">{n.nodeName}</span>
                  </div>
                  <p className="text-sm text-[#e6edf3]">{n.message}</p>
                  <p className="text-xs text-[#6e7681] mt-1">{timeAgo(n.createdAt)}</p>
                </div>
                {!n.acknowledged && (
                  <button onClick={() => ack(n.id)} className="shrink-0 text-xs text-[#8b949e] hover:text-[#e6edf3] mt-0.5">Dismiss</button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
