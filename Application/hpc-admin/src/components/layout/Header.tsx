"use client"
import { useState } from "react"
import { signOut } from "next-auth/react"
import { usePathname } from "next/navigation"
import { NotificationsPanel } from "./NotificationsPanel"
import { mockNotifications } from "@/lib/mockData/alerts"

const LABELS: Record<string, string> = {
  dashboard: "Dashboard",
  nodes: "Nodes",
  analytics: "Analytics",
  custom: "Custom Dashboards",
  "ai-chart": "AI Chart",
  chat: "Chatbot",
  config: "Configuration",
  collection: "Collection Settings",
  pipeline: "Pipeline",
  alerts: "Alerts",
  governance: "Governance",
  notifications: "Notifications",
}

function buildBreadcrumb(pathname: string): string[] {
  const parts = pathname.split("/").filter(Boolean)
  return ["HPC Monitor", ...parts.map(p => LABELS[p] ?? p)]
}

export function Header() {
  const pathname = usePathname()
  const breadcrumb = buildBreadcrumb(pathname)
  const [notifOpen, setNotifOpen] = useState(false)
  const unread = mockNotifications.filter(n => !n.acknowledged).length

  return (
    <>
      <header className="fixed top-0 left-60 right-0 h-14 bg-[#0d1117]/95 backdrop-blur border-b border-[#21262d] flex items-center justify-between px-6 z-20">
        <nav className="flex items-center gap-1.5 text-sm">
          {breadcrumb.map((crumb, i) => (
            <span key={i} className="flex items-center gap-1.5">
              {i > 0 && <span className="text-[#6e7681]">/</span>}
              <span className={i === breadcrumb.length - 1 ? "text-[#e6edf3] font-medium" : "text-[#8b949e]"}>
                {crumb}
              </span>
            </span>
          ))}
        </nav>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setNotifOpen(true)}
            className="relative p-2 rounded-md text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#161b22] transition-colors"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.8} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
            </svg>
            {unread > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-[#f85149] rounded-full" />
            )}
          </button>

          <div className="flex items-center gap-2 pl-3 border-l border-[#30363d]">
            <div className="w-7 h-7 rounded-full bg-[#1f6feb] flex items-center justify-center text-xs font-bold text-white">A</div>
            <span className="text-sm text-[#8b949e]">Admin</span>
            <button
              onClick={() => signOut({ callbackUrl: "/login" })}
              className="ml-1 p-1.5 rounded text-[#6e7681] hover:text-[#f85149] transition-colors"
              title="Sign out"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
              </svg>
            </button>
          </div>
        </div>
      </header>

      <NotificationsPanel open={notifOpen} onClose={() => setNotifOpen(false)} />
    </>
  )
}
