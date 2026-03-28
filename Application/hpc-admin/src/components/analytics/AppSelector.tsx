"use client"
import { useState, useMemo } from "react"
import type { AppUsageRow } from "@/types"

interface AppSelectorProps {
  apps: AppUsageRow[]
  selected: string[]
  onChange: (selected: string[]) => void
  loading?: boolean
}

export function AppSelector({ apps, selected, onChange, loading }: AppSelectorProps) {
  const [search, setSearch] = useState("")

  // Intersection: only apps used by ALL selected users, ranked by total cpu_seconds
  const uniqueApps = useMemo(() => {
    const totalUsers = new Set(apps.map(r => r.username)).size

    // Group by comm → distinct users that ran it + summed cpu_seconds
    const byComm = new Map<string, { users: Set<string>; cpu_seconds: number }>()
    for (const row of apps) {
      if (!byComm.has(row.comm)) byComm.set(row.comm, { users: new Set(), cpu_seconds: 0 })
      const entry = byComm.get(row.comm)!
      entry.users.add(row.username)
      entry.cpu_seconds += Number(row.cpu_seconds)
    }

    return [...byComm.entries()]
      // keep only apps every selected user has run (skip filter when ≤1 user)
      .filter(([, v]) => totalUsers <= 1 || v.users.size === totalUsers)
      .map(([comm, v]) => ({ comm, cpu_seconds: v.cpu_seconds }))
      .sort((a, b) => b.cpu_seconds - a.cpu_seconds)
  }, [apps])

  const filtered = useMemo(
    () => uniqueApps.filter(a => a.comm.toLowerCase().includes(search.toLowerCase())),
    [uniqueApps, search]
  )

  const maxCpu = uniqueApps[0]?.cpu_seconds ?? 1

  function toggle(comm: string) {
    onChange(selected.includes(comm) ? selected.filter(c => c !== comm) : [...selected, comm])
  }

  function selectTop(n: number) {
    onChange(uniqueApps.slice(0, n).map(a => a.comm))
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs font-medium text-[#8b949e]">
          Select Applications
          <span className="ml-2 text-[#6e7681] font-normal">
            ({selected.length} of {uniqueApps.length} selected)
          </span>
        </p>
        <div className="flex items-center gap-2">
          <button
            onClick={() => selectTop(5)}
            disabled={uniqueApps.length === 0}
            className="text-[10px] px-2 py-0.5 rounded border border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#58a6ff] disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
          >
            Top 5
          </button>
          <button
            onClick={() => selectTop(10)}
            disabled={uniqueApps.length === 0}
            className="text-[10px] px-2 py-0.5 rounded border border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#58a6ff] disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
          >
            Top 10
          </button>
          <button
            onClick={() => onChange(uniqueApps.map(a => a.comm))}
            disabled={uniqueApps.length === 0}
            className="text-[10px] px-2 py-0.5 rounded border border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#58a6ff] disabled:opacity-40 disabled:cursor-not-allowed transition-colors cursor-pointer"
          >
            All
          </button>
          {selected.length > 0 && (
            <button
              onClick={() => onChange([])}
              className="text-[10px] px-2 py-0.5 rounded border border-[#30363d] text-[#6e7681] hover:text-[#f85149] hover:border-[#f85149] transition-colors cursor-pointer"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Search */}
      <input
        type="text"
        placeholder="Search applications…"
        value={search}
        onChange={e => setSearch(e.target.value)}
        className="w-full mb-2 px-3 py-1.5 text-xs bg-[#0d1117] border border-[#30363d] rounded-md text-[#e6edf3] placeholder-[#6e7681] focus:outline-none focus:border-[#58a6ff] transition-colors"
      />

      {/* List */}
      {loading ? (
        <div className="h-24 rounded bg-[#1c2128] animate-pulse" />
      ) : filtered.length === 0 ? (
        <p className="text-xs text-[#6e7681] py-2">
          {uniqueApps.length === 0
            ? "No apps found for the selected users / range"
            : "No apps match the search"}
        </p>
      ) : (
        <div className="max-h-44 overflow-y-auto space-y-0.5 pr-1">
          {filtered.map(app => {
            const isSelected = selected.includes(app.comm)
            const barPct = Math.max(2, (app.cpu_seconds / maxCpu) * 100)
            return (
              <button
                key={app.comm}
                onClick={() => toggle(app.comm)}
                className={[
                  "w-full flex items-center gap-2 px-2 py-1.5 rounded text-xs text-left transition-colors cursor-pointer",
                  isSelected
                    ? "bg-[#1f6feb]/20 text-[#58a6ff]"
                    : "text-[#8b949e] hover:bg-[#1c2128] hover:text-[#e6edf3]",
                ].join(" ")}
              >
                {/* Checkbox */}
                <span
                  className={[
                    "flex-shrink-0 w-3.5 h-3.5 rounded-sm border flex items-center justify-center",
                    isSelected ? "bg-[#1f6feb] border-[#1f6feb]" : "border-[#30363d]",
                  ].join(" ")}
                >
                  {isSelected && (
                    <svg viewBox="0 0 10 8" className="w-2.5 h-2">
                      <path
                        d="M1 4l3 3 5-6"
                        stroke="white"
                        strokeWidth="1.5"
                        fill="none"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  )}
                </span>

                {/* Name */}
                <span className="flex-1 truncate font-mono">{app.comm}</span>

                {/* CPU bar */}
                <span className="flex-shrink-0 w-16 h-1.5 rounded-full bg-[#21262d] overflow-hidden">
                  <span
                    className="block h-full rounded-full bg-[#58a6ff]/60"
                    style={{ width: `${barPct}%` }}
                  />
                </span>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
