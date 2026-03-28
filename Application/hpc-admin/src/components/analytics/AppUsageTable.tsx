"use client"
import type { AppUsageRow } from "@/types"

type SortCol = "comm" | "username" | "cpu_seconds" | "peak_mem_mb" | "peak_gpu_mib" | "disk_io_mb" | "net_io_mb" | "total_processes"

interface AppUsageTableProps {
  data: AppUsageRow[]
  selectedApps: string[]
  onToggleApp: (comm: string) => void
  sortColumn: SortCol
  sortDir: "asc" | "desc"
  onSort: (col: SortCol) => void
}

const COLUMNS: { key: SortCol; label: string; color?: string }[] = [
  { key: "comm",           label: "Application" },
  { key: "username",       label: "User" },
  { key: "cpu_seconds",    label: "CPU (s)",        color: "#58a6ff" },
  { key: "peak_mem_mb",    label: "Peak Mem (MB)",  color: "#3fb950" },
  { key: "peak_gpu_mib",   label: "Peak GPU (MiB)", color: "#bc8cff" },
  { key: "disk_io_mb",     label: "Disk I/O (MB)",  color: "#d29922" },
  { key: "net_io_mb",      label: "Net I/O (MB)",   color: "#f85149" },
  { key: "total_processes", label: "Processes" },
]

function fmt(v: number | null | undefined): string {
  if (v == null) return "—"
  return Number(v) < 10 ? Number(v).toFixed(2) : Number(v).toFixed(0)
}

export function AppUsageTable({ data, selectedApps, onToggleApp, sortColumn, sortDir, onSort }: AppUsageTableProps) {
  const filtered = selectedApps.length === 0
    ? data
    : data.filter(row => selectedApps.includes(row.comm))

  const sorted = [...filtered].sort((a, b) => {
    const av = a[sortColumn] ?? 0
    const bv = b[sortColumn] ?? 0
    if (av < bv) return sortDir === "asc" ? -1 : 1
    if (av > bv) return sortDir === "asc" ? 1 : -1
    return 0
  })

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#21262d]">
            {/* Checkbox column header */}
            <th className="px-3 py-2.5 w-8" />
            {COLUMNS.map(col => (
              <th
                key={col.key}
                onClick={() => onSort(col.key)}
                className="px-4 py-2.5 text-left text-xs font-medium text-[#6e7681] cursor-pointer hover:text-[#e6edf3] transition-colors whitespace-nowrap select-none"
              >
                {col.label}
                {sortColumn === col.key && (
                  <span className="ml-1">{sortDir === "asc" ? "↑" : "↓"}</span>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 && (
            <tr>
              <td colSpan={COLUMNS.length + 1} className="px-4 py-6 text-center text-[#6e7681]">
                {selectedApps.length === 0
                  ? "Select applications above to view breakdown"
                  : "No app data for selected filters"}
              </td>
            </tr>
          )}
          {sorted.map((row, i) => {
            const isSelected = selectedApps.includes(row.comm)
            return (
              <tr
                key={`${row.username}-${row.comm}-${i}`}
                onClick={() => onToggleApp(row.comm)}
                className={[
                  "border-b border-[#21262d] last:border-0 cursor-pointer transition-colors",
                  isSelected ? "bg-[#1f6feb]/10 hover:bg-[#1f6feb]/15" : "hover:bg-[#1c2128]",
                ].join(" ")}
              >
                {/* Checkbox cell */}
                <td className="pl-3 pr-1 py-2.5">
                  <span
                    className={[
                      "flex w-3.5 h-3.5 rounded-sm border items-center justify-center",
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
                </td>
                <td className="px-4 py-2.5 font-medium text-[#e6edf3] font-mono">{row.comm}</td>
                <td className="px-4 py-2.5 text-[#8b949e]">{row.username}</td>
                <td className="px-4 py-2.5 font-mono text-[#58a6ff]">{fmt(row.cpu_seconds)}</td>
                <td className="px-4 py-2.5 font-mono text-[#3fb950]">{fmt(row.peak_mem_mb)}</td>
                <td className="px-4 py-2.5 font-mono text-[#bc8cff]">{fmt(row.peak_gpu_mib)}</td>
                <td className="px-4 py-2.5 font-mono text-[#d29922]">{fmt(row.disk_io_mb)}</td>
                <td className="px-4 py-2.5 font-mono text-[#f85149]">{fmt(row.net_io_mb)}</td>
                <td className="px-4 py-2.5 font-mono text-[#8b949e]">{fmt(row.total_processes)}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export type { SortCol }
