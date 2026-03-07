"use client"
import { useState, useEffect, useCallback } from "react"
import { UsageChart } from "@/components/analytics/UsageChart"
import { Select } from "@/components/ui/Select"
import type { ResourceType } from "@/types"

// ── Types ─────────────────────────────────────────────────────────────────────

interface SummaryUser {
  uid: number
  username: string
  group_name: string
  total_cpu_seconds: string
  peak_mem_bytes: string
  peak_gpu_mib: string
  total_disk_bytes: string
}

interface TimeseriesRow {
  t: string
  value: number
}

// ── Constants ─────────────────────────────────────────────────────────────────

const resourceOptions = [
  { value: "cpu",  label: "CPU" },
  { value: "gpu",  label: "GPU Memory" },
  { value: "mem",  label: "Memory" },
  { value: "disk", label: "Disk I/O" },
]

const timeRangeOptions = [
  { value: "1h",  label: "Last 1 hour" },
  { value: "6h",  label: "Last 6 hours" },
  { value: "24h", label: "Last 24 hours" },
  { value: "7d",  label: "Last 7 days" },
]

const chartTypeOptions = [
  { value: "line", label: "Line" },
  { value: "bar",  label: "Bar" },
]

const RESOURCE_UNIT: Record<string, string> = {
  cpu: "h", mem: "MB", gpu: "MiB", disk: "MB",
}

const RESOURCE_LABEL: Record<string, string> = {
  cpu:  "CPU Hours",
  mem:  "Peak Memory (MB)",
  gpu:  "GPU Memory Peak (MiB)",
  disk: "Disk I/O (MB)",
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function toFromDate(range: string): string {
  const ms: Record<string, number> = {
    "1h": 3_600_000, "6h": 21_600_000, "24h": 86_400_000, "7d": 604_800_000,
  }
  return new Date(Date.now() - (ms[range] ?? ms["24h"])).toISOString()
}

function fmtCpu(s: string | null) {
  return s ? (parseFloat(s) / 3600).toFixed(1) + " h" : "—"
}
function fmtMb(b: string | null) {
  return b ? (parseFloat(b) / 1_048_576).toFixed(0) + " MB" : "—"
}
function fmtMib(m: string | null) {
  return m ? parseFloat(m).toFixed(0) + " MiB" : "—"
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AnalyticsPage() {
  const [users, setUsers]               = useState<SummaryUser[]>([])
  const [selectedUids, setSelectedUids] = useState<number[]>([])
  const [resource, setResource]         = useState<ResourceType>("cpu")
  const [timeRange, setTimeRange]       = useState("24h")
  const [chartType, setChartType]       = useState<"line" | "bar">("line")
  const [series, setSeries]             = useState<{ name: string; data: { timestamp: string; value: number }[] }[]>([])
  const [loadingUsers, setLoadingUsers] = useState(true)
  const [loadingChart, setLoadingChart] = useState(false)
  const [error, setError]               = useState<string | null>(null)

  // ── Load user list (always last 7 days for the summary table) ──────────────

  const loadUsers = useCallback(async () => {
    setLoadingUsers(true)
    try {
      const from = encodeURIComponent(toFromDate("7d"))
      const to   = encodeURIComponent(new Date().toISOString())
      const res  = await fetch(`/api/analytics/user-usage?mode=summary&from=${from}&to=${to}`)
      if (!res.ok) throw new Error("Failed to load users")
      const data: SummaryUser[] = await res.json()
      setUsers(data)
      if (data.length > 0) setSelectedUids([data[0].uid])
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error")
    } finally {
      setLoadingUsers(false)
    }
  }, [])

  useEffect(() => { loadUsers() }, [loadUsers])

  // ── Load chart timeseries when selection / filters change ──────────────────

  const loadChart = useCallback(async () => {
    if (selectedUids.length === 0) { setSeries([]); return }
    setLoadingChart(true)
    try {
      const from = encodeURIComponent(toFromDate(timeRange))
      const to   = encodeURIComponent(new Date().toISOString())
      const rows = await Promise.all(
        selectedUids.map(uid =>
          fetch(`/api/analytics/user-usage?mode=timeseries&uid=${uid}&resource=${resource}&from=${from}&to=${to}`)
            .then(r => r.ok ? (r.json() as Promise<TimeseriesRow[]>) : Promise.resolve([] as TimeseriesRow[]))
        )
      )
      const userMap = new Map(users.map(u => [u.uid, u.username]))
      setSeries(
        rows.map((pts, i) => ({
          name: userMap.get(selectedUids[i]) ?? `uid:${selectedUids[i]}`,
          data: pts.map(p => ({ timestamp: p.t, value: p.value })),
        }))
      )
    } finally {
      setLoadingChart(false)
    }
  }, [selectedUids, resource, timeRange, users])

  useEffect(() => { loadChart() }, [loadChart])

  function toggleUser(uid: number) {
    setSelectedUids(prev =>
      prev.includes(uid) ? prev.filter(u => u !== uid) : [...prev, uid]
    )
  }

  // ── Skeleton ───────────────────────────────────────────────────────────────

  if (loadingUsers) {
    return (
      <div className="p-6 space-y-4">
        <div className="h-8 w-48 rounded bg-[#1c2128] animate-pulse" />
        <div className="h-40 rounded-xl bg-[#1c2128] animate-pulse" />
        <div className="h-80 rounded-xl bg-[#1c2128] animate-pulse" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="rounded-lg border border-[#f85149]/40 bg-[#f85149]/10 px-4 py-3 text-sm text-[#f85149]">
          {error}
          <button onClick={loadUsers} className="ml-3 underline cursor-pointer">Retry</button>
        </div>
      </div>
    )
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-[#e6edf3]">User Usage History</h1>
        <p className="text-sm text-[#8b949e] mt-0.5">Historical resource usage per user from TimescaleDB</p>
      </div>

      {/* Controls */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-5">
          <Select
            label="Resource"
            options={resourceOptions}
            value={resource}
            onChange={e => setResource(e.target.value as ResourceType)}
          />
          <Select
            label="Time Range"
            options={timeRangeOptions}
            value={timeRange}
            onChange={e => setTimeRange(e.target.value)}
          />
          <Select
            label="Chart Type"
            options={chartTypeOptions}
            value={chartType}
            onChange={e => setChartType(e.target.value as "line" | "bar")}
          />
        </div>

        {/* User multi-select */}
        <div>
          <p className="text-xs font-medium text-[#8b949e] mb-2">
            Select Users
            {users.length === 0 && (
              <span className="ml-2 text-[#6e7681]">(no users registered in hpc_users table)</span>
            )}
          </p>
          <div className="flex flex-wrap gap-2">
            {users.map(u => (
              <button
                key={u.uid}
                onClick={() => toggleUser(u.uid)}
                className={[
                  "px-3 py-1.5 text-xs rounded-full border transition-colors cursor-pointer",
                  selectedUids.includes(u.uid)
                    ? "bg-[#1f6feb] border-[#1f6feb] text-white"
                    : "border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#e6edf3]",
                ].join(" ")}
              >
                {u.username}
                {u.group_name && (
                  <span className="ml-1 opacity-60 text-[10px]">{u.group_name}</span>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Chart */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
        {loadingChart ? (
          <div className="h-80 rounded bg-[#1c2128] animate-pulse" />
        ) : series.length > 0 && series.some(s => s.data.length > 0) ? (
          <>
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm font-semibold text-[#e6edf3]">
                {RESOURCE_LABEL[resource] ?? resource}
              </p>
              <span className="text-xs text-[#8b949e]">
                {selectedUids.length} user(s) · {timeRange}
              </span>
            </div>
            <UsageChart
              series={series}
              chartType={chartType}
              height={320}
              unit={RESOURCE_UNIT[resource] ?? ""}
            />
          </>
        ) : (
          <div className="flex flex-col items-center justify-center h-48 gap-2">
            <p className="text-[#6e7681] text-sm">
              {selectedUids.length === 0
                ? "Select at least one user to view the chart"
                : "No data for the selected filters"}
            </p>
            <p className="text-[#6e7681] text-xs">Try a wider time range or different resource</p>
          </div>
        )}
      </div>

      {/* 7-day summary table */}
      {users.length > 0 && (
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl overflow-hidden">
          <div className="px-5 py-3 border-b border-[#30363d]">
            <h2 className="text-xs font-semibold text-[#8b949e] uppercase tracking-wide">
              7-Day User Summary
            </h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#21262d]">
                {["User", "Group", "CPU Hours", "Peak Mem", "Peak GPU", "Disk I/O"].map(h => (
                  <th key={h} className="px-4 py-2.5 text-left text-xs font-medium text-[#6e7681]">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr
                  key={u.uid}
                  onClick={() => toggleUser(u.uid)}
                  className={[
                    "border-b border-[#21262d] last:border-0 cursor-pointer transition-colors",
                    selectedUids.includes(u.uid) ? "bg-[#1f6feb]/10" : "hover:bg-[#1c2128]",
                  ].join(" ")}
                >
                  <td className="px-4 py-2.5 font-medium text-[#e6edf3]">{u.username}</td>
                  <td className="px-4 py-2.5 text-[#8b949e]">{u.group_name ?? "—"}</td>
                  <td className="px-4 py-2.5 font-mono text-[#58a6ff]">{fmtCpu(u.total_cpu_seconds)}</td>
                  <td className="px-4 py-2.5 font-mono text-[#3fb950]">{fmtMb(u.peak_mem_bytes)}</td>
                  <td className="px-4 py-2.5 font-mono text-[#bc8cff]">{fmtMib(u.peak_gpu_mib)}</td>
                  <td className="px-4 py-2.5 font-mono text-[#d29922]">{fmtMb(u.total_disk_bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
