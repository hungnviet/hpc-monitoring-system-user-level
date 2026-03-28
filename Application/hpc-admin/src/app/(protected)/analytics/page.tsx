"use client"
import { useState, useEffect, useCallback } from "react"
import { UsageChart } from "@/components/analytics/UsageChart"
import { UsagePieChart } from "@/components/analytics/UsagePieChart"
import { ResourcePillSelect } from "@/components/analytics/ResourcePillSelect"
import { AppUsageTable, type SortCol } from "@/components/analytics/AppUsageTable"
import { AppSelector } from "@/components/analytics/AppSelector"
import { DateRangePicker } from "@/components/ui/DateRangePicker"
import { Select } from "@/components/ui/Select"
import type { ResourceType, AppUsageRow } from "@/types"

// ── Types ─────────────────────────────────────────────────────────────────────

interface SummaryUser {
  uid: number
  username: string
  group_name: string
  total_cpu_seconds: string
  peak_mem_bytes: string
  peak_gpu_mib: string
  total_disk_bytes: string
  total_net_bytes: string
}

interface TimeseriesRow { t: string; value: number }
interface AppTimeseriesRow { t: string; username: string; comm: string; value: number }

// ── Constants ─────────────────────────────────────────────────────────────────

const timeRangeOptions = [
  { value: "1h",     label: "Last 1 hour" },
  { value: "6h",     label: "Last 6 hours" },
  { value: "24h",    label: "Last 24 hours" },
  { value: "7d",     label: "Last 7 days" },
  { value: "custom", label: "Custom Range" },
]

const chartTypeOptions = [
  { value: "line", label: "Line" },
  { value: "bar",  label: "Bar" },
  { value: "pie",  label: "Pie" },
]

const viewModeOptions = [
  { value: "by-app",  label: "By Application" },
  { value: "by-user", label: "By User" },
]

const RESOURCE_UNIT: Record<string, string> = {
  cpu: "s", mem: "MB", gpu: "MiB", disk: "MB", net: "MB",
}

const RESOURCE_LABEL: Record<string, string> = {
  cpu:  "CPU on time (second)",
  mem:  "Peak Memory (MB)",
  gpu:  "GPU Memory Peak (MiB)",
  disk: "Disk I/O (MB)",
  net:  "Network I/O (MB)",
}

// Maps resource key → AppUsageRow field (for pie chart aggregation)
const RESOURCE_FIELD: Record<string, "cpu_seconds" | "peak_mem_mb" | "peak_gpu_mib" | "disk_io_mb" | "net_io_mb"> = {
  cpu:  "cpu_seconds",
  mem:  "peak_mem_mb",
  gpu:  "peak_gpu_mib",
  disk: "disk_io_mb",
  net:  "net_io_mb",
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getTimeRange(range: string, customFrom: string, customTo: string) {
  if (range === "custom" && customFrom && customTo) {
    return { from: customFrom, to: customTo }
  }
  const ms: Record<string, number> = {
    "1h": 3_600_000, "6h": 21_600_000, "24h": 86_400_000, "7d": 604_800_000,
  }
  return {
    from: new Date(Date.now() - (ms[range] ?? ms["24h"])).toISOString(),
    to: new Date().toISOString(),
  }
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AnalyticsPage() {
  // Users
  const [users, setUsers]               = useState<SummaryUser[]>([])
  const [selectedUids, setSelectedUids] = useState<number[]>([])
  const [loadingUsers, setLoadingUsers] = useState(true)
  const [error, setError]               = useState<string | null>(null)

  // Filters
  const [resources, setResources]   = useState<ResourceType[]>(["cpu"])
  const [timeRange, setTimeRange]   = useState("24h")
  const [customFrom, setCustomFrom] = useState(() => new Date(Date.now() - 86_400_000).toISOString())
  const [customTo, setCustomTo]     = useState(() => new Date().toISOString())
  const [chartType, setChartType]   = useState<"line" | "bar" | "pie">("line")
  const [viewMode, setViewMode]     = useState<"by-user" | "by-app">("by-app")

  // App data
  const [appData, setAppData]           = useState<AppUsageRow[]>([])
  const [selectedApps, setSelectedApps] = useState<string[]>([])
  const [loadingApps, setLoadingApps]   = useState(false)
  const [sortCol, setSortCol]           = useState<SortCol>("cpu_seconds")
  const [sortDir, setSortDir]           = useState<"asc" | "desc">("desc")

  // Chart data: one series array per resource
  const [chartData, setChartData]     = useState<Record<string, { name: string; data: { timestamp: string; value: number }[] }[]>>({})
  const [loadingChart, setLoadingChart] = useState(false)

  // App usage breakdown collapse state
  const [isAppUsageExpanded, setIsAppUsageExpanded] = useState(true)

  // ── Load user list (always last 7 days for the summary) ─────────────────

  const loadUsers = useCallback(async () => {
    setLoadingUsers(true)
    try {
      const { from, to } = getTimeRange("7d", "", "")
      const res = await fetch(`/api/analytics/user-usage?mode=summary&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`)
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

  // ── Load app breakdown ──────────────────────────────────────────────────

  const loadApps = useCallback(async () => {
    if (selectedUids.length === 0) { setAppData([]); return }
    setLoadingApps(true)
    try {
      const { from, to } = getTimeRange(timeRange, customFrom, customTo)
      const uidParam = selectedUids.join(",")
      const res = await fetch(
        `/api/analytics/user-usage?mode=apps&uid=${uidParam}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`
      )
      if (!res.ok) throw new Error("Failed to load app data")
      const data: AppUsageRow[] = await res.json()
      setAppData(data)
      // Reset app selection when users or range change so stale comms are cleared
      setSelectedApps([])
    } catch {
      setAppData([])
    } finally {
      setLoadingApps(false)
    }
  }, [selectedUids, timeRange, customFrom, customTo])

  useEffect(() => { loadApps() }, [loadApps])

  // ── Load chart timeseries ───────────────────────────────────────────────

  const loadChart = useCallback(async () => {
    // Pie mode reads from appData directly — no timeseries needed
    if (chartType === "pie") { setChartData({}); return }
    if (selectedUids.length === 0 || resources.length === 0) { setChartData({}); return }
    setLoadingChart(true)
    try {
      const { from, to } = getTimeRange(timeRange, customFrom, customTo)
      const uidParam = selectedUids.join(",")
      const userMap = new Map(users.map(u => [u.uid, u.username]))
      const result: Record<string, { name: string; data: { timestamp: string; value: number }[] }[]> = {}

      await Promise.all(resources.map(async (res) => {
        if (viewMode === "by-app") {
          const resp = await fetch(
            `/api/analytics/user-usage?mode=app-timeseries&uid=${uidParam}&resource=${res}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`
          )
          if (!resp.ok) { result[res] = []; return }
          const rows: AppTimeseriesRow[] = await resp.json()

          // Group by "username - comm"
          const byUserApp = new Map<string, { timestamp: string; value: number }[]>()
          for (const r of rows) {
            const key = `${r.username} - ${r.comm}`
            if (!byUserApp.has(key)) byUserApp.set(key, [])
            byUserApp.get(key)!.push({ timestamp: r.t, value: r.value })
          }

          // Filter by selectedApps — empty selection means show nothing in by-app mode
          const entries = [...byUserApp.entries()].filter(([key]) => {
            if (selectedApps.length === 0) return false
            const comm = key.split(" - ").slice(1).join(" - ")
            return selectedApps.includes(comm)
          })

          result[res] = entries.map(([name, data]) => ({ name, data }))
        } else {
          // by-user: one series per user, no app filter
          const fetches = selectedUids.map(uid =>
            fetch(`/api/analytics/user-usage?mode=timeseries&uid=${uid}&resource=${res}&from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`)
              .then(r => r.ok ? (r.json() as Promise<TimeseriesRow[]>) : [])
          )
          const allRows = await Promise.all(fetches)
          result[res] = allRows.map((pts, i) => ({
            name: userMap.get(selectedUids[i]) ?? `uid:${selectedUids[i]}`,
            data: pts.map(p => ({ timestamp: p.t, value: p.value })),
          }))
        }
      }))

      setChartData(result)
    } finally {
      setLoadingChart(false)
    }
  }, [selectedUids, resources, timeRange, customFrom, customTo, viewMode, selectedApps, users, chartType])

  useEffect(() => { loadChart() }, [loadChart])

  // ── Handlers ────────────────────────────────────────────────────────────

  function toggleUser(uid: number) {
    setSelectedUids(prev =>
      prev.includes(uid) ? prev.filter(u => u !== uid) : [...prev, uid]
    )
  }

  function toggleApp(comm: string) {
    setSelectedApps(prev =>
      prev.includes(comm) ? prev.filter(c => c !== comm) : [...prev, comm]
    )
  }

  function handleSort(col: SortCol) {
    if (col === sortCol) {
      setSortDir(d => d === "asc" ? "desc" : "asc")
    } else {
      setSortCol(col)
      setSortDir("desc")
    }
  }

  // ── Skeleton / Error ────────────────────────────────────────────────────

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

  // ── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6">

      {/* Header */}
      <div>
        <h1 className="text-lg font-semibold text-[#e6edf3]">User & Application Analytics</h1>
        <p className="text-sm text-[#8b949e] mt-0.5">
          Per-user and per-application resource usage from TimescaleDB
        </p>
      </div>

      {/* ── Filters Card ────────────────────────────────────────────────── */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5 space-y-4">

        {/* Row 1: dropdowns */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
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
            onChange={e => setChartType(e.target.value as "line" | "bar" | "pie")}
          />
          <Select
            label="View Mode"
            options={viewModeOptions}
            value={viewMode}
            onChange={e => setViewMode(e.target.value as "by-user" | "by-app")}
          />
        </div>

        {/* Row 2: custom date pickers */}
        {timeRange === "custom" && (
          <DateRangePicker
            from={customFrom}
            to={customTo}
            onFromChange={setCustomFrom}
            onToChange={setCustomTo}
          />
        )}

        {/* Row 3: resource pills */}
        <ResourcePillSelect selected={resources} onChange={setResources} />

        {/* Row 4: user pills */}
        <div>
          <p className="text-xs font-medium text-[#8b949e] mb-2">
            Select Users
            {users.length === 0 && (
              <span className="ml-2 text-[#6e7681]">(no users registered)</span>
            )}
          </p>
          <div className="flex flex-wrap gap-2">
            {users.filter(u => u.uid != 0).map(u => (
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

        {/* Row 5: app selector (only relevant in by-app mode) */}
        {viewMode === "by-app" && (
          <div className="border-t border-[#21262d] pt-4">
            <AppSelector
              apps={appData}
              selected={selectedApps}
              onChange={setSelectedApps}
              loading={loadingApps}
            />
          </div>
        )}
      </div>
      
      {/* ── Charts — one card per selected resource ──────────────────────── */}
      {resources.map(res => {
        const unit = RESOURCE_UNIT[res] ?? ""
        const label = RESOURCE_LABEL[res] ?? res
        const field = RESOURCE_FIELD[res]

        // ── Pie chart mode ────────────────────────────────────────────────
        if (chartType === "pie") {
          const emptyReason =
            selectedUids.length === 0 ? "Select at least one user" :
            viewMode === "by-app" && selectedApps.length === 0 ? "Select applications above to view chart" :
            null

          if (emptyReason) {
            return (
              <div key={res} className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
                <div className="flex flex-col items-center justify-center h-40 gap-2">
                  <p className="text-sm font-semibold text-[#e6edf3]">{label}</p>
                  <p className="text-[#6e7681] text-sm">{emptyReason}</p>
                </div>
              </div>
            )
          }

          if (viewMode === "by-app") {
            // One donut per selected user — slices = selected applications
            const selectedUsers = users.filter(u => selectedUids.includes(u.uid))
            return (
              <div key={res} className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <p className="text-sm font-semibold text-[#e6edf3]">{label}</p>
                  <span className="text-xs text-[#8b949e]">
                    {selectedApps.length} app(s) · {timeRange === "custom" ? "custom range" : timeRange}
                  </span>
                </div>
                {loadingApps ? (
                  <div className="h-72 rounded bg-[#1c2128] animate-pulse" />
                ) : (
                  <div className={`grid gap-6 ${selectedUsers.length === 1 ? "grid-cols-1 max-w-md mx-auto" : "grid-cols-1 sm:grid-cols-2"}`}>
                    {selectedUsers.map(user => {
                      const slices = appData
                        .filter(row =>
                          row.username === user.username &&
                          (selectedApps.length === 0 || selectedApps.includes(row.comm))
                        )
                        .map(row => ({ name: row.comm, value: Number(row[field]) }))
                        .filter(d => d.value > 0)
                        .sort((a, b) => b.value - a.value)
                      return (
                        <UsagePieChart
                          key={user.uid}
                          title={user.username}
                          data={slices}
                          unit={unit}
                          height={280}
                        />
                      )
                    })}
                  </div>
                )}
              </div>
            )
          }

          // by-user: one donut — slices = selected users
          const userSlices = users
            .filter(u => selectedUids.includes(u.uid))
            .map(user => ({
              name: user.username,
              value: appData
                .filter(row => row.username === user.username)
                .reduce((sum, row) => sum + Number(row[field]), 0),
            }))
            .filter(d => d.value > 0)

          return (
            <div key={res} className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <p className="text-sm font-semibold text-[#e6edf3]">{label}</p>
                <span className="text-xs text-[#8b949e]">
                  {selectedUids.length} user(s) · {timeRange === "custom" ? "custom range" : timeRange}
                </span>
              </div>
              {loadingApps ? (
                <div className="h-72 rounded bg-[#1c2128] animate-pulse" />
              ) : (
                <div className="max-w-md mx-auto">
                  <UsagePieChart data={userSlices} unit={unit} height={300} />
                </div>
              )}
            </div>
          )
        }

        // ── Line / Bar chart mode ─────────────────────────────────────────
        const seriesForRes = chartData[res] ?? []
        const hasData = seriesForRes.length > 0 && seriesForRes.some(s => s.data.length > 0)

        const emptyMessage = () => {
          if (selectedUids.length === 0) return "Select at least one user"
          if (viewMode === "by-app" && selectedApps.length === 0) return "Select applications above to view chart"
          return "No data for the selected filters"
        }

        return (
          <div key={res} className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
            {loadingChart ? (
              <div className="h-72 rounded bg-[#1c2128] animate-pulse" />
            ) : hasData ? (
              <>
                <div className="flex items-center justify-between mb-4">
                  <p className="text-sm font-semibold text-[#e6edf3]">{label}</p>
                  <span className="text-xs text-[#8b949e]">
                    {viewMode === "by-app" ? `${seriesForRes.length} series` : `${selectedUids.length} user(s)`}
                    {" · "}
                    {timeRange === "custom" ? "custom range" : timeRange}
                  </span>
                </div>
                <UsageChart
                  series={seriesForRes}
                  chartType={chartType}
                  height={300}
                  unit={unit}
                  dateFrom={getTimeRange(timeRange, customFrom, customTo).from}
                  dateTo={getTimeRange(timeRange, customFrom, customTo).to}
                />
              </>
            ) : (
              <div className="flex flex-col items-center justify-center h-40 gap-2">
                <p className="text-sm font-semibold text-[#e6edf3] mb-2">{label}</p>
                <p className="text-[#6e7681] text-sm">{emptyMessage()}</p>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
