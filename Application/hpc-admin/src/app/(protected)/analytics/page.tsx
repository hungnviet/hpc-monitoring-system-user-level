"use client"
import { useState } from "react"
import { mockUserUsage } from "@/lib/mockData/analytics"
import { mockUsers } from "@/lib/mockData/nodes"
import { UsageChart } from "@/components/analytics/UsageChart"
import { Select } from "@/components/ui/Select"
import type { ResourceType } from "@/types"

const resourceOptions = [
  { value: "cpu",  label: "CPU" },
  { value: "gpu",  label: "GPU" },
  { value: "mem",  label: "Memory" },
  { value: "disk", label: "Disk" },
  { value: "net",  label: "Network" },
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

export default function AnalyticsPage() {
  const [selectedUsers, setSelectedUsers] = useState<string[]>(["u1"])
  const [resource, setResource] = useState<ResourceType>("cpu")
  const [timeRange, setTimeRange] = useState("24h")
  const [chartType, setChartType] = useState<"line" | "bar">("line")

  function toggleUser(uid: string) {
    setSelectedUsers(prev => prev.includes(uid) ? prev.filter(u => u !== uid) : [...prev, uid])
  }

  const series = mockUserUsage
    .filter(u => selectedUsers.includes(u.userId) && u.resource === resource)
    .map(u => ({ name: u.username, data: u.data }))

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-[#e6edf3]">User Usage History</h1>
        <p className="text-sm text-[#8b949e] mt-0.5">Historical resource usage per user from TimescaleDB</p>
      </div>

      {/* Controls */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-5">
          <Select label="Resource" options={resourceOptions} value={resource} onChange={e => setResource(e.target.value as ResourceType)} />
          <Select label="Time Range" options={timeRangeOptions} value={timeRange} onChange={e => setTimeRange(e.target.value)} />
          <Select label="Chart Type" options={chartTypeOptions} value={chartType} onChange={e => setChartType(e.target.value as "line" | "bar")} />
        </div>

        {/* User multi-select */}
        <div>
          <p className="text-xs font-medium text-[#8b949e] mb-2">Select Users</p>
          <div className="flex flex-wrap gap-2">
            {mockUsers.map(u => (
              <button
                key={u.id}
                onClick={() => toggleUser(u.id)}
                className={`px-3 py-1.5 text-xs rounded-full border transition-colors ${
                  selectedUsers.includes(u.id)
                    ? "bg-[#1f6feb] border-[#1f6feb] text-white"
                    : "border-[#30363d] text-[#8b949e] hover:border-[#58a6ff] hover:text-[#e6edf3]"
                }`}
              >
                {u.username}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Chart */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-5">
        {series.length > 0 ? (
          <>
            <div className="flex items-center justify-between mb-4">
              <p className="text-sm font-semibold text-[#e6edf3] capitalize">{resource.toUpperCase()} Usage</p>
              <span className="text-xs text-[#8b949e]">{selectedUsers.length} user(s) · {timeRange}</span>
            </div>
            <UsageChart series={series} chartType={chartType} height={320} />
          </>
        ) : (
          <div className="flex flex-col items-center justify-center h-48 gap-2">
            <p className="text-[#6e7681] text-sm">No data available for the selected filters</p>
            <p className="text-[#6e7681] text-xs">Try selecting different users or resource type</p>
          </div>
        )}
      </div>
    </div>
  )
}
