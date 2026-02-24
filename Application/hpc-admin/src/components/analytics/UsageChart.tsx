"use client"
import {
  LineChart, BarChart, Line, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Legend
} from "recharts"
import type { MetricPoint } from "@/types"

const COLORS = ["#58a6ff", "#3fb950", "#d29922", "#f85149", "#bc8cff", "#79c0ff"]

interface Series {
  name: string
  data: MetricPoint[]
}

interface UsageChartProps {
  series: Series[]
  chartType?: "line" | "bar" | "stacked"
  height?: number
  unit?: string
}

function formatTime(iso: string) {
  const d = new Date(iso)
  return `${d.getHours().toString().padStart(2,"0")}:${d.getMinutes().toString().padStart(2,"0")}`
}

export function UsageChart({ series, chartType = "line", height = 260, unit = "%" }: UsageChartProps) {
  // Merge all series into combined dataset indexed by timestamp
  const merged = series[0]?.data.map((pt, i) => {
    const obj: Record<string, string | number> = { time: formatTime(pt.timestamp) }
    series.forEach(s => { obj[s.name] = Math.round(s.data[i]?.value ?? 0) })
    return obj
  }) ?? []

  const tooltipStyle = {
    backgroundColor: "#1c2128",
    border: "1px solid #30363d",
    borderRadius: "6px",
    color: "#e6edf3",
    fontSize: "12px",
  }

  const commonProps = {
    data: merged,
    margin: { top: 5, right: 10, left: -20, bottom: 0 },
  }

  if (chartType === "line") return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart {...commonProps}>
        <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
        <XAxis dataKey="time" tick={{ fill: "#6e7681", fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis tick={{ fill: "#6e7681", fontSize: 11 }} tickLine={false} axisLine={false} domain={[0, 100]} unit={unit} />
        <Tooltip contentStyle={tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 12, color: "#8b949e" }} />
        {series.map((s, i) => <Line key={s.name} type="monotone" dataKey={s.name} stroke={COLORS[i % COLORS.length]} dot={false} strokeWidth={2} />)}
      </LineChart>
    </ResponsiveContainer>
  )

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart {...commonProps}>
        <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
        <XAxis dataKey="time" tick={{ fill: "#6e7681", fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis tick={{ fill: "#6e7681", fontSize: 11 }} tickLine={false} axisLine={false} domain={[0, 100]} unit={unit} />
        <Tooltip contentStyle={tooltipStyle} />
        <Legend wrapperStyle={{ fontSize: 12, color: "#8b949e" }} />
        {series.map((s, i) => (
          <Bar key={s.name} dataKey={s.name} fill={COLORS[i % COLORS.length]} stackId={chartType === "stacked" ? "stack" : undefined} radius={chartType !== "stacked" ? [2,2,0,0] : undefined} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  )
}
