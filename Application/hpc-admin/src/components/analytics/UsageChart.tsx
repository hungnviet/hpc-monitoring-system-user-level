"use client"
import { useState } from "react"
import {
  LineChart, BarChart, Line, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, CartesianGrid, Legend,
} from "recharts"
import type { MetricPoint } from "@/types"

const COLORS = ["#58a6ff", "#3fb950", "#d29922", "#f85149", "#bc8cff", "#79c0ff", "#ffa657", "#ff7b72"]

interface Series {
  name: string
  data: MetricPoint[]
}

interface UsageChartProps {
  series: Series[]
  chartType?: "line" | "bar" | "stacked"
  height?: number
  unit?: string
  dateFrom?: string
  dateTo?: string
}

function getTimeFormatter(dateFrom?: string, dateTo?: string): (iso: string) => string {
  if (!dateFrom || !dateTo) {
    return (iso: string) => {
      const d = new Date(iso)
      return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`
    }
  }
  const rangeMs = new Date(dateTo).getTime() - new Date(dateFrom).getTime()
  const rangeHours = rangeMs / (1000 * 60 * 60)
  const rangeDays = rangeHours / 24

  if (rangeHours <= 24) {
    return (iso: string) => {
      const d = new Date(iso)
      return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`
    }
  }
  if (rangeDays <= 7) {
    return (iso: string) => {
      const d = new Date(iso)
      return `${d.getDate().toString().padStart(2, "0")}/${(d.getMonth() + 1).toString().padStart(2, "0")} ${d.getHours().toString().padStart(2, "0")}:00`
    }
  }
  return (iso: string) => {
    const d = new Date(iso)
    return `${d.getDate().toString().padStart(2, "0")}/${(d.getMonth() + 1).toString().padStart(2, "0")}`
  }
}

// Custom legend that dims hidden series
function renderLegend(
  props: { payload?: { value: string; color: string }[] },
  hidden: Set<string>,
  onToggle: (name: string) => void
) {
  const { payload = [] } = props
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 justify-center mt-2">
      {payload.map(entry => {
        const isHidden = hidden.has(entry.value)
        return (
          <button
            key={entry.value}
            onClick={() => onToggle(entry.value)}
            className="flex items-center gap-1.5 text-xs cursor-pointer transition-opacity"
            style={{ opacity: isHidden ? 0.35 : 1 }}
          >
            <span
              className="inline-block w-3 h-0.5 rounded-full flex-shrink-0"
              style={{ backgroundColor: entry.color }}
            />
            <span style={{ color: isHidden ? "#6e7681" : "#8b949e" }}>{entry.value}</span>
          </button>
        )
      })}
    </div>
  )
}

export function UsageChart({
  series,
  chartType = "line",
  height = 260,
  unit = "%",
  dateFrom,
  dateTo,
}: UsageChartProps) {
  const [hidden, setHidden] = useState<Set<string>>(new Set())

  function toggleSeries(name: string) {
    setHidden(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  const formatTime = getTimeFormatter(dateFrom, dateTo)

  const allTimestamps = [...new Set(series.flatMap(s => s.data.map(p => p.timestamp)))].sort()
  const merged = allTimestamps.map(ts => {
    const obj: Record<string, string | number> = { time: formatTime(ts), rawTime: ts }
    series.forEach(s => {
      const pt = s.data.find(p => p.timestamp === ts)
      obj[s.name] = pt ? Math.round(pt.value * 100) / 100 : 0
    })
    return obj
  })

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

  const legendContent = (props: object) =>
    renderLegend(props as { payload?: { value: string; color: string }[] }, hidden, toggleSeries)

  if (chartType === "line") return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart {...commonProps}>
        <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
        <XAxis dataKey="time" tick={{ fill: "#6e7681", fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis tick={{ fill: "#6e7681", fontSize: 11 }} tickLine={false} axisLine={false} domain={[0, "auto"]} unit={unit} />
        <Tooltip contentStyle={tooltipStyle} />
        <Legend content={legendContent} />
        {series.map((s, i) => (
          <Line
            key={s.name}
            type="monotone"
            dataKey={s.name}
            stroke={COLORS[i % COLORS.length]}
            dot={false}
            strokeWidth={2}
            hide={hidden.has(s.name)}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  )

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart {...commonProps}>
        <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
        <XAxis dataKey="time" tick={{ fill: "#6e7681", fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis tick={{ fill: "#6e7681", fontSize: 11 }} tickLine={false} axisLine={false} domain={[0, "auto"]} unit={unit} />
        <Tooltip contentStyle={tooltipStyle} />
        <Legend content={legendContent} />
        {series.map((s, i) => (
          <Bar
            key={s.name}
            dataKey={s.name}
            fill={COLORS[i % COLORS.length]}
            stackId={chartType === "stacked" ? "stack" : undefined}
            radius={chartType !== "stacked" ? [2, 2, 0, 0] : undefined}
            hide={hidden.has(s.name)}
          />
        ))}
      </BarChart>
    </ResponsiveContainer>
  )
}
