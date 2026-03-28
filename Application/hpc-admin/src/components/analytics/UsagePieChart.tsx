"use client"
import { useState } from "react"
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts"

const COLORS = ["#58a6ff", "#3fb950", "#d29922", "#f85149", "#bc8cff", "#79c0ff", "#ffa657", "#ff7b72"]

export interface PieSlice {
  name: string
  value: number
}

interface UsagePieChartProps {
  title?: string
  data: PieSlice[]
  unit: string
  height?: number
}

export function UsagePieChart({ title, data, unit, height = 300 }: UsagePieChartProps) {
  const [hidden, setHidden] = useState<Set<string>>(new Set())

  function toggleSlice(name: string) {
    setHidden(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  // Stable color per name regardless of hide/show
  const colorMap = new Map(data.map((d, i) => [d.name, COLORS[i % COLORS.length]]))
  const visible = data.filter(d => !hidden.has(d.name) && d.value > 0)
  const total = visible.reduce((s, d) => s + d.value, 0)
  const hasData = data.some(d => d.value > 0)

  const tooltipStyle = {
    backgroundColor: "#1c2128",
    border: "1px solid #30363d",
    borderRadius: "6px",
    color: "#e6edf3",
    fontSize: "12px",
  }

  return (
    <div className="flex flex-col">
      {title && (
        <div className="text-center mb-1">
          <p className="text-sm font-semibold text-[#e6edf3]">{title}</p>
          {hasData && (
            <p className="text-[10px] text-[#6e7681]">
              Total: {total.toFixed(1)} {unit}
            </p>
          )}
        </div>
      )}

      {!hasData ? (
        <div className="flex items-center justify-center" style={{ height }}>
          <p className="text-xs text-[#6e7681]">No data</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={height}>
          <PieChart>
            <Pie
              data={visible}
              cx="50%"
              cy="45%"
              innerRadius="30%"
              outerRadius="55%"
              paddingAngle={2}
              dataKey="value"
              nameKey="name"
            >
              {visible.map(d => (
                <Cell key={d.name} fill={colorMap.get(d.name) ?? "#58a6ff"} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={tooltipStyle}
              formatter={(value: number, name: string) => {
                const pct = total > 0 ? ((value / total) * 100).toFixed(1) : "0"
                return [`${value.toFixed(1)} ${unit} (${pct}%)`, name]
              }}
            />
            {/* Pass full payload so hidden items remain in legend */}
            <Legend
              payload={data.map((d, i) => ({
                value: d.name,
                color: COLORS[i % COLORS.length],
                type: "circle" as const,
              }))}
              content={(props) => {
                const items = (props as { payload?: { value: string; color: string }[] }).payload ?? []
                return (
                  <div className="flex flex-wrap gap-x-3 gap-y-1 justify-center mt-2 px-2">
                    {items.map(entry => {
                      const isHidden = hidden.has(entry.value)
                      return (
                        <button
                          key={entry.value}
                          onClick={() => toggleSlice(entry.value)}
                          className="flex items-center gap-1 text-[10px] cursor-pointer transition-opacity"
                          style={{ opacity: isHidden ? 0.35 : 1 }}
                        >
                          <span
                            className="w-2 h-2 rounded-full flex-shrink-0"
                            style={{ backgroundColor: entry.color }}
                          />
                          <span style={{ color: isHidden ? "#6e7681" : "#8b949e" }}>
                            {entry.value}
                          </span>
                        </button>
                      )
                    })}
                  </div>
                )
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
