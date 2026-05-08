"use client"
import type { ResourceType } from "@/types"

const RESOURCES: { value: ResourceType; label: string; color: string }[] = [
  { value: "cpu",  label: "CPU",        color: "#58a6ff" },
  { value: "mem",  label: "Memory",     color: "#3fb950" },
  { value: "disk", label: "Disk I/O",   color: "#d29922" },
  { value: "net",  label: "Network",    color: "#f85149" },
]

interface ResourcePillSelectProps {
  selected: ResourceType[]
  onChange: (selected: ResourceType[]) => void
}

export function ResourcePillSelect({ selected, onChange }: ResourcePillSelectProps) {
  function toggle(r: ResourceType) {
    if (selected.includes(r)) {
      if (selected.length === 1) return // keep at least one
      onChange(selected.filter(v => v !== r))
    } else {
      onChange([...selected, r])
    }
  }

  return (
    <div>
      <p className="text-xs font-medium text-[#8b949e] mb-2">Resources</p>
      <div className="flex flex-wrap gap-2">
        {RESOURCES.map(r => {
          const active = selected.includes(r.value)
          return (
            <button
              key={r.value}
              onClick={() => toggle(r.value)}
              className="px-3 py-1.5 text-xs rounded-full border transition-colors cursor-pointer"
              style={active
                ? { backgroundColor: r.color + "22", borderColor: r.color, color: r.color }
                : { borderColor: "#30363d", color: "#8b949e" }
              }
            >
              {r.label}
            </button>
          )
        })}
      </div>
    </div>
  )
}

export { RESOURCES }
