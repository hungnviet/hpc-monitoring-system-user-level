import type { NodeStatus } from "@/types"

const config: Record<NodeStatus, { dot: string; text: string; label: string }> = {
  active: { dot: "bg-[#3fb950]", text: "text-[#3fb950]", label: "Active"  },
  idle:   { dot: "bg-[#d29922]", text: "text-[#d29922]", label: "Idle"    },
  down:   { dot: "bg-[#f85149]", text: "text-[#f85149]", label: "Down"    },
}

export function NodeStatusBadge({ status }: { status: NodeStatus }) {
  const c = config[status]
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-medium ${c.text}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${c.dot} ${status === "active" ? "animate-pulse" : ""}`} />
      {c.label}
    </span>
  )
}
