type Variant = "success" | "warning" | "danger" | "info" | "muted"

const styles: Record<Variant, string> = {
  success: "bg-[#1a3c2b] text-[#3fb950] border border-[#2a5a3a]",
  warning: "bg-[#3d2e05] text-[#d29922] border border-[#5a4310]",
  danger:  "bg-[#3c1a1a] text-[#f85149] border border-[#5a2525]",
  info:    "bg-[#1a2a3c] text-[#58a6ff] border border-[#1f3a5f]",
  muted:   "bg-[#21262d] text-[#8b949e] border border-[#30363d]",
}

interface BadgeProps {
  variant: Variant
  children: React.ReactNode
  className?: string
}

export function Badge({ variant, children, className = "" }: BadgeProps) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full ${styles[variant]} ${className}`}>
      {children}
    </span>
  )
}
