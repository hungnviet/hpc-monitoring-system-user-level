import type { Metadata } from "next"
import "./globals.css"

export const metadata: Metadata = {
  title: "HPC Monitor Admin",
  description: "HPC Cluster Monitoring & Configuration",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  )
}
