import { auth } from "@/auth"
import { redirect } from "next/navigation"
import { Sidebar } from "@/components/layout/Sidebar"
import { Header } from "@/components/layout/Header"

export default async function ProtectedLayout({ children }: { children: React.ReactNode }) {
  const session = await auth()
  if (!session) redirect("/login")

  return (
    <div className="min-h-screen bg-[#0d1117]">
      <Sidebar />
      <Header />
      <main className="ml-60 pt-14 min-h-screen">
        {children}
      </main>
    </div>
  )
}
