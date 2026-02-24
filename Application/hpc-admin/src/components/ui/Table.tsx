import { ReactNode } from "react"

interface Column<T> {
  key: string
  header: string
  render: (row: T) => ReactNode
  width?: string
}

interface TableProps<T> {
  columns: Column<T>[]
  data: T[]
  keyExtractor: (row: T) => string
  emptyMessage?: string
}

export function Table<T>({ columns, data, keyExtractor, emptyMessage = "No data" }: TableProps<T>) {
  return (
    <div className="w-full overflow-x-auto rounded-lg border border-[#30363d]">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-[#30363d] bg-[#161b22]">
            {columns.map(col => (
              <th key={col.key} className={`px-4 py-3 text-left text-xs font-medium text-[#8b949e] uppercase tracking-wider ${col.width ?? ""}`}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center text-[#6e7681]">{emptyMessage}</td>
            </tr>
          ) : (
            data.map(row => (
              <tr key={keyExtractor(row)} className="border-b border-[#21262d] last:border-0 hover:bg-[#161b22] transition-colors">
                {columns.map(col => (
                  <td key={col.key} className="px-4 py-3 text-[#e6edf3]">{col.render(row)}</td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  )
}
