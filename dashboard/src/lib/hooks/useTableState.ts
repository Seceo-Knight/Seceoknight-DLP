import { useMemo, useState } from 'react'
import type { SortDirection } from '@/components/ui/table'

/**
 * Shared client-side sort + pagination state for data tables (Events,
 * Incidents, Agents, ...). Sorting/pagination happens over whatever
 * array the caller passes in — for server-paginated endpoints, pass the
 * already-fetched page and treat `total` as the server's reported count
 * instead of `rows.length`.
 */
export function useTableSort<T>(rows: T[], defaultKey: string | null = null) {
  const [sortKey, setSortKey] = useState<string | null>(defaultKey)
  const [direction, setDirection] = useState<SortDirection>(defaultKey ? 'desc' : null)

  const onSort = (key: string) => {
    if (sortKey !== key) {
      setSortKey(key)
      setDirection('desc')
      return
    }
    if (direction === 'desc') {
      setDirection('asc')
    } else if (direction === 'asc') {
      setSortKey(null)
      setDirection(null)
    } else {
      setDirection('desc')
    }
  }

  const sorted = useMemo(() => {
    if (!sortKey || !direction) return rows
    const copy = [...rows]
    copy.sort((a, b) => {
      const av = (a as any)[sortKey]
      const bv = (b as any)[sortKey]
      if (av == null && bv == null) return 0
      if (av == null) return 1
      if (bv == null) return -1
      let cmp: number
      if (typeof av === 'number' && typeof bv === 'number') {
        cmp = av - bv
      } else {
        cmp = String(av).localeCompare(String(bv))
      }
      return direction === 'asc' ? cmp : -cmp
    })
    return copy
  }, [rows, sortKey, direction])

  return { sorted, sortKey, direction, onSort }
}

export function usePagination<T>(rows: T[], initialPageSize = 25) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(initialPageSize)

  const total = rows.length
  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const clampedPage = Math.min(page, totalPages)

  const pageRows = useMemo(() => {
    const start = (clampedPage - 1) * pageSize
    return rows.slice(start, start + pageSize)
  }, [rows, clampedPage, pageSize])

  return {
    page: clampedPage,
    pageSize,
    total,
    pageRows,
    setPage,
    setPageSize: (size: number) => {
      setPageSize(size)
      setPage(1)
    },
  }
}
