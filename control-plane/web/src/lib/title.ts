import { useEffect } from 'react'

/// Every page names itself "<page> - Synchronicity", so a row of browser
/// tabs reads as places rather than as the same tab six times. No restore
/// on unmount: the next page sets its own title the moment it mounts.
export function useTitle(page: string) {
  useEffect(() => {
    document.title = `${page} - Synchronicity`
  }, [page])
}
