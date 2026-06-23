import { useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSentinelStore } from '@/store/sentinelStore';
import type { AlertStatus, Threat } from '@/types/threat';

export function useFilters() {
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = useSentinelStore((state) => state.filters);
  const setFilter = useSentinelStore((state) => state.setFilter);

  const searchQuery = useMemo(() => searchParams.get('q') ?? filters.searchQuery, [filters.searchQuery, searchParams]);

  function setSearchQuery(value: string) {
    setFilter('searchQuery', value);
    const next = new URLSearchParams(searchParams);
    if (value.trim()) {
      next.set('q', value.trim());
    } else {
      next.delete('q');
    }
    setSearchParams(next, { replace: true });
  }

  function applyFilters(threats: Threat[]) {
    return threats.filter((threat) => {
      if (filters.threatLevel && threat.threat_level !== filters.threatLevel) {
        return false;
      }

      const resolvedStatus: AlertStatus = threat.status ?? 'pending';
      if (filters.status && resolvedStatus !== filters.status) {
        return false;
      }

      if (!searchQuery.trim()) {
        return true;
      }

      const q = searchQuery.toLowerCase();
      return (
        threat.source_ip.toLowerCase().includes(q) ||
        (threat.reasoning_summary ?? '').toLowerCase().includes(q) ||
        (threat.mitre_tactic ?? '').toLowerCase().includes(q)
      );
    });
  }

  return { filters, searchQuery, setFilter, setSearchQuery, applyFilters };
}
