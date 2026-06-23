import { create } from 'zustand';
import type { AlertStatus, ThreatLevel } from '@/types/threat';

interface FiltersState {
  threatLevel: ThreatLevel | null;
  status: AlertStatus | null;
  searchQuery: string;
}

interface SentinelState {
  activeSourceId: string | null;
  sourceIds: string[];
  alertStatuses: Record<string, AlertStatus>;
  alertHistory: Record<string, string[]>;
  selectedThreatId: string | null;
  filters: FiltersState;
  setActiveSourceId: (id: string | null) => void;
  setSourceIds: (ids: string[]) => void;
  setAlertStatus: (id: string, status: AlertStatus, comment?: string) => void;
  selectThreat: (id: string | null) => void;
  setFilter: <K extends keyof FiltersState>(key: K, value: FiltersState[K]) => void;
  resetFilters: () => void;
}

const initialFilters: FiltersState = {
  threatLevel: null,
  status: null,
  searchQuery: '',
};

export const useSentinelStore = create<SentinelState>((set) => ({
  activeSourceId: null,
  sourceIds: [],
  alertStatuses: {},
  alertHistory: {},
  selectedThreatId: null,
  filters: initialFilters,
  setActiveSourceId: (id) => set(() => ({ activeSourceId: id, filters: initialFilters })),
  setSourceIds: (ids) => set(() => ({ sourceIds: ids })),
  setAlertStatus: (id, status, comment) =>
    set((state) => ({
      alertStatuses: { ...state.alertStatuses, [id]: status },
      alertHistory: comment
        ? { ...state.alertHistory, [id]: [...(state.alertHistory[id] ?? []), comment] }
        : state.alertHistory,
    })),
  selectThreat: (id) => set(() => ({ selectedThreatId: id })),
  setFilter: (key, value) => set((state) => ({ filters: { ...state.filters, [key]: value } })),
  resetFilters: () => set(() => ({ filters: initialFilters })),
}));

