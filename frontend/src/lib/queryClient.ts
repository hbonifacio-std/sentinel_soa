import { QueryClient } from '@tanstack/react-query';

const pollingMsRaw = Number(import.meta.env.VITE_POLLING_INTERVAL_MS ?? 30000);
const pollingMs = Number.isFinite(pollingMsRaw) && pollingMsRaw > 0 ? pollingMsRaw : 30000;

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      gcTime: 5 * 60_000,
      retry: 1,
      refetchOnWindowFocus: false,
      refetchInterval: pollingMs,
      refetchIntervalInBackground: false,
    },
  },
});

