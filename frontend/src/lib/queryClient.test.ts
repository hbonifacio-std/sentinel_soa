import { describe, it, expect } from 'vitest';
import { queryClient } from './queryClient';

describe('queryClient', () => {
  it('disables automatic query refetching by default', () => {
    const queries = queryClient.getDefaultOptions().queries;

    expect(queries?.refetchOnWindowFocus).toBe(false);
    expect(queries?.refetchOnReconnect).toBe(false);
    expect(queries?.refetchOnMount).toBe(false);
    expect(queries?.refetchInterval).toBe(false);
    expect(queries?.refetchIntervalInBackground).toBe(false);
    expect(queries?.staleTime).toBe(Infinity);
  });
});
