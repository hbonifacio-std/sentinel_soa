export const threatKeys = {
  all: ['threats'] as const,
  lists: () => [...threatKeys.all, 'list'] as const,
  list: (sourceId: string | null, page: number, limit: number) =>
    [...threatKeys.lists(), { sourceId, page, limit }] as const,
};

export const logKeys = {
  all: ['logs'] as const,
  lists: () => [...logKeys.all, 'list'] as const,
  list: (sourceId: string | null, page: number, limit: number) =>
    [...logKeys.lists(), { sourceId, page, limit }] as const,
};

export const statsKeys = {
  all: ['stats'] as const,
  detail: (sourceId: string | null) => [...statsKeys.all, { sourceId }] as const,
};

export const sourceKeys = {
  all: ['sources'] as const,
  list: () => [...sourceKeys.all, 'list'] as const,
};

export const forensicKeys = {
  all: ['forensic'] as const,
  history: (sourceId: string | null, page: number, limit: number) =>
    [...forensicKeys.all, 'history', { sourceId, page, limit }] as const,
  report: (analysisId: string) => [...forensicKeys.all, 'report', analysisId] as const,
};


