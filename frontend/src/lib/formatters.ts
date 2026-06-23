import { format } from 'date-fns';

export function formatDate(value: string) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return format(date, 'yyyy-MM-dd HH:mm:ss');
}

export function formatScore(score: number, maxScore = 100) {
  const pct = Math.min(100, Math.max(0, (score / maxScore) * 100));
  return `${pct.toFixed(1)}%`;
}

export function formatBytes(bytes: number | null) {
  if (bytes == null) {
    return '-';
  }
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

