interface ScoreBarProps {
  label: string;
  score: number;
  maxScore?: number;
}

export function ScoreBar({ label, score, maxScore = 100 }: ScoreBarProps) {
  const pct = Math.max(0, Math.min(100, (score / maxScore) * 100));

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs text-slate-300">
        <span>{label}</span>
        <span>{score.toFixed(1)}</span>
      </div>
      <div className="h-2 rounded bg-slate-800">
        <div className="h-full rounded bg-gradient-to-r from-cyan-500 to-blue-500 transition-all" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

