export function LoadingScreen() {
  return (
    <div className="relative flex min-h-[300px] items-center justify-center overflow-hidden rounded-lg border border-surface-border bg-surface-elevated">
      <div className="absolute inset-0 h-full w-1/3 animate-scan bg-gradient-to-r from-transparent via-accent-cyan/40 to-transparent" />
      <p className="z-10 font-mono text-sm text-slate-300">Loading telemetry...</p>
    </div>
  );
}

