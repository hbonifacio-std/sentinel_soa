export function IpAddress({ value }: { value: string }) {
  return (
    <span className="font-mono text-xs text-slate-200" title={value}>
      {value}
    </span>
  );
}

