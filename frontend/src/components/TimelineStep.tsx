interface TimelineStepProps {
  title: string;
  items: string[];
}

export function TimelineStep({ title, items }: TimelineStepProps) {
  const safeItems = Array.isArray(items) ? items : [];
  return (
    <div className="relative pl-5">
      <span className="absolute left-0 top-1 h-2 w-2 rounded-full bg-accent-cyan" />
      <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-300">{title}</h4>
      <ul className="space-y-1 text-xs text-slate-400">
        {safeItems.map((item) => (
          <li key={item}>- {item}</li>
        ))}
      </ul>
    </div>
  );
}

