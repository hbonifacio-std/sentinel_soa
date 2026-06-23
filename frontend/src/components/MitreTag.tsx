interface MitreTagProps {
  id?: string | null;
  label?: string | null;
}

export function MitreTag({ id, label }: MitreTagProps) {
  if (!id || !label) {
    return null;
  }

  const href = id.startsWith('TA')
    ? `https://attack.mitre.org/tactics/${id}`
    : `https://attack.mitre.org/techniques/${id}`;

  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="inline-flex rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-1 text-xs text-cyan-300 hover:bg-cyan-500/20"
    >
      {label} ({id})
    </a>
  );
}

