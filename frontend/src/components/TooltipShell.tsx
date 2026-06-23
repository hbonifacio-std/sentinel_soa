interface TooltipShellProps {
  accentColor: string;
  children: React.ReactNode;
}

export function TooltipShell({ accentColor, children }: TooltipShellProps) {
  return (
    <div
      style={{
        background: '#111c3a',
        border: `1px solid ${accentColor}`,
        boxShadow: '0 4px 24px rgba(0,0,0,0.5)',
        borderRadius: '8px',
        padding: '12px 16px',
        minWidth: '210px',
        fontSize: '12px',
        color: '#e2e8f0',
        pointerEvents: 'none',
      }}
    >
      {children}
    </div>
  );
}

export function TooltipRow({
  label,
  value,
  color = '#e2e8f0',
}: {
  label: string;
  value: React.ReactNode;
  color?: string;
}) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '16px', marginTop: '4px' }}>
      <span style={{ color: '#94a3b8' }}>{label}</span>
      <span style={{ color, fontWeight: 600, textAlign: 'right' }}>{value}</span>
    </div>
  );
}

export function TooltipDivider() {
  return <hr style={{ borderColor: '#1e3a5f', margin: '8px 0' }} />;
}

