import { Activity, AlertTriangle, LayoutDashboard, Terminal } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import { cn } from '@/lib/cn';

const links = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/alerts', label: 'Alert Center', icon: AlertTriangle },
  { to: '/logs', label: 'Log Viewer', icon: Terminal },
];

export function Sidebar() {
  return (
    <aside className="hidden w-60 flex-col border-r border-surface-border bg-surface-elevated p-4 md:flex">
      <div className="mb-8 flex items-center gap-2">
        <Activity className="text-accent-cyan" size={20} />
        <div>
          <p className="text-sm font-semibold">Sentinel SOC</p>
          <p className="font-mono text-xs text-slate-400">v2 tactical view</p>
        </div>
      </div>
      <nav className="space-y-2">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-2 rounded-md border px-3 py-2 text-sm transition',
                isActive
                  ? 'border-accent-cyan/60 bg-accent-glow text-cyan-300'
                  : 'border-transparent text-slate-300 hover:border-surface-border hover:bg-slate-900',
              )
            }
          >
            <link.icon size={16} />
            {link.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}

