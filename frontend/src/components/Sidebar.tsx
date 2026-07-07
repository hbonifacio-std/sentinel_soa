import { Activity, AlertTriangle, LayoutDashboard, LogOut, ScanSearch, ShieldCheck, Terminal } from 'lucide-react';
import { NavLink } from 'react-router-dom';
import { cn } from '@/lib/cn';
import { useState } from 'react';
import { logout } from '@/lib/authApi';
import { ApiError } from '@/lib/apiClient';
import { useAuthStore } from '@/store/authStore';

const links = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/alerts', label: 'Alert Center', icon: AlertTriangle },
  { to: '/logs', label: 'Log Viewer', icon: Terminal },
  { to: '/rules', label: 'Rules Management', icon: ShieldCheck },
  { to: '/forensic', label: 'Forensic Analysis', icon: ScanSearch },
];

export function Sidebar() {
  const [loggingOut, setLoggingOut] = useState(false);
  const user = useAuthStore((state) => state.user);
  const clearSession = useAuthStore((state) => state.clearSession);

  async function handleLogout() {
    setLoggingOut(true);

    try {
      await logout();
    } catch (error) {
      // 401 can happen if token already expired; local cleanup is still required.
      if (!(error instanceof ApiError) || error.status !== 401) {
        console.error('Logout failed:', error);
      }
    } finally {
      clearSession();
      setLoggingOut(false);
    }
  }

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

      <div className="mt-auto rounded border border-surface-border bg-slate-950/40 p-3 text-xs text-slate-300">
        <p className="font-semibold text-slate-100">{user?.username ?? 'unknown user'}</p>
        <p className="mt-1 text-slate-400">Rol: {user?.role ?? 'n/a'}</p>
        <button
          className="mt-3 flex w-full items-center justify-center gap-2 rounded border border-surface-border px-2 py-1.5 text-xs text-slate-200 disabled:cursor-not-allowed disabled:opacity-60"
          onClick={() => void handleLogout()}
          disabled={loggingOut}
        >
          <LogOut size={14} />
          {loggingOut ? 'Cerrando sesion...' : 'Cerrar sesion'}
        </button>
      </div>
    </aside>
  );
}
