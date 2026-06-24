import { Outlet } from 'react-router-dom';
import { useAuthStore } from '@/store/authStore';
import type { UserRole } from '@/types/auth';

interface RequireRoleProps {
  allowedRoles: UserRole[];
}

export function RequireRole({ allowedRoles }: RequireRoleProps) {
  const user = useAuthStore((state) => state.user);

  if (!user || !allowedRoles.includes(user.role)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-surface-base p-6">
        <div className="w-full max-w-lg rounded-lg border border-surface-border bg-surface-elevated p-6 text-slate-200">
          <h1 className="text-lg font-semibold">Acceso denegado</h1>
          <p className="mt-2 text-sm text-slate-400">
            Tu rol actual no tiene permisos para acceder al panel de analisis y reglas.
          </p>
        </div>
      </div>
    );
  }

  return <Outlet />;
}

