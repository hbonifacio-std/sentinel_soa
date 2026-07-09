import { FormEvent, useMemo, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { login } from '@/lib/authApi';
import { ApiError } from '@/lib/apiClient';
import { useAuthStore } from '@/store/authStore';

interface LoginLocationState {
  from?: string;
}

function getLoginErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return 'Credenciales invalidas. Verifica tu usuario y password.';
    }

    if (typeof error.detail === 'string') {
      return error.detail;
    }
  }

  if (error instanceof Error) {
    return error.message;
  }

  return 'No fue posible iniciar sesion. Intenta de nuevo.';
}

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const authError = useAuthStore((state) => state.authError);
  const setAuthError = useAuthStore((state) => state.setAuthError);
  const setSession = useAuthStore((state) => state.setSession);

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  const nextPath = useMemo(() => {
    const state = location.state as LoginLocationState | null;
    return state?.from && state.from.startsWith('/') ? state.from : '/';
  }, [location.state]);

  if (isAuthenticated) {
    return <Navigate to={nextPath} replace />;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitting(true);
    setLocalError(null);
    setAuthError(null);

    try {
      const tokenResponse = await login(username.trim(), password);
      setSession(tokenResponse.access_token, tokenResponse.user, tokenResponse.tenant_api_key);
      navigate(nextPath, { replace: true });
    } catch (error) {
      setLocalError(getLoginErrorMessage(error));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-surface-base p-6">
      <div className="w-full max-w-md rounded-lg border border-surface-border bg-surface-elevated p-6 shadow-lg">
        <h1 className="text-xl font-semibold text-slate-100">Sentinel SOC Login</h1>

        <form className="mt-6 space-y-4" onSubmit={(event) => void handleSubmit(event)}>
          <label className="block text-sm text-slate-200">
            Usuario
            <input
              className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-3 py-2 text-slate-100 focus:border-cyan-400 focus:outline-none"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              required
            />
          </label>

          <label className="block text-sm text-slate-200">
            Password
            <input
              className="mt-1 w-full rounded border border-surface-border bg-slate-900 px-3 py-2 text-slate-100 focus:border-cyan-400 focus:outline-none"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              required
            />
          </label>

          {authError ? <p className="text-sm text-amber-300">{authError}</p> : null}
          {localError ? <p className="text-sm text-red-400">{localError}</p> : null}

          <button
            type="submit"
            className="w-full rounded border border-accent-cyan/50 bg-accent-glow px-3 py-2 text-sm font-medium text-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={submitting}
          >
            {submitting ? 'Ingresando...' : 'Iniciar sesion'}
          </button>
        </form>

      </div>
    </div>
  );
}

