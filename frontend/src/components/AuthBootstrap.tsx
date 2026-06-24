import { useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import { LoadingScreen } from '@/components/LoadingScreen';
import { me } from '@/lib/authApi';
import { ApiError } from '@/lib/apiClient';
import { useAuthStore } from '@/store/authStore';

interface AuthBootstrapProps {
  children: ReactNode;
}

export function AuthBootstrap({ children }: AuthBootstrapProps) {
  const didRun = useRef(false);
  const isBootstrapping = useAuthStore((state) => state.isBootstrapping);
  const hydrateSession = useAuthStore((state) => state.hydrateSession);
  const setUser = useAuthStore((state) => state.setUser);
  const clearSession = useAuthStore((state) => state.clearSession);
  const setBootstrapping = useAuthStore((state) => state.setBootstrapping);
  const setAuthError = useAuthStore((state) => state.setAuthError);

  useEffect(() => {
    if (didRun.current) {
      return;
    }
    didRun.current = true;

    async function bootstrap() {
      hydrateSession();
      const token = useAuthStore.getState().accessToken;

      if (!token) {
        setBootstrapping(false);
        return;
      }

      try {
        const currentUser = await me();
        setUser(currentUser);
        setAuthError(null);
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          setAuthError('Tu sesion expiro. Inicia sesion de nuevo.');
        }
        clearSession();
      } finally {
        setBootstrapping(false);
      }
    }

    void bootstrap();
  }, [clearSession, hydrateSession, setAuthError, setBootstrapping, setUser]);

  if (isBootstrapping) {
    return (
      <div className="min-h-screen bg-surface-base p-6">
        <LoadingScreen />
      </div>
    );
  }

  return <>{children}</>;
}
