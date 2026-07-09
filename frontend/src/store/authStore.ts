import { create } from 'zustand';
import type { AuthStateSnapshot, AuthUser } from '@/types/auth';

const AUTH_SESSION_KEY = 'sentinel.auth.session.v1';
const persistSession = String(import.meta.env.VITE_AUTH_PERSIST_SESSION ?? 'true').toLowerCase() === 'true';

interface AuthState {
  accessToken: string | null;
  tenantApiKey: string | null;
  user: AuthUser | null;
  isAuthenticated: boolean;
  isBootstrapping: boolean;
  authError: string | null;
  hydrateSession: () => void;
  setSession: (token: string, user: AuthUser, tenantApiKey?: string | null) => void;
  setUser: (user: AuthUser) => void;
  setBootstrapping: (value: boolean) => void;
  setAuthError: (error: string | null) => void;
  clearSession: () => void;
}

interface AuthStateSnapshot {
  accessToken: string;
  tenantApiKey: string | null;
  user: AuthUser;
}

function readSessionStorage(): AuthStateSnapshot | null {
  if (!persistSession) {
    return null;
  }

  try {
    const raw = window.sessionStorage.getItem(AUTH_SESSION_KEY);
    if (!raw) {
      return null;
    }

    const parsed = JSON.parse(raw) as Partial<AuthStateSnapshot>;
    if (typeof parsed.accessToken !== 'string' || !parsed.user) {
      return null;
    }

    return {
      accessToken: parsed.accessToken,
      tenantApiKey: parsed.tenantApiKey || null,
      user: parsed.user,
    };
  } catch {
    return null;
  }
}

function writeSessionStorage(snapshot: AuthStateSnapshot | null) {
  if (!persistSession) {
    return;
  }

  try {
    if (!snapshot) {
      window.sessionStorage.removeItem(AUTH_SESSION_KEY);
      return;
    }

    window.sessionStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(snapshot));
  } catch {
    // Ignore storage errors and keep auth state in memory only.
  }
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  tenantApiKey: null,
  user: null,
  isAuthenticated: false,
  isBootstrapping: true,
  authError: null,
  hydrateSession: () => {
    const snapshot = readSessionStorage();

    if (!snapshot) {
      set(() => ({
        accessToken: null,
        tenantApiKey: null,
        user: null,
        isAuthenticated: false,
      }));
      return;
    }

    set(() => ({
      accessToken: snapshot.accessToken,
      tenantApiKey: snapshot.tenantApiKey,
      user: snapshot.user,
      isAuthenticated: true,
      authError: null,
    }));
  },
  setSession: (token, user, tenantApiKey = null) => {
    writeSessionStorage({ accessToken: token, tenantApiKey, user });
    set(() => ({
      accessToken: token,
      tenantApiKey,
      user,
      isAuthenticated: true,
      authError: null,
    }));
  },
  setUser: (user) => {
    set((state) => {
      if (state.accessToken) {
        writeSessionStorage({
          accessToken: state.accessToken,
          tenantApiKey: state.tenantApiKey,
          user,
        });
      }

      return {
        user,
        isAuthenticated: Boolean(state.accessToken),
      };
    });
  },
  setBootstrapping: (value) => set(() => ({ isBootstrapping: value })),
  setAuthError: (error) => set(() => ({ authError: error })),
  clearSession: () => {
    writeSessionStorage(null);
    set(() => ({
      accessToken: null,
      tenantApiKey: null,
      user: null,
      isAuthenticated: false,
      authError: null,
      isBootstrapping: false,
    }));
  },
}));

