import { create } from 'zustand';
import type { AuthUser } from '@/types/auth';

interface AuthState {
  accessToken: string | null;
  user: AuthUser | null;
  isAuthenticated: boolean;
  isBootstrapping: boolean;
  authError: string | null;
  hydrateSession: () => void;
  setSession: (token: string, user: AuthUser) => void;
  setUser: (user: AuthUser) => void;
  setBootstrapping: (value: boolean) => void;
  setAuthError: (error: string | null) => void;
  clearSession: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: null,
  user: null,
  isAuthenticated: false,
  isBootstrapping: true,
  authError: null,
  hydrateSession: () => {
    set(() => ({
      accessToken: null,
      user: null,
      isAuthenticated: false,
      authError: null,
    }));
  },
  setSession: (token, user) => {
    set(() => ({
      accessToken: token,
      user,
      isAuthenticated: true,
      authError: null,
    }));
  },
  setUser: (user) => {
    set((state) => ({
      user,
      isAuthenticated: Boolean(state.accessToken),
    }));
  },
  setBootstrapping: (value) => set(() => ({ isBootstrapping: value })),
  setAuthError: (error) => set(() => ({ authError: error })),
  clearSession: () => {
    set(() => ({
      accessToken: null,
      user: null,
      isAuthenticated: false,
      authError: null,
      isBootstrapping: false,
    }));
  },
}));
