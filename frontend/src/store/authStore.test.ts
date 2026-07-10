import { describe, it, expect, beforeEach } from 'vitest';
import { useAuthStore } from './authStore';

describe('authStore', () => {
  beforeEach(() => {
    useAuthStore.setState({
      accessToken: null,
      tenantApiKey: null,
      user: null,
      isAuthenticated: false,
      isBootstrapping: true,
      authError: null,
    });
    window.sessionStorage.clear();
  });

  it('initializes with default state values', () => {
    const state = useAuthStore.getState();
    expect(state.accessToken).toBeNull();
    expect(state.user).toBeNull();
    expect(state.isAuthenticated).toBe(false);
    expect(state.isBootstrapping).toBe(true);
    expect(state.authError).toBeNull();
  });

  it('sets session in memory', () => {
    const fakeUser = {
      user_id: 'user-1',
      username: 'analyst1',
      role: 'analyst' as const,
      email: 'analyst@sentinel.com',
      is_active: true,
      created_at: '',
      updated_at: '',
    };
    useAuthStore.getState().setSession('token-xyz', fakeUser);

    const state = useAuthStore.getState();
    expect(state.accessToken).toBe('token-xyz');
    expect(state.tenantApiKey).toBeNull();
    expect(state.user).toEqual(fakeUser);
    expect(state.isAuthenticated).toBe(true);
    expect(window.sessionStorage.getItem('sentinel.auth.session.v1')).toBeNull();
  });

  it('ignores sessionStorage during hydrateSession', () => {
    const fakeUser = {
      user_id: 'user-2',
      username: 'admin1',
      role: 'admin' as const,
      email: 'admin@sentinel.com',
      is_active: true,
      created_at: '',
      updated_at: '',
    };
    window.sessionStorage.setItem(
      'sentinel.auth.session.v1',
      JSON.stringify({ accessToken: 'token-abc', user: fakeUser }),
    );

    useAuthStore.getState().hydrateSession();

    const state = useAuthStore.getState();
    expect(state.accessToken).toBeNull();
    expect(state.tenantApiKey).toBeNull();
    expect(state.user).toBeNull();
    expect(state.isAuthenticated).toBe(false);
  });

  it('handles hydrateSession when storage is empty', () => {
    useAuthStore.getState().hydrateSession();
    const state = useAuthStore.getState();
    expect(state.accessToken).toBeNull();
    expect(state.isAuthenticated).toBe(false);
  });

  it('updates user in state', () => {
    const initialUser = {
      user_id: 'user-3',
      username: 'viewer1',
      role: 'viewer' as const,
      email: 'viewer@sentinel.com',
      is_active: true,
      created_at: '',
      updated_at: '',
    };
    useAuthStore.getState().setSession('token-foo', initialUser);

    const updatedUser = { ...initialUser, username: 'viewer-updated' };
    useAuthStore.getState().setUser(updatedUser);

    const state = useAuthStore.getState();
    expect(state.user?.username).toBe('viewer-updated');
  });

  it('clears session correctly', () => {
    const user = {
      user_id: 'user-4',
      username: 'user4',
      role: 'viewer' as const,
      email: 'viewer@sentinel.com',
      is_active: true,
      created_at: '',
      updated_at: '',
    };
    useAuthStore.getState().setSession('token-bar', user);
    useAuthStore.getState().clearSession();

    const state = useAuthStore.getState();
    expect(state.accessToken).toBeNull();
    expect(state.user).toBeNull();
    expect(state.isAuthenticated).toBe(false);
    expect(window.sessionStorage.getItem('sentinel.auth.session.v1')).toBeNull();
  });

  it('manages authError and bootstrapping state', () => {
    useAuthStore.getState().setAuthError('Some error occurred');
    expect(useAuthStore.getState().authError).toBe('Some error occurred');

    useAuthStore.getState().setBootstrapping(false);
    expect(useAuthStore.getState().isBootstrapping).toBe(false);
  });
});
