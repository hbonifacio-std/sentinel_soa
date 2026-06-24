import { apiFetch } from '@/lib/apiClient';
import type { AuthUser, TokenResponse } from '@/types/auth';

const authBasePath = '/api/v1/auth';

export async function login(username: string, password: string): Promise<TokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'password',
    username,
    password,
  });

  return apiFetch<TokenResponse>(`${authBasePath}/token`, {
    method: 'POST',
    body: body.toString(),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    skipAuth: true,
    skipJsonContentType: true,
  });
}

export async function me(): Promise<AuthUser> {
  return apiFetch<AuthUser>(`${authBasePath}/me`);
}

export async function logout(): Promise<void> {
  await apiFetch<void>(`${authBasePath}/logout`, {
    method: 'POST',
  });
}

