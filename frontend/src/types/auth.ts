export type UserRole = 'admin' | 'analyst' | 'viewer';

export interface AuthUser {
  user_id: string;
  username: string;
  email: string;
  role: UserRole;
  is_active: boolean;
  tenant_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'bearer' | string;
  user: AuthUser;
  tenant_api_key?: string | null;
}

export interface AuthStateSnapshot {
  accessToken: string;
  tenantApiKey: string | null;
  user: AuthUser;
}

