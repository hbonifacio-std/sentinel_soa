const baseURL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

export class ApiError extends Error {
  status: number;
  detail: unknown;
  bodyText: string;

  constructor(status: number, message: string, detail: unknown, bodyText: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
    this.bodyText = bodyText;
  }
}

interface ApiClientConfig {
  getAccessToken?: () => string | null;
  refreshAccessToken?: () => Promise<string | null>;
  onUnauthorized?: () => void;
}

export interface ApiFetchOptions extends RequestInit {
  skipAuth?: boolean;
  skipJsonContentType?: boolean;
  skipUnauthorizedHandler?: boolean;
  skipAuthRefresh?: boolean;
}

let apiClientConfig: ApiClientConfig = {};
let refreshInFlight: Promise<string | null> | null = null;

export function configureApiClient(config: ApiClientConfig) {
  apiClientConfig = config;
}

async function refreshAccessToken(): Promise<string | null> {
  if (!apiClientConfig.refreshAccessToken) {
    return null;
  }
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        return await apiClientConfig.refreshAccessToken?.() ?? null;
      } finally {
        refreshInFlight = null;
      }
    })();
  }
  return refreshInFlight;
}

function getErrorMessage(status: number, detail: unknown, fallback: string): string {
  if (status === 401) {
    return 'Unauthorized request.';
  }
  if (status === 403) {
    return 'Forbidden request.';
  }
  if (status === 404) {
    return 'Resource not found.';
  }
  if (status >= 500) {
    return 'Server error. Please try again later.';
  }
  if (status === 422) {
    return 'Validation error in request data.';
  }
  if (typeof detail === 'string' && detail.trim()) {
    return detail;
  }
  return fallback || `HTTP ${status}`;
}

function isStructuredJson(value: unknown): value is Record<string, unknown> | unknown[] {
  return (typeof value === 'object' && value !== null) || Array.isArray(value);
}

export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const url = path.startsWith('http') ? path : `${baseURL}${path}`;
  const headers = new Headers(options.headers);

  if (options.body && !options.skipJsonContentType && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  if (!options.skipAuth && !headers.has('Authorization')) {
    const accessToken = apiClientConfig.getAccessToken?.();
    if (accessToken) {
      headers.set('Authorization', `Bearer ${accessToken}`);
    }
  }


  const response = await fetch(url, {
    ...options,
    headers,
    credentials: options.credentials ?? 'include',
  });

  if (!response.ok) {
    if (
      response.status === 401 &&
      !options.skipAuth &&
      !options.skipAuthRefresh
    ) {
      const refreshedToken = await refreshAccessToken();
      if (refreshedToken) {
        return apiFetch<T>(path, {
          ...options,
          skipAuthRefresh: true,
          skipUnauthorizedHandler: true,
        });
      }
    }

    let detail: unknown = null;
    let bodyText = '';

    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      const body = (await response.json()) as { detail?: unknown; message?: string };
      detail = body.detail ?? body.message ?? body;
      bodyText = JSON.stringify(body);
    } else {
      bodyText = await response.text();
      detail = null;
    }

    if (response.status === 401 && !options.skipUnauthorizedHandler) {
      apiClientConfig.onUnauthorized?.();
    }

    throw new ApiError(
      response.status,
      getErrorMessage(response.status, detail, bodyText),
      detail,
      bodyText,
    );
  }

  if (response.status === 204) {
    return {} as T;
  }

  const payload: unknown = await response.json();
  if (!isStructuredJson(payload)) {
    throw new ApiError(response.status, 'Invalid JSON response format.', payload, String(payload));
  }

  return payload as T;
}
