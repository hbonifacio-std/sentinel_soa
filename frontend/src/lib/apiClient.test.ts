import { describe, it, expect, vi, beforeEach } from 'vitest';
import { apiFetch, configureApiClient, ApiError } from './apiClient';

describe('apiClient', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    configureApiClient({});
  });

  it('performs successful json request', async () => {
    const fakeResponse = { data: 'hello' };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => fakeResponse,
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await apiFetch('/test-endpoint');
    expect(result).toEqual(fakeResponse);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining('/test-endpoint'),
      expect.any(Object),
    );
  });

  it('sends Authorization header when accessToken is configured', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
    });
    vi.stubGlobal('fetch', fetchMock);

    configureApiClient({
      getAccessToken: () => 'my-secret-token',
    });

    await apiFetch('/secured');
    const calledOptions = fetchMock.mock.calls[0][1] as RequestInit;
    const headers = calledOptions.headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer my-secret-token');
  });

  it('handles 204 No Content response', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 204,
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await apiFetch('/no-content');
    expect(result).toEqual({});
  });

  it('throws ApiError with detail on non-ok json response', async () => {
    const errorDetails = { detail: 'Something went wrong' };
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => errorDetails,
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiFetch('/error')).rejects.toThrowError(ApiError);
    try {
      await apiFetch('/error');
    } catch (err: any) {
      expect(err.status).toBe(400);
      expect(err.detail).toBe('Something went wrong');
    }
  });

  it('throws ApiError on non-ok text response', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      headers: new Headers({ 'content-type': 'text/plain' }),
      text: async () => 'Internal Server Error',
    });
    vi.stubGlobal('fetch', fetchMock);

    try {
      await apiFetch('/server-error');
    } catch (err: any) {
      expect(err.status).toBe(500);
      expect(err.message).toBe('Server error. Please try again later.');
    }
  });

  it('triggers onUnauthorized callback on 401 response', async () => {
    const onUnauthorizedMock = vi.fn();
    configureApiClient({
      onUnauthorized: onUnauthorizedMock,
    });

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => ({ detail: 'Unauthorized' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    try {
      await apiFetch('/admin');
    } catch {
      // Ignored
    }
    expect(onUnauthorizedMock).toHaveBeenCalled();
  });
});
