import { toast } from './toast';
import { cancelResponseBody, readBoundedBytesBody, readBoundedJsonBody } from './bounded-response';

/**
 * Same-origin API client. Faithful port of the legacy dashboard `api()`
 * wrapper: CSRF double-submit header on mutating methods, 401 redirects to
 * the login page, 403 surfaces a role toast. All admin data flows through
 * these helpers so auth behavior stays in one place.
 */

let csrfToken = '';

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const ERROR_BODY_MAX_BYTES = 8 * 1024;
const ERROR_BODY_TIMEOUT_MS = 2_000;
const DEFAULT_JSON_BODY_MAX_BYTES = 1024 * 1024;
const JSON_BODY_TIMEOUT_MS = 15_000;

interface ApiErrorBody {
  error?: string;
  fields?: string[];
}

const errorBodyCache = new WeakMap<Response, Promise<ApiErrorBody | null>>();

export interface ApiOptions extends RequestInit {
  allowAuthError?: boolean;
}

export async function initCsrf(): Promise<void> {
  const body = await apiJsonBounded<{ csrfToken?: string }>('/api/csrf', 16 * 1024);
  if (!body) return;
  csrfToken = body.csrfToken || '';
}

export async function api(path: string, opts: ApiOptions = {}): Promise<Response | null> {
  const { allowAuthError = false, ...fetchOpts } = opts;
  const method = String(fetchOpts.method || 'GET').toUpperCase();
  const headers = new Headers(fetchOpts.headers || {});
  if (csrfToken && MUTATING.has(method)) headers.set('x-csrf-token', csrfToken);
  let res: Response;
  try {
    // Authenticated console requests must never replay their cookie-bound
    // mutation body to a redirected endpoint. API routes are same-origin and
    // return explicit status codes, so any redirect is an invalid response.
    res = await fetch(path, { ...fetchOpts, headers, redirect: 'error' });
  } catch {
    // Network failure / server restart: collapse to the null path callers already
    // handle for a non-ok response, instead of an unhandled promise rejection.
    return null;
  }
  if (res.status === 401 && !allowAuthError) {
    cancelResponseBody(res);
    location.href = '/login.html';
    return null;
  }
  if (res.status === 403) await warnForbidden(res);
  return res;
}

function normalizeErrorBody(value: unknown): ApiErrorBody | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  const error = typeof body.error === 'string' && body.error.length <= 160 ? body.error : undefined;
  const fields = Array.isArray(body.fields)
    && body.fields.length <= 32
    && body.fields.every((field) => typeof field === 'string' && field.length <= 160)
    ? body.fields as string[]
    : undefined;
  return error || fields ? { ...(error ? { error } : {}), ...(fields ? { fields } : {}) } : {};
}

async function readBoundedErrorBody(response: Response): Promise<ApiErrorBody | null> {
  return normalizeErrorBody(await readBoundedJsonBody(response, ERROR_BODY_MAX_BYTES, ERROR_BODY_TIMEOUT_MS));
}

function boundedErrorBody(response: Response): Promise<ApiErrorBody | null> {
  const cached = errorBodyCache.get(response);
  if (cached) return cached;
  const pending = readBoundedErrorBody(response);
  errorBodyCache.set(response, pending);
  return pending;
}

/** Distinguish an expired license (read-only past the grace window) from a role denial. */
async function warnForbidden(res: Response): Promise<void> {
  const body = await boundedErrorBody(res) || {};
  if (body.error === 'license_readonly') {
    toast('License is read-only past the grace window. Install a renewal license to make changes.', 'warn');
    return;
  }
  if (body.error === 'license_revoked') {
    toast('License revoked by the vendor. AI use is blocked; contact your vendor to restore access.', 'warn');
    return;
  }
  toast('Request not allowed for this session. Refresh or use a Security Admin account.', 'warn');
}

export async function apiJson<T>(path: string, opts: ApiOptions = {}): Promise<T | null> {
  return apiJsonBounded<T>(path, DEFAULT_JSON_BODY_MAX_BYTES, opts);
}

export async function apiJsonBounded<T>(path: string, maxBytes: number, opts: ApiOptions = {}): Promise<T | null> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) return null;
  const res = await api(path, opts);
  if (!res || !res.ok) return null;
  return await readBoundedJsonBody(res, maxBytes, JSON_BODY_TIMEOUT_MS) as T | null;
}

export async function responseJsonBounded<T>(response: Response, maxBytes = DEFAULT_JSON_BODY_MAX_BYTES): Promise<T | null> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) return null;
  return await readBoundedJsonBody(response, maxBytes, JSON_BODY_TIMEOUT_MS) as T | null;
}

export async function responseBytesBounded(response: Response, maxBytes: number): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) return null;
  return readBoundedBytesBody(response, maxBytes, JSON_BODY_TIMEOUT_MS);
}

export async function apiSend<T>(path: string, method: string, body?: unknown): Promise<T | null> {
  return apiJson<T>(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

export async function apiErrorSummary(response: Response | null, fallback: string): Promise<string> {
  if (!response) return fallback;
  const body = await boundedErrorBody(response);
  if (body?.fields?.length) return `${fallback}: ${body.fields.join(', ')}`;
  if (body?.error) return `${fallback}: ${body.error}`;
  return fallback;
}
