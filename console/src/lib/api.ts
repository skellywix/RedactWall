import { toast } from './toast';

/**
 * Same-origin API client. Faithful port of the legacy dashboard `api()`
 * wrapper: CSRF double-submit header on mutating methods, 401 redirects to
 * the login page, 403 surfaces a role toast. All admin data flows through
 * these helpers so auth behavior stays in one place.
 */

let csrfToken = '';

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export interface ApiOptions extends RequestInit {
  allowAuthError?: boolean;
}

export async function initCsrf(): Promise<void> {
  const res = await api('/api/csrf');
  if (!res || !res.ok) return;
  const body = (await res.json()) as { csrfToken?: string };
  csrfToken = body.csrfToken || '';
}

export async function api(path: string, opts: ApiOptions = {}): Promise<Response | null> {
  const { allowAuthError = false, ...fetchOpts } = opts;
  const method = String(fetchOpts.method || 'GET').toUpperCase();
  const headers = new Headers(fetchOpts.headers || {});
  if (csrfToken && MUTATING.has(method)) headers.set('x-csrf-token', csrfToken);
  let res: Response;
  try {
    res = await fetch(path, { ...fetchOpts, headers });
  } catch {
    // Network failure / server restart: collapse to the null path callers already
    // handle for a non-ok response, instead of an unhandled promise rejection.
    return null;
  }
  if (res.status === 401 && !allowAuthError) {
    location.href = '/login.html';
    return null;
  }
  if (res.status === 403) await warnForbidden(res);
  return res;
}

// A 403 body only matters for the tiny license error codes, but this runs for
// every denial the app receives, so never buffer more than that.
const FORBIDDEN_BODY_LIMIT = 2048;

/** Read the `error` code from at most FORBIDDEN_BODY_LIMIT bytes of a denial body. */
async function forbiddenErrorCode(res: Response): Promise<string> {
  const reader = res.clone().body?.getReader();
  if (!reader) return '';
  const decoder = new TextDecoder();
  let text = '';
  try {
    while (text.length <= FORBIDDEN_BODY_LIMIT) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
    }
  } catch {
    return '';
  } finally {
    void reader.cancel().catch(() => {});
  }
  if (text.length > FORBIDDEN_BODY_LIMIT) return '';
  try {
    return String((JSON.parse(text) as { error?: string }).error || '');
  } catch {
    return '';
  }
}

/** Distinguish an expired license (read-only past the grace window) from a role denial. */
async function warnForbidden(res: Response): Promise<void> {
  const code = await forbiddenErrorCode(res);
  if (code === 'license_readonly') {
    toast('License is read-only past the grace window. Install a renewal license to make changes.', 'warn');
    return;
  }
  if (code === 'license_revoked') {
    toast('License revoked by the vendor. AI use is blocked; contact your vendor to restore access.', 'warn');
    return;
  }
  toast('Request not allowed for this session. Refresh or use a Security Admin account.', 'warn');
}

export async function apiJson<T>(path: string, opts: ApiOptions = {}): Promise<T | null> {
  const res = await api(path, opts);
  if (!res || !res.ok) return null;
  try {
    return (await res.json()) as T;
  } catch {
    return null;
  }
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
  try {
    const body = (await response.clone().json()) as { fields?: string[]; error?: string };
    if (Array.isArray(body.fields) && body.fields.length) return `${fallback}: ${body.fields.join(', ')}`;
    if (body.error) return `${fallback}: ${body.error}`;
  } catch {
    // fall through to the generic message
  }
  return fallback;
}
