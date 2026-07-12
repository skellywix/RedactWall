import { api } from '../lib/api';

interface ReceiptVerificationPayload {
  ok?: unknown;
  reason?: unknown;
}

export type ReceiptVerificationResult =
  | { kind: 'valid' }
  | { kind: 'invalid'; reason?: string }
  | { kind: 'unavailable' }
  | { kind: 'forbidden' }
  | { kind: 'session' };

export interface TicketSyncResult {
  status: 'complete' | 'partial' | 'skipped';
  checked: number;
  matched: number;
  checksAttempted: number;
  updated: number;
  succeeded: number;
  failed: number;
  generatedAt: string;
  reason?: 'no_ticket_channels' | 'database_unavailable' | 'provider_failures' | 'deadline_exceeded' | 'check_limit_reached';
}

export interface TicketSyncBusy {
  status: 'busy';
  reason: 'ticket_sync_in_progress';
}

export type TrustPackageFormat = 'json' | 'zip';

export type TrustPackageDownloadResult =
  | { kind: 'downloaded' }
  | { kind: 'unavailable' }
  | { kind: 'forbidden' }
  | { kind: 'session' }
  | { kind: 'malformed' }
  | { kind: 'oversize' };

type BoundedBytesResult =
  | { kind: 'ok'; bytes: Uint8Array<ArrayBuffer> }
  | { kind: 'unavailable' }
  | { kind: 'malformed' }
  | { kind: 'oversize' };

type BoundedJsonResult =
  | { kind: 'ok'; bytes: Uint8Array<ArrayBuffer>; value: unknown }
  | Exclude<BoundedBytesResult, { kind: 'ok' }>;

const API_RESPONSE_TIMEOUT_MS = 30_000;
const RECEIPT_RESPONSE_MAX_BYTES = 8 * 1024;
const TICKET_SYNC_RESPONSE_MAX_BYTES = 8 * 1024;
const TRUST_PACKAGE_MAX_BYTES = 8 * 1024 * 1024;
const TICKET_SYNC_MAX_QUERIES = 500;
const TICKET_SYNC_MAX_STATUS_CHECKS = 64;

const TRUST_PACKAGE_DOWNLOADS: Record<TrustPackageFormat, {
  mediaType: string;
  filename: string;
}> = {
  json: {
    mediaType: 'application/json',
    filename: 'redactwall-security-trust-package.json',
  },
  zip: {
    mediaType: 'application/zip',
    filename: 'redactwall-security-trust-package.zip',
  },
};

export function canReadAuditExports(role?: string | null): boolean {
  return role === 'security_admin' || role === 'auditor';
}

function mediaType(response: Response): string {
  return String(response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
}

async function discardResponse(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // Cancellation is best effort after the response has already been rejected.
  }
}

function declaredLength(response: Response): number | null | 'invalid' {
  const header = response.headers.get('content-length');
  if (header === null) return null;
  if (!/^\d+$/.test(header)) return 'invalid';
  const length = Number(header);
  return Number.isSafeInteger(length) ? length : 'invalid';
}

function mergeChunks(chunks: Uint8Array[], total: number): Uint8Array<ArrayBuffer> {
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

async function readBoundedBytes(response: Response, maxBytes: number): Promise<BoundedBytesResult> {
  const length = declaredLength(response);
  if (length === 'invalid') {
    await discardResponse(response);
    return { kind: 'malformed' };
  }
  if (length !== null && length > maxBytes) {
    await discardResponse(response);
    return { kind: 'oversize' };
  }
  const reader = response.body?.getReader();
  if (!reader) return { kind: 'malformed' };
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return { kind: 'oversize' };
      }
      chunks.push(value);
    }
  } catch {
    try {
      await reader.cancel();
    } catch {
      // The aborted stream is already unusable.
    }
    return { kind: 'unavailable' };
  }
  if (!total) return { kind: 'malformed' };
  return { kind: 'ok', bytes: mergeChunks(chunks, total) };
}

async function readBoundedJson(response: Response, maxBytes: number): Promise<BoundedJsonResult> {
  if (mediaType(response) !== 'application/json') {
    await discardResponse(response);
    return { kind: 'malformed' };
  }
  const result = await readBoundedBytes(response, maxBytes);
  if (result.kind !== 'ok') return result;
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(result.bytes);
    return { ...result, value: JSON.parse(text) as unknown };
  } catch {
    return { kind: 'malformed' };
  }
}

function responseDeadline(): { signal: AbortSignal; clear: () => void } {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), API_RESPONSE_TIMEOUT_MS);
  return { signal: controller.signal, clear: () => window.clearTimeout(timeout) };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function decodeTicketSyncResult(value: unknown): TicketSyncResult | null {
  if (!isObject(value)) return null;
  const { status, checked, matched, checksAttempted, updated, succeeded, failed, generatedAt, reason } = value;
  if (!['complete', 'partial', 'skipped'].includes(String(status))) return null;
  if (!Number.isSafeInteger(checked) || Number(checked) < 0 || Number(checked) > TICKET_SYNC_MAX_QUERIES) return null;
  if (!Number.isSafeInteger(matched) || Number(matched) < Number(checked) || Number(matched) > TICKET_SYNC_MAX_QUERIES) return null;
  if (!Number.isSafeInteger(checksAttempted) || Number(checksAttempted) < 0 || Number(checksAttempted) > TICKET_SYNC_MAX_STATUS_CHECKS) return null;
  if (!Number.isSafeInteger(updated) || Number(updated) < 0 || Number(updated) > Number(checked)) return null;
  if (!Number.isSafeInteger(succeeded) || Number(succeeded) < 0 || Number(succeeded) > TICKET_SYNC_MAX_STATUS_CHECKS) return null;
  if (!Number.isSafeInteger(failed) || Number(failed) < 0 || Number(failed) > TICKET_SYNC_MAX_STATUS_CHECKS) return null;
  if (Number(succeeded) + Number(failed) > Number(checksAttempted) || Number(updated) > Number(succeeded)) return null;
  if (typeof generatedAt !== 'string' || generatedAt.length > 40 || !Number.isFinite(Date.parse(generatedAt))) return null;
  const partialReasons = ['provider_failures', 'deadline_exceeded', 'check_limit_reached'];
  const skippedReasons = ['no_ticket_channels', 'database_unavailable'];
  if (status === 'complete' && (reason !== undefined || checked !== matched || failed !== 0 || checksAttempted !== succeeded)) return null;
  if (status === 'partial' && !partialReasons.includes(String(reason))) return null;
  if (status === 'skipped' && (!skippedReasons.includes(String(reason))
    || checked !== 0 || matched !== 0 || checksAttempted !== 0 || updated !== 0 || succeeded !== 0 || failed !== 0)) return null;
  return {
    status: status as TicketSyncResult['status'],
    checked: Number(checked),
    matched: Number(matched),
    checksAttempted: Number(checksAttempted),
    updated: Number(updated),
    succeeded: Number(succeeded),
    failed: Number(failed),
    generatedAt,
    ...(typeof reason === 'string' ? { reason: reason as TicketSyncResult['reason'] } : {}),
  };
}

function decodeTicketSyncBusy(value: unknown): TicketSyncBusy | null {
  return isObject(value) && value.status === 'busy' && value.reason === 'ticket_sync_in_progress'
    ? { status: 'busy', reason: 'ticket_sync_in_progress' }
    : null;
}

function validTrustPackageJson(value: unknown): boolean {
  return isObject(value)
    && value.schemaVersion === 'redactwall.security-trust-package.v1'
    && typeof value.generatedAt === 'string'
    && isObject(value.product)
    && isObject(value.summary)
    && isObject(value.privacyContract)
    && Array.isArray(value.controls)
    && isObject(value.sbom)
    && Array.isArray(value.documents);
}

export function validZipArchive(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 22 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) return false;
  const signature = `${bytes[2]}:${bytes[3]}`;
  if (signature !== '3:4' && signature !== '5:6' && signature !== '7:8') return false;
  const searchStart = Math.max(0, bytes.byteLength - 65_557);
  for (let index = bytes.byteLength - 22; index >= searchStart; index -= 1) {
    if (bytes[index] !== 0x50 || bytes[index + 1] !== 0x4b || bytes[index + 2] !== 0x05 || bytes[index + 3] !== 0x06) continue;
    const commentLength = bytes[index + 20] | (bytes[index + 21] << 8);
    return index + 22 + commentLength === bytes.byteLength;
  }
  return false;
}

function saveDownload(bytes: Uint8Array<ArrayBuffer>, media: string, filename: string): void {
  const url = URL.createObjectURL(new Blob([bytes], { type: media }));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export async function verifyReceipt(receipt: unknown): Promise<ReceiptVerificationResult> {
  const deadline = responseDeadline();
  try {
    const res = await api('/api/receipts/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(receipt),
      allowAuthError: true,
      signal: deadline.signal,
    });
    if (!res) return { kind: 'unavailable' };
    if (res.status === 401) {
      await discardResponse(res);
      location.href = '/login.html';
      return { kind: 'session' };
    }
    if (res.status === 403) {
      await discardResponse(res);
      return { kind: 'forbidden' };
    }
    if (res.status === 400) {
      await discardResponse(res);
      return { kind: 'invalid' };
    }
    if (!res.ok) {
      await discardResponse(res);
      return { kind: 'unavailable' };
    }
    const result = await readBoundedJson(res, RECEIPT_RESPONSE_MAX_BYTES);
    if (result.kind !== 'ok' || !isObject(result.value)) return { kind: 'unavailable' };
    const body = result.value as ReceiptVerificationPayload;
    if (body.ok === true) return { kind: 'valid' };
    if (body.ok === false) {
      return {
        kind: 'invalid',
        ...(typeof body.reason === 'string' && body.reason.length <= 128 ? { reason: body.reason } : {}),
      };
    }
    return { kind: 'unavailable' };
  } finally {
    deadline.clear();
  }
}

export async function syncTicketStatuses(): Promise<TicketSyncResult | TicketSyncBusy | null> {
  const deadline = responseDeadline();
  try {
    const res = await api('/api/tickets/sync', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
      signal: deadline.signal,
    });
    if (!res) return null;
    if (res.status === 409) {
      const busy = await readBoundedJson(res, TICKET_SYNC_RESPONSE_MAX_BYTES);
      return busy.kind === 'ok' ? decodeTicketSyncBusy(busy.value) : null;
    }
    if (!res.ok) {
      await discardResponse(res);
      return null;
    }
    const result = await readBoundedJson(res, TICKET_SYNC_RESPONSE_MAX_BYTES);
    return result.kind === 'ok' ? decodeTicketSyncResult(result.value) : null;
  } finally {
    deadline.clear();
  }
}

export async function downloadTrustPackage(format: TrustPackageFormat): Promise<TrustPackageDownloadResult> {
  const config = TRUST_PACKAGE_DOWNLOADS[format];
  const deadline = responseDeadline();
  try {
    const res = await api(`/api/security/package?format=${format}`, {
      allowAuthError: true,
      signal: deadline.signal,
    });
    if (!res) return { kind: 'unavailable' };
    if (res.status === 401) {
      await discardResponse(res);
      location.href = '/login.html';
      return { kind: 'session' };
    }
    if (res.status === 403) {
      await discardResponse(res);
      return { kind: 'forbidden' };
    }
    if (!res.ok) {
      await discardResponse(res);
      return { kind: 'unavailable' };
    }
    if (mediaType(res) !== config.mediaType) {
      await discardResponse(res);
      return { kind: 'malformed' };
    }
    if (format === 'json') {
      const result = await readBoundedJson(res, TRUST_PACKAGE_MAX_BYTES);
      if (result.kind !== 'ok') return result;
      if (!validTrustPackageJson(result.value)) return { kind: 'malformed' };
      saveDownload(result.bytes, config.mediaType, config.filename);
      return { kind: 'downloaded' };
    }
    const result = await readBoundedBytes(res, TRUST_PACKAGE_MAX_BYTES);
    if (result.kind !== 'ok') return result;
    if (!validZipArchive(result.bytes)) return { kind: 'malformed' };
    saveDownload(result.bytes, config.mediaType, config.filename);
    return { kind: 'downloaded' };
  } catch {
    return { kind: 'unavailable' };
  } finally {
    deadline.clear();
  }
}
