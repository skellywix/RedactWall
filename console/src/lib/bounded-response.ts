function cancelReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  void reader.cancel().catch(() => undefined);
}

export function cancelResponseBody(response: Response): void {
  try {
    void response.body?.cancel().catch(() => undefined);
  } catch {
    // A locked or already-consumed body is already unusable.
  }
}

function declaredLength(response: Response): number | null | 'invalid' {
  const raw = response.headers.get('content-length');
  if (raw === null) return null;
  if (!/^\d+$/.test(raw)) return 'invalid';
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : 'invalid';
}

function mergeChunks(chunks: Uint8Array[], total: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

async function readChunksUntilDone(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  maxBytes: number,
  timeout: Promise<null>,
): Promise<Uint8Array<ArrayBuffer> | null> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const part = await Promise.race([reader.read(), timeout]);
    if (part === null) {
      cancelReader(reader);
      return null;
    }
    if (part.done) return total ? mergeChunks(chunks, total) : new Uint8Array();
    if (!part.value) continue;
    total += part.value.byteLength;
    if (total > maxBytes) {
      cancelReader(reader);
      return null;
    }
    chunks.push(part.value);
  }
}

async function collectBoundedBytes(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  maxBytes: number,
  timeoutMs: number,
): Promise<Uint8Array<ArrayBuffer> | null> {
  let timeoutId: ReturnType<typeof globalThis.setTimeout> | undefined;
  const timeout = new Promise<null>((resolve) => {
    timeoutId = globalThis.setTimeout(() => resolve(null), timeoutMs);
  });
  try {
    return await readChunksUntilDone(reader, maxBytes, timeout);
  } catch {
    cancelReader(reader);
    return null;
  } finally {
    if (timeoutId !== undefined) globalThis.clearTimeout(timeoutId);
    try {
      reader.releaseLock();
    } catch {
      // Pending reads retain the lock until cancellation settles.
    }
  }
}

export async function readBoundedBytesBody(
  response: Response,
  maxBytes: number,
  timeoutMs: number,
): Promise<Uint8Array<ArrayBuffer> | null> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) return null;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) return null;
  if (response.bodyUsed) return null;
  const length = declaredLength(response);
  if (length === 'invalid' || (length !== null && length > maxBytes)) {
    cancelResponseBody(response);
    return null;
  }
  const reader = response.body?.getReader();
  if (!reader) return null;
  return collectBoundedBytes(reader, maxBytes, timeoutMs);
}

export async function readBoundedJsonBody(
  response: Response,
  maxBytes: number,
  timeoutMs: number,
): Promise<unknown | null> {
  if (response.bodyUsed) return null;
  const contentType = String(response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json' && !contentType.endsWith('+json')) {
    cancelResponseBody(response);
    return null;
  }
  const bytes = await readBoundedBytesBody(response, maxBytes, timeoutMs);
  if (!bytes?.byteLength) return null;
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    return null;
  }
}
