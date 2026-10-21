/**
 * @fileoverview Fixed-origin, bounded and cancellable MITRE catalog acquisition.
 * @module services/catalog/acquisition
 */
import { McpError, serializationError, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import {
  defaultIsTransient,
  fetchWithTimeout,
  httpErrorFromResponse,
  type RequestContext,
  withRetry,
} from '@cyanheads/mcp-ts-core/utils';
import { Unzip, UnzipInflate } from 'fflate';
import type { CapecCatalog, CatalogMetadata, CweCatalog, HttpRequest } from './types.js';
import { parseCapecCatalog, parseCweCatalog } from './xml-normalization.js';

/** Fixed upstream locations; callers cannot supply destinations. */
export const SOURCE_URLS = Object.freeze({
  cwe: 'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
  capec: 'https://capec.mitre.org/data/xml/capec_latest.xml',
  cweVersion: 'https://cwe-api.mitre.org/api/v1/cwe/version',
  hierarchy: 'https://cwe-api.mitre.org/api/v1/cwe',
});
/** Limits are enforced while consuming streams and inflating ZIP chunks. */
export const BYTE_LIMITS = Object.freeze({
  cweDownload: 10 * 1024 * 1024,
  cweXml: 50 * 1024 * 1024,
  capecXml: 20 * 1024 * 1024,
  hierarchy: 10 * 1024 * 1024,
  version: 64 * 1024,
});

function invalidArchive(): never {
  throw serializationError('The CWE archive is invalid or contains unexpected members.', {
    reason: 'unsafe_archive',
    retryable: false,
  });
}
function tooLarge(): never {
  throw serializationError('The MITRE response exceeds its supported byte limit.', {
    reason: 'response_too_large',
    retryable: false,
  });
}

async function ensureStatus(response: Response, acceptNotModified = false): Promise<Response> {
  if (response.ok || (acceptNotModified && response.status === 304)) return response;
  const error = await httpErrorFromResponse(response, { service: 'MITRE', captureBody: false });
  // Keep framework status mapping and Retry-After, without echoing remote bodies or paths.
  await response.body?.cancel();
  throw new McpError(
    error.code,
    `MITRE returned HTTP ${response.status}.`,
    { ...error.data, reason: 'upstream_http', retryable: defaultIsTransient(error) },
    { cause: error },
  );
}

/** Default adapter explicitly accepts conditional 304 before the non-2xx mapper. */
export const defaultHttpRequest: HttpRequest = async (url, options, timeoutMs, context) => {
  const { acceptNotModified, ...requestOptions } = options;
  try {
    if (acceptNotModified) {
      // The retry attempt owns the timeout signal through body consumption, not just headers.
      return await ensureStatus(await fetch(url, { ...requestOptions, redirect: 'error' }), true);
    }
    return await fetchWithTimeout(url, timeoutMs, context, {
      ...requestOptions,
      redirect: 'error',
      errorBodyLimit: 0,
    });
  } catch (cause) {
    options.signal.throwIfAborted();
    if (cause instanceof McpError) {
      const data = Object.fromEntries(
        Object.entries(cause.data ?? {}).filter(([key]) =>
          ['status', 'statusCode', 'retryAfter', 'errorSource'].includes(key),
        ),
      );
      throw new McpError(
        cause.code,
        'The MITRE request failed.',
        { ...data, reason: 'upstream_http', retryable: defaultIsTransient(cause) },
        { cause },
      );
    }
    throw serviceUnavailable(
      'MITRE could not be reached.',
      { reason: 'upstream_network', retryable: true },
      { cause },
    );
  }
};

/** Consume a response with a running byte cap and caller/deadline cancellation. */
export async function readBoundedBody(
  response: Response,
  limit: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  signal.throwIfAborted();
  const declared = response.headers.get('content-length');
  if (declared && /^\d+$/.test(declared) && Number(declared) > limit) {
    await response.body?.cancel();
    tooLarge();
  }
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array();
  const abort = () => {
    void reader.cancel(signal.reason).catch(() => {});
  };
  signal.addEventListener('abort', abort, { once: true });
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      signal.throwIfAborted();
      const { done, value } = await reader.read();
      signal.throwIfAborted();
      if (done) break;
      size += value.byteLength;
      if (size > limit) tooLarge();
      chunks.push(value);
    }
    const result = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return result;
  } finally {
    signal.removeEventListener('abort', abort);
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function decodeXml(bytes: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (cause) {
    throw serializationError(
      'The MITRE catalog is not valid UTF-8.',
      { reason: 'invalid_catalog', retryable: false },
      { cause },
    );
  }
}

function zipDirectory(bytes: Uint8Array): { name: string; size: number; crc: number } {
  if (bytes.byteLength < 22) invalidArchive();
  const data = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let end = bytes.length - 22;
  const earliest = Math.max(0, end - 65535);
  while (end >= earliest && data.getUint32(end, true) !== 0x06054b50) end--;
  if (end < earliest || end + 22 + data.getUint16(end + 20, true) !== bytes.length)
    invalidArchive();
  if (
    data.getUint16(end + 4, true) !== 0 ||
    data.getUint16(end + 6, true) !== 0 ||
    data.getUint16(end + 8, true) !== 1 ||
    data.getUint16(end + 10, true) !== 1
  )
    invalidArchive();
  const start = data.getUint32(end + 16, true);
  const directorySize = data.getUint32(end + 12, true);
  if (
    start + directorySize !== end ||
    directorySize < 46 ||
    start + 46 > end ||
    data.getUint32(start, true) !== 0x02014b50
  )
    invalidArchive();
  const nameLength = data.getUint16(start + 28, true);
  const extraLength = data.getUint16(start + 30, true);
  const commentLength = data.getUint16(start + 32, true);
  if (
    46 + nameLength + extraLength + commentLength !== directorySize ||
    data.getUint32(start + 42, true) !== 0 ||
    data.getUint16(start + 34, true) !== 0
  )
    invalidArchive();
  const flags = data.getUint16(start + 8, true);
  const compression = data.getUint16(start + 10, true);
  if ((flags & 1) !== 0 || (compression !== 0 && compression !== 8)) invalidArchive();
  const name = new TextDecoder().decode(bytes.subarray(start + 46, start + 46 + nameLength));
  if (
    !/^[^/\\]+\.xml$/i.test(name) ||
    name.includes('..') ||
    Array.from(name).some((character) => character.charCodeAt(0) < 32)
  )
    invalidArchive();
  const size = data.getUint32(start + 24, true);
  if (size > BYTE_LIMITS.cweXml) tooLarge();
  return { name, size, crc: data.getUint32(start + 16, true) };
}

/** Inflate exactly one safe XML member in bounded increments, without filesystem extraction. */
export function extractCweXml(bytes: Uint8Array, signal: AbortSignal): string {
  signal.throwIfAborted();
  if (bytes.length > BYTE_LIMITS.cweDownload) tooLarge();
  const expected = zipDirectory(bytes);
  const chunks: Uint8Array[] = [];
  let size = 0;
  let members = 0;
  let complete = false;
  let crc = 0xffffffff;
  const crcTable = Uint32Array.from({ length: 256 }, (_, initial) => {
    let value = initial;
    for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ (value & 1 ? 0xedb88320 : 0);
    return value >>> 0;
  });
  const unzip = new Unzip((file) => {
    members++;
    if (
      members !== 1 ||
      file.name !== expected.name ||
      (file.originalSize !== undefined && file.originalSize !== expected.size)
    )
      invalidArchive();
    file.ondata = (error, chunk, final) => {
      if (error instanceof McpError) throw error;
      if (error) invalidArchive();
      signal.throwIfAborted();
      size += chunk.byteLength;
      if (size > BYTE_LIMITS.cweXml || size > expected.size) tooLarge();
      for (const byte of chunk) crc = (crc >>> 8) ^ (crcTable[(crc ^ byte) & 0xff] as number);
      chunks.push(chunk);
      complete = final;
    };
    file.start();
  });
  unzip.register(UnzipInflate);
  try {
    // Feeding the whole compressed file at once would allow a zip bomb's allocation
    // before ondata can enforce the output limit. Small inputs bound each inflate.
    for (let offset = 0; offset < bytes.length; offset += 1024) {
      signal.throwIfAborted();
      unzip.push(
        bytes.subarray(offset, Math.min(offset + 1024, bytes.length)),
        offset + 1024 >= bytes.length,
      );
    }
  } catch (cause) {
    signal.throwIfAborted();
    if (cause instanceof McpError) throw cause;
    throw serializationError(
      'The CWE archive could not be decompressed.',
      { reason: 'unsafe_archive', retryable: false },
      { cause },
    );
  }
  if (
    members !== 1 ||
    !complete ||
    size !== expected.size ||
    (crc ^ 0xffffffff) >>> 0 !== expected.crc
  )
    invalidArchive();
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return decodeXml(output);
}

/** Conditional response metadata belongs to the exact downloaded source. */
export interface AcquiredCatalog<T> {
  catalog: T;
  etag?: string;
  lastModified?: string;
}

function validators(response: Response): { etag?: string; lastModified?: string } {
  const etag = response.headers.get('etag');
  const lastModified = response.headers.get('last-modified');
  return { ...(etag !== null ? { etag } : {}), ...(lastModified !== null ? { lastModified } : {}) };
}

/** One source pipeline owns retries, including its stream and deterministic parser. */
export function acquireCwe(
  request: HttpRequest,
  context: RequestContext,
  signal: AbortSignal,
): Promise<AcquiredCatalog<CweCatalog>> {
  return withRetry(
    async (attempt) => {
      const response = await ensureStatus(
        await request(SOURCE_URLS.cwe, { signal: attempt.signal }, attempt.remainingMs, context),
      );
      const body = await readBoundedBody(response, BYTE_LIMITS.cweDownload, attempt.signal);
      if (
        /^\s*<(?:!doctype\s+html|html[\s>])/i.test(new TextDecoder().decode(body.subarray(0, 256)))
      ) {
        throw serviceUnavailable('MITRE returned HTML instead of a CWE archive.', {
          reason: 'upstream_html',
          retryable: true,
        });
      }
      const catalog = parseCweCatalog(extractCweXml(body, attempt.signal));
      attempt.signal.throwIfAborted();
      return { catalog, ...validators(response) };
    },
    {
      maxRetries: 2,
      baseDelayMs: 1000,
      deadlineMs: 45000,
      operation: 'acquireCwe',
      context,
      signal,
    },
  );
}

/** A 304 is a successful unchanged result, never an exception-shaped fallback. */
export function acquireCapec(
  request: HttpRequest,
  context: RequestContext,
  signal: AbortSignal,
  previous?: { etag?: string; lastModified?: string },
): Promise<
  AcquiredCatalog<CapecCatalog> | { unchanged: true; etag?: string; lastModified?: string }
> {
  return withRetry(
    async (attempt) => {
      const headers: Record<string, string> = previous?.etag
        ? { 'If-None-Match': previous.etag }
        : previous?.lastModified
          ? { 'If-Modified-Since': previous.lastModified }
          : {};
      const response = await ensureStatus(
        await request(
          SOURCE_URLS.capec,
          { signal: attempt.signal, headers, acceptNotModified: true },
          attempt.remainingMs,
          context,
        ),
        true,
      );
      if (response.status === 304) {
        await response.body?.cancel();
        if (!previous)
          throw serializationError('MITRE returned 304 before a CAPEC catalog was loaded.', {
            reason: 'invalid_catalog',
            retryable: false,
          });
        return { unchanged: true, ...validators(response) };
      }
      const body = await readBoundedBody(response, BYTE_LIMITS.capecXml, attempt.signal);
      const catalog = parseCapecCatalog(decodeXml(body));
      attempt.signal.throwIfAborted();
      return { catalog, ...validators(response) };
    },
    {
      maxRetries: 2,
      baseDelayMs: 1000,
      deadlineMs: 45000,
      operation: 'acquireCapec',
      context,
      signal,
    },
  );
}

/** Read the REST version, keeping XML root metadata authoritative for serving. */
export function acquireCweVersion(
  request: HttpRequest,
  context: RequestContext,
  signal: AbortSignal,
): Promise<CatalogMetadata> {
  return withRetry(
    async (attempt) => {
      const response = await ensureStatus(
        await request(
          SOURCE_URLS.cweVersion,
          { signal: attempt.signal },
          attempt.remainingMs,
          context,
        ),
      );
      const body = decodeXml(await readBoundedBody(response, BYTE_LIMITS.version, attempt.signal));
      if (/^\s*</.test(body))
        throw serviceUnavailable('MITRE returned HTML instead of version metadata.', {
          reason: 'upstream_html',
          retryable: true,
        });
      let parsed: unknown;
      try {
        parsed = JSON.parse(body);
      } catch (cause) {
        throw serializationError(
          'MITRE returned invalid version JSON.',
          { reason: 'invalid_version', retryable: false },
          { cause },
        );
      }
      if (
        typeof parsed !== 'object' ||
        parsed === null ||
        !('ContentVersion' in parsed) ||
        typeof parsed.ContentVersion !== 'string' ||
        !parsed.ContentVersion ||
        !('ContentDate' in parsed) ||
        typeof parsed.ContentDate !== 'string' ||
        !parsed.ContentDate
      ) {
        throw serializationError('MITRE returned unsupported version metadata.', {
          reason: 'invalid_version',
          retryable: false,
        });
      }
      return { version: parsed.ContentVersion, date: parsed.ContentDate };
    },
    {
      maxRetries: 2,
      baseDelayMs: 1000,
      deadlineMs: 45000,
      operation: 'acquireCweVersion',
      context,
      signal,
    },
  );
}
