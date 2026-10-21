/**
 * @fileoverview Bounded catalog acquisition, archive validation, retries and cancellation.
 * @module tests/services/catalog/acquisition.test
 */
import { readFileSync } from 'node:fs';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  acquireCapec,
  acquireCwe,
  acquireCweVersion,
  BYTE_LIMITS,
  defaultHttpRequest,
  extractCweXml,
  readBoundedBody,
  SOURCE_URLS,
} from '@/services/catalog/acquisition.js';
import type { HttpRequest } from '@/services/catalog/types.js';

const cweXml = readFileSync(
  new URL('../../fixtures/catalog/cwe-normalization.xml', import.meta.url),
  'utf8',
);
const capecXml = readFileSync(
  new URL('../../fixtures/catalog/capec-normalization.xml', import.meta.url),
  'utf8',
);
const signal = () => new AbortController().signal;
const context = () => createMockContext();
const archive = (name = 'cwe.xml', xml = cweXml) => zipSync({ [name]: strToU8(xml) });

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('readBoundedBody', () => {
  it.each([undefined, '1', 'not-a-number'])(
    'enforces the running cap despite content-length %s',
    async (length) => {
      const cancel = vi.fn();
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(strToU8('abc'));
          controller.enqueue(strToU8('def'));
        },
        cancel,
      });
      const response = new Response(stream, {
        headers: length ? { 'content-length': length } : {},
      });
      await expect(readBoundedBody(response, 5, signal())).rejects.toMatchObject({
        data: { reason: 'response_too_large', retryable: false },
      });
      expect(cancel).toHaveBeenCalledOnce();
      expect(response.body?.locked).toBe(false);
    },
  );

  it('rejects an oversized declared body before consuming it', async () => {
    const cancel = vi.fn();
    const response = new Response(new ReadableStream({ cancel }), {
      headers: { 'content-length': '6' },
    });
    await expect(readBoundedBody(response, 5, signal())).rejects.toMatchObject({
      data: { reason: 'response_too_large' },
    });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it('accepts the exact cap and an absent body', async () => {
    await expect(readBoundedBody(new Response('abcde'), 5, signal())).resolves.toEqual(
      strToU8('abcde'),
    );
    await expect(readBoundedBody(new Response(null), 0, signal())).resolves.toEqual(
      new Uint8Array(),
    );
  });

  it('cancels a pending read and releases its lock on caller abort', async () => {
    const controller = new AbortController();
    const reason = new DOMException('Caller cancelled', 'AbortError');
    const cancel = vi.fn();
    const response = new Response(new ReadableStream({ cancel }));
    const pending = readBoundedBody(response, 10, controller.signal);
    const assertion = expect(pending).rejects.toBe(reason);
    controller.abort(reason);
    await assertion;
    expect(cancel).toHaveBeenCalledWith(reason);
    expect(response.body?.locked).toBe(false);
  });
});

describe('extractCweXml', () => {
  it.each([0, 6] as const)('extracts one XML member with compression level %s', (level) => {
    const bytes = zipSync({ 'cwe.xml': strToU8(cweXml) }, { level });
    expect(extractCweXml(bytes, signal())).toBe(cweXml);
  });

  it.each(['../cwe.xml', 'nested/cwe.xml', 'cwe.txt', 'cwe..xml'])(
    'rejects unsafe member %s',
    (name) => {
      expect(() => extractCweXml(archive(name), signal())).toThrow(
        expect.objectContaining({
          data: expect.objectContaining({ reason: 'unsafe_archive', retryable: false }),
        }),
      );
    },
  );

  it('rejects empty, malformed, truncated, and multi-member archives', () => {
    for (const bytes of [
      zipSync({}),
      strToU8('not a zip'),
      archive().subarray(0, 40),
      zipSync({ 'one.xml': strToU8('one'), 'two.xml': strToU8('two') }),
    ]) {
      expect(() => extractCweXml(bytes, signal())).toThrow(
        expect.objectContaining({ data: expect.objectContaining({ reason: 'unsafe_archive' }) }),
      );
    }
  });

  it('rejects a declared inflate size over the cap without allocating that output', () => {
    const bytes = archive();
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const directory = view.getUint32(bytes.length - 6, true);
    view.setUint32(directory + 24, BYTE_LIMITS.cweXml + 1, true);
    expect(() => extractCweXml(bytes, signal())).toThrow(
      expect.objectContaining({ data: expect.objectContaining({ reason: 'response_too_large' }) }),
    );
  });

  it('rejects inflation beyond the declared size even when both headers agree', () => {
    const bytes = archive('cwe.xml', 'x'.repeat(4096));
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const directory = view.getUint32(bytes.length - 6, true);
    view.setUint32(22, 1, true);
    view.setUint32(directory + 24, 1, true);
    expect(() => extractCweXml(bytes, signal())).toThrow(
      expect.objectContaining({ data: expect.objectContaining({ reason: 'response_too_large' }) }),
    );
  });

  it('rejects a CRC mismatch and invalid UTF-8', () => {
    const bytes = archive();
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const directory = view.getUint32(bytes.length - 6, true);
    view.setUint32(directory + 16, 0, true);
    expect(() => extractCweXml(bytes, signal())).toThrow(
      expect.objectContaining({ data: expect.objectContaining({ reason: 'unsafe_archive' }) }),
    );
    expect(() => extractCweXml(zipSync({ 'cwe.xml': new Uint8Array([0xff]) }), signal())).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'invalid_catalog', retryable: false }),
      }),
    );
  });

  it('honors an already aborted signal before inspecting the archive', () => {
    const controller = new AbortController();
    const reason = new Error('cancelled');
    controller.abort(reason);
    expect(() => extractCweXml(new Uint8Array(), controller.signal)).toThrow(reason);
  });
});

describe('acquisition pipelines', () => {
  it('downloads, parses and preserves source validators for each catalog', async () => {
    const request = vi
      .fn<HttpRequest>()
      .mockResolvedValueOnce(new Response(archive(), { headers: { etag: 'cwe-tag' } }))
      .mockResolvedValueOnce(
        new Response(capecXml, { headers: { 'last-modified': 'Tue, 24 Jan 2023 00:00:00 GMT' } }),
      );
    const cwe = await acquireCwe(request, context(), signal());
    const capec = await acquireCapec(request, context(), signal());
    expect(cwe).toMatchObject({
      catalog: { version: '4.test', date: '2026-04-30' },
      etag: 'cwe-tag',
    });
    expect(cwe.catalog.weaknesses.has('CWE-79')).toBe(true);
    expect(capec).toMatchObject({
      catalog: { version: '3.test' },
      lastModified: 'Tue, 24 Jan 2023 00:00:00 GMT',
    });
    expect(request.mock.calls.map(([url]) => url)).toEqual([SOURCE_URLS.cwe, SOURCE_URLS.capec]);
  });

  it.each([{ etag: 'tag', lastModified: 'date' }, { lastModified: 'date' }])(
    'accepts conditional 304 with validators %j',
    async (previous) => {
      const request = vi
        .fn<HttpRequest>()
        .mockResolvedValue(new Response(null, { status: 304, headers: { etag: 'new-tag' } }));
      await expect(acquireCapec(request, context(), signal(), previous)).resolves.toEqual({
        unchanged: true,
        etag: 'new-tag',
      });
      expect(request.mock.calls[0]?.[1]).toMatchObject({
        acceptNotModified: true,
        headers: 'etag' in previous ? { 'If-None-Match': 'tag' } : { 'If-Modified-Since': 'date' },
      });
    },
  );

  it('rejects an initial 304 without retrying', async () => {
    const request = vi.fn<HttpRequest>().mockResolvedValue(new Response(null, { status: 304 }));
    await expect(acquireCapec(request, context(), signal())).rejects.toMatchObject({
      data: { reason: 'invalid_catalog', retryable: false },
    });
    expect(request).toHaveBeenCalledOnce();
  });

  it.each([
    [404, JsonRpcErrorCode.NotFound, false],
    [429, JsonRpcErrorCode.RateLimited, true],
    [500, JsonRpcErrorCode.ServiceUnavailable, true],
    [501, JsonRpcErrorCode.ServiceUnavailable, false],
    [503, JsonRpcErrorCode.ServiceUnavailable, true],
    [504, JsonRpcErrorCode.Timeout, true],
  ] as const)(
    'classifies HTTP %s and applies its retry policy',
    async (status, code, retryable) => {
      vi.useFakeTimers();
      const cancels: ReturnType<typeof vi.fn>[] = [];
      const request = vi.fn<HttpRequest>().mockImplementation(async () => {
        const cancel = vi.fn();
        cancels.push(cancel);
        return new Response(new ReadableStream({ cancel }), {
          status,
          headers: { 'retry-after': '1' },
        });
      });
      const assertion = expect(
        acquireCweVersion(request, context(), signal()),
      ).rejects.toMatchObject({
        code,
        data: { reason: 'upstream_http', status, retryable, retryAfter: '1' },
      });
      await vi.runAllTimersAsync();
      await assertion;
      expect(request).toHaveBeenCalledTimes(retryable ? 3 : 1);
      for (const cancel of cancels) expect(cancel).toHaveBeenCalledOnce();
    },
  );

  it.each(['<broken>', '<WrongRoot/>', String.fromCharCode(0xff)])(
    'does not retry deterministic invalid CAPEC input %j',
    async (body) => {
      const request = vi.fn<HttpRequest>().mockResolvedValue(new Response(body));
      await expect(acquireCapec(request, context(), signal())).rejects.toMatchObject({
        data: { reason: 'invalid_catalog', retryable: false },
      });
      expect(request).toHaveBeenCalledOnce();
    },
  );

  it('does not retry unsafe archives or an oversized version response', async () => {
    const request = vi
      .fn<HttpRequest>()
      .mockResolvedValueOnce(new Response(strToU8('not zip')))
      .mockResolvedValueOnce(
        new Response('{}', { headers: { 'content-length': String(BYTE_LIMITS.version + 1) } }),
      );
    await expect(acquireCwe(request, context(), signal())).rejects.toMatchObject({
      data: { reason: 'unsafe_archive', retryable: false },
    });
    await expect(acquireCweVersion(request, context(), signal())).rejects.toMatchObject({
      data: { reason: 'response_too_large', retryable: false },
    });
    expect(request).toHaveBeenCalledTimes(2);
  });

  it('stores version metadata and validators without edge whitespace or line breaks', async () => {
    const version = vi
      .fn<HttpRequest>()
      .mockResolvedValue(
        Response.json({ ContentVersion: ' 4.20\r\n', ContentDate: ' April\r\n 30, 2026　' }),
      );
    await expect(acquireCweVersion(version, context(), signal())).resolves.toEqual({
      version: '4.20',
      date: 'April 30, 2026',
    });
    // Header values arrive without HTTP whitespace at their edges, but may keep a no-break space.
    const download = vi.fn<HttpRequest>().mockResolvedValueOnce(
      new Response(capecXml, {
        headers: { etag: ' "capec-tag" ', 'last-modified': ' Tue, 24 Jan 2023' },
      }),
    );
    await expect(acquireCapec(download, context(), signal())).resolves.toMatchObject({
      etag: '"capec-tag"',
      lastModified: 'Tue, 24 Jan 2023',
    });
  });

  it.each([
    'not-json',
    '{}',
    '{"ContentVersion":4,"ContentDate":"date"}',
    '{"ContentVersion":" \\r\\n ","ContentDate":"date"}',
  ])('rejects invalid version metadata %s without retries', async (body) => {
    const request = vi.fn<HttpRequest>().mockResolvedValue(new Response(body));
    await expect(acquireCweVersion(request, context(), signal())).rejects.toMatchObject({
      data: { reason: 'invalid_version', retryable: false },
    });
    expect(request).toHaveBeenCalledOnce();
  });

  it('retries network and HTML failures through a complete successful version parse', async () => {
    vi.useFakeTimers();
    const request = vi
      .fn<HttpRequest>()
      .mockRejectedValueOnce(new TypeError('connection reset'))
      .mockResolvedValueOnce(new Response('<html>temporary outage</html>'))
      .mockResolvedValueOnce(Response.json({ ContentVersion: '4.20', ContentDate: '2026-04-30' }));
    const assertion = expect(acquireCweVersion(request, context(), signal())).resolves.toEqual({
      version: '4.20',
      date: '2026-04-30',
    });
    await vi.runAllTimersAsync();
    await assertion;
    expect(request).toHaveBeenCalledTimes(3);
  });

  it('stops the acquisition stream and suppresses retries on cancellation', async () => {
    const controller = new AbortController();
    const cancel = vi.fn();
    const response = new Response(new ReadableStream({ cancel }));
    const request = vi.fn<HttpRequest>().mockResolvedValue(response);
    const pending = acquireCapec(request, context(), controller.signal);
    const assertion = expect(pending).rejects.toThrow();
    await vi.waitFor(() => expect(response.body?.locked).toBe(true));
    controller.abort(new DOMException('cancelled', 'AbortError'));
    await assertion;
    expect(request.mock.calls[0]?.[1].signal.aborted).toBe(true);
    expect(cancel).toHaveBeenCalledOnce();
    expect(request).toHaveBeenCalledOnce();
  });
});

describe('acquisition through the production HTTP adapter', () => {
  /** The default adapter (fetchWithTimeout) throws for every non-2xx status itself. */
  const stubFetch = (respond: () => Response) => {
    const fetch = vi.fn(async () => respond());
    vi.stubGlobal('fetch', fetch);
    return fetch;
  };
  const settle = async <T>(pending: Promise<T>) => {
    const outcome = pending.catch((error: unknown) => error);
    await vi.runAllTimersAsync();
    return outcome;
  };

  it.each([
    [401, JsonRpcErrorCode.Unauthorized, false],
    [404, JsonRpcErrorCode.NotFound, false],
    [429, JsonRpcErrorCode.RateLimited, true],
    [500, JsonRpcErrorCode.ServiceUnavailable, true],
    [501, JsonRpcErrorCode.ServiceUnavailable, false],
  ] as const)(
    'classifies HTTP %s and applies its retry policy',
    async (status, code, retryable) => {
      vi.useFakeTimers();
      const fetch = stubFetch(() => new Response(null, { status }));
      expect(
        await settle(acquireCweVersion(defaultHttpRequest, context(), signal())),
      ).toMatchObject({ code, data: { reason: 'upstream_http', status, retryable } });
      expect(fetch).toHaveBeenCalledTimes(retryable ? 3 : 1);
    },
  );

  it.each<[string, () => Promise<unknown>]>([
    ['version check', () => acquireCweVersion(defaultHttpRequest, context(), signal())],
    ['CWE download', () => acquireCwe(defaultHttpRequest, context(), signal())],
    ['CAPEC download', () => acquireCapec(defaultHttpRequest, context(), signal())],
  ])(
    'reports an edge 403 on the %s as a temporary refusal after one request',
    async (_source, acquire) => {
      vi.useFakeTimers();
      const fetch = stubFetch(
        () => new Response('{"supportID": "8278137309397805653"}', { status: 403 }),
      );
      const error = (await settle(acquire())) as { message: string; data: unknown };
      expect(error).toMatchObject({
        code: JsonRpcErrorCode.ServiceUnavailable,
        message: expect.stringMatching(/MITRE temporarily refused .*wait a few minutes/i),
        data: { status: 403, retryable: true },
      });
      expect(JSON.stringify([error.message, error.data])).not.toContain('8278137309397805653');
      expect(fetch).toHaveBeenCalledTimes(1);
    },
  );

  it('maps a 403 Response from an injected adapter the same way', async () => {
    vi.useFakeTimers();
    const request = vi.fn<HttpRequest>(async () => new Response(null, { status: 403 }));
    expect(await settle(acquireCweVersion(request, context(), signal()))).toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
      data: { status: 403, retryable: true },
    });
    expect(request).toHaveBeenCalledOnce();
  });
});

describe('defaultHttpRequest', () => {
  it('accepts an explicitly conditional 304 and forbids redirects', async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValue(new Response(null, { status: 304 }));
    vi.stubGlobal('fetch', fetch);
    await expect(
      defaultHttpRequest(
        SOURCE_URLS.capec,
        { signal: signal(), acceptNotModified: true },
        1000,
        context(),
      ),
    ).resolves.toMatchObject({ status: 304 });
    expect(fetch).toHaveBeenCalledWith(
      SOURCE_URLS.capec,
      expect.objectContaining({ redirect: 'error' }),
    );
  });

  it('classifies a rejected fetch without exposing its message', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('private upstream detail')));
    await expect(
      defaultHttpRequest(
        SOURCE_URLS.capec,
        { signal: signal(), acceptNotModified: true },
        1000,
        context(),
      ),
    ).rejects.toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
      message: expect.not.stringContaining('private upstream detail'),
      data: { reason: 'upstream_network', retryable: true },
    });
  });

  it('preserves caller cancellation instead of mapping it to a retryable network failure', async () => {
    const controller = new AbortController();
    const reason = new DOMException('cancelled', 'AbortError');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async () => {
        controller.abort(reason);
        throw reason;
      }),
    );
    await expect(
      defaultHttpRequest(
        SOURCE_URLS.capec,
        { signal: controller.signal, acceptNotModified: true },
        1000,
        context(),
      ),
    ).rejects.toBe(reason);
  });
});
