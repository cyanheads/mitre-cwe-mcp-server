/**
 * @fileoverview Catalog publication, refresh health, scheduling and owned cancellation.
 * @module tests/services/catalog/catalog-service.test
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants, readFileSync } from 'node:fs';
import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readdir,
  readFile,
  rm,
  utimes,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { logger } from '@cyanheads/mcp-ts-core/utils';
import { strToU8, zipSync } from 'fflate';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BYTE_LIMITS, SOURCE_URLS } from '@/services/catalog/acquisition.js';
import { CatalogCache } from '@/services/catalog/catalog-cache.js';
import {
  CatalogService,
  disposeCatalogService,
  getCatalogService,
  initCatalogService,
  REFRESH_INTERVALS,
} from '@/services/catalog/catalog-service.js';
import type { CatalogClock, HttpRequest } from '@/services/catalog/types.js';

const cweXml = readFileSync(
  new URL('../../fixtures/catalog/cwe-normalization.xml', import.meta.url),
  'utf8',
);
const capecXml = readFileSync(
  new URL('../../fixtures/catalog/capec-normalization.xml', import.meta.url),
  'utf8',
);
const initialTime = Date.parse('2026-10-20T00:00:00Z');
const iso = (time: number) => new Date(time).toISOString();

class Clock implements CatalogClock {
  time = initialTime;
  jobs: { callback: () => void; at: number; cancelled: boolean }[] = [];
  now() {
    return this.time;
  }
  schedule(callback: () => void, delayMs: number) {
    const job = { callback, at: this.time + delayMs, cancelled: false };
    this.jobs.push(job);
    return {
      cancel: () => {
        job.cancelled = true;
      },
    };
  }
  fireNext() {
    const job = this.jobs.filter((item) => !item.cancelled).sort((a, b) => a.at - b.at)[0];
    if (!job) throw new Error('No scheduled job');
    this.time = job.at;
    job.cancelled = true;
    job.callback();
  }
  active() {
    return this.jobs.filter((job) => !job.cancelled);
  }
}

function cweResponse(version = '4.test') {
  return new Response(zipSync({ 'cwe.xml': strToU8(cweXml.replace('4.test', version)) }));
}
function capecResponse(
  version = '3.test',
  headers: Record<string, string> = { etag: 'capec-tag' },
) {
  return new Response(capecXml.replace('3.test', version), { headers });
}
function fixtureRequest() {
  return vi.fn<HttpRequest>().mockImplementation(async (url) => {
    if (url === SOURCE_URLS.cwe) return cweResponse();
    if (url === SOURCE_URLS.capec) return capecResponse();
    if (url === SOURCE_URLS.cweVersion)
      return Response.json({ ContentVersion: '4.test', ContentDate: 'api-date' });
    throw new Error(`Unexpected URL ${url}`);
  });
}
const owned: CatalogService[] = [];
function service(request: HttpRequest, clock = new Clock()) {
  const instance = new CatalogService({
    request,
    clock,
    context: createMockContext(),
    onRefreshError: vi.fn(),
  });
  owned.push(instance);
  return instance;
}
const tempDirs: string[] = [];
async function tempDir() {
  const dir = await mkdtemp(join(tmpdir(), 'mitre-cwe-cache-test-'));
  tempDirs.push(dir);
  return dir;
}
afterEach(async () => {
  await disposeCatalogService();
  await Promise.all(owned.splice(0).map((instance) => instance.dispose()));
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
  for (const dir of tempDirs.splice(0)) {
    await chmod(dir, 0o700).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  }
});

describe('CatalogService', () => {
  it('awaits cancellation of pending initial requests without publishing the singleton', async () => {
    const entered = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const signals: AbortSignal[] = [];
    const request = vi.fn<HttpRequest>().mockImplementation(async (_url, options) => {
      signals.push(options.signal);
      if (signals.length === 2) entered.resolve();
      return new Promise((_resolve, reject) => {
        options.signal.addEventListener(
          'abort',
          () => {
            void release.promise.then(() => reject(options.signal.reason));
          },
          { once: true },
        );
      });
    });
    const clock = new Clock();
    const starting = initCatalogService({ request, clock, context: createMockContext() });
    const rejected = expect(starting).rejects.toMatchObject({
      data: { reason: 'service_stopped' },
    });
    await entered.promise;
    expect(() => getCatalogService()).toThrow();
    await expect(initCatalogService({ request, clock })).rejects.toMatchObject({
      data: { reason: 'catalog_already_initialized' },
    });
    let disposed = false;
    const stopping = disposeCatalogService().then(() => {
      disposed = true;
    });
    expect(signals.every((signal) => signal.aborted)).toBe(true);
    await Promise.resolve();
    expect(disposed).toBe(false);
    release.resolve();
    await Promise.all([stopping, rejected]);
    expect(() => getCatalogService()).toThrow();
    expect(clock.active()).toEqual([]);
    expect(request).toHaveBeenCalledTimes(2);
  });

  it('publishes the singleton only after initialization, disposes it, and permits a fresh initialization', async () => {
    expect(() => getCatalogService()).toThrow();
    const clock = new Clock();
    const request = fixtureRequest();
    const first = await initCatalogService({ request, clock, context: createMockContext() });
    expect(getCatalogService()).toBe(first);
    await expect(initCatalogService({ request, clock })).rejects.toMatchObject({
      data: { reason: 'catalog_already_initialized' },
    });
    await disposeCatalogService();
    expect(() => getCatalogService()).toThrow();
    expect(clock.active()).toEqual([]);
    await expect(first.start()).rejects.toMatchObject({ data: { reason: 'service_stopped' } });
    const second = await initCatalogService({ request, clock, context: createMockContext() });
    expect(second).not.toBe(first);
    expect(getCatalogService()).toBe(second);
    expect(request).toHaveBeenCalledTimes(4);
  });

  it('coalesces startup and publishes neither source until both validate', async () => {
    const pending = Promise.withResolvers<Response>();
    const request = fixtureRequest()
      .mockImplementationOnce(async () => cweResponse())
      .mockImplementationOnce(() => pending.promise);
    const clock = new Clock();
    const catalog = service(request, clock);
    const start = catalog.start();
    expect(catalog.start()).toBe(start);
    expect(() => catalog.snapshot()).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'catalog_not_initialized' }),
      }),
    );
    pending.resolve(capecResponse());
    await start;
    expect(request).toHaveBeenCalledTimes(2);
    expect(catalog.snapshot().provenance).toMatchObject({
      cweVersion: '4.test',
      capecVersion: '3.test',
      loadedAt: iso(initialTime),
    });
    expect(clock.active().map((job) => job.at)).toEqual([initialTime + REFRESH_INTERVALS.cwe]);
  });

  it('aborts the other initial source and leaves no published state after validation failure', async () => {
    let otherSignal: AbortSignal | undefined;
    const request = vi.fn<HttpRequest>().mockImplementation(async (url, options) => {
      if (url === SOURCE_URLS.cwe) return new Response('invalid zip');
      otherSignal = options.signal;
      return new Promise((_resolve, reject) =>
        options.signal.addEventListener('abort', () => reject(options.signal.reason), {
          once: true,
        }),
      );
    });
    const clock = new Clock();
    const catalog = service(request, clock);
    await expect(catalog.start()).rejects.toMatchObject({ data: { reason: 'unsafe_archive' } });
    expect(otherSignal?.aborted).toBe(true);
    expect(() => catalog.snapshot()).toThrow();
    expect(clock.active()).toEqual([]);
  });

  it.each([{ etag: 'tag', 'last-modified': 'date' }, { 'last-modified': 'date' }])(
    'treats conditional 304 as successful without changing loaded provenance (%j)',
    async (headers) => {
      const request = fixtureRequest();
      request
        .mockImplementationOnce(async () => cweResponse())
        .mockImplementationOnce(async () => capecResponse('3.test', headers));
      const clock = new Clock();
      const catalog = service(request, clock);
      await catalog.start();
      const before = catalog.snapshot();
      request.mockImplementation(async (url) =>
        url === SOURCE_URLS.capec
          ? new Response(null, { status: 304 })
          : Response.json({ ContentVersion: '4.test', ContentDate: 'api-date' }),
      );
      clock.time += REFRESH_INTERVALS.capec;
      await catalog.refresh();
      const after = catalog.snapshot();
      expect(after.provenance).toEqual(before.provenance);
      expect(after.health.capec).toMatchObject({
        loadedAt: iso(initialTime),
        lastCheckAt: iso(clock.time),
        lastSuccessfulCheckAt: iso(clock.time),
        nextCheckAt: iso(clock.time + REFRESH_INTERVALS.capec),
      });
      const call = request.mock.calls.findLast(([url]) => url === SOURCE_URLS.capec);
      expect(call?.[1]).toMatchObject({
        acceptNotModified: true,
        headers: 'etag' in headers ? { 'If-None-Match': 'tag' } : { 'If-Modified-Since': 'date' },
      });
      expect(after.health.cwe.apiDate).toBe('api-date');
      expect(request.mock.calls.filter(([url]) => url === SOURCE_URLS.cwe)).toHaveLength(1);
    },
  );

  it('compares 200 CAPEC root metadata before replacing and atomically refreshes new versions', async () => {
    const request = fixtureRequest();
    const clock = new Clock();
    const catalog = service(request, clock);
    await catalog.start();
    const original = catalog.snapshot();
    clock.time += REFRESH_INTERVALS.capec;
    await catalog.refresh();
    expect(catalog.snapshot().provenance).toEqual(original.provenance);
    request.mockImplementation(async (url) => {
      if (url === SOURCE_URLS.cwe) return cweResponse('4.next');
      if (url === SOURCE_URLS.capec) return capecResponse('3.next');
      return Response.json({ ContentVersion: '4.next', ContentDate: 'different-api-date' });
    });
    clock.time += REFRESH_INTERVALS.capec;
    await catalog.refresh();
    expect(catalog.snapshot().provenance).toMatchObject({
      cweVersion: '4.next',
      capecVersion: '3.next',
      cweDate: '2026-04-30',
      loadedAt: iso(clock.time),
    });
    expect(original.provenance.cweVersion).toBe('4.test');
    expect(catalog.snapshot().cwe.weaknesses.get('CWE-79')?.relatedAttackPatterns).toEqual([
      { id: 'CAPEC-1', name: 'Synthetic attack' },
    ]);
  });

  it('retains good data and success timestamps after a failed check, then clears failure on recovery', async () => {
    const request = fixtureRequest();
    const clock = new Clock();
    const catalog = service(request, clock);
    await catalog.start();
    const original = catalog.snapshot();
    request.mockImplementation(async () => new Response('private malformed payload'));
    clock.time += REFRESH_INTERVALS.cwe;
    await catalog.refresh();
    expect(catalog.snapshot().provenance).toEqual(original.provenance);
    expect(catalog.snapshot().health.cwe).toMatchObject({
      loadedAt: iso(initialTime),
      lastSuccessfulCheckAt: iso(initialTime),
      lastCheckAt: iso(clock.time),
      nextCheckAt: iso(clock.time + REFRESH_INTERVALS.cwe),
      lastRefreshError: { time: iso(clock.time) },
    });
    expect(JSON.stringify(catalog.snapshot().health)).not.toContain('private');
    request.mockImplementation(async () =>
      Response.json({ ContentVersion: '4.test', ContentDate: 'api-date' }),
    );
    clock.time += REFRESH_INTERVALS.cwe;
    await catalog.refresh();
    expect(catalog.snapshot().health.cwe.lastRefreshError).toBeUndefined();
    expect(catalog.snapshot().health.cwe.lastSuccessfulCheckAt).toBe(iso(clock.time));
  });

  it('reports MITRE edge refusals through the production adapter as temporary at startup and refresh', async () => {
    let refuse = true;
    const fetch = vi.fn(async (url: string) => {
      if (refuse) return new Response('{"supportID": "1"}', { status: 403 });
      if (url === SOURCE_URLS.cwe) return cweResponse();
      if (url === SOURCE_URLS.capec) return capecResponse();
      return Response.json({ ContentVersion: '4.test', ContentDate: 'api-date' });
    });
    vi.stubGlobal('fetch', fetch);
    const clock = new Clock();
    const blocked = new CatalogService({ clock, context: createMockContext() });
    owned.push(blocked);
    await expect(blocked.start()).rejects.toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
      data: { status: 403, retryable: true },
    });
    const startUrls = fetch.mock.calls.map(([url]) => url);
    expect(new Set(startUrls).size).toBe(startUrls.length);
    refuse = false;
    const onRefreshError = vi.fn();
    const catalog = new CatalogService({ clock, context: createMockContext(), onRefreshError });
    owned.push(catalog);
    await catalog.start();
    refuse = true;
    fetch.mockClear();
    clock.time += REFRESH_INTERVALS.cwe;
    await catalog.refresh();
    expect(catalog.snapshot().health.cwe.lastRefreshError).toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
    });
    expect(onRefreshError).toHaveBeenCalledWith(
      'cwe',
      expect.objectContaining({ code: JsonRpcErrorCode.ServiceUnavailable }),
    );
    expect(fetch.mock.calls.map(([url]) => url)).toEqual([SOURCE_URLS.cweVersion]);
  });

  it('coalesces parallel refresh calls and cancels pending owned requests at teardown', async () => {
    const request = fixtureRequest();
    const clock = new Clock();
    const catalog = service(request, clock);
    await catalog.start();
    const before = catalog.snapshot();
    const entered = Promise.withResolvers<AbortSignal>();
    request.mockImplementation(async (_url, options) => {
      entered.resolve(options.signal);
      return new Promise((_resolve, reject) =>
        options.signal.addEventListener('abort', () => reject(options.signal.reason), {
          once: true,
        }),
      );
    });
    clock.time += REFRESH_INTERVALS.cwe;
    const first = catalog.refresh();
    expect(catalog.refresh()).toBe(first);
    const signal = await entered.promise;
    await catalog.dispose();
    await first;
    expect(signal.aborted).toBe(true);
    expect(request).toHaveBeenCalledTimes(3);
    expect(catalog.snapshot()).toBe(before);
    expect(clock.active()).toEqual([]);
    await expect(catalog.start()).rejects.toMatchObject({ data: { reason: 'service_stopped' } });
    await catalog.refresh();
    expect(request).toHaveBeenCalledTimes(3);
  });

  it('runs the earliest due source from its scheduler and schedules the next ordinary check', async () => {
    const request = fixtureRequest();
    const clock = new Clock();
    const catalog = service(request, clock);
    await catalog.start();
    clock.fireNext();
    await catalog.refresh();
    expect(request.mock.calls.map(([url]) => url)).toEqual([
      SOURCE_URLS.cwe,
      SOURCE_URLS.capec,
      SOURCE_URLS.cweVersion,
    ]);
    expect(clock.active().map((job) => job.at)).toEqual([clock.time + REFRESH_INTERVALS.cwe]);
  });

  it('bounds a stuck CWE refresh with the injected source deadline and retains success health', async () => {
    const request = fixtureRequest();
    const clock = new Clock();
    const catalog = service(request, clock);
    await catalog.start();
    const entered = Promise.withResolvers<AbortSignal>();
    request.mockImplementation(async (_url, options) => {
      entered.resolve(options.signal);
      return new Promise((_resolve, reject) =>
        options.signal.addEventListener('abort', () => reject(options.signal.reason), {
          once: true,
        }),
      );
    });
    clock.time += REFRESH_INTERVALS.cwe;
    const checkedAt = clock.time;
    const pending = catalog.refresh();
    const signal = await entered.promise;
    clock.fireNext();
    await pending;
    expect(signal.aborted).toBe(true);
    expect(signal.reason).toMatchObject({ data: { reason: 'source_deadline' } });
    expect(catalog.snapshot().health.cwe).toMatchObject({
      loadedAt: iso(initialTime),
      lastSuccessfulCheckAt: iso(initialTime),
      lastCheckAt: iso(checkedAt),
      nextCheckAt: iso(clock.time + REFRESH_INTERVALS.cwe),
      lastRefreshError: { time: iso(clock.time) },
    });
    expect(request).toHaveBeenCalledTimes(3);
    expect(clock.active().map((job) => job.at)).toEqual([clock.time + REFRESH_INTERVALS.cwe]);
  });
});

describe('CatalogService last-known-good cache', () => {
  const CWE_FILE = 'cwec_latest.xml.zip';
  const CAPEC_FILE = 'capec_latest.xml';
  const minutes = (count: number) => count * 60 * 1000;
  const cweLastModified = 'Thu, 30 Apr 2026 09:15:04 GMT';
  const cweBytes = (version = '4.test') =>
    zipSync({ 'cwe.xml': strToU8(cweXml.replace('4.test', version)) });
  const capecBytes = (version = '3.test') => strToU8(capecXml.replace('3.test', version));
  /** Serves fixed bytes, so a saved file can be compared byte for byte with what was served. */
  function servingRequest(cwe = cweBytes(), capec = capecBytes(), apiVersion = '4.test') {
    return vi.fn<HttpRequest>().mockImplementation(async (url) => {
      if (url === SOURCE_URLS.cwe)
        return new Response(cwe, { headers: { 'last-modified': cweLastModified } });
      if (url === SOURCE_URLS.capec) return new Response(capec, { headers: { etag: 'capec-tag' } });
      if (url === SOURCE_URLS.cweVersion)
        return Response.json({ ContentVersion: apiVersion, ContentDate: 'api-date' });
      throw new Error(`Unexpected URL ${url}`);
    });
  }
  const refusing = () =>
    vi.fn<HttpRequest>().mockImplementation(async () => new Response(null, { status: 403 }));
  function cached(request: HttpRequest, cacheDir: string, clock = new Clock()) {
    const instance = new CatalogService({
      request,
      clock,
      cacheDir,
      context: createMockContext(),
      onRefreshError: vi.fn(),
    });
    owned.push(instance);
    return instance;
  }
  const sidecar = async (dir: string, file: string) =>
    JSON.parse(await readFile(join(dir, `${file}.json`), 'utf8')) as unknown;
  /** A previous process's successful start leaves both catalogs and sidecars behind. */
  async function seededDir() {
    const dir = await tempDir();
    const first = cached(servingRequest(), dir);
    await first.start();
    await first.dispose();
    return dir;
  }
  const urls = (request: ReturnType<typeof vi.fn<HttpRequest>>) =>
    request.mock.calls.map(([url]) => url);
  const SAVE_FAILED = 'Could not save the MITRE catalog to the cache directory.';

  it('cold-starts schema 8 and reloads its exact cached bytes without network access', async () => {
    const dir = await tempDir();
    const bytes = zipSync({
      'cwe.xml': strToU8(
        readFileSync(new URL('../../fixtures/catalog/cwe-schema8.xml', import.meta.url), 'utf8'),
      ),
    });
    const first = cached(servingRequest(bytes, capecBytes(), '5.test'), dir);
    await first.start();
    expect(first.snapshot().health.cwe.counts).toEqual({
      weaknesses: 2,
      categories: 0,
      groupings: 2,
      views: 1,
    });
    expect(first.snapshot().cwe.weaknesses.get('CWE-900')?.type).toBe('grouping');
    await first.dispose();
    const request = refusing();
    const restart = cached(request, dir);
    await restart.start();
    expect(request).not.toHaveBeenCalled();
    expect(restart.snapshot().health.cwe).toMatchObject({
      source: 'cache',
      version: '5.test',
      counts: { groupings: 2, categories: 0 },
    });
    expect(restart.snapshot().cwe.weaknesses.get('CWE-1209')?.technicalNuance).toBe(
      'Precise **nuance**.\n\nSecond paragraph.',
    );
    expect(new Uint8Array(await readFile(join(dir, CWE_FILE)))).toEqual(bytes);
  });

  it('atomically refreshes cached schema 7 to schema 8 and retains schema 8 after an invalid replacement', async () => {
    const dir = await seededDir();
    const clock = new Clock();
    const schema8 = readFileSync(
      new URL('../../fixtures/catalog/cwe-schema8.xml', import.meta.url),
      'utf8',
    );
    let release: ((response: Response) => void) | undefined;
    let invalid = false;
    const request: HttpRequest = async (url) => {
      if (url === SOURCE_URLS.cweVersion)
        return Response.json({
          ContentVersion: invalid ? 'future' : '5.test',
          ContentDate: 'api-date',
        });
      if (url === SOURCE_URLS.capec) return new Response(null, { status: 304 });
      if (url === SOURCE_URLS.cwe) {
        if (invalid)
          return new Response(zipSync({ 'cwe.xml': strToU8(schema8.replace('cwe-8', 'cwe-9')) }));
        return new Promise<Response>((resolve) => {
          release = resolve;
        });
      }
      throw new Error(`Unexpected URL ${url}`);
    };
    const catalog = cached(request, dir, clock);
    await catalog.start();
    const before = catalog.snapshot();
    expect(before.cwe.version).toBe('4.test');
    const refreshing = catalog.refresh();
    for (let hop = 0; hop < 20 && !release; hop++) await Promise.resolve();
    expect(release).toBeTypeOf('function');
    expect(catalog.snapshot()).toBe(before);
    release!(new Response(zipSync({ 'cwe.xml': strToU8(schema8) })));
    await refreshing;
    const current = catalog.snapshot();
    expect(current.cwe.version).toBe('5.test');
    expect(current.cwe.weaknesses.get('CWE-900')?.type).toBe('grouping');
    expect(before.cwe.weaknesses.get('CWE-900')?.type).toBe('category');
    expect(before.cwe.version).toBe('4.test');
    invalid = true;
    clock.time += REFRESH_INTERVALS.cwe;
    await catalog.refresh();
    expect(catalog.snapshot().cwe.weaknesses.get('CWE-900')).toEqual({
      id: 'CWE-900',
      type: 'grouping',
      name: 'Grouping',
      description: 'Organizational **summary**.',
      status: 'Stable',
      sourceUrl: 'https://cwe.mitre.org/data/definitions/900.html',
      members: [
        {
          id: 'CWE-901',
          viewId: 'CWE-1000',
          dimensions: [{ type: 'Technology', value: 'Hardware' }],
          name: 'Nested grouping',
          type: 'grouping',
          status: 'Incomplete',
        },
      ],
      references: [
        {
          id: 'REF-8',
          title: 'Source',
          url: 'https://example.test/source',
          altUrl: 'https://example.test/alt_a?q=1&b=2',
          altUrlDate: '2026-10-23',
          mediaTypes: ['Video', 'Text'],
          accessRestrictions: 'Minimal-Registration',
          rationales: ['Early-Publication', 'Other'],
        },
      ],
      mappingNotes: { usage: 'Prohibited', reasons: ['Grouping'] },
      notes: [{ type: 'Maintenance', version: '5.0', text: 'Grouping note.' }],
    });
    expect(catalog.snapshot().health.cwe).toMatchObject({
      version: '5.test',
      lastRefreshError: {
        message: 'The catalog refresh failed; the previously loaded catalog is retained.',
      },
    });
    const restart = cached(refusing(), dir);
    await restart.start();
    expect(restart.snapshot().cwe.version).toBe('5.test');
  });
  /** Logged warnings as `<source>: <message>`, sorted because both sources load concurrently. */
  const warnings = (calls: Parameters<typeof logger.warning>[]) =>
    calls
      .map(
        ([message, context]) =>
          `${(context?.extra as { source?: string } | undefined)?.source}: ${message}`,
      )
      .sort();

  it('fails start as before when the cache is empty and MITRE refuses, writing nothing', async () => {
    const dir = await tempDir();
    const clock = new Clock();
    const catalog = cached(refusing(), dir, clock);
    await expect(catalog.start()).rejects.toMatchObject({
      code: JsonRpcErrorCode.ServiceUnavailable,
      data: { status: 403, retryable: true },
    });
    expect(() => catalog.snapshot()).toThrow(
      expect.objectContaining({
        data: expect.objectContaining({ reason: 'catalog_not_initialized' }),
      }),
    );
    expect(clock.active()).toEqual([]);
    expect(await readdir(dir)).toEqual([]);
  });

  it('touches no cache files when built without a cache directory', async () => {
    const read = vi.spyOn(CatalogCache.prototype, 'read');
    const write = vi.spyOn(CatalogCache.prototype, 'write');
    const request = servingRequest(cweBytes('4.test'), capecBytes(), '4.next');
    const clock = new Clock();
    const catalog = service(request, clock);
    await catalog.start();
    clock.time += REFRESH_INTERVALS.capec;
    await catalog.refresh();
    expect(urls(request)).toEqual([
      SOURCE_URLS.cwe,
      SOURCE_URLS.capec,
      SOURCE_URLS.cweVersion,
      SOURCE_URLS.capec,
      SOURCE_URLS.cwe,
    ]);
    expect(read).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(catalog.snapshot().health.cwe.source).toBe('upstream');
  });

  it('saves each start download as its exact bytes with a sidecar bound to the parsed root', async () => {
    const root = await tempDir();
    const dir = join(root, 'nested', 'cache');
    const cwe = cweBytes();
    const capec = capecBytes();
    const catalog = cached(servingRequest(cwe, capec), dir);
    await catalog.start();
    expect(new Uint8Array(await readFile(join(dir, CWE_FILE)))).toEqual(cwe);
    expect(new Uint8Array(await readFile(join(dir, CAPEC_FILE)))).toEqual(capec);
    expect(await sidecar(dir, CWE_FILE)).toEqual({
      version: '4.test',
      date: '2026-04-30',
      sha256: createHash('sha256').update(cwe).digest('hex'),
      fetchedAt: iso(initialTime),
      lastModified: cweLastModified,
    });
    expect(await sidecar(dir, CAPEC_FILE)).toEqual({
      version: '3.test',
      date: '2023-01-24',
      sha256: createHash('sha256').update(capec).digest('hex'),
      fetchedAt: iso(initialTime),
      etag: 'capec-tag',
    });
    expect((await readdir(dir)).sort()).toEqual(
      [CAPEC_FILE, `${CAPEC_FILE}.json`, CWE_FILE, `${CWE_FILE}.json`].sort(),
    );
    expect(catalog.snapshot().health.cwe).toMatchObject({
      source: 'upstream',
      fetchedAt: iso(initialTime),
      loadedAt: iso(initialTime),
      lastSuccessfulCheckAt: iso(initialTime),
      nextCheckAt: iso(initialTime + REFRESH_INTERVALS.cwe),
    });
  });

  it('starts from the saved catalogs without a request while MITRE refuses, then checks at once', async () => {
    const dir = await seededDir();
    const request = refusing();
    const clock = new Clock();
    clock.time = initialTime + minutes(90);
    const catalog = cached(request, dir, clock);
    await catalog.start();
    expect(request).not.toHaveBeenCalled();
    expect(catalog.snapshot().provenance).toMatchObject({
      cweVersion: '4.test',
      capecVersion: '3.test',
      loadedAt: iso(clock.time),
    });
    const { cwe, capec } = catalog.snapshot().health;
    expect(cwe).toMatchObject({
      source: 'cache',
      fetchedAt: iso(initialTime),
      lastModified: cweLastModified,
      loadedAt: iso(clock.time),
      nextCheckAt: iso(clock.time),
      counts: { weaknesses: 2, categories: 1, views: 2 },
    });
    expect(capec).toMatchObject({
      source: 'cache',
      fetchedAt: iso(initialTime),
      etag: 'capec-tag',
      nextCheckAt: iso(clock.time),
    });
    expect(cwe).not.toHaveProperty('lastSuccessfulCheckAt');
    expect(capec).not.toHaveProperty('lastSuccessfulCheckAt');
    expect(clock.active().map((job) => job.at)).toEqual([clock.time]);
    await catalog.dispose();
    expect(clock.active()).toEqual([]);
  });

  it('retries a cache-loaded source after 5, 10, 20, 40, then every 60 minutes until a check succeeds', async () => {
    const dir = await seededDir();
    const request = refusing();
    const clock = new Clock();
    const catalog = cached(request, dir, clock);
    await catalog.start();
    for (const delay of [5, 10, 20, 40, 60, 60, 60].map(minutes)) {
      clock.fireNext();
      await catalog.refresh();
      const { cwe, capec } = catalog.snapshot().health;
      for (const health of [cwe, capec])
        expect(health).toMatchObject({
          source: 'cache',
          lastCheckAt: iso(clock.time),
          nextCheckAt: iso(clock.time + delay),
          lastRefreshError: { code: JsonRpcErrorCode.ServiceUnavailable },
        });
      expect(cwe).not.toHaveProperty('lastSuccessfulCheckAt');
      expect(clock.active().map((job) => job.at)).toEqual([clock.time + delay]);
    }
    // Each failed check asked only for the CWE version and the conditional CAPEC download.
    expect(new Set(urls(request))).toEqual(new Set([SOURCE_URLS.cweVersion, SOURCE_URLS.capec]));
    // Recovery: CWE reports the same version and CAPEC is unchanged, so both stay cache-sourced.
    request.mockImplementation(async (url) =>
      url === SOURCE_URLS.capec
        ? new Response(null, { status: 304 })
        : Response.json({ ContentVersion: '4.test', ContentDate: 'api-date' }),
    );
    clock.fireNext();
    await catalog.refresh();
    const recovered = catalog.snapshot().health;
    expect(recovered.cwe).toMatchObject({
      source: 'cache',
      fetchedAt: iso(initialTime),
      lastSuccessfulCheckAt: iso(clock.time),
      nextCheckAt: iso(clock.time + REFRESH_INTERVALS.cwe),
    });
    expect(recovered.capec).toMatchObject({
      source: 'cache',
      lastSuccessfulCheckAt: iso(clock.time),
      nextCheckAt: iso(clock.time + REFRESH_INTERVALS.capec),
    });
    expect(recovered.cwe).not.toHaveProperty('lastRefreshError');
    // Seven failed checks and the recovery all sent the sidecar's validator: a failure keeps it.
    expect(
      request.mock.calls
        .filter(([url]) => url === SOURCE_URLS.capec)
        .map(([, options]) => options.headers),
    ).toEqual(Array(8).fill({ 'If-None-Match': 'capec-tag' }));
    // After one success a failed check waits for the ordinary interval again.
    request.mockImplementation(async () => new Response(null, { status: 403 }));
    clock.fireNext();
    await catalog.refresh();
    expect(catalog.snapshot().health.cwe).toMatchObject({
      lastRefreshError: { code: JsonRpcErrorCode.ServiceUnavailable },
      nextCheckAt: iso(clock.time + REFRESH_INTERVALS.cwe),
    });
  });

  it('marks a refresh download as upstream and saves it over the cached copy', async () => {
    const dir = await seededDir();
    const clock = new Clock();
    clock.time = initialTime + minutes(30);
    const nextCwe = cweBytes('4.next');
    const sameCapec = capecBytes();
    const request = refusing();
    const catalog = cached(request, dir, clock);
    await catalog.start();
    const startedAt = clock.time;
    request.mockImplementation(servingRequest(nextCwe, sameCapec, '4.next'));
    clock.time += minutes(1);
    await catalog.refresh();
    const { cwe, capec } = catalog.snapshot().health;
    expect(cwe).toMatchObject({
      source: 'upstream',
      version: '4.next',
      fetchedAt: iso(clock.time),
      loadedAt: iso(clock.time),
    });
    // A 200 with the same root version replaces no records but is still a fresh download.
    expect(capec).toMatchObject({
      source: 'upstream',
      version: '3.test',
      fetchedAt: iso(clock.time),
      loadedAt: iso(startedAt),
    });
    expect(urls(request)).toEqual([SOURCE_URLS.cweVersion, SOURCE_URLS.capec, SOURCE_URLS.cwe]);
    expect(new Uint8Array(await readFile(join(dir, CWE_FILE)))).toEqual(nextCwe);
    expect(await sidecar(dir, CWE_FILE)).toMatchObject({
      version: '4.next',
      fetchedAt: iso(clock.time),
    });
    expect(await sidecar(dir, CAPEC_FILE)).toMatchObject({ fetchedAt: iso(clock.time) });
  });

  /** A sidecar for the seeded CAPEC bytes, usable unless a field is overridden. */
  const capecSidecar = (fields: Record<string, string> = {}) =>
    JSON.stringify({
      version: '3.test',
      date: '2023-01-24',
      sha256: createHash('sha256').update(capecBytes()).digest('hex'),
      fetchedAt: '2026-10-19T00:00:00.000Z',
      etag: 'stale',
      ...fields,
    });
  it.each<[string, string | undefined, boolean]>([
    ['usable', capecSidecar(), true],
    ['missing', undefined, false],
    ['unparseable', '{"version":', false],
    [
      'written for other bytes',
      capecSidecar({ sha256: createHash('sha256').update(capecBytes('3.old')).digest('hex') }),
      false,
    ],
    ['for another version', capecSidecar({ version: '3.old' }), false],
    ['for another date', capecSidecar({ date: '2000-01-01' }), false],
    ['holding an etag that is no header value', capecSidecar({ etag: 'a\r\nb' }), false],
    ['holding a fetchedAt that is no time', capecSidecar({ fetchedAt: 'x' }), false],
  ])(
    'loads seeded bytes whose sidecar is %s, taking validators only from a usable one',
    async (_case, content, usable) => {
      const dir = await tempDir();
      await writeFile(join(dir, CWE_FILE), cweBytes());
      await writeFile(join(dir, CAPEC_FILE), capecBytes());
      if (content !== undefined) await writeFile(join(dir, `${CAPEC_FILE}.json`), content);
      const request = refusing();
      const clock = new Clock();
      const catalog = cached(request, dir, clock);
      await catalog.start();
      expect(request).not.toHaveBeenCalled();
      const { capec } = catalog.snapshot().health;
      expect(capec).toMatchObject({ source: 'cache', version: '3.test' });
      expect(capec).not.toHaveProperty('lastSuccessfulCheckAt');
      if (usable)
        expect(capec).toMatchObject({ etag: 'stale', fetchedAt: '2026-10-19T00:00:00.000Z' });
      else
        for (const key of ['etag', 'lastModified', 'fetchedAt'])
          expect(capec).not.toHaveProperty(key);
      request.mockImplementation(servingRequest());
      clock.fireNext();
      await catalog.refresh();
      const capecCall = request.mock.calls.find(([url]) => url === SOURCE_URLS.capec);
      expect(capecCall?.[1].headers).toEqual(usable ? { 'If-None-Match': 'stale' } : {});
      expect(catalog.snapshot().health.capec).toMatchObject({
        source: 'upstream',
        etag: 'capec-tag',
        fetchedAt: iso(clock.time),
      });
      expect(await sidecar(dir, CAPEC_FILE)).toMatchObject({
        version: '3.test',
        etag: 'capec-tag',
      });
    },
  );

  it.each([
    ['CWE', CWE_FILE, () => new Uint8Array(BYTE_LIMITS.cweDownload + 1)],
    ['CWE', CWE_FILE, () => strToU8('not a zip')],
    ['CWE', CWE_FILE, () => zipSync({ 'cwe.xml': strToU8('<WrongRoot/>') })],
    ['CAPEC', CAPEC_FILE, () => new Uint8Array(BYTE_LIMITS.capecXml + 1).fill(0x20)],
    ['CAPEC', CAPEC_FILE, () => new Uint8Array([0x3c, 0xff])],
    ['CAPEC', CAPEC_FILE, () => strToU8('<WrongRoot/>')],
  ] as const)(
    'treats an unusable cached %s file as absent with one warning (%#)',
    async (_name, file, bytes) => {
      const dir = await seededDir();
      await writeFile(join(dir, file), bytes());
      const warning = vi.spyOn(logger, 'warning');
      const cwe = cweBytes();
      const capec = capecBytes();
      const request = servingRequest(cwe, capec);
      const catalog = cached(request, dir);
      await catalog.start();
      expect(warning).toHaveBeenCalledOnce();
      expect(urls(request)).toEqual([file === CWE_FILE ? SOURCE_URLS.cwe : SOURCE_URLS.capec]);
      const health = catalog.snapshot().health;
      expect(file === CWE_FILE ? health.cwe.source : health.capec.source).toBe('upstream');
      expect(file === CWE_FILE ? health.capec.source : health.cwe.source).toBe('cache');
      // The synchronous download replaced the unusable file.
      expect(new Uint8Array(await readFile(join(dir, file)))).toEqual(
        file === CWE_FILE ? cwe : capec,
      );
    },
  );

  it('starts from the network with a warning when the cache path is a file', async () => {
    const dir = await tempDir();
    const path = join(dir, 'not-a-directory');
    await writeFile(path, 'x');
    const warning = vi.spyOn(logger, 'warning');
    const catalog = cached(servingRequest(), path);
    await catalog.start();
    expect(catalog.snapshot().health.cwe.source).toBe('upstream');
    // Reading under a file is "nothing cached"; only the failed saves warn.
    expect(warnings(warning.mock.calls)).toEqual([`capec: ${SAVE_FAILED}`, `cwe: ${SAVE_FAILED}`]);
    expect(await readFile(path, 'utf8')).toBe('x');
  });

  it('reads a read-only cache and keeps the previous copy when a refresh cannot save', async () => {
    const dir = await seededDir();
    const before = await readFile(join(dir, CWE_FILE));
    await chmod(dir, 0o555);
    const request = refusing();
    const clock = new Clock();
    const catalog = cached(request, dir, clock);
    await catalog.start();
    expect(catalog.snapshot().health.cwe.source).toBe('cache');
    const warning = vi.spyOn(logger, 'warning');
    request.mockImplementation(servingRequest(cweBytes('4.next'), capecBytes(), '4.next'));
    clock.fireNext();
    await catalog.refresh();
    expect(catalog.snapshot().health.cwe).toMatchObject({ source: 'upstream', version: '4.next' });
    expect(catalog.snapshot().health.cwe).not.toHaveProperty('lastRefreshError');
    expect(warnings(warning.mock.calls)).toEqual([`capec: ${SAVE_FAILED}`, `cwe: ${SAVE_FAILED}`]);
    expect(await readFile(join(dir, CWE_FILE))).toEqual(before);
    expect((await readdir(dir)).filter((name) => name.endsWith('.tmp'))).toEqual([]);
  });

  it('removes its temporary file when replacing a cached file fails', async () => {
    const dir = await tempDir();
    await mkdir(join(dir, CAPEC_FILE, 'occupied'), { recursive: true });
    const warning = vi.spyOn(logger, 'warning');
    const catalog = cached(servingRequest(), dir);
    await catalog.start();
    expect(catalog.snapshot().health.capec.source).toBe('upstream');
    expect(warnings(warning.mock.calls)).toEqual([
      `capec: ${SAVE_FAILED}`,
      'capec: Ignoring a cached MITRE catalog that is not a file within its byte limit.',
    ]);
    expect((await readdir(dir)).sort()).toEqual([CAPEC_FILE, CWE_FILE, `${CWE_FILE}.json`].sort());
  });

  it.skipIf(process.platform === 'win32')(
    'treats a FIFO at the data or sidecar path as unusable instead of blocking start',
    async () => {
      for (const name of [CWE_FILE, `${CAPEC_FILE}.json`]) {
        const dir = await seededDir();
        const path = join(dir, name);
        await rm(path);
        execFileSync('mkfifo', [path]);
        const catalog = cached(servingRequest(), dir);
        let guard: ReturnType<typeof setTimeout> | undefined;
        const outcome = await Promise.race([
          catalog.start().then(() => 'started'),
          // Not a timing assertion: it only breaks a blocked open so a failure cannot wedge the worker.
          new Promise<string>((resolve) => {
            guard = setTimeout(() => resolve('blocked'), 3000);
          }),
        ]);
        clearTimeout(guard);
        if (outcome === 'blocked')
          await open(path, constants.O_WRONLY | constants.O_NONBLOCK).then(
            (writer) => writer.close(),
            () => {},
          );
        expect(outcome).toBe('started');
        const { cwe, capec } = catalog.snapshot().health;
        expect([cwe.source, capec.source]).toEqual(
          name === CWE_FILE ? ['upstream', 'cache'] : ['cache', 'cache'],
        );
        // A sidecar that is not a regular file supplies no validators.
        if (name !== CWE_FILE) expect(capec).not.toHaveProperty('etag');
      }
    },
  );

  it('replaces both validators with those of a refresh download', async () => {
    const dir = await seededDir();
    const request = refusing();
    const clock = new Clock();
    const catalog = cached(request, dir, clock);
    await catalog.start();
    const lastModified = 'Mon, 01 Jun 2026 00:00:00 GMT';
    request.mockImplementation(async (url) => {
      if (url === SOURCE_URLS.capec)
        return new Response(capecBytes('3.next'), { headers: { 'last-modified': lastModified } });
      return Response.json({ ContentVersion: '4.test', ContentDate: 'api-date' });
    });
    clock.fireNext();
    await catalog.refresh();
    const { capec } = catalog.snapshot().health;
    expect(capec).toMatchObject({ source: 'upstream', version: '3.next', lastModified });
    expect(capec).not.toHaveProperty('etag');
    clock.time += REFRESH_INTERVALS.capec;
    request.mockImplementation(async () => new Response(null, { status: 304 }));
    await catalog.refresh();
    expect(request.mock.calls.at(-1)?.[1].headers).toEqual({ 'If-Modified-Since': lastModified });
  });

  it('removes cache temp files over an hour old, keeping a live writer’s and unrelated files', async () => {
    const dir = await seededDir();
    // Removal compares mtimes with Date.now(), so fix it and age each file around the hour.
    const now = Date.parse('2026-10-21T12:00:00Z');
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(now);
    const files = {
      stale: [`${CWE_FILE}.99999.0f0e1d2c-0000-4000-8000-000000000000.tmp`, 61],
      live: [`${CAPEC_FILE}.json.99998.0f0e1d2c-0000-4000-8000-000000000001.tmp`, 59],
      unrelated: ['notes.99997.0f0e1d2c-0000-4000-8000-000000000002.tmp', 120],
    } as const;
    for (const [name, ageMinutes] of Object.values(files)) {
      const mtime = new Date(now - minutes(ageMinutes));
      await writeFile(join(dir, name), 'partial');
      await utimes(join(dir, name), mtime, mtime);
    }
    const request = refusing();
    const clock = new Clock();
    const catalog = cached(request, dir, clock);
    await catalog.start();
    request.mockImplementation(servingRequest(cweBytes('4.next'), capecBytes(), '4.next'));
    clock.fireNext();
    await catalog.refresh();
    const temps = (await readdir(dir)).filter((name) => name.endsWith('.tmp'));
    expect(temps.sort()).toEqual([files.live[0], files.unrelated[0]].sort());
  });
});
