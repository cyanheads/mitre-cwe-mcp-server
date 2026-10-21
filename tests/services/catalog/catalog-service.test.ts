/**
 * @fileoverview Catalog publication, refresh health, scheduling and owned cancellation.
 * @module tests/services/catalog/catalog-service.test
 */
import { readFileSync } from 'node:fs';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { strToU8, zipSync } from 'fflate';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SOURCE_URLS } from '@/services/catalog/acquisition.js';
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
afterEach(async () => {
  await disposeCatalogService();
  await Promise.all(owned.splice(0).map((instance) => instance.dispose()));
  vi.unstubAllGlobals();
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
