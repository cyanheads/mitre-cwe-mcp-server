/**
 * @fileoverview Atomic catalog startup, refresh ownership, and lazy service access.
 * @module services/catalog/catalog-service
 */
import {
  configurationError,
  JsonRpcErrorCode,
  McpError,
  requestCancelled,
  timeout,
} from '@cyanheads/mcp-ts-core/errors';
import { logger, type RequestContext, requestContextService } from '@cyanheads/mcp-ts-core/utils';
import {
  type AcquiredCatalog,
  acquireCapec,
  acquireCwe,
  acquireCweVersion,
  defaultHttpRequest,
  SOURCE_URLS,
} from './acquisition.js';
import { buildCatalogSnapshot } from './catalog-index.js';
import type {
  CapecCatalog,
  CatalogClock,
  CatalogHealth,
  CatalogSnapshot,
  CweCatalog,
  HttpRequest,
} from './types.js';

/** Refresh intervals are shared output contracts, not environment configuration. */
export const REFRESH_INTERVALS = Object.freeze({
  cwe: 24 * 60 * 60 * 1000,
  capec: 7 * 24 * 60 * 60 * 1000,
});
/** Production scheduler never keeps a process alive by itself. */
export const systemCatalogClock: CatalogClock = {
  now: () => Date.now(),
  schedule(callback, delayMs) {
    const timer = setTimeout(callback, delayMs);
    timer.unref();
    return { cancel: () => clearTimeout(timer) };
  },
};

/** Service boundaries support fixture HTTP responses and deterministic refresh clocks. */
export interface CatalogServiceOptions {
  clock?: CatalogClock;
  context?: RequestContext;
  onRefreshError?: (
    source: 'cwe' | 'capec',
    error: NonNullable<CatalogHealth['lastRefreshError']>,
  ) => void;
  request?: HttpRequest;
}

type Refreshed<T> = { catalog: T; health: CatalogHealth; changed: boolean };
function iso(time: number): string {
  return new Date(time).toISOString();
}
function clearFailure(health: CatalogHealth): CatalogHealth {
  const { lastRefreshError: _lastRefreshError, ...rest } = health;
  return rest;
}
function counts(catalog: CweCatalog | CapecCatalog): Record<string, number> {
  if ('attackPatterns' in catalog)
    return {
      attackPatterns: catalog.attackPatterns.size,
      categories: catalog.categories.size,
      views: catalog.views.size,
    };
  return {
    weaknesses: [...catalog.weaknesses.values()].filter((entry) => entry.type === 'weakness')
      .length,
    categories: [...catalog.weaknesses.values()].filter((entry) => entry.type === 'category')
      .length,
    views: catalog.views.size,
  };
}
function initialHealth(
  { catalog, ...validators }: AcquiredCatalog<CweCatalog | CapecCatalog>,
  sourceUrl: string,
  now: number,
  interval: number,
): CatalogHealth {
  const loadedAt = iso(now);
  return {
    version: catalog.version,
    date: catalog.date,
    sourceUrl,
    loadedAt,
    counts: counts(catalog),
    nextCheckAt: iso(now + interval),
    lastSuccessfulCheckAt: loadedAt,
    ...validators,
  };
}

/** Shared public catalog state; callers capture snapshot() exactly once per operation. */
export class CatalogService {
  private readonly request: HttpRequest;
  private readonly clock: CatalogClock;
  private readonly context: RequestContext;
  private readonly onRefreshError: NonNullable<CatalogServiceOptions['onRefreshError']>;
  private readonly owner = new AbortController();
  private current: CatalogSnapshot | undefined;
  private initialLoad: Promise<void> | undefined;
  private inFlight: Promise<void> | undefined;
  private scheduler: { cancel(): void } | undefined;
  private stopped = false;

  constructor(options: CatalogServiceOptions = {}) {
    this.request = options.request ?? defaultHttpRequest;
    this.clock = options.clock ?? systemCatalogClock;
    this.context =
      options.context ?? requestContextService.createRequestContext({ operation: 'mitreCatalog' });
    this.onRefreshError =
      options.onRefreshError ??
      ((source, error) => {
        logger.warning('MITRE catalog refresh failed; retaining the loaded catalog.', {
          ...this.context,
          extra: { source, error },
        });
      });
  }

  /** Load both sources concurrently, publish once, and begin owned scheduling. */
  start(): Promise<void> {
    if (this.stopped)
      return Promise.reject(
        requestCancelled('The catalog service has stopped.', {
          reason: 'service_stopped',
          retryable: false,
        }),
      );
    this.initialLoad ??= this.loadInitial();
    return this.initialLoad;
  }

  /** An immutable snapshot remains valid even after a later refresh replaces it. */
  snapshot(): CatalogSnapshot {
    if (!this.current)
      throw configurationError(
        'The catalog service is not initialized; await start() in setup().',
        { reason: 'catalog_not_initialized', retryable: false },
      );
    return this.current;
  }

  private async loadInitial(): Promise<void> {
    const cwe = acquireCwe(this.request, this.context, this.owner.signal);
    const capec = acquireCapec(this.request, this.context, this.owner.signal);
    try {
      const [loadedCwe, loadedCapec] = await Promise.all([cwe, capec]);
      this.owner.signal.throwIfAborted();
      if ('unchanged' in loadedCapec)
        throw configurationError('CAPEC cannot be unchanged before initialization.', {
          reason: 'catalog_not_initialized',
          retryable: false,
        });
      const now = this.clock.now();
      this.current = buildCatalogSnapshot(
        loadedCwe.catalog,
        loadedCapec.catalog,
        {
          cwe: initialHealth(loadedCwe, SOURCE_URLS.cwe, now, REFRESH_INTERVALS.cwe),
          capec: initialHealth(loadedCapec, SOURCE_URLS.capec, now, REFRESH_INTERVALS.capec),
        },
        iso(now),
      );
      this.scheduleNext();
    } catch (cause) {
      this.owner.abort(cause);
      await Promise.allSettled([cwe, capec]);
      throw cause;
    }
  }

  private scheduleNext(): void {
    this.scheduler?.cancel();
    if (this.stopped || !this.current) return;
    const next = Math.min(
      Date.parse(this.current.health.cwe.nextCheckAt),
      Date.parse(this.current.health.capec.nextCheckAt),
    );
    this.scheduler = this.clock.schedule(
      () => {
        void this.refresh();
      },
      Math.max(0, next - this.clock.now()),
    );
  }

  /** Coalesce concurrent due checks; failed checks wait for their ordinary interval. */
  refresh(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.inFlight) return this.inFlight;
    const snapshot = this.snapshot();
    const now = this.clock.now();
    const cweDue = now >= Date.parse(snapshot.health.cwe.nextCheckAt);
    const capecDue = now >= Date.parse(snapshot.health.capec.nextCheckAt);
    if (!cweDue && !capecDue) return Promise.resolve();
    this.scheduler?.cancel();
    const flight = this.refreshDue(snapshot, cweDue, capecDue).finally(() => {
      this.inFlight = undefined;
      this.scheduleNext();
    });
    this.inFlight = flight;
    return flight;
  }

  private async withSourceDeadline<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const deadline = new AbortController();
    const timer = this.clock.schedule(
      () =>
        deadline.abort(
          timeout('The MITRE source refresh exceeded its time budget.', {
            reason: 'source_deadline',
            retryable: true,
          }),
        ),
      45000,
    );
    try {
      return await operation(AbortSignal.any([this.owner.signal, deadline.signal]));
    } finally {
      timer.cancel();
    }
  }

  private refreshCwe(snapshot: CatalogSnapshot): Promise<Refreshed<CweCatalog>> {
    const health = snapshot.health.cwe;
    const checkedAt = iso(this.clock.now());
    return this.withSourceDeadline(async (signal) => {
      const api = await acquireCweVersion(this.request, this.context, signal);
      const loaded =
        api.version !== snapshot.cwe.version
          ? await acquireCwe(this.request, this.context, signal)
          : undefined;
      const candidate = loaded?.catalog ?? snapshot.cwe;
      const changed =
        candidate.version !== snapshot.cwe.version || candidate.date !== snapshot.cwe.date;
      const catalog = changed ? candidate : snapshot.cwe;
      return {
        catalog,
        changed,
        health: {
          ...clearFailure(health),
          version: catalog.version,
          date: catalog.date,
          ...(loaded?.etag !== undefined ? { etag: loaded.etag } : {}),
          ...(loaded?.lastModified !== undefined ? { lastModified: loaded.lastModified } : {}),
          apiVersion: api.version,
          apiDate: api.date,
          lastCheckAt: checkedAt,
          lastSuccessfulCheckAt: iso(this.clock.now()),
          nextCheckAt: iso(this.clock.now() + REFRESH_INTERVALS.cwe),
          ...(changed ? { loadedAt: iso(this.clock.now()), counts: counts(catalog) } : {}),
        },
      };
    });
  }

  private async refreshCapec(snapshot: CatalogSnapshot): Promise<Refreshed<CapecCatalog>> {
    const health = snapshot.health.capec;
    const checkedAt = iso(this.clock.now());
    const loaded = await acquireCapec(this.request, this.context, this.owner.signal, health);
    const candidate = 'unchanged' in loaded ? snapshot.capec : loaded.catalog;
    const changed =
      candidate.version !== snapshot.capec.version || candidate.date !== snapshot.capec.date;
    const catalog = changed ? candidate : snapshot.capec;
    return {
      catalog,
      changed,
      health: {
        ...clearFailure(health),
        version: catalog.version,
        date: catalog.date,
        ...(loaded.etag !== undefined ? { etag: loaded.etag } : {}),
        ...(loaded.lastModified !== undefined ? { lastModified: loaded.lastModified } : {}),
        lastCheckAt: checkedAt,
        lastSuccessfulCheckAt: iso(this.clock.now()),
        nextCheckAt: iso(this.clock.now() + REFRESH_INTERVALS.capec),
        ...(changed ? { loadedAt: iso(this.clock.now()), counts: counts(catalog) } : {}),
      },
    };
  }

  private failureHealth(
    source: 'cwe' | 'capec',
    health: CatalogHealth,
    cause: unknown,
    checkedAt: string,
  ): CatalogHealth {
    const error = {
      code: cause instanceof McpError ? cause.code : JsonRpcErrorCode.ServiceUnavailable,
      // Do not publish arbitrary remote or transport messages, paths, or bodies.
      message: 'The catalog refresh failed; the previously loaded catalog is retained.',
      time: iso(this.clock.now()),
    };
    this.onRefreshError(source, error);
    return {
      ...health,
      lastCheckAt: checkedAt,
      nextCheckAt: iso(this.clock.now() + REFRESH_INTERVALS[source]),
      lastRefreshError: error,
    };
  }

  private async refreshDue(
    snapshot: CatalogSnapshot,
    cweDue: boolean,
    capecDue: boolean,
  ): Promise<void> {
    const checkedAt = iso(this.clock.now());
    const [cwe, capec] = await Promise.allSettled([
      cweDue
        ? this.refreshCwe(snapshot)
        : Promise.resolve({ catalog: snapshot.cwe, health: snapshot.health.cwe, changed: false }),
      capecDue
        ? this.refreshCapec(snapshot)
        : Promise.resolve({
            catalog: snapshot.capec,
            health: snapshot.health.capec,
            changed: false,
          }),
    ]);
    if (this.stopped) return;
    const nextCwe =
      cwe.status === 'fulfilled'
        ? cwe.value
        : {
            catalog: snapshot.cwe,
            health: this.failureHealth('cwe', snapshot.health.cwe, cwe.reason, checkedAt),
            changed: false,
          };
    const nextCapec =
      capec.status === 'fulfilled'
        ? capec.value
        : {
            catalog: snapshot.capec,
            health: this.failureHealth('capec', snapshot.health.capec, capec.reason, checkedAt),
            changed: false,
          };
    this.current = buildCatalogSnapshot(
      nextCwe.catalog,
      nextCapec.catalog,
      { cwe: nextCwe.health, capec: nextCapec.health },
      nextCwe.changed || nextCapec.changed ? iso(this.clock.now()) : snapshot.provenance.loadedAt,
    );
  }

  /** Stop scheduling, cancel owned I/O, and wait until all owned work has settled. */
  async dispose(): Promise<void> {
    this.stopped = true;
    this.scheduler?.cancel();
    this.scheduler = undefined;
    this.owner.abort(
      requestCancelled('The catalog service is shutting down.', {
        reason: 'service_stopped',
        retryable: false,
      }),
    );
    await Promise.allSettled([this.initialLoad, this.inFlight]);
  }
}

let service: CatalogService | undefined;
let initializing: CatalogService | undefined;

/** Initialize once in setup(); a failed load never publishes the accessor. */
export async function initCatalogService(
  options: CatalogServiceOptions = {},
): Promise<CatalogService> {
  if (service || initializing)
    throw configurationError('The catalog service has already been initialized.', {
      reason: 'catalog_already_initialized',
      retryable: false,
    });
  const candidate = new CatalogService(options);
  initializing = candidate;
  try {
    await candidate.start();
    service = candidate;
    return candidate;
  } finally {
    if (initializing === candidate) initializing = undefined;
  }
}

/** Retrieve the initialized service at request time. */
export function getCatalogService(): CatalogService {
  if (!service)
    throw configurationError(
      'The catalog service is not initialized; await initCatalogService() in setup().',
      { reason: 'catalog_not_initialized', retryable: false },
    );
  return service;
}

/** Release the singleton in createApp teardown(). */
export async function disposeCatalogService(): Promise<void> {
  const current = service ?? initializing;
  service = undefined;
  initializing = undefined;
  await current?.dispose();
}
