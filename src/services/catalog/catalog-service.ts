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
  parseCapecBytes,
  parseCweBytes,
  SOURCE_URLS,
} from './acquisition.js';
import { type CachedSource, CatalogCache } from './catalog-cache.js';
import { buildCatalogSnapshot } from './catalog-index.js';
import type {
  CapecCatalog,
  CatalogClock,
  CatalogHealth,
  CatalogMetadata,
  CatalogSnapshot,
  CweCatalog,
  HttpRequest,
} from './types.js';

/** Refresh intervals are shared output contracts, not environment configuration. */
export const REFRESH_INTERVALS = Object.freeze({
  cwe: 24 * 60 * 60 * 1000,
  capec: 7 * 24 * 60 * 60 * 1000,
});
/**
 * A cache-loaded source with no successful check yet retries a failed check after 5 minutes,
 * doubling to every 60, instead of waiting a whole refresh interval on possibly stale data.
 */
const STALE_RETRY = Object.freeze({ firstMs: 5 * 60 * 1000, maxMs: 60 * 60 * 1000 });
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
  /** Directory for last-known-good downloads; without it the service reads and writes no files. */
  cacheDir?: string;
  clock?: CatalogClock;
  context?: RequestContext;
  onRefreshError?: (
    source: 'cwe' | 'capec',
    error: NonNullable<CatalogHealth['lastRefreshError']>,
  ) => void;
  request?: HttpRequest;
}

type Refreshed<T> = { catalog: T; health: CatalogHealth; changed: boolean };
/** A served catalog and where its bytes came from. */
type Loaded<T> = Pick<CatalogHealth, 'source' | 'fetchedAt' | 'etag' | 'lastModified'> & {
  catalog: T;
};
function iso(time: number): string {
  return new Date(time).toISOString();
}
function clearFailure(health: CatalogHealth): CatalogHealth {
  const { lastRefreshError: _lastRefreshError, ...rest } = health;
  return rest;
}
/** A download replaces both validators; a 304 updates only those it returns. */
function withoutValidators(health: CatalogHealth): CatalogHealth {
  const { etag: _etag, lastModified: _lastModified, ...rest } = health;
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
    groupings: [...catalog.weaknesses.values()].filter((entry) => entry.type === 'grouping').length,
    views: catalog.views.size,
  };
}
function initialHealth(
  { catalog, ...origin }: Loaded<CweCatalog | CapecCatalog>,
  sourceUrl: string,
  now: number,
  interval: number,
): CatalogHealth {
  const loadedAt = iso(now);
  // A start download was itself a check; a cached copy is checked as soon as start completes.
  const checked = origin.source === 'upstream';
  return {
    version: catalog.version,
    date: catalog.date,
    sourceUrl,
    loadedAt,
    counts: counts(catalog),
    nextCheckAt: checked ? iso(now + interval) : loadedAt,
    ...(checked ? { lastSuccessfulCheckAt: loadedAt } : {}),
    ...origin,
  };
}

/** Shared public catalog state; callers capture snapshot() exactly once per operation. */
export class CatalogService {
  private readonly request: HttpRequest;
  private readonly clock: CatalogClock;
  private readonly context: RequestContext;
  private readonly onRefreshError: NonNullable<CatalogServiceOptions['onRefreshError']>;
  private readonly cache: CatalogCache | undefined;
  private readonly owner = new AbortController();
  private current: CatalogSnapshot | undefined;
  private initialLoad: Promise<void> | undefined;
  private inFlight: Promise<void> | undefined;
  private scheduler: { cancel(): void } | undefined;
  /** Failed checks of each cache-loaded source since start; sets its stale retry delay. */
  private readonly staleFailures = { cwe: 0, capec: 0 };
  private stopped = false;

  constructor(options: CatalogServiceOptions = {}) {
    this.request = options.request ?? defaultHttpRequest;
    this.clock = options.clock ?? systemCatalogClock;
    this.context =
      options.context ?? requestContextService.createRequestContext({ operation: 'mitreCatalog' });
    this.cache = options.cacheDir ? new CatalogCache(options.cacheDir, this.context) : undefined;
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

  /** Each source starts from a usable cached copy without a request, otherwise from MITRE. */
  private async loadInitial(): Promise<void> {
    const cwe = this.initialCwe();
    const capec = this.initialCapec();
    try {
      const [loadedCwe, loadedCapec] = await Promise.all([cwe, capec]);
      this.owner.signal.throwIfAborted();
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

  private async initialCwe(): Promise<Loaded<CweCatalog>> {
    const cached = await this.fromCache('cwe', (bytes) => parseCweBytes(bytes, this.owner.signal));
    if (cached) return cached;
    return this.save('cwe', await acquireCwe(this.request, this.context, this.owner.signal));
  }

  private async initialCapec(): Promise<Loaded<CapecCatalog>> {
    const cached = await this.fromCache('capec', parseCapecBytes);
    if (cached) return cached;
    const loaded = await acquireCapec(this.request, this.context, this.owner.signal);
    if ('unchanged' in loaded)
      throw configurationError('CAPEC cannot be unchanged before initialization.', {
        reason: 'catalog_not_initialized',
        retryable: false,
      });
    return this.save('capec', loaded);
  }

  /**
   * A cached copy passes the same limits, archive checks, and parser as a download, or reads as
   * absent. Its sidecar supplies validators and fetchedAt only when it names the parsed root.
   */
  private async fromCache<T extends CatalogMetadata>(
    source: CachedSource,
    parse: (bytes: Uint8Array) => T,
  ): Promise<Loaded<T> | undefined> {
    if (!this.cache) return;
    const cached = await this.cache.read(source);
    if (!cached) return;
    let catalog: T;
    try {
      catalog = parse(cached.bytes);
    } catch (error) {
      this.owner.signal.throwIfAborted();
      this.cache.warn('Ignoring a cached MITRE catalog that failed validation.', source, error);
      return;
    }
    const { sidecar } = cached;
    if (sidecar?.version !== catalog.version || sidecar.date !== catalog.date)
      return { catalog, source: 'cache' };
    const { version: _version, date: _date, ...origin } = sidecar;
    return { catalog, source: 'cache', ...origin };
  }

  /** Save a download inside the start or refresh that made it; a failed save only warns. */
  private async save<T extends CatalogMetadata>(
    source: CachedSource,
    { bytes, catalog, ...validators }: AcquiredCatalog<T>,
  ): Promise<Loaded<T>> {
    const fetchedAt = iso(this.clock.now());
    await this.cache?.write(source, bytes, {
      version: catalog.version,
      date: catalog.date,
      fetchedAt,
      ...validators,
    });
    return { catalog, source: 'upstream', fetchedAt, ...validators };
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

  /**
   * Coalesce concurrent due checks. A failed check waits for its ordinary interval, or for its
   * stale retry delay while the source is cache-loaded with no successful check yet.
   */
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
          ? await this.save('cwe', await acquireCwe(this.request, this.context, signal))
          : undefined;
      const { catalog: candidate = snapshot.cwe, ...origin }: Partial<Loaded<CweCatalog>> =
        loaded ?? {};
      const changed =
        candidate.version !== snapshot.cwe.version || candidate.date !== snapshot.cwe.date;
      const catalog = changed ? candidate : snapshot.cwe;
      return {
        catalog,
        changed,
        health: {
          ...(loaded ? withoutValidators(clearFailure(health)) : clearFailure(health)),
          version: catalog.version,
          date: catalog.date,
          ...origin,
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
    const response = await acquireCapec(this.request, this.context, this.owner.signal, health);
    let loaded: Partial<Loaded<CapecCatalog>>;
    if ('unchanged' in response) {
      // A 304 keeps the served bytes and their origin, updating only the validators it returned.
      const { unchanged: _unchanged, ...validators } = response;
      loaded = validators;
    } else loaded = await this.save('capec', response);
    const { catalog: candidate = snapshot.capec, ...origin } = loaded;
    const changed =
      candidate.version !== snapshot.capec.version || candidate.date !== snapshot.capec.date;
    const catalog = changed ? candidate : snapshot.capec;
    return {
      catalog,
      changed,
      health: {
        ...(loaded.catalog ? withoutValidators(clearFailure(health)) : clearFailure(health)),
        version: catalog.version,
        date: catalog.date,
        ...origin,
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
    const stale = health.source === 'cache' && health.lastSuccessfulCheckAt === undefined;
    const delay = stale
      ? Math.min(STALE_RETRY.firstMs * 2 ** this.staleFailures[source]++, STALE_RETRY.maxMs)
      : REFRESH_INTERVALS[source];
    return {
      ...health,
      lastCheckAt: checkedAt,
      nextCheckAt: iso(this.clock.now() + delay),
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
