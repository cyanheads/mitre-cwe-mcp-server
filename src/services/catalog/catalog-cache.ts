/**
 * @fileoverview Last-known-good catalog files: raw MITRE downloads plus JSON sidecars, written by
 * temp file and rename so readers and concurrent writers only ever see complete files.
 * @module services/catalog/catalog-cache
 */
import { createHash, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, mkdir, open, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { z } from '@cyanheads/mcp-ts-core';
import { logger, type RequestContext } from '@cyanheads/mcp-ts-core/utils';
import { BYTE_LIMITS, SOURCE_URLS } from './acquisition.js';

/** A catalog source the cache holds. */
export type CachedSource = 'cwe' | 'capec';

/** Upstream file names, so an operator can seed the directory with a manual download. */
const CACHE_FILES = Object.freeze({
  cwe: basename(new URL(SOURCE_URLS.cwe).pathname),
  capec: basename(new URL(SOURCE_URLS.capec).pathname),
});
/** A cached file passes the same byte limit as the download it stands in for. */
const CACHE_LIMITS = Object.freeze({ cwe: BYTE_LIMITS.cweDownload, capec: BYTE_LIMITS.capecXml });
/** A sidecar is a few hundred bytes; a larger file is not one. */
const SIDECAR_LIMIT = 4096;
/**
 * O_NONBLOCK keeps a FIFO at a cache path from blocking the open until a writer appears. Regular
 * files ignore it; Windows defines no such constant, and OR-ing undefined adds nothing.
 */
const READ_FLAGS = constants.O_RDONLY | constants.O_NONBLOCK;
/** A live writer's temp file exists for seconds; one an hour old was left by a crashed writer. */
const STALE_TEMP_MS = 60 * 60 * 1000;

/** A validator is sent back as a request header, so it holds only what a header value can. */
const headerValue = z.string().regex(/^[\t\x20-\x7e]*$/);
/** Root metadata and digest of the bytes beside it, when they were downloaded, and their validators. */
const sidecarSchema = z.object({
  version: z.string(),
  date: z.string(),
  sha256: z.string(),
  fetchedAt: z.iso.datetime(),
  etag: headerValue.exactOptional(),
  lastModified: headerValue.exactOptional(),
});
/** What a sidecar records about a download; the digest that binds it to the bytes stays here. */
type CacheSidecar = Omit<z.infer<typeof sidecarSchema>, 'sha256'>;

/** A cached file's bytes and its sidecar, when one parses and was written for these bytes. */
interface CachedCatalog {
  bytes: Uint8Array;
  sidecar?: CacheSidecar;
}

/** Missing files and a missing directory mean "nothing cached", which needs no warning. */
function isAbsent(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === 'ENOENT' || code === 'ENOTDIR';
}

function digest(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * A regular file's bytes, or undefined when the path holds another kind of file or one over
 * `limit`. Type and size come from the open handle, so a file swapped in after the check is never read.
 */
async function readRegularFile(path: string, limit: number): Promise<Uint8Array | undefined> {
  const handle = await open(path, READ_FLAGS);
  try {
    const stats = await handle.stat();
    if (!stats.isFile() || stats.size > limit) return;
    return new Uint8Array(await handle.readFile());
  } finally {
    await handle.close();
  }
}

/**
 * The sidecar written with these exact bytes. A missing, unreadable, malformed one, or one written
 * for other bytes of the same version, reads as none; the bytes alone still load.
 */
async function readSidecar(path: string, bytes: Uint8Array): Promise<CacheSidecar | undefined> {
  try {
    const file = await readRegularFile(`${path}.json`, SIDECAR_LIMIT);
    if (!file) return;
    const parsed = sidecarSchema.safeParse(JSON.parse(new TextDecoder().decode(file)));
    if (!parsed.success || parsed.data.sha256 !== digest(bytes)) return;
    const { sha256: _sha256, ...sidecar } = parsed.data;
    return sidecar;
  } catch {
    return;
  }
}

/** Reads and writes the cache directory; every failure becomes a warning, never an exception. */
export class CatalogCache {
  constructor(
    private readonly dir: string,
    private readonly context: RequestContext,
  ) {}

  /** Log a cache problem once; the caller continues as if the file were absent or unsaved. */
  warn(message: string, source: CachedSource, error?: unknown): void {
    const code = (error as NodeJS.ErrnoException | undefined)?.code;
    logger.warning(message, {
      ...this.context,
      extra: { source, cacheDir: this.dir, ...(code ? { code } : {}) },
    });
  }

  /** The cached bytes of a source, or undefined when absent, unreadable, or over its byte limit. */
  async read(source: CachedSource): Promise<CachedCatalog | undefined> {
    const path = join(this.dir, CACHE_FILES[source]);
    let bytes: Uint8Array | undefined;
    try {
      bytes = await readRegularFile(path, CACHE_LIMITS[source]);
    } catch (error) {
      if (!isAbsent(error)) this.warn('Could not read a cached MITRE catalog.', source, error);
      return;
    }
    if (!bytes) {
      this.warn(
        'Ignoring a cached MITRE catalog that is not a file within its byte limit.',
        source,
      );
      return;
    }
    const sidecar = await readSidecar(path, bytes);
    return { bytes, ...(sidecar ? { sidecar } : {}) };
  }

  /**
   * Save downloaded bytes, then their sidecar, then remove temp files a crashed writer left. A
   * failed step removes its temp file, leaves the previous files in place, and logs a warning;
   * the sidecar is skipped when the data failed.
   */
  async write(source: CachedSource, bytes: Uint8Array, sidecar: CacheSidecar): Promise<void> {
    const path = join(this.dir, CACHE_FILES[source]);
    try {
      await mkdir(this.dir, { recursive: true });
      await this.replace(path, bytes);
      await this.replace(
        `${path}.json`,
        `${JSON.stringify({ ...sidecar, sha256: digest(bytes) })}\n`,
      );
    } catch (error) {
      this.warn('Could not save the MITRE catalog to the cache directory.', source, error);
      return;
    }
    await this.removeStaleTemps(source);
  }

  private async replace(path: string, content: Uint8Array | string): Promise<void> {
    const temp = `${path}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(temp, content, { flag: 'wx' });
      await rename(temp, path);
    } catch (error) {
      await rm(temp, { force: true });
      throw error;
    }
  }

  /** Temp names are `<cache file>.<pid>.<uuid>.tmp`; only an hour-old one is removed. */
  private async removeStaleTemps(source: CachedSource): Promise<void> {
    const cutoff = Date.now() - STALE_TEMP_MS;
    const files = Object.values(CACHE_FILES);
    try {
      const temps = (await readdir(this.dir)).filter(
        (name) => name.endsWith('.tmp') && files.some((file) => name.startsWith(`${file}.`)),
      );
      for (const name of temps) {
        const temp = join(this.dir, name);
        // Another writer can rename its temp away between the listing and this check.
        const stats = await lstat(temp).catch(() => undefined);
        if (stats?.isFile() && stats.mtimeMs < cutoff) await rm(temp, { force: true });
      }
    } catch (error) {
      this.warn('Could not remove stale temporary files from the cache directory.', source, error);
    }
  }
}
