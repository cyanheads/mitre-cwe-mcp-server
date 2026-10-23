/**
 * @fileoverview Server-specific environment configuration: the catalog cache directory.
 * @module config/server-config
 */
import { homedir } from 'node:os';
import path from 'node:path';
import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';
import { logger } from '@cyanheads/mcp-ts-core/utils';

const ServerConfigSchema = z.object({
  cacheDir: z
    .string()
    .optional()
    .describe(
      'Directory for last-known-good MITRE catalog downloads; relative to the working directory.',
    ),
});

/** Resolved server configuration. */
interface ServerConfig {
  /** Absolute cache directory, or undefined when none can be resolved (the server runs uncached). */
  cacheDir: string | undefined;
}

/** The process facts a default cache location depends on. */
export interface CacheHost {
  cwd: string;
  env: Readonly<Record<string, string | undefined>>;
  /** The user's home directory; undefined when the platform reports none. */
  home: string | undefined;
  platform: NodeJS.Platform;
}

/**
 * A configured value resolves against the working directory. Otherwise the per-user cache
 * directory: `~/Library/Caches` on macOS, `%LOCALAPPDATA%` (else `~/AppData/Local`) on Windows,
 * otherwise `$XDG_CACHE_HOME` (else `~/.cache`). Environment values and the home directory count
 * only when absolute, so a default never lands relative to the working directory.
 */
export function resolveCacheDir(
  configured: string | undefined,
  host: CacheHost,
): string | undefined {
  const paths = host.platform === 'win32' ? path.win32 : path.posix;
  if (configured !== undefined) return paths.resolve(host.cwd, configured);
  const absolute = (value: string | undefined) =>
    value && paths.isAbsolute(value) ? value : undefined;
  const home = absolute(host.home);
  const base =
    host.platform === 'darwin'
      ? home && paths.join(home, 'Library', 'Caches')
      : host.platform === 'win32'
        ? (absolute(host.env.LOCALAPPDATA) ?? (home && paths.join(home, 'AppData', 'Local')))
        : (absolute(host.env.XDG_CACHE_HOME) ?? (home && paths.join(home, '.cache')));
  return base ? paths.join(base, 'mitre-cwe-mcp-server') : undefined;
}

/** `os.homedir()` throws where the platform knows no home directory for the user. */
function homeDirectory(): string | undefined {
  try {
    return homedir();
  } catch {
    return;
  }
}

/** Parse server env against an explicit host; logs one warning when no cache directory resolves. */
export function parseServerConfig(
  env: Record<string, string | undefined>,
  host: CacheHost,
): ServerConfig {
  const parsed = parseEnvConfig(ServerConfigSchema, { cacheDir: 'CWE_CACHE_DIR' }, env);
  const cacheDir = resolveCacheDir(parsed.cacheDir, host);
  if (!cacheDir)
    logger.warning(
      'No user cache directory could be resolved and CWE_CACHE_DIR is unset; MITRE catalogs will not be cached, so a restart needs MITRE to be reachable.',
    );
  return { cacheDir };
}

let config: ServerConfig | undefined;

/** Parse once; call in setup() so an invalid value fails startup naming its variable. */
export function getServerConfig(): ServerConfig {
  config ??= parseServerConfig(process.env, {
    cwd: process.cwd(),
    env: process.env,
    home: homeDirectory(),
    platform: process.platform,
  });
  return config;
}
