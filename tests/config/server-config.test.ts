/**
 * @fileoverview CWE_CACHE_DIR parsing and per-platform default cache directory resolution.
 * @module tests/config/server-config.test
 */
import { logger } from '@cyanheads/mcp-ts-core/utils';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { type CacheHost, parseServerConfig, resolveCacheDir } from '@/config/server-config.js';

const host = (fields: Partial<CacheHost>): CacheHost => ({
  cwd: '/srv/app',
  env: {},
  home: '/home/user',
  platform: 'linux',
  ...fields,
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('resolveCacheDir', () => {
  it.each<[string, Partial<CacheHost>, string | undefined]>([
    [
      'macOS',
      { platform: 'darwin', home: '/Users/user' },
      '/Users/user/Library/Caches/mitre-cwe-mcp-server',
    ],
    ['Linux without XDG_CACHE_HOME', {}, '/home/user/.cache/mitre-cwe-mcp-server'],
    [
      'Linux with XDG_CACHE_HOME',
      { env: { XDG_CACHE_HOME: '/var/cache/user' } },
      '/var/cache/user/mitre-cwe-mcp-server',
    ],
    [
      'Linux with a relative XDG_CACHE_HOME',
      { env: { XDG_CACHE_HOME: 'cache' } },
      '/home/user/.cache/mitre-cwe-mcp-server',
    ],
    [
      'Linux with no home and an absolute XDG_CACHE_HOME',
      { home: undefined, env: { XDG_CACHE_HOME: '/xdg' } },
      '/xdg/mitre-cwe-mcp-server',
    ],
    ['Linux with no home', { home: undefined }, undefined],
    ['Linux with a relative home', { home: 'user' }, undefined],
    [
      'Windows with LOCALAPPDATA',
      { platform: 'win32', home: 'C:\\Users\\user', env: { LOCALAPPDATA: 'D:\\Local' } },
      'D:\\Local\\mitre-cwe-mcp-server',
    ],
    [
      'Windows with a relative LOCALAPPDATA',
      { platform: 'win32', home: 'C:\\Users\\user', env: { LOCALAPPDATA: 'Local' } },
      'C:\\Users\\user\\AppData\\Local\\mitre-cwe-mcp-server',
    ],
    [
      'Windows without LOCALAPPDATA',
      { platform: 'win32', home: 'C:\\Users\\user' },
      'C:\\Users\\user\\AppData\\Local\\mitre-cwe-mcp-server',
    ],
    ['Windows with no home or LOCALAPPDATA', { platform: 'win32', home: undefined }, undefined],
    ['macOS with no home', { platform: 'darwin', home: undefined }, undefined],
  ])('defaults on %s', (_case, fields, expected) => {
    expect(resolveCacheDir(undefined, host(fields))).toBe(expected);
  });

  it('resolves a configured value against the working directory, absolute values unchanged', () => {
    expect(resolveCacheDir('.cache', host({}))).toBe('/srv/app/.cache');
    expect(resolveCacheDir('../shared/cache', host({ home: undefined }))).toBe('/srv/shared/cache');
    expect(resolveCacheDir('/data/cwe', host({}))).toBe('/data/cwe');
    expect(resolveCacheDir('cache', host({ platform: 'win32', cwd: 'C:\\app' }))).toBe(
      'C:\\app\\cache',
    );
  });
});

describe('parseServerConfig', () => {
  it('reads CWE_CACHE_DIR, treating blank and unsubstituted placeholders as unset', () => {
    const warning = vi.spyOn(logger, 'warning');
    expect(parseServerConfig({ CWE_CACHE_DIR: 'state' }, host({}))).toEqual({
      cacheDir: '/srv/app/state',
    });
    // An MCPB or plugin host forwards a blank option as its unsubstituted placeholder.
    const placeholder = `\${CWE_CACHE_DIR}`;
    for (const value of ['', placeholder])
      expect(parseServerConfig({ CWE_CACHE_DIR: value }, host({}))).toEqual({
        cacheDir: '/home/user/.cache/mitre-cwe-mcp-server',
      });
    expect(warning).not.toHaveBeenCalled();
  });

  it('runs uncached after one warning when no value is set and no home directory exists', () => {
    const warning = vi.spyOn(logger, 'warning');
    expect(parseServerConfig({}, host({ home: undefined }))).toEqual({ cacheDir: undefined });
    expect(warning).toHaveBeenCalledOnce();
    expect(warning.mock.calls[0]?.[0]).toContain('CWE_CACHE_DIR');
  });

  it('still honors CWE_CACHE_DIR without a home directory', () => {
    const warning = vi.spyOn(logger, 'warning');
    expect(parseServerConfig({ CWE_CACHE_DIR: '/data' }, host({ home: undefined }))).toEqual({
      cacheDir: '/data',
    });
    expect(warning).not.toHaveBeenCalled();
  });
});
