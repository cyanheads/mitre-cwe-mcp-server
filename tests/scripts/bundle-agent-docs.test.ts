/**
 * @fileoverview Bundle cleanup retains dependency runtime modules named skills.
 * @module tests/scripts/bundle-agent-docs.test
 */
import { describe, expect, it } from 'vitest';
import { AGENT_DOC_ENTRY, filterAgentDocEntries } from '../../scripts/clean-mcpb.js';
import {
  checkBundleEntries,
  AGENT_DOC_ENTRY as lintAgentDocEntry,
} from '../../scripts/lint-packaging.js';

describe('dependency agent-doc cleanup', () => {
  it('strips package-root agent docs while preserving SDK runtime skills modules', () => {
    const runtime = [
      'node_modules/@modelcontextprotocol/server/dist/ext/skills/index.mjs',
      'node_modules/@modelcontextprotocol/server/dist/ext/skills/node.cjs',
      'node_modules/parent/node_modules/@modelcontextprotocol/server/dist/ext/skills/index.mjs',
    ];
    const docs = [
      'node_modules/@cyanheads/mcp-ts-core/framework-skills/add-tool/SKILL.md',
      'node_modules/example/skills/example/SKILL.md',
      'node_modules/@scope/parent/node_modules/example/.agents/skills/example/SKILL.md',
      'node_modules/example/SKILL.md',
    ];
    expect(filterAgentDocEntries([...runtime, ...docs])).toEqual(docs);
    expect(lintAgentDocEntry.source).toBe(AGENT_DOC_ENTRY.source);
    expect(checkBundleEntries(runtime, 'fixture.mcpb')).toEqual([]);
  });
});
