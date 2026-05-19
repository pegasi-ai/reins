import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { getClaudeToolMetadata } = require('../dist/lib/claude-tool-metadata.js');

test('normalizes Claude Code WebFetch to Network.fetch', () => {
  const metadata = getClaudeToolMetadata('WebFetch', {
    url: 'https://example.com/report',
  });

  assert.equal(metadata.moduleName, 'Network');
  assert.equal(metadata.methodName, 'fetch');
  assert.equal(metadata.policyKind, 'none');
  assert.equal(metadata.actionSummary, 'https://example.com/report');
});

test('normalizes MCP fetch tools to Network.fetch instead of generic MCP', () => {
  const metadata = getClaudeToolMetadata('mcp__fetch__fetch', {
    url: 'https://example.com/report',
  });

  assert.equal(metadata.moduleName, 'Network');
  assert.equal(metadata.methodName, 'fetch');
  assert.equal(metadata.policyKind, 'none');
  assert.equal(metadata.actionSummary, 'https://example.com/report');
});

test('keeps non-fetch MCP tools in the MCP policy namespace', () => {
  const toolName = 'mcp__github__create_issue';
  const metadata = getClaudeToolMetadata(toolName, {});

  assert.equal(metadata.moduleName, 'MCP');
  assert.equal(metadata.methodName, toolName);
  assert.equal(metadata.policyKind, 'mcp');
});
