// protocol.test.mjs - speaks the real protocol to the real server over stdio.
//
// A tool that only works when called directly from a unit test is not an MCP server. This spawns
// the process, performs initialize / tools/list / tools/call as a client would, and asserts on the
// framed JSON-RPC responses.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeWorld, openWork, runHappyPath } from '../../src/fixture.mjs';
import { CLAIMS, HOLDS, FAILS } from '../../src/auditor.mjs';

const PROTOCOL = '2025-06-18';

function client() {
  const child = spawn(process.execPath, ['server.mjs'], { cwd: join(import.meta.dirname, '..'), stdio: ['pipe', 'pipe', 'pipe'] });
  let buffer = '';
  const pending = new Map();
  let nextId = 1;
  let stderr = '';
  child.stderr.on('data', (d) => { stderr += String(d); });
  child.stdout.on('data', (chunk) => {
    buffer += String(chunk);
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      let message;
      try { message = JSON.parse(line); } catch (error) { continue; }
      if (message.id !== undefined && pending.has(message.id)) {
        pending.get(message.id)(message);
        pending.delete(message.id);
      }
    }
  });
  const send = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => reject(new Error('timeout waiting for ' + method + '; stderr: ' + stderr)), 20000);
    pending.set(id, (message) => { clearTimeout(timer); resolve(message); });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  });
  const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method, params }) + '\n');
  return { child, send, notify, getStderr: () => stderr };
}

async function asLedger() {
  const world = await makeWorld();
  const work = await openWork(world);
  await runHappyPath(world, work);
  return world.cp.ledger.rows;
}

async function connected(fn) {
  const c = client();
  try {
    const init = await c.send('initialize', { protocolVersion: PROTOCOL, capabilities: {}, clientInfo: { name: 'auditor-test', version: '1.0.0' } });
    assert.ok(init.result, 'initialize failed: ' + JSON.stringify(init));
    c.notify('notifications/initialized', {});
    return await fn(c);
  } finally {
    c.child.kill();
  }
}

test('the server speaks MCP: initialize, tools/list, tools/call', async () => {
  await connected(async (c) => {
    const list = await c.send('tools/list', {});
    assert.ok(list.result, JSON.stringify(list));
    const names = list.result.tools.map((t) => t.name).sort();
    assert.deepEqual(names, ['audit_ledger', 'list_audit_claims']);
    for (const tool of list.result.tools) {
      assert.equal(tool.annotations.readOnlyHint, true, tool.name + ' must be advertised read-only');
      assert.equal(tool.annotations.destructiveHint, false);
      assert.ok(tool.inputSchema, tool.name + ' must publish an input schema');
    }

    const rows = await asLedger();
    const call = await c.send('tools/call', { name: 'audit_ledger', arguments: { ledger: { rows } } });
    assert.ok(call.result, JSON.stringify(call));
    assert.equal(call.result.structuredContent.verdict, HOLDS);
    assert.equal(call.result.structuredContent.claims.length, CLAIMS.length);
    assert.ok(call.result.content[0].text.includes('HOLDS'));

    const claims = await c.send('tools/call', { name: 'list_audit_claims', arguments: {} });
    assert.equal(claims.result.structuredContent.claims.length, CLAIMS.length);
  });
});

test('the server reports a tampered ledger as FAILS', async () => {
  await connected(async (c) => {
    const rows = await asLedger();
    const tampered = { rows: rows.map((r, i) => (i === 3 ? { ...r, payload: { ...r.payload, tampered: true } } : r)) };
    const call = await c.send('tools/call', { name: 'audit_ledger', arguments: { ledger: tampered } });
    assert.equal(call.result.structuredContent.verdict, FAILS);
    const a1 = call.result.structuredContent.claims.find((x) => x.id === 'A1');
    assert.equal(a1.verdict, FAILS);
  });
});

test('the server reads a file, and fails actionably when it cannot', async () => {
  await connected(async (c) => {
    const dir = mkdtempSync(join(tmpdir(), 'gar-mcp-'));
    const file = join(dir, 'ledger.json');
    writeFileSync(file, JSON.stringify({ rows: await asLedger() }));
    const ok = await c.send('tools/call', { name: 'audit_ledger', arguments: { path: file } });
    assert.equal(ok.result.structuredContent.verdict, HOLDS);

    const missing = await c.send('tools/call', { name: 'audit_ledger', arguments: { path: join(dir, 'nope.json') } });
    assert.equal(missing.result.isError, true);
    assert.ok(missing.result.content[0].text.includes('Could not read'));

    const neither = await c.send('tools/call', { name: 'audit_ledger', arguments: {} });
    assert.equal(neither.result.isError, true);
    assert.ok(neither.result.content[0].text.includes('ledger'));
  });
});
