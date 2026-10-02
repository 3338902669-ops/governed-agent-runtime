#!/usr/bin/env node
// Read-only MCP adapter for the auditor.
//
// It exposes exactly one capability - "can this record be used as evidence?" - and nothing else.
// There is deliberately no tool here that grants, approves, promotes, revokes or blocks: an
// adapter that could decide authority would inherit the unclosed authorisation surface that six
// rounds of scanning kept finding (SECURITY-SCAN-LOG.md). This one only reads.
//
// Transport: stdio, for a local client. Start it with:
//   node mcp/server.mjs

import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { auditLedger, CLAIMS, HOLDS, FAILS, UNKNOWN } from '../src/auditor.mjs';

const server = new McpServer({
  name: 'governed-agent-runtime-audit',
  version: '0.1.0',
});

const annotations = {
  readOnlyHint: true,     // the point of the whole adapter
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,   // it reads a file the caller names and nothing else
};

const claimSchema = z.object({
  id: z.string(),
  title: z.string(),
  verdict: z.enum([HOLDS, FAILS, UNKNOWN]),
  detail: z.string(),
  evidence: z.array(z.unknown()),
});

const reportShape = {
  verdict: z.enum([HOLDS, FAILS, UNKNOWN]),
  counts: z.object({ HOLDS: z.number(), FAILS: z.number(), UNKNOWN: z.number() }),
  claims: z.array(claimSchema),
};

server.registerTool(
  'audit_ledger',
  {
    title: 'Audit a runtime ledger',
    description:
      'Re-check a governed-agent-runtime ledger export against seven claims: the hash chain is intact, ' +
      'every execution consumed a grant the gate issued, every piece of evidence is attached to the ' +
      'execution that produced it by its author, every verification came from a different ACTOR than the ' +
      'work it checked, every done fact rests on a verification of that task own work, every external ' +
      'action carries a matching unexpired approval, and nothing executed after its artifact trust was ' +
      'revoked. Each claim answers HOLDS, FAILS or UNKNOWN - UNKNOWN means the record does not carry the ' +
      'field the claim needs, which is not the same as passing. This tool reads and reports; it never ' +
      'blocks, changes or authorises anything.',
    inputSchema: {
      ledger: z
        .union([z.array(z.unknown()), z.object({ rows: z.array(z.unknown()) })])
        .optional()
        .describe('The ledger export: either an array of rows, or an object shaped { rows: [...] }. Provide this or path.'),
      path: z
        .string()
        .optional()
        .describe('Path to a JSON file holding the ledger export. Read-only; the server never writes.'),
    },
    outputSchema: reportShape,
    annotations,
  },
  async ({ ledger, path }) => {
    if (!ledger && !path) {
      return {
        isError: true,
        content: [{ type: 'text', text: 'Provide either "ledger" (inline export) or "path" (a JSON file). Nothing was read.' }],
      };
    }
    let input = ledger;
    if (!input) {
      try {
        input = JSON.parse(readFileSync(path, 'utf8'));
      } catch (error) {
        return {
          isError: true,
          content: [{ type: 'text', text: 'Could not read ' + path + ': ' + String(error && error.message ? error.message : error) }],
        };
      }
    }
    const report = auditLedger(input);
    if (report.error) {
      return { isError: true, content: [{ type: 'text', text: report.error }] };
    }
    const summary = report.counts.HOLDS + ' HOLDS / ' + report.counts.FAILS + ' FAILS / ' + report.counts.UNKNOWN + ' UNKNOWN'
      + ' - ' + (report.verdict === HOLDS ? 'the record holds up'
        : report.verdict === UNKNOWN ? 'the record cannot be fully judged; see the UNKNOWN rows'
          : 'the record does not hold up');
    const text = summary + '\n\n' + report.claims
      .map((c) => c.id + ' ' + c.verdict + ' - ' + c.title + '\n    ' + c.detail)
      .join('\n');
    return { content: [{ type: 'text', text }], structuredContent: { verdict: report.verdict, counts: report.counts, claims: report.claims } };
  },
);

server.registerTool(
  'list_audit_claims',
  {
    title: 'List what the auditor checks',
    description:
      'List the seven claims the auditor re-checks and what each one asserts. Useful before deciding ' +
      'whether an audit result is relevant to the question being asked. Read-only.',
    inputSchema: {},
    outputSchema: { claims: z.array(z.object({ id: z.string(), title: z.string() })) },
    annotations,
  },
  async () => {
    const text = CLAIMS.map((c) => c.id + ' - ' + c.title).join('\n');
    return { content: [{ type: 'text', text }], structuredContent: { claims: CLAIMS } };
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
