// audit.mjs - the read-only auditor, as a command.
//
//   node bin/audit.mjs <ledger-export.json> [--json]
//
// Exit codes: 0 every claim holds; 1 something FAILS; 2 the input cannot be judged at all.
// It never blocks anything and never writes anything: it answers whether a record can be used as
// evidence, not whether an action may be taken.

import { readFileSync } from 'node:fs';
import { auditLedger, CLAIMS, HOLDS, FAILS, UNKNOWN } from '../src/auditor.mjs';

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const file = args.find((a) => !a.startsWith('--'));

if (!file) {
  console.error('usage: node bin/audit.mjs <ledger-export.json> [--json]');
  console.error('       the export is {"rows": [...]} from a runtime ledger, or a bare array of rows');
  process.exitCode = 2;
} else {
  let input;
  try {
    input = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    console.error('cannot read ' + file + ': ' + String(error && error.message ? error.message : error));
    process.exitCode = 2;
  }
  if (input !== undefined) {
    const report = auditLedger(input);
    if (report.error) {
      console.error(report.error);
      process.exitCode = 2;
    } else if (asJson) {
      console.log(JSON.stringify(report, null, 2));
      process.exitCode = report.verdict === FAILS ? 1 : 0;
    } else {
      console.log('');
      console.log('| claim | what it asserts | verdict | detail |');
      console.log('|---|---|---|---|');
      for (const claim of report.claims) {
        console.log('| ' + claim.id + ' | ' + claim.title + ' | ' + claim.verdict + ' | ' + claim.detail + ' |');
      }
      console.log('');
      console.log(report.counts.HOLDS + ' HOLDS / ' + report.counts.FAILS + ' FAILS / ' + report.counts.UNKNOWN + ' UNKNOWN');
      console.log(report.verdict === FAILS ? 'RECORD DOES NOT HOLD UP'
        : report.verdict === UNKNOWN ? 'RECORD CANNOT BE FULLY JUDGED - see UNKNOWN rows'
          : 'RECORD HOLDS UP');
      process.exitCode = report.verdict === FAILS ? 1 : 0;
    }
  }
}
