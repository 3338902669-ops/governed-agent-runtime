// check-claims.mjs - the numbers in the prose must equal the numbers in the code.
//
// This repository published four different test counts across four files, because nothing checked
// them. The sibling project has a claims checker for exactly this; this is the same idea, small.
//
// It reads the live counts out of the test files and the mutation table, then refuses any document
// that states a different number. Run it directly, or as a step of scripts/gate.mjs.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, '..');

const countTests = (file) => {
  const source = readFileSync(join(REPO, file), 'utf8');
  return (source.match(/^test\(/gm) || []).length;
};

const INVARIANTS = countTests('test/invariants.test.mjs');
const ATTACKS = countTests('test/adversarial.test.mjs');
const AUDITOR = countTests('test/auditor.test.mjs');
const TESTS = INVARIANTS + ATTACKS + AUDITOR;

const gateSource = readFileSync(join(REPO, 'scripts/gate.mjs'), 'utf8');
const mutations = gateSource.slice(gateSource.indexOf('const MUTATIONS = ['), gateSource.indexOf('];', gateSource.indexOf('const MUTATIONS = [')));
const MUTATIONS = (mutations.match(/^    id: '/gm) || []).length;

export const live = { tests: TESTS, invariants: INVARIANTS, attacks: ATTACKS, auditor: AUDITOR, mutations: MUTATIONS };

const DOCS = ['README.md', 'VERIFICATION.md', 'SECURITY-SCAN-LOG.md', 'bench/RESULTS.md', 'INVARIANTS.md'];

/** Numbers that may legitimately appear next to these words. */
const ALLOWED_NEAR_TEST = new Set([TESTS, INVARIANTS, ATTACKS, AUDITOR]);

const problems = [];

for (const doc of DOCS) {
  const text = readFileSync(join(REPO, doc), 'utf8');

  // "49 tests", "49-test suite", "49 checks", "34-test suite" ...
  // No newline crossing (that matched "Node 18+\ntest") and not the engine requirement.
  for (const match of text.matchAll(/(?<!Node )(?<!node )(\d+)[ \t-]*(?:test|check)s?\b/gi)) {
    const n = Number(match[1]);
    if (!ALLOWED_NEAR_TEST.has(n)) {
      problems.push(doc + ': says "' + match[0].trim() + '" but the suite holds ' + TESTS +
        ' tests (' + INVARIANTS + ' invariants + ' + ATTACKS + ' attacks)');
    }
  }

  // "16 injected faults", "seven injected faults"
  for (const match of text.matchAll(/(\d+)\s+injected faults/gi)) {
    const n = Number(match[1]);
    if (n !== MUTATIONS) problems.push(doc + ': says "' + match[0] + '" but the gate injects ' + MUTATIONS);
  }
}

const WORDS = { eight: 8, seven: 7, fifteen: 15, sixteen: 16, eighteen: 18 };
for (const doc of DOCS) {
  const text = readFileSync(join(REPO, doc), 'utf8');
  for (const match of text.matchAll(/\b(eight|seven|fifteen|sixteen)\s+injected faults/gi)) {
    const n = WORDS[match[1].toLowerCase()];
    if (n !== MUTATIONS) problems.push(doc + ': says "' + match[0] + '" but the gate injects ' + MUTATIONS);
  }
}

if (problems.length) {
  console.error('CLAIMS FAILED:');
  for (const p of problems) console.error('  - ' + p);
  process.exitCode = 1;
} else {
  console.log('claims: ' + TESTS + ' tests (' + INVARIANTS + ' invariants + ' + ATTACKS + ' attacks + ' +
    AUDITOR + ' auditor), ' + MUTATIONS + ' injected faults - every document agrees');
}

export default live;
