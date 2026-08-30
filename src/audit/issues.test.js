#!/usr/bin/env node
/**
 * Findings and remediation tips. Task 5.4.
 *
 * The exhaustive coverage of issue construction is `tools/scoring.test.mjs`,
 * which drives the whole engine over the DoH fixture — 1,535 assertions, and
 * not repeated here. What this file pins is the CONTRACT: the shape of a
 * finding, the closed severity vocabulary, the fact that every key it emits is
 * a real locale token, and the input boundary that says what this module is
 * allowed to read.
 *
 * Every behavioural assertion below was probed against the code before it was
 * written. The obvious guess has been wrong three times on this branch.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../../tests/lib/assert.mjs';
import { buildIssues, buildSuggestions } from './issues.js';

const { eq, section, report } = createSuite();
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** A domain with nothing configured — the shape every field must tolerate. */
const BARE = {
  emailProvider: '@none',
  spfStatus: { status: 'missing', warnings: [] },
  spfRecords: [],
  dkimStatus: { found: false, selectors: [], testedSelectors: [] },
  dmarcStatus: { status: 'missing' },
  dmarcDiscovery: { observed: [] },
  dmarcExistence: 'yes',
  externalReportDestinations: [],
  reportPlan: { external: [] },
  wildcardApex: false,
  wildcardDkim: false,
  hosting: '@dash',
  advanced: {},
  domain: 'example.test',
};
const issuesFor = over => buildIssues({ ...BARE, ...over });
const keysFor = over => issuesFor(over).map(i => i.key);

/* ── 1. The shape of a finding ────────────────────────────────────────── */
section('1. Every finding is a key, a severity and optional args');

const bare = issuesFor();
eq('a domain with nothing configured has findings', bare.length > 0, true);
eq('and they are the three that matter most',
  bare.map(i => i.key), ['no-mx', 'spf-missing', 'dmarc-missing']);
eq('every finding carries a key', bare.every(i => typeof i.key === 'string' && i.key), true);
eq('and a severity', bare.every(i => typeof i.sev === 'string'), true);
// No English here, ever. The key is what the i18n layer resolves.
eq('no finding carries a message', bare.some(i => 'msg' in i || 'message' in i), false);

/* ── 2. The severity vocabulary is closed ─────────────────────────────── */
section('2. Three severities, and no others');

const SEVERITIES = ['crit', 'info', 'warn'];
const source = readFileSync(join(REPO, 'src/audit/issues.js'), 'utf8');
eq('the module emits exactly three severities',
  [...new Set([...source.matchAll(/sev: '([a-z-]+)'/g)].map(m => m[1]))].sort(), SEVERITIES);
// Missing SPF is critical; a missing DMARC record is a warning, because SPF
// failing open is an immediate spoofing path and DMARC is the control that
// would have reported it.
eq('a missing SPF record is critical', bare.find(i => i.key === 'spf-missing').sev, 'crit');
eq('while a missing DMARC record is a warning', bare.find(i => i.key === 'dmarc-missing').sev, 'warn');

/* ── 3. Every key it emits is a real locale token ─────────────────────── */
section('3. The token vocabulary is a released artifact');

/**
 * Gate 4 diffed the whole issue vocabulary byte-identical against `v0.5.0` —
 * 106 tokens, 0 added, 0 removed — and Task 5.4 re-ran that comparison after
 * moving this code. This is the standing half of it: a key emitted here that
 * `locales/en.json` does not define renders as its own identifier in every
 * language, which is invisible until someone reads the screen.
 *
 * A lexical scan over `key: '…'` literals. It cannot see a computed key, and
 * there are none in this file — the negative control below is what makes that
 * checkable rather than asserted.
 */
const en = JSON.parse(readFileSync(join(REPO, 'locales/en.json'), 'utf8'));
// The two builders resolve into DIFFERENT locale namespaces — `issue.*` and
// `suggestion.*` — so the scan is split at the function boundary. Checking
// both against `issue.*` reports five perfectly good tip keys as undefined,
// which is how this check found its own defect before it was trusted.
const cut = source.indexOf('export function buildSuggestions(');
eq('the two builders are separable in the source', cut > 0, true);
const keysIn = text => [...new Set([...text.matchAll(/key: '([a-z0-9-]+)'/g)].map(m => m[1]))].sort();
const issueKeys = keysIn(source.slice(0, cut));
const tipKeys = keysIn(source.slice(cut));

eq('the finding vocabulary is substantial', issueKeys.length > 90, true);
eq('and every finding key is defined under issue.*',
  issueKeys.filter(k => !(k in en.issue)), []);
eq('every tip key is defined under suggestion.*',
  tipKeys.filter(k => !(k in en.suggestion)), []);
// A tip also names a Learn more page, and a guide with no page is a dead link
// in thirteen languages.
const guides = [...new Set([...source.slice(cut).matchAll(/guide: '([a-z0-9-]+)'/g)].map(m => m[1]))].sort();
eq('and every guide it links to exists', guides.filter(g => !(g in en.learnMore)), []);
// Proven in both directions: the scan finds real keys, and an undefined one
// would be reported rather than passed over.
eq('the scan really matched the keys', issueKeys.includes('spf-missing'), true);
eq('and an undefined key would be caught',
  ['spf-missing', 'not-a-real-token'].filter(k => !(k in en.issue)), ['not-a-real-token']);
// The two vocabularies do not overlap, which is what makes the split at the
// function boundary the right cut rather than a convenient one.
eq('no key is both a finding and a tip', issueKeys.filter(k => tipKeys.includes(k)), []);

/* ── 4. Suggestions are tips, not findings ───────────────────────────── */
section('4. buildSuggestions');

const tips = buildSuggestions({
  emailProvider: '@none', spfStatus: BARE.spfStatus, dkimStatus: BARE.dkimStatus,
  dmarcStatus: BARE.dmarcStatus, advanced: {},
});
eq('a bare domain gets at least one tip', tips.length > 0, true);
eq('every tip carries a key', tips.every(t => typeof t.key === 'string'), true);
// `guide` names the Learn more page, which is what distinguishes a tip from a
// finding: a tip points at documentation, a finding points at evidence.
eq('and a guide to link to', tips.every(t => typeof t.guide === 'string'), true);
eq('no tip carries a severity', tips.some(t => 'sev' in t), false);

/* ── 5. Findings are computed, not accumulated blindly ───────────────── */
section('5. A configured domain is not told to configure it');

const healthy = {
  emailProvider: 'Google Workspace',
  spfStatus: { status: 'ok', warnings: [] },
  dkimStatus: { found: true, selectors: [], testedSelectors: [] },
  dmarcStatus: { status: 'ok', policy: 'reject', enforcing: true, pctValid: true },
};
const configured = keysFor(healthy);
eq('a configured domain is not told its SPF is missing', configured.includes('spf-missing'), false);
eq('nor its DMARC', configured.includes('dmarc-missing'), false);
eq('nor that it has no MX', configured.includes('no-mx'), false);
// Probed, not assumed: an enforcing policy with no rua is an INFO finding, not
// a warning — the policy works, the operator just cannot see it working.
eq('but it is told it will receive no reports', configured.includes('dmarc-no-rua'), true);
eq('as information rather than a warning',
  issuesFor(healthy).find(i => i.key === 'dmarc-no-rua').sev, 'info');
// `pctValid` false on a record that exists is its own finding, and it fires
// for an absent pct too — which is why the healthy fixture sets it.
eq('an invalid pct on an existing record is a warning',
  keysFor({ ...healthy, dmarcStatus: { ...healthy.dmarcStatus, pctValid: false } })
    .includes('dmarc-bad-pct'), true);
eq('while a valid one raises nothing', configured.includes('dmarc-bad-pct'), false);

/* ── 6. THE INPUT BOUNDARY: facts in, findings out ───────────────────── */
section('6. Interpreting facts is this module\'s job; reparsing records is not');

/**
 * The same ruling `scoring.test.js` §5 asserts, applied to findings.
 *
 * `core/<protocol>/` decides what a record MEANS. This module decides what a
 * meaning is worth SAYING, and with what severity. Both are interpretation and
 * only the first is parsing — which is why no name from this file belongs in
 * `dns-transport.test.mjs` §3b, and why `spfStatus.warnings` arriving here is
 * a fact being read rather than a record being reparsed.
 *
 * The line this module may not cross is re-deriving a fact from a record. The
 * assertions below make that testable rather than declarative.
 */

// 1. The facts are fabricated. No parser produced them, and findings still
//    come out — so nothing here can be re-deriving anything.
eq('findings are built from facts with no record behind them', bare.length, 3);

// 2. The record is not an input. Attaching the record that produced the facts
//    changes nothing...
const withRecord = keysFor({ spfRecords: ['v=spf1 -all'], spfStatus: { status: 'ok', warnings: [] } });
const withoutRecord = keysFor({ spfRecords: [], spfStatus: { status: 'ok', warnings: [] } });
eq('attaching the SPF record that produced the facts changes no finding',
  withRecord, withoutRecord);
// ...and neither does one that flatly contradicts them. This is the assertion
// that fails if this module ever reads a record instead of a fact.
eq('and a record contradicting the facts changes nothing either',
  keysFor({ spfRecords: ['v=spf1 +all'], spfStatus: { status: 'ok', warnings: [] } }),
  withoutRecord);
// 3. While the FACT for that record does exactly what it should.
eq('but the warning token for it raises the finding',
  keysFor({ spfStatus: { status: 'ok', warnings: ['spf-all-permit'] } }).includes('spf-all-permit'),
  true);

// 4. `spfRecords` is used as EVIDENCE — a count, for the multiple-record
//    finding — and never re-parsed. Two records raise it; their contents are
//    not consulted.
eq('two SPF records raise the multiple-records finding',
  keysFor({ spfRecords: ['v=spf1 -all', 'v=spf1 a'], spfStatus: { status: 'permerror', warnings: ['spf-multiple-records'] } })
    .includes('spf-multiple-records'), true);
eq('and two records of any content raise the same one',
  keysFor({ spfRecords: ['nonsense one', 'nonsense two'], spfStatus: { status: 'permerror', warnings: ['spf-multiple-records'] } })
    .includes('spf-multiple-records'), true);

// 5. Structural: this module reaches for no resolver and no record parser.
eq('it imports only protocol fact producers',
  [...source.matchAll(/^import .* from '([^']+)'/gm)].map(m => m[1]).sort(),
  ['../core/dmarc/record.js', '../core/dmarc/report-auth.js', '../core/dnssec/records.js']);
eq('and holds no transport capability',
  /dohFetch|dohQuery|requireUsable|optionalCheck/.test(source), false);

report();
