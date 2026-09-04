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

/* ── 3. Four vocabularies, and the fourteen keys no literal scan sees ── */
section('3. The token vocabularies');

/**
 * Gate 4 diffed the issue vocabulary byte-identical against `v0.5.0` — 106
 * tokens — and Task 5.4 re-ran it after the move. This is the standing half:
 * a key emitted here that `locales/en.json` does not define renders as its own
 * identifier in every language, which is invisible until someone reads it.
 *
 * ── Four vocabularies, kept apart ───────────────────────────────────────
 *
 * The first draft of this check scanned `key: '…'` across the whole file and
 * tested every hit against `en.issue`. It was wrong twice over: the two
 * builders resolve into DIFFERENT namespaces, and — the part that mattered —
 * **a literal scan sees only 92 of the 106 issue keys.** It passed on
 * `issueKeys.length > 90`, which is green for the wrong reason.
 *
 * | Vocabulary | Resolves through | Found by |
 * | --- | --- | --- |
 * | Direct literal issue keys | `en.issue` | a `key: '…'` scan of `buildIssues` |
 * | **Computed / forwarded issue keys** | `en.issue` | **nothing lexical** — the reviewed registry is the source of truth |
 * | Suggestion keys | `en.suggestion` | a `key: '…'` scan of `buildSuggestions` |
 * | Learn-more guides | `en.learnMore` | a `guide: '…'` scan |
 *
 * `legacy-shapes.test.mjs` §6 is the other half of this: it proves the literal
 * scan under-reports, which is why `tests/state-algebras.json` is a REVIEWED
 * document rather than an extracted one.
 */
const en = JSON.parse(readFileSync(join(REPO, 'locales/en.json'), 'utf8'));
const registry = JSON.parse(readFileSync(join(REPO, 'tests/state-algebras.json'), 'utf8'));
const issueAlgebra = registry.algebras.find(a => a.id === 'audit.issue.key').members.slice().sort();
const spfWarnings = registry.algebras.find(a => a.id === 'spf.warnings').members.slice().sort();

const cut = source.indexOf('export function buildSuggestions(');
eq('the two builders are separable in the source', cut > 0, true);
const occurrencesIn = text => [...text.matchAll(/key: '([a-z0-9-]+)'/g)].map(m => m[1]);
const literalIssueKeys = [...new Set(occurrencesIn(source.slice(0, cut)))].sort();
const tipKeys = [...new Set(occurrencesIn(source.slice(cut)))].sort();

eq('the registry records 111 issue tokens', issueAlgebra.length, 111);
eq('and they are exactly the locale issue keys', issueAlgebra, Object.keys(en.issue).sort());

/* ── 3a. Direct literals ─────────────────────────────────────────────── */
eq('buildIssues writes 98 key literals', occurrencesIn(source.slice(0, cut)).length, 98);
eq('which are 97 distinct keys — one is written twice', literalIssueKeys.length, 97);
eq('every literal is a registry member', literalIssueKeys.filter(k => !issueAlgebra.includes(k)), []);
eq('and every literal has a locale entry', literalIssueKeys.filter(k => !(k in en.issue)), []);

/* ── 3b. The fourteen a literal scan cannot see ──────────────────────── */

/**
 * **Reviewed inventory, with the mechanism that emits each.** Not derived from
 * the source — that is the whole point — but pinned against it in both
 * directions below, so neither this list nor the registry can drift alone.
 */
const NON_LITERAL_ISSUE_KEYS = {
  'dkim-missing': 'the DKIM confidence ternary',
  'dkim-unverified': 'the DKIM confidence ternary',
  'dmarc-version-not-first': 'the DIAGNOSIS_KEYS table',
  'dmarc-version-bad-value': 'the DIAGNOSIS_KEYS table',
  'dmarc-version-missing': 'the DIAGNOSIS_KEYS table',
  'dnssec-key-algorithm-ineligible': 'pushKeyFinding()',
  'dnssec-key-not-zone-key': 'pushKeyFinding()',
  'dnssec-key-malformed': 'pushKeyFinding()',
  'spf-all-permit': 'forwarded from spf.warnings',
  'spf-neutral': 'forwarded from spf.warnings',
  'spf-softfail': 'forwarded from spf.warnings',
  'spf-missing-google': 'forwarded from spf.warnings',
  'spf-missing-icloud': 'forwarded from spf.warnings',
  'spf-missing-microsoft': 'forwarded from spf.warnings',
};
const nonLiteral = Object.keys(NON_LITERAL_ISSUE_KEYS).sort();

eq('fourteen issue keys are emitted without ever being written as a literal',
  nonLiteral.length, 14);
// The two directions that stop the inventory and the registry drifting apart.
eq('the inventory is exactly the registry minus the literals',
  nonLiteral, issueAlgebra.filter(k => !literalIssueKeys.includes(k)));
eq('so literals plus non-literals close the 111-member vocabulary',
  [...literalIssueKeys, ...nonLiteral].sort(), issueAlgebra);
eq('every one of the fourteen has a locale entry',
  nonLiteral.filter(k => !(k in en.issue)), []);
// And each really is invisible to the scan — the blind spot, asserted where
// the code lives rather than only in the contract file.
eq('none of the fourteen appears as a key literal',
  nonLiteral.filter(k => literalIssueKeys.includes(k)), []);
// Four mechanisms, named. A fifth would be a decision, not a drift.
eq('and they arrive by four mechanisms',
  [...new Set(Object.values(NON_LITERAL_ISSUE_KEYS))].sort(),
  ['forwarded from spf.warnings', 'pushKeyFinding()', 'the DIAGNOSIS_KEYS table',
    'the DKIM confidence ternary']);

/* ── 3c. Their emission paths, exercised ─────────────────────────────── */

// The DKIM ternary: one branch each, chosen by `confidence`.
const dkimKeys = confidence => keysFor({
  emailProvider: 'Google Workspace',
  dkimStatus: { found: false, confidence, selectors: [], testedSelectors: [] },
});
eq('a sampled DKIM scan reports unverified', dkimKeys('sampled').includes('dkim-unverified'), true);
eq('any other confidence reports missing', dkimKeys('full').includes('dkim-missing'), true);
eq('and the two are exclusive', dkimKeys('sampled').includes('dkim-missing'), false);

// DIAGNOSIS_KEYS: the walk's `why` value selects the token.
const diagnosis = why => keysFor({
  dmarcDiscovery: { observed: [{ why, queryName: '_dmarc.example.test' }] },
});
eq('a version field that is not first is diagnosed',
  diagnosis('version-not-first').includes('dmarc-version-not-first'), true);
eq('a bad version value is diagnosed',
  diagnosis('version-bad-case').includes('dmarc-version-bad-value'), true);
eq('an absent version is diagnosed',
  diagnosis('version-absent').includes('dmarc-version-missing'), true);
// It names the DNS name the broken record is actually at — the walk visits up
// to eight names, and an unlocated finding sends the operator to the wrong zone.
eq('and the finding names where the record was found',
  issuesFor({ dmarcDiscovery: { observed: [{ why: 'version-absent', queryName: '_dmarc.parent.test' }] } })
    .find(i => i.key === 'dmarc-version-missing').args, ['_dmarc.parent.test']);

// pushKeyFinding: a confirmed DS whose matched key has a defect.
const keyFinding = over => keysFor({
  advanced: { dnssec: { signed: true, ds: [{ match: 'confirmed', matchedKeyTag: 12345, ...over }] } },
});
eq('an ineligible algorithm on a confirmed key is reported',
  keyFinding({ matchedKeyAlgorithmEligibility: 'ineligible' }).includes('dnssec-key-algorithm-ineligible'), true);
eq('a missing zone flag is reported',
  keyFinding({ matchedKeyHasZoneFlag: false }).includes('dnssec-key-not-zone-key'), true);
eq('an invalid key structure is reported',
  keyFinding({ matchedKeyStructure: 'invalid' }).includes('dnssec-key-malformed'), true);
// Reported separately because they have different remedies, not merged.
eq('and a key with all three defects raises all three',
  keyFinding({ matchedKeyAlgorithmEligibility: 'ineligible', matchedKeyHasZoneFlag: false, matchedKeyStructure: 'invalid' })
    .filter(k => k.startsWith('dnssec-key-')).sort(),
  ['dnssec-key-algorithm-ineligible', 'dnssec-key-malformed', 'dnssec-key-not-zone-key']);

/**
 * The forwarded SPF warnings, and the precondition that makes forwarding safe.
 *
 * `buildIssues()` does `spfStatus.warnings.forEach(key => issues.push({ key }))`
 * — it does not filter, and it does not know the vocabulary. **It TRUSTS the
 * closed `spf.warnings` algebra its owner produces.** That is a compositional
 * precondition, not a property of this function, and stating it the other way
 * round would be a false claim: arbitrary fabricated input forwards an
 * arbitrary token, which is asserted below rather than glossed over.
 */
const SIX_FORWARDED = nonLiteral.filter(k => k.startsWith('spf-'));
eq('six of the fourteen are forwarded SPF warnings', SIX_FORWARDED.length, 6);
eq('each is a member of the closed spf.warnings algebra',
  SIX_FORWARDED.filter(k => !spfWarnings.includes(k)), []);
for (const token of SIX_FORWARDED) {
  eq(`${token} is forwarded as a warning`,
    issuesFor({ spfStatus: { status: 'ok', warnings: [token] } }).find(i => i.key === token).sev, 'warn');
}
// The seventh member is deliberately NOT forwarded: on a permerror the record
// never evaluates, and `spf-multiple-records` is already raised as critical
// above — re-pushing it would list one finding twice at two severities.
eq('the seventh member is spf-multiple-records', spfWarnings.filter(k => !SIX_FORWARDED.includes(k)), ['spf-multiple-records']);
eq('and it is not forwarded, because a permerror suppresses the whole loop',
  issuesFor({ spfStatus: { status: 'permerror', warnings: ['spf-multiple-records'] } })
    .filter(i => i.key === 'spf-multiple-records').length, 1);
// The precondition, stated honestly: this function does not validate the
// vocabulary, so the owner's algebra being closed is what keeps it closed.
eq('an arbitrary fabricated token would be forwarded verbatim',
  keysFor({ spfStatus: { status: 'ok', warnings: ['not-a-real-token'] } }).includes('not-a-real-token'), true);
eq('which is why the owner algebra is the control, not a filter here',
  /warnings\.forEach/.test(source), true);

/* ── 3d. Suggestions and guides ──────────────────────────────────────── */
eq('every tip key is defined under suggestion.*', tipKeys.filter(k => !(k in en.suggestion)), []);
const guides = [...new Set([...source.slice(cut).matchAll(/guide: '([a-z0-9-]+)'/g)].map(m => m[1]))].sort();
eq('and every guide it links to exists', guides.filter(g => !(g in en.learnMore)), []);
eq('no key is both a finding and a tip', literalIssueKeys.filter(k => tipKeys.includes(k)), []);
// The scan is proven able to fail, in both namespaces.
eq('the scan really matched the finding keys', literalIssueKeys.includes('spf-missing'), true);
eq('and an undefined key would be caught',
  ['spf-missing', 'not-a-real-token'].filter(k => !(k in en.issue)), ['not-a-real-token']);

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

/* ── 6. THE INPUT BOUNDARY: facts and evidence in, findings out ──────── */
section('6. Interpreting facts is this module\'s job; reparsing records is not');

/**
 * The same ruling `scoring.test.js` §5 asserts, applied to findings — and
 * stated more carefully than the first draft managed.
 *
 * **"The record is not an input" was too strong and simply false.**
 * `spfRecords` IS an input: `spf-multiple-records` carries
 * `args: [spfRecords.length || 2]`, because saying "2" costs nothing and tells
 * the operator how many records conflicted. The rule is narrower and sharper:
 *
 * | May be consumed | May not |
 * | --- | --- |
 * | Owner-produced FACTS — `spfStatus.status`, `spfStatus.warnings`, `dmarcStatus.removedTags`, `advanced.dnssec.ds[].match` | Record CONTENTS — nothing here parses or interprets the text of a record |
 * | EVIDENCE about those records, including how many there are | — |
 *
 * `core/<protocol>/` decides what a record MEANS. This module decides what a
 * meaning is worth SAYING, and with what severity. If a finding ever needs
 * something no owner reports, the owner grows the fact; a record must not be
 * re-read here to recover it.
 */

// 1. The facts are fabricated. No parser produced them, and findings still
//    come out — so nothing here can be re-deriving anything.
eq('findings are built from facts with no record behind them', bare.length, 3);

// 2. CONTENTS are never read. Two record sets of the SAME cardinality and
//    contradictory contents must produce completely identical findings — not
//    just the same keys, but the same severities and the same args. This is
//    the assertion that fails if any record text is ever parsed here.
const permerror = { status: 'permerror', warnings: ['spf-multiple-records'] };
const strict = issuesFor({ spfRecords: ['v=spf1 -all', 'v=spf1 a'], spfStatus: permerror });
const permissive = issuesFor({ spfRecords: ['v=spf1 +all', 'nonsense at all'], spfStatus: permerror });
eq('two record sets of equal cardinality and opposite contents are identical findings',
  strict, permissive);
eq('down to the arguments', strict.map(i => i.args), permissive.map(i => i.args));
// The same, one field over: an SPF record attached to an ok status changes no
// finding, whatever it says.
const okFacts = { status: 'ok', warnings: [] };
eq('a record attached to an ok status changes nothing',
  issuesFor({ spfRecords: ['v=spf1 -all'], spfStatus: okFacts }),
  issuesFor({ spfRecords: [], spfStatus: okFacts }));
eq('and neither does one contradicting it',
  issuesFor({ spfRecords: ['v=spf1 +all'], spfStatus: okFacts }),
  issuesFor({ spfRecords: [], spfStatus: okFacts }));

// 3. CARDINALITY is evidence, and it is consumed. Under the owner's permerror
//    fact, how many records there are changes the finding's arguments — which
//    is the half the "not an input" wording got wrong.
eq('three conflicting records say three',
  issuesFor({ spfRecords: ['a', 'b', 'c'], spfStatus: permerror })
    .find(i => i.key === 'spf-multiple-records').args, [3]);
eq('two say two',
  issuesFor({ spfRecords: ['a', 'b'], spfStatus: permerror })
    .find(i => i.key === 'spf-multiple-records').args, [2]);
// The fallback exists because the permerror fact is the owner's, and a caller
// that supplies no evidence still gets a truthful minimum rather than a zero.
eq('and no evidence at all falls back to the minimum the fact implies',
  issuesFor({ spfRecords: [], spfStatus: permerror })
    .find(i => i.key === 'spf-multiple-records').args, [2]);

// 4. The FACT is what raises a finding, never the record that produced it.
eq('the warning token raises the finding',
  keysFor({ spfStatus: { status: 'ok', warnings: ['spf-all-permit'] } }).includes('spf-all-permit'),
  true);
eq('while the record that would justify it, alone, raises nothing',
  keysFor({ spfRecords: ['v=spf1 +all'], spfStatus: okFacts }).includes('spf-all-permit'), false);

// 5. Structural: this module reaches for no resolver and no record parser.
eq('it imports only protocol fact producers',
  [...source.matchAll(/^import .* from '([^']+)'/gm)].map(m => m[1]).sort(),
  ['../core/dmarc/record.js', '../core/dmarc/report-auth.js', '../core/dnssec/records.js']);
eq('and holds no transport capability',
  /dohFetch|dohQuery|requireUsable|optionalCheck/.test(source), false);

/* ── 6. 0.9.1: the MX address-validity emission paths ─────────────────── */
section('6. MX address validity');

// A host is a full mxHealth host record; buildIssues reads reachability,
// isAddressLiteral and the two record-level flags.
const mxHost = over => ({
  host: 'mail.example.test', preference: 10, preferences: [10], addresses: [],
  v4Count: 0, v6Count: 0, resolves: 'yes', isCname: false, cnameUnknown: false,
  inAudited: false, isAddressLiteral: false, addressScopes: [], reachability: 'global',
  ...over,
});
const mxKeys = (hosts, top = {}) => keysFor({
  advanced: {
    mxHealth: {
      hosts, danglingHosts: [], cnameHosts: [], duplicatePreferences: [],
      singleHost: false, ipv6Coverage: 'all', sharedPrefixes: [], unknown: false,
      addressLiteralHosts: [], unroutableHosts: [], partiallyRoutableHosts: [],
      nullMxConflict: false, invalidPreferences: [], ...top,
    },
  },
});

const unroutable = mxKeys([mxHost({
  addresses: ['127.0.0.1'], v4Count: 1, reachability: 'none',
  addressScopes: [{ address: '127.0.0.1', scope: 'loopback' }],
})]);
eq('an unreachable host is reported', unroutable.includes('mx-unroutable'), true);
// It resolved, so it is not dangling — which is why it went unreported before.
eq('and not as dangling', unroutable.includes('mx-dangling'), false);

const mixed = mxKeys([mxHost({
  addresses: ['210.71.187.212', '10.0.0.4'], v4Count: 2, reachability: 'partial',
  addressScopes: [{ address: '210.71.187.212', scope: 'global' },
    { address: '10.0.0.4', scope: 'private' }],
})]);
eq('a partly reachable host is reported', mixed.includes('mx-partially-routable'), true);
eq('and is not also called unreachable', mixed.includes('mx-unroutable'), false);

// The argument names the address and its space: a host name alone does not
// tell the operator which record to change.
const unroutableArgs = issuesFor({
  advanced: { mxHealth: {
    hosts: [mxHost({ addresses: ['10.0.0.4'], v4Count: 1, reachability: 'none',
      addressScopes: [{ address: '10.0.0.4', scope: 'private' }] })],
    danglingHosts: [], cnameHosts: [], duplicatePreferences: [], singleHost: false,
    ipv6Coverage: 'all', sharedPrefixes: [], unknown: false, addressLiteralHosts: [],
    unroutableHosts: [], partiallyRoutableHosts: [], nullMxConflict: false,
    invalidPreferences: [],
  } },
}).find(i => i.key === 'mx-unroutable');
eq('and it names the address and its scope',
  unroutableArgs.args, ['mail.example.test', '10.0.0.4 (private)']);

eq('an address literal is reported',
  mxKeys([mxHost({ host: '203.0.113.5', resolves: 'no', isAddressLiteral: true,
    reachability: 'unknown' })], { addressLiteralHosts: ['203.0.113.5'] })
    .includes('mx-address-literal'), true);

eq('a null MX beside a real host is reported',
  mxKeys([mxHost({})], { nullMxConflict: true }).includes('mx-null-conflict'), true);
eq('and an ordinary set raises nothing',
  mxKeys([mxHost({})]).includes('mx-null-conflict'), false);

eq('an out-of-range preference is reported',
  mxKeys([mxHost({})], { invalidPreferences: [99999] }).includes('mx-invalid-preference'), true);

// A healthy host raises none of the five.
eq('a globally reachable host raises no address-validity finding',
  mxKeys([mxHost({ addresses: ['210.71.187.212'], v4Count: 1,
    addressScopes: [{ address: '210.71.187.212', scope: 'global' }] })])
    .filter(k => /^mx-(unroutable|partially-routable|address-literal|null-conflict|invalid-preference)$/.test(k)),
  []);

// Regression: buildIssues is reached with contexts assembled elsewhere, and an
// mxHealth predating 0.9.1 carries none of these fields. Reading them
// unguarded threw a TypeError and discarded the whole audit, not just the MX
// section — the first version of this release did exactly that.
const preRelease = () => keysFor({
  advanced: { mxHealth: {
    hosts: [{ host: 'mail.example.test', preference: 10, preferences: [10],
      addresses: ['210.71.187.212'], v4Count: 1, v6Count: 0, resolves: 'yes',
      isCname: false, cnameUnknown: false, inAudited: false }],
    danglingHosts: [], cnameHosts: [], duplicatePreferences: [], singleHost: false,
    ipv6Coverage: 'all', sharedPrefixes: [], unknown: false,
  } },
});
eq('an mxHealth without the 0.9.1 fields does not throw', typeof preRelease(), 'object');
eq('and reports none of the five', preRelease()
  .filter(k => /^mx-(unroutable|partially-routable|address-literal|null-conflict|invalid-preference)$/.test(k)), []);

report();
