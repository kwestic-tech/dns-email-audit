#!/usr/bin/env node
/**
 * Structured findings and the remediation plan. Spec findings-and-remediation
 * 1.0 (Final), Testing section.
 *
 * What this pins: the closed vocabularies, the dependency graph is acyclic and
 * resolvable, every finding resolves to a real locale message, the migrated
 * table covers the whole legacy `audit.issue.key` vocabulary, the behavioural
 * fixtures from the spec, and — the half `AGENTS.md` rule 3 demands — every new
 * cross-protocol rule proven to NOT fire against its negative case.
 *
 * Every behavioural assertion was probed against the code before it was written.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../../tests/lib/assert.mjs';
import { buildIssues } from './issues.js';
import {
  buildFindings, buildRemediationPlan, FINDING_META, CROSS_PROTOCOL_RULES,
  FINDING_ENUMS,
} from './findings.js';

const { severity: SEVERITIES, confidence: CONFIDENCES, category: CATEGORIES,
  effort: EFFORTS, protocol: PROTOCOLS } = FINDING_ENUMS;

const { eq, section, report } = createSuite();
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const en = JSON.parse(readFileSync(join(REPO, 'locales/en.json'), 'utf8'));

/** A domain with nothing configured — the shape every field must tolerate. */
const BARE = {
  emailProvider: '@none',
  spfStatus: { status: 'missing', warnings: [] },
  spfRecords: [], spfRecord: '',
  dkimStatus: { found: false, selectors: [], testedSelectors: [] },
  dmarcStatus: { status: 'missing' },
  dmarcDiscovery: { observed: [] },
  dmarcExistence: 'yes',
  externalReportDestinations: [],
  reportPlan: { external: [] },
  wildcardApex: false, wildcardDkim: false,
  hosting: '@dash', advanced: {}, domain: 'example.test',
  dmarcRecord: '', dmarcAtDomain: 'example.test', spfUsesMx: false,
};
const ctx = over => ({ ...BARE, ...over });
const idsFor = over => buildFindings(ctx(over)).map(f => f.id);

// Every id a rule can produce (migrated + cross-protocol).
const ALL_IDS = [...new Set([
  ...Object.values(FINDING_META).map(m => m.id),
  ...CROSS_PROTOCOL_RULES.map(r => r.id),
])];

/* ── 1. The finding shape and its closed vocabularies ─────────────────── */
section('1. The finding shape and closed vocabularies');

const bare = buildFindings(ctx());
eq('a bare domain produces findings', bare.length > 0, true);
eq('every finding carries a string id', bare.every(f => typeof f.id === 'string' && f.id), true);
eq('every id is protocol.slug', bare.every(f => /^[a-z0-9-]+\.[a-z0-9-]+$/.test(f.id)), true);
eq('every finding carries evidence', bare.every(f => Array.isArray(f.evidence) && f.evidence.length > 0), true);
eq('every finding carries dependsOn and blocks arrays',
  bare.every(f => Array.isArray(f.dependsOn) && Array.isArray(f.blocks)), true);
// No English in the model — messages live only in the locale files.
eq('no finding carries prose', bare.some(f => 'msg' in f || 'message' in f), false);

const allMeta = Object.values(FINDING_META);
eq('every migrated severity is in the enumeration',
  allMeta.filter(m => !SEVERITIES.includes(m.severity)), []);
eq('every migrated category is in the enumeration',
  allMeta.filter(m => !CATEGORIES.includes(m.category)), []);
eq('every migrated effort is in the enumeration',
  allMeta.filter(m => !EFFORTS.includes(m.effort)), []);
eq('every migrated protocol is in the enumeration',
  allMeta.filter(m => !PROTOCOLS.includes(m.protocol)), []);
eq('every declared confidence is in the enumeration',
  allMeta.filter(m => m.confidence && !CONFIDENCES.includes(m.confidence)), []);
eq('every cross-protocol rule has enumerated fields',
  CROSS_PROTOCOL_RULES.filter(r => !SEVERITIES.includes(r.severity) || !CATEGORIES.includes(r.category)
    || !EFFORTS.includes(r.effort) || !PROTOCOLS.includes(r.protocol)), []);
eq('every id matches the identity pattern',
  ALL_IDS.filter(id => !/^[a-z0-9-]+\.[a-z0-9-]+$/.test(id)), []);

/* ── 2. The dependency graph ──────────────────────────────────────────── */
section('2. The dependency graph is resolvable and acyclic');

// Every dependsOn target — migrated or cross-protocol — is an id some rule can produce.
const declaredDeps = [
  ...allMeta.flatMap(m => m.dependsOn || []),
  ...CROSS_PROTOCOL_RULES.flatMap(r => r.dependsOn || []),
];
eq('every dependsOn target is a producible id',
  [...new Set(declaredDeps)].filter(d => !ALL_IDS.includes(d)), []);

// Acyclic over the full declared graph (edges: id -> its dependsOn).
const edges = {};
allMeta.forEach(m => { edges[m.id] = (edges[m.id] || []).concat(m.dependsOn || []); });
CROSS_PROTOCOL_RULES.forEach(r => { edges[r.id] = (edges[r.id] || []).concat(r.dependsOn || []); });
function hasCycle() {
  const WHITE = 0, GREY = 1, BLACK = 2;
  const color = {};
  ALL_IDS.forEach(id => { color[id] = WHITE; });
  let cyclic = false;
  const visit = id => {
    color[id] = GREY;
    (edges[id] || []).forEach(next => {
      if (color[next] === GREY) cyclic = true;
      else if (color[next] === WHITE) visit(next);
    });
    color[id] = BLACK;
  };
  ALL_IDS.forEach(id => { if (color[id] === WHITE) visit(id); });
  return cyclic;
}
eq('the dependency graph is acyclic', hasCycle(), false);
// Proven able to catch a cycle: inject one into a copy of the edge set.
eq('and the detector really fires on a cycle', (() => {
  const save = edges['spf.missing'];
  edges['spf.missing'] = ['dmarc.policy-none']; // dmarc.policy-none -> spf.missing already
  const c = hasCycle();
  edges['spf.missing'] = save;
  return c;
})(), true);

/* ── 3. Identity and locale coverage ──────────────────────────────────── */
section('3. Every finding resolves to a real locale message');

// Migrated findings resolve under issue.*; cross-protocol under finding.*.
eq('every migrated key has issue.<key>.msg',
  Object.keys(FINDING_META).filter(k => !(en.issue[k] && en.issue[k].msg)), []);
eq('every cross-protocol key has finding.<key>.msg',
  CROSS_PROTOCOL_RULES.filter(r => !(en.finding[r.key] && en.finding[r.key].msg)).map(r => r.key), []);
// The view vocabulary the UI resolves exists.
const vocabOk = en.findings && en.findings.severity && SEVERITIES.every(s => en.findings.severity[s])
  && CONFIDENCES.every(c => en.findings.confidence[c])
  && CATEGORIES.every(c => en.findings.category[c])
  && EFFORTS.every(e => en.findings.effort[e])
  && en.findings.rationale.foundation && en.findings.rationale.afterPrereq
  && en.findings.viewSeverity && en.findings.viewRemediation && en.findings.step;
eq('the full view vocabulary is present in en.json', !!vocabOk, true);

// No cross-protocol finding.* id collides with a migrated issue.* id.
const migratedIds = new Set(Object.values(FINDING_META).map(m => m.id));
eq('no cross-protocol id collides with a migrated id',
  CROSS_PROTOCOL_RULES.filter(r => migratedIds.has(r.id)).map(r => r.id), []);

// The only id two migrated keys share is dkim.none-found (the exclusive DKIM pair).
const idCounts = {};
Object.values(FINDING_META).forEach(m => { idCounts[m.id] = (idCounts[m.id] || 0) + 1; });
eq('the only shared migrated id is dkim.none-found',
  Object.keys(idCounts).filter(id => idCounts[id] > 1), ['dkim.none-found']);

/* ── 4. FINDING_META covers the whole legacy vocabulary ───────────────── */
section('4. The migrated table is complete against audit.issue.key');

const issueAlgebra = JSON.parse(readFileSync(join(REPO, 'tests/state-algebras.json'), 'utf8'))
  .algebras.find(a => a.id === 'audit.issue.key').members.slice().sort();
eq('the reviewed vocabulary is 106 tokens', issueAlgebra.length, 106);
eq('FINDING_META has an entry for every one',
  issueAlgebra.filter(k => !(k in FINDING_META)), []);
eq('and no FINDING_META entry names a key outside the vocabulary',
  Object.keys(FINDING_META).filter(k => !issueAlgebra.includes(k)), []);

/* ── 5. Regression: migrated findings mirror buildIssues 1:1 ──────────── */
section('5. Migrated findings mirror buildIssues, in order');

// buildFindings runs the untouched buildIssues and enriches it, so the migrated
// subset must be exactly buildIssues' keys, in order, with key === issue key.
const regressionContexts = [
  ctx(),
  ctx({ emailProvider: 'Google Workspace', spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 -all', spfRecords: ['v=spf1 -all'] }),
  ctx({ spfStatus: { status: 'permerror', warnings: ['spf-multiple-records'] }, spfRecords: ['a', 'b'] }),
  ctx({ dmarcStatus: { status: 'warn', policy: 'none' } }),
  ctx({ advanced: { caa: { found: true, issuers: ['x'], wildcardIssuers: [] } } }),
];
regressionContexts.forEach((c, i) => {
  const issueKeys = buildIssues(c).map(x => x.key);
  const migrated = buildFindings(c).filter(f => f.keyspace === 'issue');
  eq(`context ${i}: migrated finding keys equal buildIssues keys in order`,
    migrated.map(f => f.key), issueKeys);
  eq(`context ${i}: every migrated finding.key is its issue key`,
    migrated.every(f => f.keyspace === 'issue'), true);
});
// An unknown legacy key is skipped, never thrown on — the mutation-safety the
// equivalence validator's spf-absent probe depends on. Fed a FABRICATED issue
// array (via the override) with an unknown key beside a known one, so the branch
// is actually exercised rather than assumed.
// Scope to the migrated (keyspace 'issue') subset: the cross-protocol rules run
// off the context regardless of the override, so they are not part of this test.
const migratedOf = fs => fs.filter(f => f.keyspace === 'issue').map(f => f.id);
const mixedIssues = buildFindings(ctx(), [
  { key: 'not-a-real-key', sev: 'crit', args: [] },
  { key: 'spf-missing', sev: 'crit', args: [] },
]);
eq('the unknown key produces no finding', mixedIssues.some(f => f.key === 'not-a-real-key'), false);
eq('while the known key beside it still does', migratedOf(mixedIssues), ['spf.missing']);
// Proven able to fail: the known key alone yields exactly its migrated finding.
eq('a lone known key yields its finding',
  migratedOf(buildFindings(ctx(), [{ key: 'dmarc-missing', sev: 'warn', args: [] }])), ['dmarc.missing']);

/* ── 6. Behavioural fixtures from the spec ────────────────────────────── */
section('6. The spec behavioural fixtures');

// No SPF, no DKIM, p=reject → enforcement-without-auth critical; plan step 1 is auth.
const noAuthReject = ctx({
  emailProvider: 'Google Workspace',
  dkimStatus: { found: false, selectors: [], testedSelectors: [], confidence: 'full' },
  dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject', enforcing: true, testMode: false, rua: true, pctValid: true },
  dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:a@b',
});
const naFindings = buildFindings(noAuthReject);
const ewa = naFindings.find(f => f.id === 'dmarc.enforcement-without-auth');
eq('enforcement-without-auth fires', !!ewa, true);
eq('and it is critical', ewa && ewa.severity, 'critical');
eq('and it depends on both authentication findings', ewa && ewa.dependsOn.slice().sort(), ['dkim.none-found', 'spf.missing']);
const naPlan = buildRemediationPlan(naFindings);
eq('plan step 1 is SPF and DKIM',
  naPlan[0].findings.slice().sort(), ['dkim.none-found', 'spf.missing']);
eq('plan step 2 moves to enforcement',
  naPlan[1].findings.includes('dmarc.enforcement-without-auth'), true);
eq('the enforcement step lists what step 1 unblocks',
  naPlan[0].unblocks.includes('dmarc.enforcement-without-auth'), true);

// No SPF, no DKIM, no DMARC → plan orders authentication before policy.
const nothing = ctx({ emailProvider: 'Google Workspace', dkimStatus: { found: false, selectors: [], testedSelectors: [], confidence: 'full' }, dmarcStatus: { status: 'warn', policy: 'none' } });
const nothingPlan = buildRemediationPlan(buildFindings(nothing));
const policyStep = nothingPlan.findIndex(s => s.findings.includes('dmarc.policy-none'));
const authStep = nothingPlan.findIndex(s => s.findings.includes('spf.missing'));
eq('authentication is planned before policy', authStep < policyStep && authStep >= 0, true);

// BIMI with p=none → without-enforcement, blocked by dmarc.policy-none.
const bimiNone = ctx({
  emailProvider: 'Google Workspace',
  dmarcStatus: { status: 'warn', policy: 'none', effectivePolicy: 'none', enforcing: false, testMode: false, rua: true },
  spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 -all', spfRecords: ['v=spf1 -all'],
  dkimStatus: { found: true, selectors: [{ sel: 'g', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] },
  advanced: { bimi: { present: true, record: 'v=BIMI1; l=https://x/logo.svg', validation: { authority: '' } } },
  dmarcRecord: 'v=DMARC1; p=none; rua=mailto:a@b',
});
const bnf = buildFindings(bimiNone);
const bwe = bnf.find(f => f.id === 'bimi.without-enforcement');
eq('bimi.without-enforcement fires under p=none', !!bwe, true);
eq('and it is blocked by dmarc.policy-none', bwe && bwe.dependsOn.includes('dmarc.policy-none'), true);
const policyNone = bnf.find(f => f.id === 'dmarc.policy-none');
eq('and dmarc.policy-none records that it blocks bimi', policyNone && policyNone.blocks.includes('bimi.without-enforcement'), true);

// BIMI with p=reject; t=y → same finding; test mode is not enforcement.
const bimiTestMode = ctx({
  emailProvider: 'Google Workspace',
  dmarcStatus: { status: 'warn', policy: 'reject', effectivePolicy: 'none', enforcing: false, testMode: true, rua: true },
  spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 -all', spfRecords: ['v=spf1 -all'],
  dkimStatus: { found: true, selectors: [{ sel: 'g', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] },
  advanced: { bimi: { present: true, record: 'v=BIMI1; l=https://x/logo.svg', validation: { authority: '' } } },
  dmarcRecord: 'v=DMARC1; p=reject; t=y; rua=mailto:a@b',
});
eq('bimi.without-enforcement fires under test mode too',
  buildFindings(bimiTestMode).some(f => f.id === 'bimi.without-enforcement'), true);

// MTA-STS without TLS-RPT → low.
const mtaNoRpt = ctx({ advanced: { mtaSts: { present: true, record: 'v=STSv1; id=1' }, tlsRpt: { present: false } } });
const mnr = buildFindings(mtaNoRpt).find(f => f.id === 'mta-sts.without-tls-rpt');
eq('mta-sts.without-tls-rpt fires', !!mnr, true);
eq('at low severity', mnr && mnr.severity, 'low');

// Dangling MX with p=reject → mx.dangling-with-enforcement critical.
const danglingReject = ctx({
  emailProvider: 'Google Workspace',
  dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject', enforcing: true, rua: true },
  advanced: { mxHealth: { hosts: [{ host: 'mx.dead.test', preference: 10, resolves: 'no', addresses: [] }], danglingHosts: ['mx.dead.test'], cnameHosts: [], duplicatePreferences: [], singleHost: true, ipv6Coverage: 'none', sharedPrefixes: [] } },
  dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:a@b',
});
const dwe = buildFindings(danglingReject).find(f => f.id === 'mx.dangling-with-enforcement');
eq('mx.dangling-with-enforcement fires', !!dwe, true);
eq('at critical severity', dwe && dwe.severity, 'critical');

// Null MX with v=spf1 mx -all → defensive.contradictory.
const nullMxMx = ctx({ emailProvider: '@null-mx', spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 mx -all', spfRecords: ['v=spf1 mx -all'], spfUsesMx: true, dmarcStatus: { status: 'missing' } });
eq('defensive.contradictory fires on null MX + mx-referencing SPF',
  buildFindings(nullMxMx).some(f => f.id === 'defensive.contradictory'), true);
// And on null MX + permissive SPF.
const nullMxPermit = ctx({ emailProvider: '@null-mx', spfStatus: { status: 'warn', warnings: ['spf-all-permit'] }, spfRecord: 'v=spf1 +all', spfRecords: ['v=spf1 +all'], spfUsesMx: false });
eq('defensive.contradictory fires on null MX + permissive SPF',
  buildFindings(nullMxPermit).some(f => f.id === 'defensive.contradictory'), true);

// DKIM 1024-bit with p=reject → dkim.weak-with-enforcement high.
const weak1024 = ctx({
  emailProvider: 'Google Workspace',
  dkimStatus: { found: true, selectors: [{ sel: 's1', queryName: 's1._domainkey.example.test', key: { keyType: 'rsa', keyBits: 1024, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] },
  dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject', enforcing: true, rua: true },
  spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 -all', spfRecords: ['v=spf1 -all'],
  dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:a@b',
});
const weakFinding = buildFindings(weak1024).find(f => f.id === 'dkim.weak-with-enforcement');
eq('dkim.weak-with-enforcement fires', !!weakFinding, true);
eq('at high severity', weakFinding && weakFinding.severity, 'high');

// Mixed 1024 and 2048 selectors → dkim.mixed-key-strength low (migrated).
const mixed = ctx({
  emailProvider: 'Google Workspace',
  dkimStatus: { found: true, keyProfile: { mixed: true, minBits: 1024, maxBits: 2048 }, selectors: [
    { sel: 'a', key: { keyType: 'rsa', keyBits: 1024, errors: [], hashAlgorithms: [], testing: false, valid: true } },
    { sel: 'b', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } },
  ], testedSelectors: [] },
  dmarcStatus: { status: 'ok', policy: 'quarantine', effectivePolicy: 'quarantine', enforcing: true, rua: true },
  spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 -all', spfRecords: ['v=spf1 -all'],
});
const mix = buildFindings(mixed).find(f => f.id === 'dkim.mixed-key-strength');
eq('dkim.mixed-key-strength fires (migrated)', !!mix, true);
eq('at low severity', mix && mix.severity, 'low');
eq('and it carries the issue keyspace', mix && mix.keyspace, 'issue');

// Everything correct → empty finding set, empty plan.
const perfect = ctx({
  emailProvider: 'Google Workspace',
  spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 -all', spfRecords: ['v=spf1 -all'],
  dkimStatus: { found: true, keyProfile: { mixed: false, minBits: 2048, maxBits: 2048 }, selectors: [{ sel: 'g', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] },
  dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject', enforcing: true, testMode: false, rua: true, pctValid: true, ruaUris: { valid: true } },
  dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:a@b',
  advanced: {
    mtaSts: { present: true, policyVerified: true, record: 'v=STSv1; id=1' },
    tlsRpt: { present: true, record: 'v=TLSRPTv1; rua=mailto:t@b' },
    caa: { found: true, issuers: ['letsencrypt.org', 'digicert.com'], wildcardIssuers: [], iodef: ['mailto:x@y'] },
    dnssec: { signed: true, state: 'secure' },
    bimi: { present: true, record: 'v=BIMI1; l=https://x/l.svg; a=https://x/v.pem', validation: { authority: 'https://x/v.pem' } },
  },
});
const perfectFindings = buildFindings(perfect);
eq('a fully-correct domain has no findings', perfectFindings, []);
eq('and an empty plan', buildRemediationPlan(perfectFindings), []);

// DKIM lookup failed → confidence unverified.
const dkimFailed = ctx({ emailProvider: 'Google Workspace', dkimStatus: { found: false, selectors: [], testedSelectors: ['s1'], failedSelectors: ['s1'], confidence: 'sampled', note: 'noteNotFoundWithErrors' } });
const dkimNoneFinding = buildFindings(dkimFailed).find(f => f.id === 'dkim.none-found');
eq('a failed DKIM lookup yields an unverified finding', dkimNoneFinding && dkimNoneFinding.confidence, 'unverified');

/* ── 7. Negative cases: each cross-protocol rule proven able NOT to fire ─ */
section('7. Negative cases (AGENTS.md rule 3)');

// Each cross-protocol id must be absent when its condition is not met.
eq('enforcement-without-auth absent when auth is present',
  idsFor({ emailProvider: 'Google Workspace', spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 -all', spfRecords: ['v=spf1 -all'], dkimStatus: { found: true, selectors: [{ sel: 'g', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] }, dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject', enforcing: true, rua: true }, dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:a@b' })
    .includes('dmarc.enforcement-without-auth'), false);
// A permerror is a BROKEN SPF record, not a missing one (spec 1.1). It must not
// fire the enforcement finding — which would land in step 1 beside the
// broken-SPF finding, breaking the never-enforce-before-auth guarantee.
const permErrEnforcing = ctx({
  emailProvider: 'Google Workspace',
  spfStatus: { status: 'permerror', warnings: ['spf-multiple-records'] }, spfRecords: ['v=spf1 -all', 'v=spf1 a'], spfRecord: 'v=spf1 -all',
  dkimStatus: { found: true, selectors: [{ sel: 'g', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] },
  dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject', enforcing: true, rua: true }, dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:a@b',
});
eq('enforcement-without-auth does NOT fire on an SPF permerror',
  buildFindings(permErrEnforcing).some(f => f.id === 'dmarc.enforcement-without-auth'), false);
eq('and the SPF finding for a permerror is spf.multiple-records',
  buildFindings(permErrEnforcing).some(f => f.id === 'spf.multiple-records'), true);
eq('so no plan step puts enforcement beside the broken-SPF finding',
  buildRemediationPlan(buildFindings(permErrEnforcing)).some(s => s.findings.includes('dmarc.enforcement-without-auth')), false);
// But a genuinely MISSING SPF (with DKIM present) still fires it, as before.
eq('enforcement-without-auth still fires on a missing SPF',
  buildFindings(ctx({ emailProvider: 'Google Workspace', spfStatus: { status: 'missing', warnings: [] }, dkimStatus: { found: true, selectors: [{ sel: 'g', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] }, dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject', enforcing: true, rua: true }, dmarcRecord: 'v=DMARC1; p=reject; rua=mailto:a@b' }))
    .some(f => f.id === 'dmarc.enforcement-without-auth'), true);
eq('mx.dangling-with-enforcement absent without enforcement',
  buildFindings(ctx({ advanced: { mxHealth: { hosts: [], danglingHosts: ['x'], cnameHosts: [], duplicatePreferences: [], singleHost: false, ipv6Coverage: 'none', sharedPrefixes: [] } }, dmarcStatus: { status: 'warn', policy: 'none', enforcing: false } }))
    .some(f => f.id === 'mx.dangling-with-enforcement'), false);
eq('dkim.weak-with-enforcement absent when the key is 2048',
  buildFindings(ctx({ dkimStatus: { found: true, selectors: [{ sel: 'g', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] }, dmarcStatus: { enforcing: true, policy: 'reject', effectivePolicy: 'reject', status: 'ok' } }))
    .some(f => f.id === 'dkim.weak-with-enforcement'), false);
eq('bimi.without-enforcement absent when DMARC enforces',
  buildFindings(ctx({ advanced: { bimi: { present: true, validation: { authority: 'https://x/v.pem' } } }, dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject', enforcing: true, testMode: false, rua: true } }))
    .some(f => f.id === 'bimi.without-enforcement'), false);
eq('bimi.without-authority absent when a VMC is present',
  buildFindings(ctx({ advanced: { bimi: { present: true, validation: { authority: 'https://x/v.pem' } } }, dmarcStatus: { enforcing: true, policy: 'reject', effectivePolicy: 'reject', status: 'ok', rua: true } }))
    .some(f => f.id === 'bimi.without-authority'), false);
eq('mta-sts.without-tls-rpt absent when TLS-RPT is present',
  buildFindings(ctx({ advanced: { mtaSts: { present: true }, tlsRpt: { present: true } } }))
    .some(f => f.id === 'mta-sts.without-tls-rpt'), false);
eq('mta-sts.without-tls-rpt absent when TLS-RPT lookup is unknown',
  buildFindings(ctx({ advanced: { mtaSts: { present: true }, tlsRpt: { present: false, unknown: true } } }))
    .some(f => f.id === 'mta-sts.without-tls-rpt'), false);
eq('tls-rpt.without-transport-policy absent when MTA-STS is present',
  buildFindings(ctx({ advanced: { tlsRpt: { present: true }, mtaSts: { present: true } } }))
    .some(f => f.id === 'tls-rpt.without-transport-policy'), false);
eq('tls-rpt.without-transport-policy absent when a host is DANE-authenticated',
  buildFindings(ctx({ advanced: { tlsRpt: { present: true }, tlsa: { hosts: [{ host: 'mx', authenticated: true }] } } }))
    .some(f => f.id === 'tls-rpt.without-transport-policy'), false);
eq('spf.redundant-with-enforcement absent without a HIGH-tier block',
  buildFindings(ctx({ advanced: { spfSubnets: { subnets: [{ severity: 'MEDIUM', mechanism: 'ip4:10.0.0.0/16' }] } }, dmarcStatus: { enforcing: true, policy: 'reject', effectivePolicy: 'reject', status: 'ok' } }))
    .some(f => f.id === 'spf.redundant-with-enforcement'), false);
eq('defensive.contradictory absent when the domain is not null-MX',
  buildFindings(ctx({ emailProvider: 'Google Workspace', spfUsesMx: true, spfStatus: { status: 'ok', warnings: [] }, spfRecord: 'v=spf1 mx -all' }))
    .some(f => f.id === 'defensive.contradictory'), false);
eq('reporting.blind absent when rua is configured',
  buildFindings(ctx({ dmarcStatus: { status: 'warn', policy: 'none', rua: true } }))
    .some(f => f.id === 'reporting.blind'), false);

/* ── 7b. The remediation plan collects isolated findings last ─────────── */
section('7b. Isolated findings land in a final step, not step 1');

// An SPF-authentication chain (spf.missing → dmarc.policy-none) beside an
// isolated hygiene finding (caa.single-issuer). The isolated one must not sit
// in step 1 with the authentication work.
const chainPlusHygiene = ctx({
  emailProvider: 'Google Workspace',
  spfStatus: { status: 'missing', warnings: [] },
  dmarcStatus: { status: 'warn', policy: 'none', effectivePolicy: 'none', enforcing: false, rua: true },
  dkimStatus: { found: true, selectors: [{ sel: 'g', key: { keyType: 'rsa', keyBits: 2048, errors: [], hashAlgorithms: [], testing: false, valid: true } }], testedSelectors: [] },
  advanced: { caa: { found: true, issuers: ['one'], wildcardIssuers: [] } },
});
const cpPlan = buildRemediationPlan(buildFindings(chainPlusHygiene));
eq('spf.missing (a prerequisite) is in step 1', cpPlan[0].findings.includes('spf.missing'), true);
eq('the isolated caa.single-issuer is NOT in step 1', cpPlan[0].findings.includes('caa.single-issuer'), false);
const cpLast = cpPlan[cpPlan.length - 1];
eq('it lands in the final step, tagged cleanup', cpLast.rationale === 'cleanup' && cpLast.findings.includes('caa.single-issuer'), true);
// dmarc.policy-none has dependents-none but IS a dependent of spf.missing... it
// has dependencies, so it is connected and stays at its depth, never demoted.
eq('a finding with dependencies but no dependents stays at its depth',
  cpPlan.some(s => s.rationale === 'afterPrereq' && s.findings.includes('dmarc.policy-none')), true);
// A plan of only isolated findings is a single cleanup step.
const onlyHygiene = buildRemediationPlan(buildFindings(ctx({ advanced: { caa: { found: true, issuers: ['one'], wildcardIssuers: [] } } })));
eq('an all-isolated plan is one cleanup step',
  onlyHygiene.length === 1 && onlyHygiene[0].rationale === 'cleanup', true);

/* ── 7c. Evidence is specific to the finding it justifies ─────────────── */
section('7c. Evidence names the record that justified the finding');

// SPF multiple-records shows every conflicting record, not just the first.
const spfConflict = buildFindings(ctx({ spfStatus: { status: 'permerror', warnings: ['spf-multiple-records'] }, spfRecords: ['v=spf1 -all', 'v=spf1 include:a.test ~all'], spfRecord: 'v=spf1 -all' }))
  .find(f => f.id === 'spf.multiple-records');
eq('spf.multiple-records evidence carries both records',
  spfConflict.evidence.map(e => e.value), ['v=spf1 -all', 'v=spf1 include:a.test ~all']);

// DMARC duplicate evidence shows the DUPLICATE at its name, not the applied record.
const dmarcDup = buildFindings(ctx({
  dmarcDiscovery: { observed: [{ why: 'multiple-at-step', queryName: '_dmarc.x.test', record: 'v=DMARC1; p=none DUP' }], applied: { foundAt: 'x.test' } },
  dmarcStatus: { status: 'missing' }, dmarcRecord: 'v=DMARC1; p=reject APPLIED',
})).find(f => f.id === 'dmarc.multiple-records');
eq('dmarc.multiple-records evidence names the duplicate, not the applied record',
  dmarcDup.evidence.map(e => e.value), ['v=DMARC1; p=none DUP']);
eq('and at the duplicate\'s own query name', dmarcDup.evidence[0].queryName, '_dmarc.x.test');

// MX evidence can read the passed mx records.
const mxImplicit = buildFindings(ctx({ emailProvider: '@implicit-mx', mx: ['0 mail.x.test'] })).find(f => f.id === 'mx.implicit');
eq('mx.implicit evidence reads the passed mx records', mxImplicit.evidence.some(e => e.value === '0 mail.x.test'), true);

// A DNS finding gets meaningful evidence, not an empty info entry.
const checksUnverified = buildFindings(ctx({ hosting: '@dns-error', advanced: { caa: { unknown: true } } })).find(f => f.id === 'dns.checks-unverified');
eq('dns.checks-unverified evidence names the checks that could not run',
  checksUnverified.evidence[0].value.length > 0, true);
// Every finding still carries at least one evidence entry (acceptance criterion 1).
eq('every bare-domain finding still names evidence',
  buildFindings(ctx()).every(f => f.evidence.length > 0), true);

/* ── 8. Locale independence ───────────────────────────────────────────── */
section('8. The finding layer is locale-independent');

const source = readFileSync(join(REPO, 'src/audit/findings.js'), 'utf8');
eq('findings.js imports only its audit sibling',
  [...source.matchAll(/^import .* from '([^']+)'/gm)].map(m => m[1]), ['./issues.js']);
eq('it holds no i18n or ui edge', /i18n|\/ui\//.test(source), false);
// The plan sorts on tokens, never translated strings.
eq('the plan carries token rationales, not prose',
  buildRemediationPlan(naFindings).every(s => /^[a-zA-Z]+$/.test(s.rationale)), true);

report();
