#!/usr/bin/env node
/**
 * Unit tests for the DMARC parser and the weighted scoring model.
 *
 * Loads js/dns.js in a minimal browser-ish sandbox (it's a plain IIFE that
 * attaches to `window`), so there's nothing to mock and no network involved.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..');
const sandbox = { window: { __PUBLIC_SUFFIX_RULES__: ['com', 'co.uk', '*.ck', '!www.ck'] }, fetch: async () => ({ ok: false }), console, AbortController, URLSearchParams, setTimeout, clearTimeout };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(readFileSync(`${REPO}/js/dkim-selectors.js`, 'utf8'), sandbox);
vm.runInContext(readFileSync(`${REPO}/js/dns.js`, 'utf8'), sandbox);
const D = sandbox.window.DnsAudit;

let pass = 0, fail = 0;
const eq = (label, actual, expected) => {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; return; }
  fail++;
  console.log(`  ✗ ${label}\n      expected ${e}\n      actual   ${a}`);
};
const section = s => console.log(`\n${s}\n${'─'.repeat(s.length)}`);

/* ── 1. Tag parsing — the bugs found in the design doc ────────────────── */
section('1. Tag parsing (regressions from the design doc)');

// p= must not be captured from sp= / np=, in any tag order.
eq('sp before p',        D.analyzeDmarc('v=DMARC1; sp=reject; p=none').policy, 'none');
eq('np before p',        D.analyzeDmarc('v=DMARC1; np=quarantine; p=reject').policy, 'reject');
eq('sp read correctly',  D.analyzeDmarc('v=DMARC1; sp=reject; p=none').sp, 'reject');
eq('np read correctly',  D.analyzeDmarc('v=DMARC1; np=quarantine; p=reject').np, 'quarantine');

// Tag names and values are case-insensitive (RFC 7489 §6.4).
eq('uppercase policy',   D.analyzeDmarc('V=DMARC1; P=REJECT').policy, 'reject');
eq('mixed-case sp',      D.analyzeDmarc('v=DMARC1; p=reject; SP=Quarantine').sp, 'quarantine');
eq('uppercase rua',      D.analyzeDmarc('v=DMARC1; p=reject; RUA=mailto:a@b.com').rua, true);

// Whitespace tolerance.
eq('spaces around =',    D.analyzeDmarc('v=DMARC1 ; p = reject ; pct = 50').policy, 'reject');
eq('spaces around pct',  D.analyzeDmarc('v=DMARC1 ; p = reject ; pct = 50').pct, 50);

/* ── 2. pct guards ───────────────────────────────────────────────────── */
section('2. pct validation (parsed for reporting; removed by RFC 9989)');

eq('absent → 100',       D.analyzeDmarc('v=DMARC1; p=reject').pct, 100);
eq('valid 50',           D.analyzeDmarc('v=DMARC1; p=reject; pct=50').pct, 50);
eq('non-numeric flagged',D.analyzeDmarc('v=DMARC1; p=reject; pct=abc').pctValid, false);
eq('non-numeric → 100',  D.analyzeDmarc('v=DMARC1; p=reject; pct=abc').pct, 100);
eq('over-range clamped', D.analyzeDmarc('v=DMARC1; p=reject; pct=250').pct, 100);
eq('over-range flagged', D.analyzeDmarc('v=DMARC1; p=reject; pct=250').pctValid, false);
eq('negative clamped',   D.analyzeDmarc('v=DMARC1; p=reject; pct=-10').pct, 0);
eq('pct=0 kept',         D.analyzeDmarc('v=DMARC1; p=reject; pct=0').pct, 0);

/* ── 3. sp/np inheritance ────────────────────────────────────────────── */
section('3. Subdomain policy inheritance (RFC 9989 §5.4)');

const inh = D.analyzeDmarc('v=DMARC1; p=reject');
eq('absent sp inherits p',       inh.effectiveSp, 'reject');
eq('absent np inherits p',       inh.effectiveNp, 'reject');

const spOnly = D.analyzeDmarc('v=DMARC1; p=reject; sp=quarantine');
eq('np inherits sp not p',       spOnly.effectiveNp, 'quarantine');

const npOnly = D.analyzeDmarc('v=DMARC1; p=reject; np=none');
eq('np explicit wins',           npOnly.effectiveNp, 'none');
eq('sp still inherits p',        npOnly.effectiveSp, 'reject');

/* ── 4. DMARC sub-score ──────────────────────────────────────────────── */
section('4. DMARC sub-score (max 30, RFC 9989 rubric)');

const dscore = rec => D.calcDmarcScore(D.analyzeDmarc(rec)).pts;

// Components: policy 12 / subdomain 6 / rua 6 / alignment 3 / ruf 2 / uris 1.
eq('missing record',             D.calcDmarcScore(D.analyzeDmarc('')).pts, 0);
// policy 12 + sub 6 (inherited) + rua 6 + uris 1 = 25
eq('p=reject + rua (inherited)', dscore('v=DMARC1; p=reject; rua=mailto:a@b.com'), 25);
// Inherited reject must score the SAME as explicit sp=reject — this is the
// design-doc bug: inheritance is equally protective, so it must not be penalised.
eq('explicit sp=reject equal',   dscore('v=DMARC1; p=reject; sp=reject; rua=mailto:a@b.com'), 25);
// Explicitly weakened subdomains must score LOWER.
eq('sp=none scores lower',       dscore('v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com'), 20);
// np=none is the weakest link even when sp inherits reject.
eq('np=none penalised',          dscore('v=DMARC1; p=reject; np=none; rua=mailto:a@b.com'), 20);
// RFC 9989 removed pct, so it must no longer move the score in either direction.
eq('pct=50 costs nothing now',   dscore('v=DMARC1; p=reject; pct=50; rua=mailto:a@b.com'), 25);
eq('pct=0 costs nothing now',    dscore('v=DMARC1; p=reject; pct=0; rua=mailto:a@b.com'), 25);
eq('pct absent = pct present',
  dscore('v=DMARC1; p=reject; pct=100; rua=mailto:a@b.com'),
  dscore('v=DMARC1; p=reject; rua=mailto:a@b.com'));
// Full marks: reject + strict alignment both ways + ruf + deliverable URIs.
const perfect = 'v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:a@b.com; ruf=mailto:f@b.com; adkim=s; aspf=s';
eq('perfect record = 30',        dscore(perfect), 30);
eq('never exceeds 30',           dscore(perfect) <= 30, true);
// policy 3 + sub 1 + rua 6 + uris 1 = 11
eq('p=none + rua',               dscore('v=DMARC1; p=none; rua=mailto:a@b.com'), 11);

// A published rua= that cannot be delivered to forfeits the uris point — it
// looks like monitoring and silently is not.
eq('unusable rua loses uris pt', dscore('v=DMARC1; p=reject; rua=dmarc@b.com'), 24);
eq('no rua at all',              dscore('v=DMARC1; p=reject'), 18);

// t=y suppresses enforcement, so it must score at the p=none tier however
// strong the published policy looks.
eq('t=y scores as none',         dscore('v=DMARC1; p=reject; t=y; rua=mailto:a@b.com'), 11);
eq('t=y equals p=none',
  dscore('v=DMARC1; p=reject; t=y; rua=mailto:a@b.com'),
  dscore('v=DMARC1; p=none; rua=mailto:a@b.com'));
eq('t=n is enforcement',         dscore('v=DMARC1; p=reject; t=n; rua=mailto:a@b.com'), 25);
// Test mode collapses subdomain coverage too — nothing is being applied.
eq('t=y ignores sp=reject',      dscore('v=DMARC1; p=reject; sp=reject; t=y; rua=mailto:a@b.com'), 11);

/* ── 5. SPF sub-score ────────────────────────────────────────────────── */
section('5. SPF sub-score (max 15)');

const spf = (status, warnings = []) => ({ status, warnings });
eq('-all full marks',    D.calcSpfScore(spf('ok')), 15);
eq('~all partial',       D.calcSpfScore(spf('softfail')), 10);
eq('present partial',    D.calcSpfScore(spf('present')), 8);
eq('missing zero',       D.calcSpfScore(spf('missing')), 0);
eq('+all worthless',     D.calcSpfScore(spf('warn', ['spf-all-permit'])), 0);
eq('?all worthless',     D.calcSpfScore(spf('warn', ['spf-neutral'])), 0);
// A missing provider include is a real record one line short — keeps credit.
eq('missing include partial', D.calcSpfScore(spf('warn', ['spf-missing-google'])), 8);
// Over 10 lookups = permerror = SPF never passes, however strict it looks.
eq('permerror zeroes -all',   D.calcSpfScore(spf('ok'), { spfLookups: { error: true, count: 14 } }), 0);
eq('near-limit unaffected',   D.calcSpfScore(spf('ok'), { spfLookups: { warning: true, error: false, count: 9 } }), 15);

/* ── 6. Grade ladder ─────────────────────────────────────────────────── */
section('6. Grade ladder and DNSSEC gate');

eq('85 signed → A++',    D.gradeFor(85, true).grade, 'A++');
eq('75 signed → A+',     D.gradeFor(75, true).grade, 'A+');
eq('65 signed → A',      D.gradeFor(65, true).grade, 'A');   // was unreachable in the doc
eq('90 unsigned → B',    D.gradeFor(90, false).grade, 'B');  // DNSSEC gate holds
eq('50 → B',             D.gradeFor(50, true).grade, 'B');
eq('30 → C',             D.gradeFor(30, true).grade, 'C');
eq('10 → D',             D.gradeFor(10, true).grade, 'D');
eq('0 → F',              D.gradeFor(0, true).grade, 'F');
eq('A tier reachable',   D.GRADE_THRESHOLDS.some(t => t.grade === 'A'), true);

/* ── 7. Weights sum to 100 ───────────────────────────────────────────── */
section('7. Rubric integrity');

const sum = o => Object.values(o).reduce((a, b) => a + b, 0);
eq('active weights = 100', sum(D.WEIGHTS), 100);
eq('parked weights = 100', sum(D.PARKED_WEIGHTS), 100);
eq('tlsRpt is scored',     D.WEIGHTS.tlsRpt > 0, true);

/* ── 8. End-to-end calcScore ─────────────────────────────────────────── */
section('8. calcScore integration');

const full = {
  bimi: { present: true }, mtaSts: { present: true }, tlsRpt: { present: true },
  caa: { found: true }, dnssec: { signed: true },
  spfLookups: { count: 3, warning: false, error: false },
};
const bare = {
  bimi: { present: false }, mtaSts: { present: false }, tlsRpt: { present: false },
  caa: { found: false }, dnssec: { signed: false },
  spfLookups: { count: 2, warning: false, error: false },
};

const best = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; sp=reject; np=reject; rua=mailto:a@b.com; ruf=mailto:f@b.com; adkim=s; aspf=s'),
  advanced: full,
});
eq('best case = 100 / A++', [best.pts, best.grade], [100, 'A++']);

const noDnssec = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  advanced: Object.assign({}, full, { dnssec: { signed: false } }),
});
eq('strong but unsigned → B', noDnssec.grade, 'B');

const worst = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('missing'), dkimStatus: { found: false },
  dmarcStatus: D.analyzeDmarc(''), advanced: bare,
});
eq('nothing configured = 0 / F', [worst.pts, worst.grade], [0, 'F']);

// A wildcard TXT record used to zero this outright. Scoring no longer takes
// any wildcard input at all: the furthest a wildcard reaches is DKIM
// discovery, and that is expressed through the DKIM pillar. Section 25 covers
// the behaviour end to end.
const wildcard = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  advanced: full,
});
eq('no instant-F path remains', [wildcard.grade, wildcard.pts], ['A++', 95]);

// pct=abc previously produced NaN → every comparison false → silent F.
const nanPct = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; pct=abc; rua=mailto:a@b.com'),
  advanced: full,
});
eq('malformed pct is not NaN', Number.isFinite(nanPct.pts), true);
eq('malformed pct still graded', nanPct.grade !== 'F', true);

/* ── 9. Parked-domain path ───────────────────────────────────────────── */
section('9. Parked domains (no MX)');

const parkedHard = D.calcScore({
  emailProvider: '@null-mx',
  spfStatus: spf('ok'), dkimStatus: { found: false },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject;'),
  advanced: full,
});
eq('hardened parked = 100', parkedHard.pts, 100);
eq('parked flagged',        parkedHard.parked, true);
eq('parked reaches A tier', parkedHard.grade, 'A++');

const parkedBare = D.calcScore({
  emailProvider: '@null-mx',
  spfStatus: spf('missing'), dkimStatus: { found: false },
  dmarcStatus: D.analyzeDmarc(''), advanced: bare,
});
eq('bare parked = 0 / F', [parkedBare.pts, parkedBare.grade], [0, 'F']);
// DKIM must not drag down a domain that cannot have it.
eq('parked has no dkim pillar',
  parkedHard.breakdown.pillars.some(p => p.key === 'dkim'), false);

/* ── 10. Breakdown shape (consumed by the UI) ────────────────────────── */
section('10. Breakdown contract');

eq('pillars present',    Array.isArray(best.breakdown.pillars), true);
eq('8 active pillars',   best.breakdown.pillars.length, 8);
eq('pillar maxes sum 100', best.breakdown.pillars.reduce((s, p) => s + p.max, 0), 100);
eq('pts never exceed max', best.breakdown.pillars.every(p => p.pts <= p.max), true);
eq('dmarc parts exposed', Object.keys(best.breakdown.dmarc).sort(),
  ['alignment', 'policy', 'rua', 'ruf', 'subdomain', 'uris']);
// Every part the UI can render must have a matching score.dmarcParts.* label.
const dmarcPartLabels = JSON.parse(readFileSync(`${REPO}/locales/en.json`, 'utf8')).score.dmarcParts;
eq('every dmarc part has a label',
  Object.keys(best.breakdown.dmarc).filter(k => !(k in dmarcPartLabels)), []);

/* ── 11. New issue keys fire correctly ───────────────────────────────── */
section('11. Issue detection');

const issuesFor = (rec, adv) => D.buildIssues({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc(rec),
  hosting: 'Custom', advanced: adv || full,
}).map(i => i.key);

eq('inherited sp → no warning',
  issuesFor('v=DMARC1; p=reject; rua=mailto:a@b.com').includes('dmarc-weak-sp'), false);
eq('sp=none → dmarc-weak-sp',
  issuesFor('v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com').includes('dmarc-weak-sp'), true);
eq('np=none → dmarc-weak-np',
  issuesFor('v=DMARC1; p=reject; np=none; rua=mailto:a@b.com').includes('dmarc-weak-np'), true);
eq('pct=50 → dmarc-partial-pct',
  issuesFor('v=DMARC1; p=reject; pct=50; rua=mailto:a@b.com').includes('dmarc-partial-pct'), true);
eq('pct=100 → no pct warning',
  issuesFor('v=DMARC1; p=reject; pct=100; rua=mailto:a@b.com').includes('dmarc-partial-pct'), false);
eq('pct=abc → dmarc-bad-pct',
  issuesFor('v=DMARC1; p=reject; pct=abc; rua=mailto:a@b.com').includes('dmarc-bad-pct'), true);
eq('p=bogus → dmarc-invalid-policy',
  issuesFor('v=DMARC1; p=bogus; rua=mailto:a@b.com').includes('dmarc-invalid-policy'), true);
eq('quarantine → dmarc-quarantine',
  issuesFor('v=DMARC1; p=quarantine; rua=mailto:a@b.com').includes('dmarc-quarantine'), true);
eq('reject → no quarantine nudge',
  issuesFor('v=DMARC1; p=reject; rua=mailto:a@b.com').includes('dmarc-quarantine'), false);
// p=none must not also fire subdomain warnings — it isn't enforcing anything.
eq('p=none → no sp warning',
  issuesFor('v=DMARC1; p=none; sp=none; rua=mailto:a@b.com').includes('dmarc-weak-sp'), false);

/* ── 12. Case-insensitive record selection ───────────────────────────── */
section('12. Case-insensitive record selection');

eq('V=DMARC1 selected',  D.startsWithCI('V=DMARC1; P=REJECT', 'v=DMARC1'), true);
eq('v=spf1 upper',       D.startsWithCI('V=SPF1 -all', 'v=spf1'), true);
eq('v=DKIM1 mixed',      D.startsWithCI('V=dkim1; k=rsa', 'v=DKIM1'), true);
eq('non-match rejected', D.startsWithCI('x=DMARC1', 'v=DMARC1'), false);
eq('empty safe',         D.startsWithCI('', 'v=DMARC1'), false);
eq('null safe',          D.startsWithCI(null, 'v=DMARC1'), false);

/* ── 13. Invalid policy earns nothing ────────────────────────────────── */
section('13. Invalid p= value');

const bogus = D.analyzeDmarc('v=DMARC1; p=totallywrong; rua=mailto:a@b.com');
eq('status is present',     bogus.status, 'present');
// Receivers cannot act on an unrecognised policy, so it must not score as p=none.
eq('scores 0 not 3',        D.calcDmarcScore(bogus).pts, 0);
eq('flagged critical',
  D.buildIssues({ emailProvider: 'Google Workspace', spfStatus: spf('ok'),
    dkimStatus: { found: true }, dmarcStatus: bogus,
    hosting: 'Custom', advanced: full })
    .filter(i => i.key === 'dmarc-invalid-policy')[0].sev, 'crit');

/* ── 14. Multiple-record permerror ───────────────────────────────────── */
section('14. Multiple-record permerror (SPF, DMARC)');

// RFC 7208 §4.5 — SPF fails for all mail, regardless of record contents.
eq('SPF permerror status',      D.analyzeSpf('', 'unknown', true).status, 'permerror');
eq('SPF permerror scores 0',    D.calcSpfScore(D.analyzeSpf('', 'unknown', true), null), 0);
// Even a perfect -all record scores nothing when duplicated.
eq('SPF -all + dup still 0',    D.calcSpfScore(D.analyzeSpf('v=spf1 include:_spf.google.com -all', 'unknown', true), null), 0);
eq('SPF permerror is crit',     D.analyzeSpf('', 'unknown', true).cls, 'crit');
eq('SPF carries the issue key', D.analyzeSpf('', 'unknown', true).warnings, ['spf-multiple-records']);

// RFC 7489 §6.6.3 — policy discovery terminates, DMARC not applied.
eq('DMARC permerror status',    D.analyzeDmarc('', true).status, 'permerror');
eq('DMARC permerror scores 0',  D.calcDmarcScore(D.analyzeDmarc('', true)).pts, 0);
// p=reject duplicated is worth exactly as much as no DMARC at all.
eq('DMARC reject + dup still 0',
  D.calcDmarcScore(D.analyzeDmarc('v=DMARC1; p=reject; sp=reject; rua=mailto:a@b.com', true)).pts, 0);
eq('DMARC permerror not enforcing', D.analyzeDmarc('v=DMARC1; p=reject', true).enforcing, false);

// Regression guard: the common single-record case must be untouched.
eq('SPF single unaffected',     D.analyzeSpf('v=spf1 -all', 'unknown', false).status, 'ok');
eq('SPF undefined arg = single', D.analyzeSpf('v=spf1 -all', 'unknown').status, 'ok');
eq('DMARC single unaffected',   D.analyzeDmarc('v=DMARC1; p=reject', false).policy, 'reject');
eq('DMARC undefined arg = single', D.analyzeDmarc('v=DMARC1; p=reject').policy, 'reject');

/* ── 15. Issue routing: permerror vs missing ─────────────────────────── */
section('15. Permerror must not also report "missing"');

const permIssues = (spfStatus, dmarcStatus, adv) => D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus, dkimStatus: { found: true, duplicated: [] },
  dmarcStatus, hosting: 'Custom', advanced: adv || full,
}).map(i => i.key);

const spfDup = permIssues(D.analyzeSpf('', 'unknown', true), D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'));
eq('spf dup raises multiple',   spfDup.includes('spf-multiple-records'), true);
// The two states need different fix instructions — delete a duplicate vs publish one.
eq('spf dup NOT also missing',  spfDup.includes('spf-missing'), false);
// The key also lives in spfStatus.warnings; the warnings loop must not re-push
// it, or the same finding appears twice at two different severities.
eq('spf dup listed exactly once',
  spfDup.filter(k => k === 'spf-multiple-records').length, 1);
// Content warnings are moot on a permerror — the record never evaluates.
eq('permerror suppresses content warnings',
  permIssues(D.analyzeSpf('v=spf1 +all', 'unknown', true), D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'))
    .includes('spf-all-permit'), false);

const dmarcDup = permIssues(spf('ok'), D.analyzeDmarc('', true));
eq('dmarc dup raises multiple', dmarcDup.includes('dmarc-multiple-records'), true);
eq('dmarc dup NOT also missing', dmarcDup.includes('dmarc-missing'), false);
// A permerror DMARC is not enforcing, so subdomain/pct warnings must stay quiet.
eq('dmarc dup no sp warning',   dmarcDup.includes('dmarc-weak-sp'), false);
eq('dmarc dup no pct warning',  dmarcDup.includes('dmarc-partial-pct'), false);

/* ── 16. MTA-STS / TLS-RPT / BIMI duplicates ─────────────────────────── */
section('16. MTA-STS, TLS-RPT, BIMI duplicates (RFC 8461/8460, BIMI draft)');

// All three specs say: if the count is not exactly one, treat as not implemented.
const dupAdv = {
  bimi: { present: false, multiple: true }, mtaSts: { present: false, multiple: true },
  tlsRpt: { present: false, multiple: true }, caa: { found: true }, dnssec: { signed: true },
  spfLookups: { count: 2, warning: false, error: false },
};
const dupKeys = permIssues(spf('ok'), D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'), dupAdv);
eq('mta-sts dup flagged',  dupKeys.includes('mta-sts-multiple-records'), true);
eq('tls-rpt dup flagged',  dupKeys.includes('tls-rpt-multiple-records'), true);
eq('bimi dup flagged',     dupKeys.includes('bimi-multiple-records'), true);

// present:false means the pillar scores zero — the control really is inactive.
const dupScore = D.calcScore({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; sp=reject; rua=mailto:a@b.com'),
  advanced: dupAdv,
});
const pillar = k => dupScore.breakdown.pillars.find(p => p.key === k).pts;
eq('mta-sts dup scores 0', pillar('mtaSts'), 0);
eq('tls-rpt dup scores 0', pillar('tlsRpt'), 0);
eq('bimi dup scores 0',    pillar('bimi'), 0);

// Do not tell someone to publish a record they already have twice.
const dupTips = D.buildSuggestions({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: true }, dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  advanced: dupAdv,
}).map(t => t.key);
eq('no mta-sts "add it" tip', dupTips.includes('mta-sts'), false);
eq('no tls-rpt "add it" tip', dupTips.includes('tls-rpt'), false);
eq('no bimi "add it" tip',    dupTips.filter(k => k.startsWith('bimi')).length, 0);

// Genuinely absent records still get their suggestion — no over-suppression.
const absentTips = D.buildSuggestions({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: true }, dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  advanced: { bimi: { present: false }, mtaSts: { present: false }, tlsRpt: { present: false },
    caa: { found: true }, dnssec: { signed: true }, spfLookups: { count: 1 } },
}).map(t => t.key);
eq('absent mta-sts still tipped', absentTips.includes('mta-sts'), true);
eq('absent tls-rpt still tipped', absentTips.includes('tls-rpt'), true);

/* ── 17. DKIM duplicate keys per selector ────────────────────────────── */
section('17. DKIM duplicate keys (RFC 6376 §3.6.2.2)');

const dkimDup = D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: true, selectors: [{ sel: 'google' }], duplicated: ['google', 's1'] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  hosting: 'Custom', advanced: full,
});
const dkimIssue = dkimDup.find(i => i.key === 'dkim-multiple-records');
eq('dkim dup flagged',       !!dkimIssue, true);
eq('dkim dup lists selectors', dkimIssue.args, ['google, s1']);
eq('dkim dup severity warn', dkimIssue.sev, 'warn');
// No duplicates → no issue.
eq('clean dkim not flagged', D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: true, selectors: [{ sel: 'google' }], duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  hosting: 'Custom', advanced: full,
}).some(i => i.key === 'dkim-multiple-records'), false);

/* ── 18. CAA and MX multiples are legal, not errors ──────────────────── */
section('18. Record types where multiples are legitimate');

// CAA is designed for multiple records (several CAs, issue + issuewild + iodef).
// Flagging it would be a false positive, so assert we never do.
const multiCaa = D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'), dkimStatus: { found: true, duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  hosting: 'Custom',
  advanced: Object.assign({}, full, {
    caa: { found: true, records: ['0 issue "letsencrypt.org"', '0 issue "digicert.com"', '0 iodef "mailto:a@b.com"'], atDomain: 'x.com' },
  }),
}).map(i => i.key);
eq('multiple CAA not flagged', multiCaa.some(k => k.indexOf('caa-multiple') !== -1), false);
eq('multiple CAA still scores full',
  D.calcScore({ emailProvider: 'Google Workspace', spfStatus: spf('ok'), dkimStatus: { found: true },
    dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; sp=reject; rua=mailto:a@b.com'),
    advanced: full }).breakdown.pillars.find(p => p.key === 'caa').pts, D.WEIGHTS.caa);

/* ── 19. Standards-sensitive regressions ────────────────────────────── */
section('19. MX, SPF, DMARC and PSL regressions');

eq('uppercase SPF -ALL recognized', D.analyzeSpf('V=SPF1 -ALL', '@custom').status, 'ok');
eq('null MX recognized', D.isNullMx(['0 .']), true);
eq('null MX provider', D.detectEmailProvider(['0 .'], 'example.com', ['192.0.2.1']), '@null-mx');
eq('absent MX with address uses implicit MX', D.detectEmailProvider([], 'example.com', ['192.0.2.1']), '@implicit-mx');
eq('absent MX and address is no mail', D.detectEmailProvider([], 'example.com', []), '@none');
eq('same-domain CNAME is not automatically a loop', D.detectHosting([], ['host.example.com'], 'example.com'), '@custom');

const tenExists = 'v=spf1 ' + Array.from({ length: 10 }, (_, i) => `exists:x${i}.example`).join(' ') + ' -all';
const elevenExists = tenExists.replace(' -all', ' exists:x10.example -all');
const tenA = 'v=spf1 ' + Array(10).fill('a').join(' ') + ' -all';
eq('exactly 10 SPF terms is allowed', (await D.countSpfLookups(tenExists, 'example.com')).error, false);
eq('11 SPF terms is permerror', (await D.countSpfLookups(elevenExists, 'example.com')).error, true);
eq('adjacent a mechanisms all counted', (await D.countSpfLookups(tenA, 'example.com')).count, 10);

eq('organizational domain for co.uk', D.getOrganizationalDomain('mail.example.co.uk'), 'example.co.uk');
eq('PSL wildcard rule', D.getOrganizationalDomain('a.b.ck'), 'a.b.ck');
eq('PSL exception rule', D.getOrganizationalDomain('a.www.ck'), 'www.ck');
eq('DMARC missing p is malformed', D.analyzeDmarc('v=DMARC1; rua=mailto:a@example.com').status, 'present');
eq('DMARC duplicate p is malformed', D.analyzeDmarc('v=DMARC1; p=none; p=reject').status, 'present');

/* ── 20. Confidence and advanced-record validation ──────────────────── */
section('20. Confidence and advanced record validation');

const sampledDkim = D.calcScore({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: false, confidence: 'sampled' },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  advanced: full,
});
eq('sampled DKIM produces a score range', sampledDkim.uncertain, true);
eq('DKIM unknown is not stored as zero', sampledDkim.breakdown.pillars.find(p => p.key === 'dkim').pts, null);
eq('sampled DKIM is informational', D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: false, confidence: 'sampled', note: 'noteNotFound', duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject'),
  hosting: 'Custom', advanced: full,
}).find(i => i.key === 'dkim-unverified').sev, 'info');

eq('valid MTA-STS TXT', D.validateMtaStsRecord('v=STSv1; id=20260817').valid, true);
eq('MTA-STS requires id', D.validateMtaStsRecord('v=STSv1').valid, false);
eq('valid TLS-RPT rua', D.validateTlsRptRecord('v=TLSRPTv1; rua=mailto:tls@example.com').valid, true);
eq('TLS-RPT requires rua', D.validateTlsRptRecord('v=TLSRPTv1').valid, false);
eq('BIMI requires HTTPS logo', D.validateBimiRecord('v=BIMI1; l=https://example.com/logo.svg').valid, true);
eq('BIMI rejects HTTP logo', D.validateBimiRecord('v=BIMI1; l=http://example.com/logo.svg').valid, false);

const failedTransport = await D.dohFetch('failure.example', 'A', { retries: 0, noCache: true });
eq('HTTP failure is not converted to empty success', failedTransport.kind, 'http-error');

/* ── 21. Recognized DKIM selector catalog ───────────────────────────── */
section('21. Recognized DKIM selector catalog');

const googleSelectors = D.buildDkimSelectorList([], 'Google Workspace', false);
const comprehensiveSelectors = D.buildDkimSelectorList([], '@custom-unknown', true);
const excludedFixedSesSelectors = ['amazonses', 'amazonses2', 'aws', 'aws1', 'aws2', 'ses'];
eq('normal scan adds provider selectors', googleSelectors.includes('20230601'), true);
eq('normal scan excludes generic expansion', googleSelectors.includes('newsletter1024'), false);
eq('normal scan excludes temporal expansion', googleSelectors.includes('2030q4'), false);
eq('comprehensive scan uses all 1,677 vetted exact selectors', comprehensiveSelectors.length, 1677);
eq('comprehensive scan includes generic selectors', comprehensiveSelectors.includes('newsletter1024'), true);
eq('comprehensive scan includes temporal selectors', comprehensiveSelectors.includes('2030q4'), true);
eq('fixed SES guesses are excluded from scans', excludedFixedSesSelectors.every(s => !comprehensiveSelectors.includes(s)), true);
eq('custom selectors are retained', D.buildDkimSelectorList(['campaign-2026'], 'Google Workspace', false)[0], 'campaign-2026');
eq('active DKIM key accepted', D.dkimKeyRecords([{ type: 16, data: '"v=DKIM1; k=rsa; p=abc123"' }]).length, 1);
eq('DKIM v tag may be omitted', D.dkimKeyRecords([{ type: 16, data: '"k=rsa; p=abc123"' }]).length, 1);
eq('unrelated TXT rejected', D.dkimKeyRecords([{ type: 16, data: '"verification=abc123"' }]).length, 0);
eq('revoked empty DKIM key rejected', D.dkimKeyRecords([{ type: 16, data: '"v=DKIM1; p="' }]).length, 0);
eq('catalog selector is recognized', D.isRecognizedDkimSelector('selector1'), true);
eq('fixed SES guesses are not recognized', excludedFixedSesSelectors.every(s => !D.isRecognizedDkimSelector(s)), true);
eq('unknown supplied selector is uncommon', D.isRecognizedDkimSelector('campaign-live'), false);

sandbox.fetch = async url => {
  const name = new URL(url).searchParams.get('name');
  let answer = [];
  if (name === 'campaign-live._domainkey.example.com') {
    answer = [{ type: 16, data: '"v=DKIM1; p=campaignPublicKey"' }];
  } else if (name === 'easy-token._domainkey.ses-example.com') {
    answer = [{ type: 5, data: 'easy-token.dkim.amazonses.com.' }];
  } else if (name === 'easy-token.dkim.amazonses.com') {
    answer = [{ type: 16, data: '"v=DKIM1; p=sesPublicKey"' }];
  }
  return { ok: true, json: async () => ({ Status: 0, Answer: answer }) };
};
const uncommonDkim = await D.checkDKIM('example.com', false, ['campaign-live'], '@custom-unknown', false, {});
eq('uncommon supplied selector is found', uncommonDkim.found, true);
eq('uncommon finding is labeled', uncommonDkim.selectors[0].uncommon, true);
eq('uncommon finding includes query name', uncommonDkim.selectors[0].queryName, 'campaign-live._domainkey.example.com');
eq('uncommon finding includes TXT data', uncommonDkim.selectors[0].value, 'v=DKIM1; p=campaignPublicKey');

const easyDkim = await D.checkDKIM('ses-example.com', false, ['easy-token'], '@custom-unknown', false, {});
eq('Easy DKIM CNAME is followed', easyDkim.found, true);
eq('Easy DKIM reports the source record type', easyDkim.selectors[0].type, 'cname');
eq('Easy DKIM reports the CNAME target', easyDkim.selectors[0].cname, 'easy-token.dkim.amazonses.com');
eq('Easy DKIM reports the resolved TXT key', easyDkim.selectors[0].value, 'v=DKIM1; p=sesPublicKey');

const missingDkim = await D.checkDKIM('missing.example', false, ['does-not-exist'], '@custom-unknown', false, {});
eq('missing supplied selector does not verify DKIM', missingDkim.found, false);
eq('missing selector is listed', missingDkim.missingSelectors[0].queryName, 'does-not-exist._domainkey.missing.example');

/* ── 22. RFC 9989 conformance ────────────────────────────────────────── */
section('22. RFC 9989 conformance (DMARCbis, May 2026)');

const dm = rec => D.analyzeDmarc(rec);
const keys = (rec, domain) => D.buildIssues({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: dm(rec),
  hosting: 'Custom', advanced: full, domain,
}).map(i => i.key);

// ── v= placement and case (§5.4: violations mean the record MUST be ignored)
eq('v first + exact → valid',    D.validateDmarcVersion('v=DMARC1; p=reject').valid, true);
eq('leading space tolerated',    D.validateDmarcVersion('  v=DMARC1; p=reject').valid, true);
eq('uppercase tag name ok',      D.validateDmarcVersion('V=DMARC1; p=reject').valid, true);
eq('lowercase value rejected',   D.validateDmarcVersion('v=dmarc1; p=reject').reason, 'bad-value');
eq('DMARC2 rejected',            D.validateDmarcVersion('v=DMARC2; p=reject').reason, 'bad-value');
eq('v not first rejected',       D.validateDmarcVersion('p=reject; v=DMARC1').reason, 'not-first');
eq('no tags at all',             D.validateDmarcVersion('').reason, 'absent');
eq('bad version → present',      dm('v=dmarc1; p=reject').status, 'present');
eq('bad version scores 0',       dscore('v=dmarc1; p=reject; rua=mailto:a@b.com'), 0);
eq('lowercase v → version issue',keys('v=dmarc1; p=reject').includes('dmarc-version-bad-value'), true);
eq('v not first → its own key',  keys('p=reject; v=DMARC1').includes('dmarc-version-not-first'), true);
eq('bad version is not "invalid policy"',
  keys('v=dmarc1; p=reject').includes('dmarc-invalid-policy'), false);

// ── t= test mode (§5.4, new in RFC 9989)
eq('t=y parsed',                 dm('v=DMARC1; p=reject; t=y').testMode, true);
eq('t=n parsed',                 dm('v=DMARC1; p=reject; t=n').testMode, false);
eq('t absent defaults n',        dm('v=DMARC1; p=reject').testMode, false);
eq('T=Y case-insensitive',       dm('v=DMARC1; p=reject; T=Y').testMode, true);
eq('t=y keeps published policy', dm('v=DMARC1; p=reject; t=y').policy, 'reject');
eq('t=y effective is none',      dm('v=DMARC1; p=reject; t=y').effectivePolicy, 'none');
eq('t=y is not enforcing',       dm('v=DMARC1; p=reject; t=y').enforcing, false);
eq('t=y downgrades status',      dm('v=DMARC1; p=reject; t=y').status, 'warn');
eq('t=y → dmarc-test-mode',      keys('v=DMARC1; p=reject; t=y').includes('dmarc-test-mode'), true);
eq('t=n → no test-mode issue',   keys('v=DMARC1; p=reject; t=n').includes('dmarc-test-mode'), false);
eq('t=maybe flagged',            dm('v=DMARC1; p=reject; t=maybe').tValid, false);
eq('t=maybe → dmarc-bad-t',      keys('v=DMARC1; p=reject; t=maybe').includes('dmarc-bad-t'), true);
// t=y must not masquerade as "no DMARC policy at all".
eq('t=y does not fire dmarc-none', keys('v=DMARC1; p=reject; t=y').includes('dmarc-none'), false);

// ── pct= removal (§ Appendix A.6)
eq('pct still parsed',           dm('v=DMARC1; p=reject; pct=50').pct, 50);
eq('pct presence tracked',       dm('v=DMARC1; p=reject; pct=50').pctPresent, true);
eq('pct absence tracked',        dm('v=DMARC1; p=reject').pctPresent, false);
eq('pct listed as removed',      dm('v=DMARC1; p=reject; pct=50').removedTags, ['pct']);
// pct is not double-reported as a generic removed tag.
eq('pct not in removed-tags issue',
  keys('v=DMARC1; p=reject; pct=50').includes('dmarc-removed-tags'), false);
eq('rf/ri are removed-tags',     keys('v=DMARC1; p=reject; rf=afrf; ri=86400').includes('dmarc-removed-tags'), true);

// "Remove this obsolete tag" is advice, so it belongs in Recommendations —
// and must NOT also appear as an Issue, or the same point is made twice in
// one panel.
const tips = (rec, adv) => D.buildSuggestions({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: dm(rec), advanced: adv === undefined ? full : adv,
}).map(s => s.key);

eq('pct → recommendation',       tips('v=DMARC1; p=reject; pct=100').includes('dmarc-pct-obsolete'), true);
eq('pct=50 → recommendation',    tips('v=DMARC1; p=reject; pct=50').includes('dmarc-pct-obsolete'), true);
eq('no pct → no recommendation', tips('v=DMARC1; p=reject').includes('dmarc-pct-obsolete'), false);
eq('pct is not also an issue',   keys('v=DMARC1; p=reject; pct=100').includes('dmarc-pct-obsolete'), false);
// A pct below 100 still has a live consequence, so that keeps its own warning.
eq('pct=100 raises no warning',  keys('v=DMARC1; p=reject; pct=100').includes('dmarc-partial-pct'), false);
eq('pct=50 still warns',         keys('v=DMARC1; p=reject; pct=50').includes('dmarc-partial-pct'), true);
// Derived from the DMARC record alone, so it must survive advanced checks off.
eq('pct advice without advanced checks',
  tips('v=DMARC1; p=reject; pct=50', null).includes('dmarc-pct-obsolete'), true);
eq('missing record → no pct advice', tips('').includes('dmarc-pct-obsolete'), false);

// Every recommendation must carry a translation, and any guide it links to
// must actually exist — a dangling guide renders a dead "Learn more" button.
const enBundle = JSON.parse(readFileSync(`${REPO}/locales/en.json`, 'utf8'));
const allTips = D.buildSuggestions({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: dm('v=DMARC1; p=reject; pct=50'), advanced: bare,
});
eq('every recommendation has text',
  allTips.filter(s => !(s.key in enBundle.suggestion)).map(s => s.key), []);
eq('every recommendation guide exists',
  allTips.filter(s => s.guide && !(s.guide in enBundle.learnMore)).map(s => s.guide), []);

// ── psd= (§5.4, new in RFC 9989)
eq('psd defaults to u',          dm('v=DMARC1; p=reject').psd, 'u');
eq('psd=y parsed',               dm('v=DMARC1; p=reject; psd=y').psd, 'y');
eq('psd=maybe flagged',          dm('v=DMARC1; p=reject; psd=maybe').psdValid, false);
eq('psd=maybe → issue',          keys('v=DMARC1; p=reject; psd=maybe').includes('dmarc-bad-psd'), true);
eq('psd=y on an org domain → issue',
  keys('v=DMARC1; p=reject; psd=y', 'example.com').includes('dmarc-psd-invalid'), true);
eq('psd=y without a domain is not guessed at',
  keys('v=DMARC1; p=reject; psd=y').includes('dmarc-psd-invalid'), false);

// ── rua/ruf URI parsing (§5.4)
const uri = v => D.parseDmarcUriList(v);
eq('plain mailto valid',         uri('mailto:a@b.com').valid, true);
eq('domain extracted',           uri('mailto:a@b.com').domains, ['b.com']);
eq('size limit accepted',        uri('mailto:a@b.com!10m').valid, true);
eq('size limit captured',        uri('mailto:a@b.com!10m').uris[0].sizeLimit, '10m');
eq('bare size limit accepted',   uri('mailto:a@b.com!20').valid, true);
eq('bad size limit rejected',    uri('mailto:a@b.com!huge').valid, false);
eq('two destinations',           uri('mailto:a@b.com, mailto:c@d.org').count, 2);
eq('both domains extracted',     uri('mailto:a@b.com, mailto:c@d.org').domains, ['b.com', 'd.org']);
eq('missing scheme rejected',    uri('a@b.com').valid, false);
eq('https marked unsupported',   uri('https://reports.example/ingest').uris[0].unsupportedScheme, true);
eq('https not valid for DMARC',  uri('https://reports.example/ingest').valid, false);
eq('empty list is not valid',    uri('').valid, false);
eq('one bad destination sinks the list',
  uri('mailto:a@b.com, oops').valid, false);
eq('bad destination reported',   uri('mailto:a@b.com, oops').invalid, ['oops']);
eq('bad rua → issue',            keys('v=DMARC1; p=reject; rua=dmarc@b.com').includes('dmarc-rua-invalid'), true);
eq('good rua → no issue',        keys('v=DMARC1; p=reject; rua=mailto:a@b.com').includes('dmarc-rua-invalid'), false);
eq('bad ruf → issue',
  keys('v=DMARC1; p=reject; rua=mailto:a@b.com; ruf=forensics@b.com').includes('dmarc-ruf-invalid'), true);

// ── fo= (§5.4)
eq('fo defaults to 0',           dm('v=DMARC1; p=reject').fo, '0');
eq('fo=1 valid',                 dm('v=DMARC1; p=reject; fo=1').foValid, true);
eq('fo=d:s valid',               dm('v=DMARC1; p=reject; fo=d:s').foValid, true);
eq('fo=x invalid',               dm('v=DMARC1; p=reject; fo=x').foValid, false);
eq('fo=x → issue',               keys('v=DMARC1; p=reject; fo=x; ruf=mailto:f@b.com').includes('dmarc-bad-fo'), true);
eq('fo without ruf → issue',     keys('v=DMARC1; p=reject; fo=1; rua=mailto:a@b.com').includes('dmarc-fo-without-ruf'), true);
eq('fo with ruf → no issue',
  keys('v=DMARC1; p=reject; fo=1; rua=mailto:a@b.com; ruf=mailto:f@b.com').includes('dmarc-fo-without-ruf'), false);

// ── External report authorization (§5.6)
const ext = (rec, domain) => D.findExternalReportDestinations(dm(rec), domain);
eq('same domain is not external',
  ext('v=DMARC1; p=reject; rua=mailto:d@example.com', 'example.com'), []);
eq('subdomain of org is not external',
  ext('v=DMARC1; p=reject; rua=mailto:d@mail.example.com', 'example.com'), []);
eq('sibling subdomain resolves to the same org domain',
  ext('v=DMARC1; p=reject; rua=mailto:d@example.com', 'mail.example.com'), []);
eq('vendor hosted under your own org domain is not external',
  ext('v=DMARC1; p=reject; rua=mailto:x@vendor.example.com', 'example.com'), []);
eq('genuinely outside domain is external',
  ext('v=DMARC1; p=reject; rua=mailto:x@vendor.com', 'example.com'), ['vendor.com']);
eq('ruf destinations count too',
  ext('v=DMARC1; p=reject; rua=mailto:d@example.com; ruf=mailto:x@vendor.com', 'example.com'), ['vendor.com']);
eq('external destinations deduplicated',
  ext('v=DMARC1; p=reject; rua=mailto:a@vendor.com; ruf=mailto:b@vendor.com', 'example.com'), ['vendor.com']);
eq('external → issue',
  keys('v=DMARC1; p=reject; rua=mailto:x@vendor.com', 'example.com').includes('dmarc-external-reporting'), true);
eq('internal → no issue',
  keys('v=DMARC1; p=reject; rua=mailto:d@example.com', 'example.com').includes('dmarc-external-reporting'), false);

// Mixed internal + external is the common real-world shape (a vendor address
// alongside your own mailbox). RFC 9990 §4.3 evaluates authorization per URI,
// so only the external one is ever at risk — the record itself stays valid.
const mixed = 'v=DMARC1; p=reject; rua=mailto:a@vendor.com,mailto:b@example.com';
eq('mixed record is still valid',      dm(mixed).status, 'ok');
eq('mixed record scores normally',     dscore(mixed), 25);
eq('only the outside address is flagged',
  ext(mixed, 'example.com'), ['vendor.com']);

// ── Verdict-driven findings (RFC 9990 §4.3)
const withAuth = states => Object.assign({}, full, {
  reportAuth: states.map(([destination, state]) => ({ destination, state })),
});
const keysAuth = (rec, domain, adv) => D.buildIssues({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: dm(rec),
  hosting: 'Custom', advanced: adv, domain,
}).map(i => i.key);

const extRec = 'v=DMARC1; p=reject; rua=mailto:x@vendor.com';
// A vendor that HAS published the record must produce no finding at all —
// this is the false positive the blanket notice used to raise on every domain.
eq('authorized → silent',
  keysAuth(extRec, 'example.com', withAuth([['vendor.com', 'authorized']]))
    .some(k => k.startsWith('dmarc-external')), false);
eq('unauthorized → warning',
  keysAuth(extRec, 'example.com', withAuth([['vendor.com', 'unauthorized']]))
    .includes('dmarc-external-unauthorized'), true);
// A failed lookup is unknown, not a finding against the operator.
eq('unverifiable is info, not a warning',
  keysAuth(extRec, 'example.com', withAuth([['vendor.com', 'unverifiable']]))
    .includes('dmarc-external-unverifiable'), true);
eq('unverifiable does not claim unauthorized',
  keysAuth(extRec, 'example.com', withAuth([['vendor.com', 'unverifiable']]))
    .includes('dmarc-external-unauthorized'), false);
// Only the failing destination is named.
const twoVendors = 'v=DMARC1; p=reject; rua=mailto:a@good.com,mailto:b@bad.com';
const mixedVerdict = D.buildIssues({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: dm(twoVendors), hosting: 'Custom',
  advanced: withAuth([['good.com', 'authorized'], ['bad.com', 'unauthorized']]),
  domain: 'example.com',
}).find(i => i.key === 'dmarc-external-unauthorized');
eq('only the unauthorized vendor is named', mixedVerdict.args, ['bad.com']);
// With the check switched off, fall back to the advisory notice.
eq('no reportAuth → advisory fallback',
  keysAuth(extRec, 'example.com', Object.assign({}, full, { reportAuth: null }))
    .includes('dmarc-external-reporting'), true);

// ── Unknown tags (§5.4: "Unknown tags MUST be ignored")
eq('typo tag detected',          dm('v=DMARC1; p=reject; rau=mailto:a@b.com').unknownTags, ['rau']);
eq('typo tag → issue',           keys('v=DMARC1; p=reject; rau=mailto:a@b.com').includes('dmarc-unknown-tags'), true);
// The whole point: a misspelled rua is ALSO a missing report destination.
eq('typo rua means no rua',      dm('v=DMARC1; p=reject; rau=mailto:a@b.com').rua, false);
eq('clean record has no unknown tags',
  dm('v=DMARC1; p=reject; sp=reject; np=reject; adkim=s; aspf=s; fo=1; rua=mailto:a@b.com; ruf=mailto:f@b.com; psd=n; t=n').unknownTags, []);
eq('every RFC 9989 tag is accepted',
  D.DMARC_TAGS_RFC9989.length, 11);
eq('removed tag list is exactly pct/rf/ri',
  D.DMARC_TAGS_REMOVED.slice().sort(), ['pct', 'rf', 'ri']);

// ── Duplicate tags get their own finding, not "invalid policy"
eq('duplicate p → present',      dm('v=DMARC1; p=none; p=reject').status, 'present');
eq('duplicate p → duplicate key', keys('v=DMARC1; p=none; p=reject').includes('dmarc-duplicate-tags'), true);
eq('duplicate p is not "invalid policy"',
  keys('v=DMARC1; p=none; p=reject').includes('dmarc-invalid-policy'), false);

// ── Every issue key the analyzer can emit must exist in en.json
const enIssues = JSON.parse(readFileSync(`${REPO}/locales/en.json`, 'utf8')).issue;
const emitted = new Set([
  ...keys('v=dmarc1; p=reject'),
  ...keys('p=reject; v=DMARC1'),
  ...keys('v=DMARC1; p=none; p=reject'),
  ...keys('v=DMARC1; p=bogus'),
  ...keys('v=DMARC1; p=reject; t=y; pct=50; fo=x; psd=maybe; rf=afrf; rau=1; rua=nope'),
  ...keys('v=DMARC1; p=reject; t=maybe; fo=1; rua=mailto:x@vendor.com; ruf=bad', 'example.com'),
  ...keys('v=DMARC1; p=reject; psd=y', 'example.com'),
]);
eq('no issue key is missing a translation',
  [...emitted].filter(k => !(k in enIssues)).sort(), []);

/* ── 23. External report authorization lookup (RFC 9990 §4.3) ────────── */
section('23. External report authorization lookup (RFC 9990 §4.3)');

// Mirrors the real Cloudflare setup: an exact per-domain record at the vendor,
// a vendor publishing the wildcard form, a vendor with nothing, a vendor whose
// record is malformed, and a destination whose lookup fails outright.
sandbox.fetch = async url => {
  const name = new URL(url).searchParams.get('name');
  const txt = {
    'example.com._report._dmarc.exact-vendor.com': ['"v=DMARC1;"'],
    '*._report._dmarc.wildcard-vendor.com': ['"v=DMARC1"'],
    'example.com._report._dmarc.malformed-vendor.com': ['"p=reject; v=DMARC1"'],
  }[name];
  if (name.endsWith('broken-vendor.com')) return { ok: true, json: async () => ({ Status: 2 }) };
  return {
    ok: true,
    json: async () => ({ Status: 0, Answer: (txt || []).map(data => ({ type: 16, data })) }),
  };
};

const auth = await D.checkExternalReportAuth('example.com', [
  'exact-vendor.com', 'wildcard-vendor.com', 'silent-vendor.com',
  'malformed-vendor.com', 'broken-vendor.com',
], {});
const byDest = Object.fromEntries(auth.map(a => [a.destination, a]));

eq('exact record authorizes',        byDest['exact-vendor.com'].state, 'authorized');
eq('exact match is reported as such', byDest['exact-vendor.com'].via, 'exact');
eq('query name is the RFC form',     byDest['exact-vendor.com'].queryName,
  'example.com._report._dmarc.exact-vendor.com');
// Vendors with many customers publish the wildcard rather than one record each.
eq('wildcard record authorizes',     byDest['wildcard-vendor.com'].state, 'authorized');
eq('wildcard match is reported',     byDest['wildcard-vendor.com'].via, 'wildcard');
eq('no record → unauthorized',       byDest['silent-vendor.com'].state, 'unauthorized');
// RFC 9989 §5.4 applies here too: v= must come first, so this does not qualify.
eq('v= not first → unauthorized',    byDest['malformed-vendor.com'].state, 'unauthorized');
eq('malformed record is distinguished', byDest['malformed-vendor.com'].malformed, true);
// A SERVFAIL is missing evidence, not evidence of a missing record.
eq('DNS failure → unverifiable',     byDest['broken-vendor.com'].state, 'unverifiable');
eq('one verdict per destination',    auth.length, 5);

// Duplicate destinations are collapsed so a vendor named twice is queried once.
const deduped = await D.checkExternalReportAuth('example.com',
  ['exact-vendor.com', 'exact-vendor.com', 'EXACT-VENDOR.COM.'], {});
eq('destinations deduplicated', deduped.length, 1);

/* ── 24. Optional checks degrade instead of aborting the audit ───────── */
section('24. Resilience: a failed optional lookup must not discard the audit');

// The regression this guards: intercamsa.com resolved perfectly for NS, MX,
// TXT and _dmarc, but Cloudflare returned a transient SERVFAIL for
// www.intercamsa.com and for a nonexistent probe name. Both were optional
// checks, both threw, and the throw destroyed a complete, valid audit.

// A resolver that answers the core records but SERVFAILs everything else —
// the shape of a broken or flaky subdomain.
// Only the core lookups answer. Anything not listed here — CAA, www, the
// wildcard probe, _mta-sts, _smtp._tls, default._bimi — returns SERVFAIL.
const CORE = {
  'flaky.example': {
    NS: [{ type: 2, data: 'ns1.host.example.' }],
    MX: [{ type: 15, data: '10 mail.host.example.' }],
    TXT: [{ type: 16, data: '"v=spf1 -all"' }],
    A: [{ type: 1, data: '203.0.113.10' }],
    AAAA: [],
  },
  '_dmarc.flaky.example': {
    TXT: [{ type: 16, data: '"v=DMARC1; p=reject; rua=mailto:d@flaky.example"' }],
  },
};
sandbox.fetch = async url => {
  const params = new URL(url).searchParams;
  const name = params.get('name');
  const typeName = { 1: 'A', 2: 'NS', 15: 'MX', 16: 'TXT', 28: 'AAAA', 5: 'CNAME', 257: 'CAA' }[params.get('type')];
  const entry = CORE[name];
  if (entry && entry[typeName] !== undefined) {
    return { ok: true, json: async () => ({ Status: 0, AD: false, Answer: entry[typeName] }) };
  }
  return { ok: true, json: async () => ({ Status: 2 }) };
};

const resilient = await D.analyzeDomain('flaky.example', {
  www: true, advanced: true, dkim: false, wildcard: true, retries: 0,
});

eq('audit completes despite SERVFAILs', !!resilient, true);
eq('core records still parsed',         resilient.mx.length, 1);
eq('SPF still analysed',                resilient.spfStatus.status, 'ok');
eq('DMARC still analysed',              resilient.dmarcStatus.policy, 'reject');
eq('a real score is produced',          Number.isFinite(resilient.score.pts), true);
eq('grade is not F',                    resilient.score.grade !== 'F', true);

// Failed optional checks must read as unknown, never as absent.
eq('CAA marked unknown',      resilient.advanced.caa.unknown, true);
eq('CAA not claimed missing', resilient.advanced.caa.found, false);
eq('MTA-STS marked unknown',  resilient.advanced.mtaSts.unknown, true);
eq('TLS-RPT marked unknown',  resilient.advanced.tlsRpt.unknown, true);
eq('BIMI marked unknown',     resilient.advanced.bimi.unknown, true);
eq('hosting reports a lookup failure', resilient.hosting, '@dns-error');

// Both wildcard probes failed here. Neither depth may read as "wildcard
// present" on the strength of a lookup that never answered.
eq('failed apex probe reports no wildcard',    resilient.wildcardApex, false);
eq('failed DKIM-depth probe reports no wildcard', resilient.wildcardDkim, false);

// Unknown pillars are unscored, not zeroed, so the grade is a range.
const pillarsBy = Object.fromEntries(resilient.score.breakdown.pillars.map(p => [p.key, p]));
eq('CAA pillar is unknown',      pillarsBy.caa.unknown, true);
eq('CAA pillar scores null',     pillarsBy.caa.pts, null);
eq('MTA-STS pillar is unknown',  pillarsBy.mtaSts.unknown, true);
eq('BIMI pillar is unknown',     pillarsBy.bimi.unknown, true);
eq('TLS-RPT pillar is unknown',  pillarsBy.tlsRpt.unknown, true);
eq('score is reported as a range', resilient.score.uncertain, true);
eq('max possible exceeds score',   resilient.score.maxPossible > resilient.score.pts, true);

// The gap is stated rather than silently omitted.
const resilientKeys = resilient.issues.map(i => i.key);
eq('unverified checks are named', resilientKeys.includes('checks-unverified'), true);
const unverifiedIssue = resilient.issues.find(i => i.key === 'checks-unverified');
eq('the named checks are listed', unverifiedIssue.args[0].includes('CAA'), true);

// No "you have not configured this" advice for a check that never completed.
const resilientTips = resilient.suggestions.map(s => s.key);
eq('no CAA advice when unverified',     resilientTips.includes('caa'), false);
eq('no MTA-STS advice when unverified', resilientTips.includes('mta-sts'), false);
eq('no TLS-RPT advice when unverified', resilientTips.includes('tls-rpt'), false);

// Advanced completion excludes unverified checks from its denominator.
eq('unverified checks leave the denominator', resilient.advScore.total < 5, true);

// The DKIM note interpolates two counts. Without them the UI renders the raw
// "{0}"/"{1}" placeholders, and a failed lookup makes this note far more common.
const dkimNoteIssue = D.buildIssues({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'),
  dkimStatus: { found: false, confidence: 'sampled', note: 'noteNotFoundWithErrors', testedSelectors: new Array(17), failedSelectors: new Array(5) },
  dmarcStatus: dm('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  hosting: 'Custom', advanced: full,
}).find(i => i.noteKey);
eq('DKIM note carries its counts', dkimNoteIssue.noteArgs, [12, 5]);

// A total resolver failure is still a hard error: with no NS there is nothing
// to audit, and inventing a result would be worse than reporting the failure.
sandbox.fetch = async () => ({ ok: true, json: async () => ({ Status: 2 }) });
let coreFailed = false;
try { await D.analyzeDomain('dead.example', { www: true, advanced: true, retries: 0 }); }
catch { coreFailed = true; }
eq('core NS failure still aborts', coreFailed, true);

// optionalCheck itself: swallow failures, but never swallow cancellation.
eq('fallback value returned',
  await D.optionalCheck(async () => { throw new Error('servfail'); }, 'fallback'), 'fallback');
eq('fallback may be a function',
  await D.optionalCheck(async () => { throw new Error('boom'); }, () => 'computed'), 'computed');
eq('success passes through',
  await D.optionalCheck(async () => 'value', 'fallback'), 'value');
let abortPropagated = false;
try {
  await D.optionalCheck(async () => {
    const e = new Error('cancelled'); e.name = 'AbortError'; throw e;
  }, 'fallback');
} catch { abortPropagated = true; }
eq('cancellation is not swallowed', abortPropagated, true);

/* ── 25. Wildcard TXT is judged at the depth that predicts the harm ──── */
section('25. Wildcard TXT: apex synthesis vs synthesis over _domainkey');

// The probe used to ask one label deep and infer harm to DKIM, which lives two
// labels deep at <selector>._domainkey.<domain>. Those are different questions,
// and on apple.com and ibm.com they get different answers: both publish an apex
// wildcard, neither lets it reach DKIM. Both scored F=0 on the strength of the
// shallow probe alone.
//
// Depth is measured, not inferred. RFC 4592 §2.2.1 stops synthesis below an
// existing node, so publishing _domainkey ought to be protection enough — but
// netflix.com publishes `_domainkey.netflix.com` and its nameservers synthesize
// under it anyway. Only the deeper probe can tell.

const WILDCARD_ZONES = {
  // Synthesis one label deep only: the shape apple.com and ibm.com serve.
  'apex.example': { depth: 1, wildcardValue: '"v=spf1 redirect=_spf.apex.example"' },
  // Synthesis at any depth, the shape netflix.com's nameservers serve. The
  // value is deliberately a well-formed DKIM key — an audit that trusts it
  // reports DKIM present on every selector it tries.
  'deep.example': { depth: 9, wildcardValue: '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB"' },
};

const answer = records => ({ ok: true, json: async () => ({ Status: 0, AD: false, Answer: records }) });
const nxdomain = { ok: true, json: async () => ({ Status: 3 }) };

sandbox.fetch = async url => {
  const params = new URL(url).searchParams;
  const name = params.get('name');
  const typeName = { 1: 'A', 2: 'NS', 15: 'MX', 16: 'TXT', 28: 'AAAA', 5: 'CNAME', 257: 'CAA' }[params.get('type')];
  const zone = Object.keys(WILDCARD_ZONES).find(z => name === z || name.endsWith(`.${z}`));
  if (!zone) return nxdomain;
  const cfg = WILDCARD_ZONES[zone];

  if (name === zone) {
    if (typeName === 'NS') return answer([{ type: 2, data: 'ns1.example.' }]);
    if (typeName === 'MX') return answer([{ type: 15, data: '10 mail.example.' }]);
    if (typeName === 'TXT') return answer([{ type: 16, data: '"v=spf1 include:_spf.example -all"' }]);
    if (typeName === 'A') return answer([{ type: 1, data: '203.0.113.5' }]);
    return answer([]);
  }
  if (name === `_dmarc.${zone}`) {
    return typeName === 'TXT'
      ? answer([{ type: 16, data: `"v=DMARC1; p=reject; rua=mailto:d@${zone}"` }])
      : answer([]);
  }
  // Everything else is undefined in the zone, so the wildcard answers it —
  // but only as deep as this nameserver is willing to synthesize.
  const depth = name.slice(0, -(zone.length + 1)).split('.').length;
  if (typeName === 'TXT' && depth <= cfg.depth) return answer([{ type: 16, data: cfg.wildcardValue }]);
  return nxdomain;
};

const WILDCARD_OPTS = { www: false, advanced: false, dkim: true, wildcard: true, retries: 0 };
const apexZone = await D.analyzeDomain('apex.example', WILDCARD_OPTS);
const deepZone = await D.analyzeDomain('deep.example', WILDCARD_OPTS);

// ── Apex-only: reported, not penalised ──
eq('apex wildcard detected',              apexZone.wildcardApex, true);
eq('apex wildcard does not reach DKIM',   apexZone.wildcardDkim, false);
const apexIssue = apexZone.issues.find(i => i.key === 'wildcard-txt-apex');
eq('apex wildcard is informational',      apexIssue && apexIssue.sev, 'info');
eq('no DKIM-depth issue raised',          apexZone.issues.some(i => i.key === 'wildcard-txt-dkim'), false);
eq('apex wildcard costs no points',       apexZone.score.pts > 0, true);
eq('apex wildcard is not an F',           apexZone.score.grade !== 'F', true);
// No DKIM is found in either zone, so both report the sampled confidence a
// selector scan can honestly claim. What separates them is why, and the note
// records it: nothing published here, versus a lookup that cannot answer.
eq('apex absence is a plain not-found',   apexZone.dkimStatus.note, 'noteNotFound');

// ── Over _domainkey: DKIM becomes unknown, everything else still counts ──
eq('deep wildcard detected at DKIM depth', deepZone.wildcardDkim, true);
const deepIssue = deepZone.issues.find(i => i.key === 'wildcard-txt-dkim');
eq('deep wildcard raises a warning',       deepIssue && deepIssue.sev, 'warn');
// The synthesized value parses as a valid DKIM key. Trusting it would report a
// key at every selector the scan tries, which is worse than reporting none.
eq('synthesized value is not a DKIM key',  deepZone.dkimStatus.found, false);
eq('DKIM is sampled, not missing',         deepZone.dkimStatus.confidence, 'sampled');
eq('the wildcard is named as the reason',  deepZone.dkimStatus.note, 'noteWildcard');

const deepPillars = Object.fromEntries(deepZone.score.breakdown.pillars.map(p => [p.key, p]));
eq('DKIM pillar is unknown',               deepPillars.dkim.unknown, true);
eq('DKIM pillar is unscored, not zeroed',  deepPillars.dkim.pts, null);
eq('grade is reported as a range',         deepZone.score.grade.includes('–'), true);
eq('score is not zeroed',                  deepZone.score.pts > 0, true);
// The point of retiring the instant F: a wildcard makes DKIM unknowable and
// nothing else. These stay measured.
eq('SPF still scored under the wildcard',   deepPillars.spf.pts > 0, true);
eq('DMARC still scored under the wildcard', deepPillars.dmarc.pts > 0, true);

/* ── Summary ─────────────────────────────────────────────────────────── */
console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
