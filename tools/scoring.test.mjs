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
section('2. pct validation');

eq('absent → 100',       D.analyzeDmarc('v=DMARC1; p=reject').pct, 100);
eq('valid 50',           D.analyzeDmarc('v=DMARC1; p=reject; pct=50').pct, 50);
eq('non-numeric flagged',D.analyzeDmarc('v=DMARC1; p=reject; pct=abc').pctValid, false);
eq('non-numeric → 100',  D.analyzeDmarc('v=DMARC1; p=reject; pct=abc').pct, 100);
eq('over-range clamped', D.analyzeDmarc('v=DMARC1; p=reject; pct=250').pct, 100);
eq('over-range flagged', D.analyzeDmarc('v=DMARC1; p=reject; pct=250').pctValid, false);
eq('negative clamped',   D.analyzeDmarc('v=DMARC1; p=reject; pct=-10').pct, 0);
eq('pct=0 kept',         D.analyzeDmarc('v=DMARC1; p=reject; pct=0').pct, 0);

/* ── 3. sp/np inheritance ────────────────────────────────────────────── */
section('3. Subdomain policy inheritance (RFC 7489 §6.3, RFC 9091 §2)');

const inh = D.analyzeDmarc('v=DMARC1; p=reject');
eq('absent sp inherits p',       inh.effectiveSp, 'reject');
eq('absent np inherits p',       inh.effectiveNp, 'reject');

const spOnly = D.analyzeDmarc('v=DMARC1; p=reject; sp=quarantine');
eq('np inherits sp not p',       spOnly.effectiveNp, 'quarantine');

const npOnly = D.analyzeDmarc('v=DMARC1; p=reject; np=none');
eq('np explicit wins',           npOnly.effectiveNp, 'none');
eq('sp still inherits p',        npOnly.effectiveSp, 'reject');

/* ── 4. DMARC sub-score ──────────────────────────────────────────────── */
section('4. DMARC sub-score (max 30)');

const dscore = rec => D.calcDmarcScore(D.analyzeDmarc(rec)).pts;

eq('missing record',             D.calcDmarcScore(D.analyzeDmarc('')).pts, 0);
// p=reject 10 + sub 6 (inherited) + pct 4 + rua 5 = 25
eq('p=reject + rua (inherited)', dscore('v=DMARC1; p=reject; rua=mailto:a@b.com'), 25);
// Inherited reject must score the SAME as explicit sp=reject — this is the
// design-doc bug: inheritance is equally protective, so it must not be penalised.
eq('explicit sp=reject equal',   dscore('v=DMARC1; p=reject; sp=reject; rua=mailto:a@b.com'), 25);
// Explicitly weakened subdomains must score LOWER.
eq('sp=none scores lower',       dscore('v=DMARC1; p=reject; sp=none; rua=mailto:a@b.com'), 20);
// np=none is the weakest link even when sp inherits reject.
eq('np=none penalised',          dscore('v=DMARC1; p=reject; np=none; rua=mailto:a@b.com'), 20);
// pct=50 halves the 4-point enforcement-rate component.
eq('pct=50 costs 2',             dscore('v=DMARC1; p=reject; pct=50; rua=mailto:a@b.com'), 23);
// Full marks: reject + strict alignment both ways + ruf.
eq('perfect record = 30',        dscore('v=DMARC1; p=reject; sp=reject; np=reject; pct=100; rua=mailto:a@b.com; ruf=mailto:f@b.com; adkim=s; aspf=s'), 30);
eq('never exceeds 30',           dscore('v=DMARC1; p=reject; sp=reject; np=reject; pct=100; rua=mailto:a@b.com; ruf=mailto:f@b.com; adkim=s; aspf=s') <= 30, true);
// p=none: policy 3 + sub 1 + pct 4 (irrelevant) + rua 5 = 13
eq('p=none + rua',               dscore('v=DMARC1; p=none; rua=mailto:a@b.com'), 13);

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
  wildcardBug: false, advanced: full,
});
eq('best case = 100 / A++', [best.pts, best.grade], [100, 'A++']);

const noDnssec = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  wildcardBug: false,
  advanced: Object.assign({}, full, { dnssec: { signed: false } }),
});
eq('strong but unsigned → B', noDnssec.grade, 'B');

const worst = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('missing'), dkimStatus: { found: false },
  dmarcStatus: D.analyzeDmarc(''), wildcardBug: false, advanced: bare,
});
eq('nothing configured = 0 / F', [worst.pts, worst.grade], [0, 'F']);

const wildcard = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  wildcardBug: true, advanced: full,
});
eq('wildcard TXT → instant F', [wildcard.grade, wildcard.pts], ['F', 0]);

// pct=abc previously produced NaN → every comparison false → silent F.
const nanPct = D.calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; pct=abc; rua=mailto:a@b.com'),
  wildcardBug: false, advanced: full,
});
eq('malformed pct is not NaN', Number.isFinite(nanPct.pts), true);
eq('malformed pct still graded', nanPct.grade !== 'F', true);

/* ── 9. Parked-domain path ───────────────────────────────────────────── */
section('9. Parked domains (no MX)');

const parkedHard = D.calcScore({
  emailProvider: '@null-mx',
  spfStatus: spf('ok'), dkimStatus: { found: false },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject;'),
  wildcardBug: false, advanced: full,
});
eq('hardened parked = 100', parkedHard.pts, 100);
eq('parked flagged',        parkedHard.parked, true);
eq('parked reaches A tier', parkedHard.grade, 'A++');

const parkedBare = D.calcScore({
  emailProvider: '@null-mx',
  spfStatus: spf('missing'), dkimStatus: { found: false },
  dmarcStatus: D.analyzeDmarc(''), wildcardBug: false, advanced: bare,
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
  ['alignment', 'pct', 'policy', 'rua', 'ruf', 'subdomain']);

/* ── 11. New issue keys fire correctly ───────────────────────────────── */
section('11. Issue detection');

const issuesFor = (rec, adv) => D.buildIssues({
  emailProvider: 'Google Workspace',
  spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc(rec), wildcardBug: false,
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
    dkimStatus: { found: true }, dmarcStatus: bogus, wildcardBug: false,
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
  dmarcStatus, wildcardBug: false, hosting: 'Custom', advanced: adv || full,
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
  wildcardBug: false, advanced: dupAdv,
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
  wildcardBug: false, hosting: 'Custom', advanced: full,
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
  wildcardBug: false, hosting: 'Custom', advanced: full,
}).some(i => i.key === 'dkim-multiple-records'), false);

/* ── 18. CAA and MX multiples are legal, not errors ──────────────────── */
section('18. Record types where multiples are legitimate');

// CAA is designed for multiple records (several CAs, issue + issuewild + iodef).
// Flagging it would be a false positive, so assert we never do.
const multiCaa = D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'), dkimStatus: { found: true, duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'), wildcardBug: false,
  hosting: 'Custom',
  advanced: Object.assign({}, full, {
    caa: { found: true, records: ['0 issue "letsencrypt.org"', '0 issue "digicert.com"', '0 iodef "mailto:a@b.com"'], atDomain: 'x.com' },
  }),
}).map(i => i.key);
eq('multiple CAA not flagged', multiCaa.some(k => k.indexOf('caa-multiple') !== -1), false);
eq('multiple CAA still scores full',
  D.calcScore({ emailProvider: 'Google Workspace', spfStatus: spf('ok'), dkimStatus: { found: true },
    dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; sp=reject; rua=mailto:a@b.com'), wildcardBug: false,
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
  wildcardBug: false, advanced: full,
});
eq('sampled DKIM produces a score range', sampledDkim.uncertain, true);
eq('DKIM unknown is not stored as zero', sampledDkim.breakdown.pillars.find(p => p.key === 'dkim').pts, null);
eq('sampled DKIM is informational', D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: false, confidence: 'sampled', note: 'noteNotFound', duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject'), wildcardBug: false,
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

/* ── Summary ─────────────────────────────────────────────────────────── */
console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
