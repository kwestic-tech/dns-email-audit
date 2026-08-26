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
import { dohFixture, txt, ns, mx, a, aaaa, cname, caa, tlsa, ds, dnskey, rrsig, TYPE_NUM } from './lib/doh-fixture.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..');
// `crypto` is here for the OPTIONAL half of the DKIM key analysis — the Web
// Crypto structural check. `atob` is deliberately NOT provided: the DER length
// walk that produces every key size must work with nothing but the language,
// and leaving the global out is what proves it does. A sandbox that handed the
// code a convenience the browser might not have would test the wrong thing.
const sandbox = { window: { __PUBLIC_SUFFIX_RULES__: ['com', 'co.uk', '*.ck', '!www.ck'] }, fetch: async () => ({ ok: false }), console, AbortController, URLSearchParams, setTimeout, clearTimeout, crypto };
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(readFileSync(`${REPO}/js/dkim-selectors.js`, 'utf8'), sandbox);
vm.runInContext(readFileSync(`${REPO}/js/dns.js`, 'utf8'), sandbox);
const D = sandbox.window.DnsAudit;

let pass = 0, fail = 0;
// BigInt has no JSON representation, and the IPv6 address helpers return one.
const show = v => JSON.stringify(v, (k, x) => (typeof x === 'bigint' ? `${x}n` : x));
const eq = (label, actual, expected) => {
  const a = show(actual), e = show(expected);
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
section('3. Subdomain policy inheritance (RFC 9989 §4.7)');

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
// Nor may an unverifiable DKIM check mark a parked grade — there is no DKIM
// pillar here, so no points were lost and there is nothing to recover.
eq('unproven DKIM cannot mark a parked grade', D.calcScore({
  emailProvider: '@null-mx',
  spfStatus: spf('ok'), dkimStatus: { found: false, confidence: 'sampled' },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject;'),
  advanced: full,
}).unproven, []);
// But a check a parked domain *is* scored on still marks it.
eq('unproven CAA marks a parked grade', D.calcScore({
  emailProvider: '@null-mx',
  spfStatus: spf('ok'), dkimStatus: { found: false },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject;'),
  advanced: Object.assign({}, full, { caa: { found: false, unknown: true } }),
}).unproven, ['caa']);

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
eq('sampled DKIM scores zero, not a range', sampledDkim.breakdown.pillars.find(p => p.key === 'dkim').pts, 0);
eq('sampled DKIM produces a single-letter grade', /^[A-F][+]{0,2}$/.test(sampledDkim.grade), true);
eq('sampled DKIM result has no range fields', 'gradeMin' in sampledDkim, false);
// The zero is real, but the UI still has to say it rests on an unverified
// check — that marker is what replaced the range, and it must not move points.
eq('sampled DKIM marks the grade unproven', sampledDkim.unproven, ['dkim']);
eq('sampled DKIM is a warning', D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: false, confidence: 'sampled', note: 'noteNotFound', duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject'),
  hosting: 'Custom', advanced: full,
}).find(i => i.key === 'dkim-unverified').sev, 'warn');

// Indeterminate DNSSEC is the same bargain: unproven scores zero, and the
// A-tier gate stays shut because gradeFor() reads `signed`, which is false.
const indeterminateDnssec = D.calcScore({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: true, selectors: [{ sel: 'google' }] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  advanced: Object.assign({}, full, { dnssec: { signed: false, state: 'indeterminate' } }),
});
eq('indeterminate DNSSEC scores zero', indeterminateDnssec.breakdown.pillars.find(p => p.key === 'dnssec').pts, 0);
eq('indeterminate DNSSEC marks the grade unproven', indeterminateDnssec.unproven, ['dnssec']);
eq('indeterminate DNSSEC grades a single letter', /^[A-F][+]{0,2}$/.test(indeterminateDnssec.grade), true);
eq('indeterminate DNSSEC cannot reach A tier', ['A', 'A+', 'A++'].includes(indeterminateDnssec.grade), false);
eq('DNSSEC indeterminate issue is a warning', D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: true, selectors: [], duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject'),
  hosting: 'Custom', advanced: Object.assign({}, full, { dnssec: { signed: false, state: 'indeterminate' } }),
}).find(i => i.key === 'dnssec-indeterminate').sev, 'warn');

// Opting out of DKIM checking still costs the pillar, so the point loss has to
// be stated — without mislabelling the opt-out as a missing record.
const dkimSkipped = D.calcScore({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: false, confidence: 'not-checked' },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@b.com'),
  advanced: full,
});
eq('not-checked DKIM scores zero', dkimSkipped.breakdown.pillars.find(p => p.key === 'dkim').pts, 0);
eq('not-checked DKIM marks the grade unproven', dkimSkipped.unproven, ['dkim']);

// A fully measured domain must carry no marker at all, or the asterisk means
// nothing. `best` is the all-controls-present fixture from section 6.
eq('a fully verified grade is unmarked', best.unproven, []);

const skippedIssues = D.buildIssues({
  emailProvider: 'Google Workspace', spfStatus: spf('ok'),
  dkimStatus: { found: false, confidence: 'not-checked', duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject'),
  hosting: 'Custom', advanced: full,
});
eq('not-checked DKIM raises its own issue', skippedIssues.find(i => i.key === 'dkim-not-checked')?.sev, 'info');
eq('not-checked DKIM raises neither dkim-unverified nor dkim-missing',
  skippedIssues.some(i => i.key === 'dkim-unverified' || i.key === 'dkim-missing'), false);

// A domain with no email must not be nagged about a DKIM check it never needed.
eq('parked domain raises no dkim-not-checked', D.buildIssues({
  emailProvider: '@null-mx', spfStatus: spf('ok'),
  dkimStatus: { found: false, confidence: 'not-checked', duplicated: [] },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject'),
  hosting: 'Custom', advanced: full,
}).some(i => i.key === 'dkim-not-checked'), false);

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
const uncommonDkim = await D.checkDKIM('example.com', false, ['campaign-live'], '@custom-unknown', false, '', {});
eq('uncommon supplied selector is found', uncommonDkim.found, true);
eq('uncommon finding is labeled', uncommonDkim.selectors[0].uncommon, true);
eq('uncommon finding includes query name', uncommonDkim.selectors[0].queryName, 'campaign-live._domainkey.example.com');
eq('uncommon finding includes TXT data', uncommonDkim.selectors[0].value, 'v=DKIM1; p=campaignPublicKey');

const easyDkim = await D.checkDKIM('ses-example.com', false, ['easy-token'], '@custom-unknown', false, '', {});
eq('Easy DKIM CNAME is followed', easyDkim.found, true);
eq('Easy DKIM reports the source record type', easyDkim.selectors[0].type, 'cname');
eq('Easy DKIM reports the CNAME target', easyDkim.selectors[0].cname, 'easy-token.dkim.amazonses.com');
eq('Easy DKIM reports the resolved TXT key', easyDkim.selectors[0].value, 'v=DKIM1; p=sesPublicKey');

const missingDkim = await D.checkDKIM('missing.example', false, ['does-not-exist'], '@custom-unknown', false, '', {});
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
// A record with a bad v= is no longer SELECTED, so it no longer reaches
// analyzeDmarc() as a `present` status: the Tree Walk's strict pass is
// validateDmarcVersion() itself. The diagnosis now arrives through the walk's
// observed[] evidence instead, which is asserted in section 28 below — where
// it can be checked end to end, against a real query, rather than against a
// hand-built status object that the walk would never produce.
eq('a bad version is never selected as policy',
  D.isDmarcPolicyRecord('v=dmarc1; p=reject'), false);
eq('a misplaced version is never selected as policy',
  D.isDmarcPolicyRecord('p=reject; v=DMARC1'), false);

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
// `dmarc-psd-invalid` was removed in 0.3.0. It asked the Public Suffix List
// whether a psd=y declaration was justified — breaking OQ-DMARC-04's rule that
// no DMARC decision consults the PSL — and asked about the audited name rather
// than the name carrying the applied record, so it fired on domains inheriting
// the genuine `_dmarc.gov` PSD policy. There is no DNS-only test that disproves
// a psd= declaration; the declaration is the protocol's source of truth.
eq('a psd=y declaration is not second-guessed against the suffix list',
  keys('v=DMARC1; p=reject; psd=y', 'example.com').includes('dmarc-psd-invalid'), false);
// The protocol-defined half still applies: `psd=` has a value vocabulary.
eq('an out-of-vocabulary psd= value is still flagged',
  keys('v=DMARC1; p=reject; psd=maybe').includes('dmarc-bad-psd'), true);

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
// RFC 9990 §4 compares ORGANIZATIONAL DOMAINS on both sides, and after 0.3.0
// those come from the Tree Walk rather than the Public Suffix List. The map
// stands in for the walked answers — in analyzeDomain it is built by
// resolveDestinationOrgDomains(). An unmapped name falls back to itself, which
// is §4.10.2's own fallback and can only ever make a destination look
// external, never internal.
const ORG = new Map(Object.entries({
  'example.com': 'example.com',
  'mail.example.com': 'example.com',
  'vendor.example.com': 'example.com',
  'vendor.com': 'vendor.com',
}));
const ext = (rec, domain) => D.findExternalReportDestinations(dm(rec), domain, ORG);
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
// alongside your own mailbox). RFC 9990 §4 evaluates authorization per URI,
// so only the external one is ever at risk — the record itself stays valid.
const mixed = 'v=DMARC1; p=reject; rua=mailto:a@vendor.com,mailto:b@example.com';
eq('mixed record is still valid',      dm(mixed).status, 'ok');
eq('mixed record scores normally',     dscore(mixed), 25);
eq('only the outside address is flagged',
  ext(mixed, 'example.com'), ['vendor.com']);

// ── Verdict-driven findings (RFC 9990 §4)
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

/* ── 23. External report authorization lookup (RFC 9990 §4) ────────── */
section('23. External report authorization lookup (RFC 9990 §4)');

// Mirrors the real Cloudflare setup: an exact per-domain record at the vendor,
// a vendor publishing the wildcard form, a vendor with nothing, a vendor whose
// record is malformed, and a destination whose lookup fails outright.
// The wildcard vendor is expressed as a wildcard OWNER, and the fixture
// resolver synthesizes it while answering the constructed query — which is what
// a real resolver does, and the only way this test says anything true about
// RFC 9990's single-query algorithm.
sandbox.fetch = dohFixture({
  'example.com._report._dmarc.exact-vendor.com TXT': txt('v=DMARC1;'),
  '*._report._dmarc.wildcard-vendor.com TXT': txt('v=DMARC1'),
  'example.com._report._dmarc.malformed-vendor.com TXT': txt('p=reject; v=DMARC1'),
  'example.com._report._dmarc.broken-vendor.com TXT': 'servfail',
}, { fallback: 'nodata' });

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
// There is exactly one query, so 'via' can only ever be the constructed name.
// A DoH JSON answer carries no evidence of whether the resolver synthesized it
// from a wildcard, and the old code's second, literal `*` query was not that
// evidence — it asked a different question (RFC 4592 §2.3).
eq('a synthesized answer is still reported at the constructed name',
  byDest['wildcard-vendor.com'].via, 'exact');
eq('only one query is issued per destination',
  sandbox.fetch.calls.filter(c => c.includes('wildcard-vendor.com')).length, 1);
eq('the literal asterisk owner is never queried',
  sandbox.fetch.calls.some(c => c.startsWith('*.')), false);
eq('no record → unauthorized',       byDest['silent-vendor.com'].state, 'unauthorized');
// RFC 9989 §4.7 applies here too: v= must come first, so this does not qualify.
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

// A check that never answered scores zero, like every other unproven control.
// The audit still completes and the measurable pillars still earn their points
// — what it must never do is invent a grade range out of the gap.
const pillarsBy = Object.fromEntries(resilient.score.breakdown.pillars.map(p => [p.key, p]));
eq('CAA pillar scores zero',      pillarsBy.caa.pts, 0);
eq('MTA-STS pillar scores zero',  pillarsBy.mtaSts.pts, 0);
eq('BIMI pillar scores zero',     pillarsBy.bimi.pts, 0);
eq('TLS-RPT pillar scores zero',  pillarsBy.tlsRpt.pts, 0);
eq('no pillar is left unscored',  resilient.score.breakdown.pillars.every(p => Number.isFinite(p.pts)), true);
eq('grade is a single letter',    /^[A-F][+]{0,2}$/.test(resilient.score.grade), true);
// Every failed optional lookup is named on the score, so one marker can stand
// for all of them rather than the asterisk being a DKIM special case. This
// audit also ran with dkim: false, so the opt-out is named alongside them.
eq('failed lookups mark the grade', resilient.score.unproven.slice().sort(),
  ['bimi', 'caa', 'dkim', 'mtaSts', 'tlsRpt']);

// The gap is stated rather than silently omitted — and now that it costs
// points, stated as a warning rather than a footnote.
const resilientKeys = resilient.issues.map(i => i.key);
eq('unverified checks are named', resilientKeys.includes('checks-unverified'), true);
const unverifiedIssue = resilient.issues.find(i => i.key === 'checks-unverified');
eq('the named checks are listed', unverifiedIssue.args[0].includes('CAA'), true);
eq('unverified checks warn',      unverifiedIssue.sev, 'warn');

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
eq('DKIM pillar scores zero',              deepPillars.dkim.pts, 0);
eq('grade is a single letter',             /^[A-F][+]{0,2}$/.test(deepZone.score.grade), true);
eq('score is not zeroed',                  deepZone.score.pts > 0, true);
// The wildcard costs the DKIM pillar, so it must say so rather than let 15
// points disappear behind a note about the wildcard.
eq('unverified DKIM is raised',            deepZone.issues.some(i => i.key === 'dkim-unverified'), true);
// The point of retiring the instant F: a wildcard makes DKIM unknowable and
// nothing else. These stay measured.
eq('SPF still scored under the wildcard',   deepPillars.spf.pts > 0, true);
eq('DMARC still scored under the wildcard', deepPillars.dmarc.pts > 0, true);


/* ── 26. SPF subnet size and a/mx redundancy ─────────────────────────── */
section('26. SPF subnet size and a/mx redundancy');

// ── Address parsing ──
// 128 bits does not fit in a Number. If any of this ever ran through one,
// the low bits would round away and containment would start saying yes to
// addresses outside the block.
eq('IPv6 max is exact',          D.ipv6ToBigInt('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') === (1n << 128n) - 1n, true);
eq('adjacent addresses differ',  D.ipv6ToBigInt('2001:db8::2') - D.ipv6ToBigInt('2001:db8::1'), 1n);

// `::` elides a run of zero hextets. Expanding it wrong misaligns every bit
// of the address, so compressed and uncompressed must land on one value.
eq('compressed == expanded',     D.ipv6ToBigInt('2001:db8::1') === D.ipv6ToBigInt('2001:0db8:0000:0000:0000:0000:0000:0001'), true);
eq('trailing :: expands',        D.ipv6ToBigInt('2001:db8::') === D.ipv6ToBigInt('2001:0db8:0:0:0:0:0:0'), true);
eq('leading :: expands',         D.ipv6ToBigInt('::1'), 1n);
eq('bare :: is zero',            D.ipv6ToBigInt('::'), 0n);
// A real record from nih.gov, written with both a padded group and '::'.
eq('nih.gov form == plain form', D.ipv6ToBigInt('2607:f220:0404:8104::0') === D.ipv6ToBigInt('2607:f220:404:8104:0:0:0:0'), true);
eq('dotted-quad tail (RFC 4291)', D.ipv6ToBigInt('::ffff:192.0.2.1') === D.ipv6ToBigInt('::ffff:c000:201'), true);

// ── Prefix parsing: malformed input returns null, never throws ──
eq('ip4 /33 rejected',      D.parseIpCidr('1.2.3.4/33', 'ipv4'), null);
eq('ip4 /-1 rejected',      D.parseIpCidr('1.2.3.4/-1', 'ipv4'), null);
eq('ip4 /abc rejected',     D.parseIpCidr('1.2.3.4/abc', 'ipv4'), null);
eq('ip4 empty prefix',      D.parseIpCidr('1.2.3.4/', 'ipv4'), null);
eq('ip4 bad octet',         D.parseIpCidr('999.1.1.1', 'ipv4'), null);
eq('ip4 too few octets',    D.parseIpCidr('1.2.3', 'ipv4'), null);
eq('ip6 /129 rejected',     D.parseIpCidr('2001:db8::/129', 'ipv6'), null);
eq('ip6 double :: rejected', D.parseIpCidr('2001:db8::1::2/64', 'ipv6'), null);
eq('ip6 bad hextet',        D.parseIpCidr('gggg::1', 'ipv6'), null);
eq('IPv4 text is not IPv6', D.parseIpCidr('1.2.3.4', 'ipv6'), null);

// /31 and /32 are ordinary valid prefixes, not edge cases to filter out.
eq('/31 accepted',          D.parseIpCidr('1.2.3.4/31', 'ipv4').prefix, 31);
eq('/32 accepted',          D.parseIpCidr('1.2.3.4/32', 'ipv4').prefix, 32);
eq('/0 accepted',           D.parseIpCidr('0.0.0.0/0', 'ipv4').prefix, 0);
// An absent prefix is a single host, not a wildcard.
eq('no prefix → /32',       D.parseIpCidr('1.2.3.4', 'ipv4').prefix, 32);
eq('no prefix → /128',      D.parseIpCidr('2001:db8::1', 'ipv6').prefix, 128);

// ── Containment ──
const v4Block = D.parseIpCidr('203.0.113.0/28', 'ipv4');
eq('first address in /28',  D.cidrContains(v4Block, D.ipv4ToBigInt('203.0.113.0')), true);
eq('last address in /28',   D.cidrContains(v4Block, D.ipv4ToBigInt('203.0.113.15')), true);
eq('one past /28 excluded', D.cidrContains(v4Block, D.ipv4ToBigInt('203.0.113.16')), false);
const v6Block = D.parseIpCidr('2001:db8::/64', 'ipv6');
eq('host in /64',           D.cidrContains(v6Block, D.ipv6ToBigInt('2001:db8::1')), true);
eq('last host in /64',      D.cidrContains(v6Block, D.ipv6ToBigInt('2001:db8::ffff:ffff:ffff:ffff')), true);
eq('sibling /64 excluded',  D.cidrContains(v6Block, D.ipv6ToBigInt('2001:db8:0:1::1')), false);
eq('/0 contains anything',  D.cidrContains(D.parseIpCidr('0.0.0.0/0', 'ipv4'), D.ipv4ToBigInt('8.8.8.8')), true);

// ── Classification ──
eq('ip4 /32 informational', D.classifySpfSubnet(32, 'ipv4'), 'LOW');
eq('ip4 /29 informational', D.classifySpfSubnet(29, 'ipv4'), 'LOW');
eq('ip4 /28 medium',        D.classifySpfSubnet(28, 'ipv4'), 'MEDIUM');
eq('ip4 /25 medium',        D.classifySpfSubnet(25, 'ipv4'), 'MEDIUM');
eq('ip4 /24 high',          D.classifySpfSubnet(24, 'ipv4'), 'HIGH');
eq('ip4 /0 high',           D.classifySpfSubnet(0, 'ipv4'), 'HIGH');
eq('ip6 /128 informational', D.classifySpfSubnet(128, 'ipv6'), 'LOW');
eq('ip6 /65 informational',  D.classifySpfSubnet(65, 'ipv6'), 'LOW');
eq('ip6 /64 informational',  D.classifySpfSubnet(64, 'ipv6'), 'LOW');
eq('ip6 /63 medium',         D.classifySpfSubnet(63, 'ipv6'), 'MEDIUM');
eq('ip6 /48 medium',         D.classifySpfSubnet(48, 'ipv6'), 'MEDIUM');
eq('ip6 /47 high',           D.classifySpfSubnet(47, 'ipv6'), 'HIGH');
eq('ip6 /32 high',           D.classifySpfSubnet(32, 'ipv6'), 'HIGH');

// The headline of the separate IPv6 table: a /64 is the standard single-subnet
// allocation (RFC 4291 §2.5.4), often one mail server. Reusing the IPv4
// host-count reasoning would rate it 2^64 hosts and flag it hardest of all.
eq('/64 is not judged like /24', [D.classifySpfSubnet(64, 'ipv6'), D.classifySpfSubnet(24, 'ipv4')], ['LOW', 'HIGH']);

// ── Record-level classification (pure, no DNS) ──
const sized = D.classifySpfSubnets('v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.7 ip6:2001:db8::/64 ip6:2001:db8::/32 -all');
eq('one finding per block',    sized.subnets.length, 4);
eq('/24 → HIGH',               sized.subnets[0].severity, 'HIGH');
eq('bare ip4 → /32 LOW',       [sized.subnets[1].severity, sized.subnets[1].prefix], ['LOW', 32]);
eq('ip6 /64 → LOW',            sized.subnets[2].severity, 'LOW');
eq('ip6 /32 → HIGH',           sized.subnets[3].severity, 'HIGH');
eq('family is recorded',       sized.subnets.map(s => s.family), ['ipv4', 'ipv4', 'ipv6', 'ipv6']);
eq('mechanism is quoted verbatim', sized.subnets[0].mechanism, 'ip4:203.0.113.0/24');
eq('schema type is stable',    sized.subnets[0].type, 'SPF_LARGE_SUBNET');

// A malformed mechanism drops itself, not the record around it.
const messy = D.classifySpfSubnets('v=spf1 ip4:1.2.3.4/33 ip4:1.2.3.4/-1 ip4:nonsense ip6:gg::/64 ip4:203.0.113.0/24 -all');
eq('malformed blocks ignored',  messy.subnets.length, 1);
eq('valid block still audited', messy.subnets[0].mechanism, 'ip4:203.0.113.0/24');

// Qualifiers are part of SPF syntax, not part of the address.
eq('qualified mechanism parsed', D.classifySpfSubnets('v=spf1 +ip4:203.0.113.0/24 -all').subnets.length, 1);

// A record with no ip4:/ip6: mechanisms produces nothing at all.
eq('include-only record is silent', D.classifySpfSubnets('v=spf1 include:_spf.google.com ~all').subnets.length, 0);
eq('empty record is silent',        D.classifySpfSubnets('').subnets.length, 0);

// ── Redundancy, over stubbed DNS ──
// One resolver for all the redundancy scenarios. Each domain isolates one
// case; names are distinct because the DoH cache is shared across the run.
const SPFNET = {
  // Bare `a`, IPv4 only, inside the block → redundant.
  'covered.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], MX: [], AAAA: [],
    A: [{ type: 1, data: '203.0.113.5' }],
    TXT: [{ type: 16, data: '"v=spf1 a ip4:203.0.113.0/28 -all"' }],
  },
  // `a:host` resolving outside every block → not redundant.
  'outside.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], MX: [], AAAA: [], A: [{ type: 1, data: '198.51.100.1' }],
    TXT: [{ type: 16, data: '"v=spf1 a:mail.outside.example ip4:203.0.113.0/28 -all"' }],
  },
  'mail.outside.example': { A: [{ type: 1, data: '198.51.100.200' }], AAAA: [] },
  // Dual-stack, both families fully covered → redundant.
  'dual.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], MX: [],
    A: [{ type: 1, data: '203.0.113.5' }],
    AAAA: [{ type: 28, data: '2001:db8::5' }],
    TXT: [{ type: 16, data: '"v=spf1 a ip4:203.0.113.0/28 ip6:2001:db8::/64 -all"' }],
  },
  // IPv4 covered, but an AAAA exists and the record has no ip6: at all.
  // Removing `a` here would silently drop IPv6 authorization.
  'halfstack.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], MX: [],
    A: [{ type: 1, data: '203.0.113.5' }],
    AAAA: [{ type: 28, data: '2001:db8::5' }],
    TXT: [{ type: 16, data: '"v=spf1 a ip4:203.0.113.0/28 -all"' }],
  },
  // Three MX targets, two inside the block and one outside → partial.
  'partial.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], A: [], AAAA: [],
    MX: [
      { type: 15, data: '10 mx1.partial.example.' },
      { type: 15, data: '20 mx2.partial.example.' },
      { type: 15, data: '30 mx3.partial.example.' },
    ],
    TXT: [{ type: 16, data: '"v=spf1 mx ip4:203.0.113.0/28 -all"' }],
  },
  'mx1.partial.example': { A: [{ type: 1, data: '203.0.113.1' }], AAAA: [] },
  'mx2.partial.example': { A: [{ type: 1, data: '203.0.113.2' }], AAAA: [] },
  'mx3.partial.example': { A: [{ type: 1, data: '198.51.100.9' }], AAAA: [] },
  // The address families must never cross-check. The IPv4 address here sits
  // at the same numeric offset the IPv6 block starts at; testing one against
  // the other must not produce a match.
  'crossfamily.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], MX: [],
    A: [{ type: 1, data: '198.51.100.1' }],
    AAAA: [{ type: 28, data: '2001:db8::1' }],
    TXT: [{ type: 16, data: '"v=spf1 a ip4:203.0.113.0/28 ip6:2001:db8::/64 -all"' }],
  },
  // A dual-CIDR suffix widens `mx` past the addresses it resolves to, so
  // containment of the bare addresses proves nothing.
  'dualcidr.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], A: [], AAAA: [],
    MX: [{ type: 15, data: '10 mx1.partial.example.' }],
    TXT: [{ type: 16, data: '"v=spf1 mx/24 ip4:203.0.113.0/28 -all"' }],
  },
  // `-all` ends in the letters of no mechanism, but it *starts* with 'a'
  // once the qualifier is stripped, and `ptr:` is excluded outright. Both
  // resolve inside the block here, so if either were mistaken for the `a`
  // mechanism this domain would produce a redundancy finding — and the advice
  // would be to delete the record's own `-all`.
  'lookalike.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], MX: [], AAAA: [],
    A: [{ type: 1, data: '203.0.113.5' }],
    TXT: [{ type: 16, data: '"v=spf1 ip4:203.0.113.0/28 ptr exists:%{i}.x.example -all"' }],
  },
  // No ip4:/ip6: block at all — the a/mx resolution must be skipped entirely.
  'noblocks.example': {
    NS: [{ type: 2, data: 'ns1.example.' }], MX: [], AAAA: [],
    A: [{ type: 1, data: '203.0.113.5' }],
    TXT: [{ type: 16, data: '"v=spf1 a mx include:_spf.example -all"' }],
  },
};

let spfQueries = [];
sandbox.fetch = async url => {
  const params = new URL(url).searchParams;
  const name = params.get('name');
  const typeName = { 1: 'A', 2: 'NS', 15: 'MX', 16: 'TXT', 28: 'AAAA', 5: 'CNAME', 257: 'CAA' }[params.get('type')];
  spfQueries.push(`${name} ${typeName}`);
  const entry = SPFNET[name];
  if (entry && entry[typeName] !== undefined) {
    return { ok: true, json: async () => ({ Status: 0, AD: false, Answer: entry[typeName] }) };
  }
  return { ok: true, json: async () => ({ Status: 0, AD: false, Answer: [] }) };
};

const runSpf = d => D.analyzeDomain(d, { advanced: true, dkim: false, www: false, wildcard: false, retries: 0 });

const covered = await runSpf('covered.example');
eq('bare a flagged redundant',    covered.advanced.spfSubnets.redundancy.length, 1);
eq('redundancy is full',          covered.advanced.spfSubnets.redundancy[0].full, true);
eq('the covering block is named', covered.advanced.spfSubnets.redundancy[0].coveredBy, ['ip4:203.0.113.0/28']);
eq('schema type is stable',       covered.advanced.spfSubnets.redundancy[0].type, 'SPF_REDUNDANCY');
eq('removal is recommended',      covered.issues.some(i => i.key === 'spf-redundant-mechanism'), true);
// Advisory only: it must not move the score.
eq('redundancy is not scored',    covered.issues.find(i => i.key === 'spf-redundant-mechanism').sev, 'info');

const outside = await runSpf('outside.example');
eq('a:host outside blocks not flagged', outside.advanced.spfSubnets.redundancy.length, 0);
eq('no removal advice',                 outside.issues.some(i => i.key.startsWith('spf-redundant')), false);

const dual = await runSpf('dual.example');
eq('both families covered → redundant', dual.advanced.spfSubnets.redundancy[0].full, true);
eq('both addresses counted',            dual.advanced.spfSubnets.redundancy[0].total, 2);
eq('both blocks credited',              dual.advanced.spfSubnets.redundancy[0].coveredBy.length, 2);

// The dual-stack rule. This is the one that matters most: the IPv4 side is
// fully covered, so a naive check says "remove the a mechanism" — and doing
// so would drop IPv6 authorization on the floor without saying a word.
const halfstack = await runSpf('halfstack.example');
eq('uncovered IPv6 blocks removal', halfstack.advanced.spfSubnets.redundancy[0].full, false);
eq('reported as partial instead',   halfstack.issues.some(i => i.key === 'spf-partial-coverage'), true);
eq('removal is NOT recommended',    halfstack.issues.some(i => i.key.startsWith('spf-redundant')), false);
eq('the covered half is counted',   [halfstack.advanced.spfSubnets.redundancy[0].covered, halfstack.advanced.spfSubnets.redundancy[0].total], [1, 2]);

const partial = await runSpf('partial.example');
eq('2 of 3 MX targets covered',   [partial.advanced.spfSubnets.redundancy[0].covered, partial.advanced.spfSubnets.redundancy[0].total], [2, 3]);
eq('partial is not full',         partial.advanced.spfSubnets.redundancy[0].full, false);
eq('surfaced as informational',   partial.issues.find(i => i.key === 'spf-partial-coverage').sev, 'info');
eq('no removal recommendation',   partial.issues.some(i => i.key.startsWith('spf-redundant')), false);

const cross = await runSpf('crossfamily.example');
eq('IPv6 matched its own block',    cross.advanced.spfSubnets.redundancy[0].coveredBy, ['ip6:2001:db8::/64']);
eq('IPv4 not matched cross-family', cross.advanced.spfSubnets.redundancy[0].covered, 1);
eq('so the mechanism stays',        cross.advanced.spfSubnets.redundancy[0].full, false);

const dualCidr = await runSpf('dualcidr.example');
eq('mx/24 is not judged redundant', dualCidr.advanced.spfSubnets.redundancy.length, 0);

const lookalike = await runSpf('lookalike.example');
eq('-all is not the a mechanism',  lookalike.advanced.spfSubnets.redundancy.length, 0);
eq('ptr is excluded (RFC 7208 §5.5)', lookalike.issues.some(i => i.key.startsWith('spf-redundant')), false);
eq('the block is still classified',   lookalike.advanced.spfSubnets.subnets.length, 1);

// With no ip4:/ip6: block there is nothing to be contained in, so the audit
// must not spend DNS lookups resolving a/mx targets to find that out.
spfQueries = [];
const noBlocks = await runSpf('noblocks.example');
eq('no findings without blocks', [noBlocks.advanced.spfSubnets.subnets.length, noBlocks.advanced.spfSubnets.redundancy.length], [0, 0]);
eq('and no errors',              noBlocks.error, undefined);
eq('no MX lookup for redundancy', spfQueries.filter(q => q === 'noblocks.example MX').length <= 1, true);

// ── Issue surfacing ──
// Single-host blocks are classified but never surfaced: stanford.edu
// publishes 15 ip4: mechanisms, 13 of them /32s, and a line each saying
// "this is one host, which is fine" buries everything worth reading.
const quiet = D.buildIssues({
  emailProvider: '@none', spfStatus: { status: 'ok', warnings: [] }, dkimStatus: {},
  dmarcStatus: { status: 'ok', warnings: [], policy: 'reject' },
  advanced: { spfSubnets: { subnets: D.classifySpfSubnets('v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 ip6:2001:db8::/64 -all').subnets, redundancy: [] } },
});
eq('LOW blocks raise no issue', quiet.filter(i => i.key.startsWith('spf-') && i.key.endsWith('subnet')).length, 0);

const noisy = D.buildIssues({
  emailProvider: '@none', spfStatus: { status: 'ok', warnings: [] }, dkimStatus: {},
  dmarcStatus: { status: 'ok', warnings: [], policy: 'reject' },
  advanced: { spfSubnets: { subnets: D.classifySpfSubnets('v=spf1 ip4:203.0.113.0/24 ip4:198.51.100.0/16 ip4:192.0.2.0/26 -all').subnets, redundancy: [] } },
});
const largeIssue = noisy.find(i => i.key === 'spf-large-subnet');
const mediumIssue = noisy.find(i => i.key === 'spf-medium-subnet');
eq('HIGH blocks grouped into one line', largeIssue.args[0], 'ip4:203.0.113.0/24, ip4:198.51.100.0/16');
eq('MEDIUM blocks grouped separately',  mediumIssue.args[0], 'ip4:192.0.2.0/26');
// Advisory, not a fault: irs.gov, github.com, bbc.co.uk and cloudflare.com
// all publish their own large blocks. Ranking these critical would train
// people to skim past the list where "no SPF record" lives.
eq('large blocks warn, never crit', largeIssue.sev, 'warn');
eq('medium blocks are informational', mediumIssue.sev, 'info');

/* ── 27. SPF-referenced DKIM selectors ───────────────────────────────── */
section('27. SPF-referenced DKIM selectors (provider-aware mode)');

// An `include:` is the domain naming a vendor that sends mail for it. MX
// detection can only ever name one provider, so without this a Zendesk or
// SendGrid key sitting in plain sight goes untested outside a comprehensive
// scan. slack.com is the live example: MX is Google, SPF names Zendesk, and
// zendesk1/zendesk2 are published.
const zendeskSpf = 'v=spf1 include:_spf.qualtrics.com include:mail.zendesk.com -all';
const m365Zendesk = D.buildDkimSelectorList([], 'Microsoft 365', false, zendeskSpf);
eq('SPF-named provider selectors are tested', m365Zendesk.includes('zendesk1'), true);
eq('MX-detected provider selectors are still tested', m365Zendesk.includes('selector1'), true);
eq('unrelated providers stay out', m365Zendesk.includes('sendgrid'), false);

// A vendor whose catalog key differs from the include hostname.
eq('sendgrid.net maps to the Twilio SendGrid key',
  [...D.spfReferencedCatalogKeys('v=spf1 include:sendgrid.net -all')], ['Twilio SendGrid']);
eq('SendGrid selectors are added under that key',
  D.buildDkimSelectorList([], 'Microsoft 365', false, 'v=spf1 include:sendgrid.net -all').includes('sendgrid'), true);

// redirect= delegates the whole record, so it names a vendor just as include: does.
eq('redirect= is evaluated like include:',
  [...D.spfReferencedCatalogKeys('v=spf1 redirect=mail.zendesk.com')], ['Zendesk']);
eq('subdomains of a mapped host match',
  [...D.spfReferencedCatalogKeys('v=spf1 include:_spf.hubspotemail.net -all')], ['HubSpot']);
eq('mechanism case is irrelevant',
  [...D.spfReferencedCatalogKeys('v=spf1 INCLUDE:MAIL.ZENDESK.COM -all')], ['Zendesk']);
eq('a qualified include still counts',
  [...D.spfReferencedCatalogKeys('v=spf1 ~include:mail.zendesk.com -all')], ['Zendesk']);
eq('two hostnames for one vendor collapse to one key',
  [...D.spfReferencedCatalogKeys('v=spf1 include:servers.mcsv.net include:mandrillapp.com -all')],
  ['Mailchimp / Mandrill']);

// The guard against this quietly becoming comprehensive-by-default: no
// include, no extra selectors.
const unreferenced = D.buildDkimSelectorList([], 'Microsoft 365', false, 'v=spf1 include:spf.protection.outlook.com -all');
eq('an unreferenced provider is not tested', unreferenced.includes('zendesk1'), false);
eq('a non-vendor include matches nothing', D.spfReferencedCatalogKeys('v=spf1 include:_spf.example.org -all').size, 0);
// A macro cannot be reduced to a literal hostname (RFC 7208 §7).
eq('macro includes are skipped', D.spfReferencedCatalogKeys('v=spf1 include:%{i}.mail.zendesk.com -all').size, 0);
eq('a/mx/exists mechanisms are not includes', D.spfReferencedCatalogKeys('v=spf1 a:mail.zendesk.com mx exists:mailgun.org -all').size, 0);

// Mailgun resolves to the same catalog key down both paths — MX detection
// ('Mailgun' → 'Mailgun') and the SPF table (mailgun.org → 'Mailgun') — so it
// is the fixture that proves the key !== providerKey skip actually fires.
const mailgunBoth = D.catalogSelectors('Mailgun', false, 'v=spf1 include:mailgun.org -all');
eq('the MX provider is not concatenated twice', mailgunBoth.filter(s => s === 'mg1').length, 1);
eq('a doubly-matched provider adds nothing', mailgunBoth, D.catalogSelectors('Mailgun', false, ''));

// No SPF record at all, and the pre-existing three-argument call, must both
// behave exactly as they did before this existed.
const googleBaseline = D.buildDkimSelectorList([], 'Google Workspace', false);
eq('an empty SPF record changes nothing', D.buildDkimSelectorList([], 'Google Workspace', false, ''), googleBaseline);
eq('a missing SPF argument changes nothing', D.buildDkimSelectorList([], 'Google Workspace', false, undefined), googleBaseline);

// Comprehensive mode already covers every provider; it must not shift.
eq('comprehensive scan is untouched',
  D.buildDkimSelectorList([], '@custom-unknown', true, zendeskSpf).length, 1677);

// End to end: the same domain, the same published key, found only when SPF
// names the vendor.
sandbox.fetch = async url => {
  const name = new URL(url).searchParams.get('name');
  let answer = [];
  if (name === 'zendesk1._domainkey.helpdesk.example') {
    answer = [{ type: 5, data: 'zendesk1._domainkey.zendesk.com.' }];
  } else if (name === 'zendesk1._domainkey.zendesk.com') {
    answer = [{ type: 16, data: '"v=DKIM1; k=rsa; p=zendeskPublicKey"' }];
  }
  return { ok: true, json: async () => ({ Status: 0, Answer: answer }) };
};

const viaSpf = await D.checkDKIM('helpdesk.example', false, [], 'Microsoft 365', false, zendeskSpf, {});
eq('provider-aware scan finds the SPF-named vendor key', viaSpf.found, true);
eq('the finding is the Zendesk selector', viaSpf.selectors[0].sel, 'zendesk1');
eq('the CNAME to the vendor is followed', viaSpf.selectors[0].cname, 'zendesk1._domainkey.zendesk.com');
eq('the key is not flagged uncommon', viaSpf.selectors[0].uncommon, false);
eq('the scan is still provider-aware, not comprehensive', viaSpf.scanMode, 'provider-aware');
eq('confidence is unchanged by the new signal', viaSpf.confidence, 'observed');

const withoutSpf = await D.checkDKIM('helpdesk.example', false, [], 'Microsoft 365', false, 'v=spf1 -all', {});
eq('the same key stays hidden with no SPF reference', withoutSpf.found, false);
eq('and the selector was never queried', withoutSpf.testedSelectors.includes('zendesk1'), false);

// Attribution: a selector nobody asked for needs to say why it was tested.
eq('the finding names the vendor SPF pointed at', viaSpf.selectors[0].viaSpf, 'Zendesk');

const sources = D.spfSelectorSources([], 'Microsoft 365', false, zendeskSpf);
eq('every SPF-only selector is attributed', sources.get('zendesk2'), 'Zendesk');
eq('nothing else is attributed', [...new Set(sources.values())], ['Zendesk']);
eq('the MX provider\'s own selectors are not attributed', sources.has('selector1'), false);
eq('the base selector list is not attributed', sources.has('google'), false);

// A selector the user typed in would have been tested regardless, so crediting
// SPF for it would be a lie.
eq('a user-supplied selector is not credited to SPF',
  D.spfSelectorSources(['zendesk1'], 'Microsoft 365', false, zendeskSpf).has('zendesk1'), false);
eq('but its sibling still is',
  D.spfSelectorSources(['zendesk1'], 'Microsoft 365', false, zendeskSpf).get('zendesk2'), 'Zendesk');

// When SPF names the provider MX already found, nothing is attributed — those
// selectors were never added by this path.
eq('a doubly-matched provider attributes nothing',
  D.spfSelectorSources([], 'Mailgun', false, 'v=spf1 include:mailgun.org -all').size, 0);
// Comprehensive mode tests everything anyway, so "via SPF" would explain nothing.
eq('comprehensive mode attributes nothing',
  D.spfSelectorSources([], 'Microsoft 365', true, zendeskSpf).size, 0);
eq('no SPF record attributes nothing', D.spfSelectorSources([], 'Microsoft 365', false, '').size, 0);

// Ordinary findings carry no tag at all.
const plainDkim = await D.checkDKIM('helpdesk.example', false, [], 'Microsoft 365', false, zendeskSpf, {});
eq('an untagged finding reports an empty source',
  plainDkim.selectors.every(x => x.sel.startsWith('zendesk') ? x.viaSpf === 'Zendesk' : x.viaSpf === ''), true);

/* ── 28. RFC 9989 DNS Tree Walk ──────────────────────────────────────── */
section('28. DMARCbis Tree Walk discovery (RFC 9989 §4.10)');

// Every fixture below runs against a programmable sandbox `fetch` (see
// tools/lib/doh-fixture.mjs) — no network, no production test seam, and the
// real URL building, JSON parsing, cache, limiter and retry loop all exercised.
// Fixtures use distinct domain names so dohFetch's cache never carries an
// answer from one case into the next; the one case that WANTS a cache hit says
// so explicitly.
// `noCache` keeps each fixture hermetic. dohFetch's cache is module-level and
// keyed only on name and type, so without it an answer from one fixture is
// served to the next — a `_dmarc.example` NXDOMAIN cached by one case silently
// replaces the SERVFAIL the next case is trying to test. The one case that
// WANTS the cache says so by leaving this off.
const walk = async (domain, map, opts) => {
  sandbox.fetch = dohFixture(map);
  const result = await D.discoverDmarc(domain, { retries: 0, noCache: true }, opts);
  result.fixtureCalls = sandbox.fetch.calls.slice();
  return result;
};
const POLICY = 'v=DMARC1; p=reject; rua=mailto:d@example.com';

// ── Label arithmetic (§4.10 steps 3, 4 and 7) ─────────────────────────
// Transcribed from the RFC's own worked example, which lists all eight names.
eq('13 labels → exactly 8 queries',
  D.dmarcWalkTargets('a.b.c.d.e.f.g.h.i.j.mail.example.com').length, 8);
eq('13 labels → the RFC’s own eight names',
  D.dmarcWalkTargets('a.b.c.d.e.f.g.h.i.j.mail.example.com'), [
    'a.b.c.d.e.f.g.h.i.j.mail.example.com',
    'g.h.i.j.mail.example.com',
    'h.i.j.mail.example.com',
    'i.j.mail.example.com',
    'j.mail.example.com',
    'mail.example.com',
    'example.com',
    'com',
  ]);
eq('the last query is the TLD',
  D.dmarcWalkTargets('a.b.c.d.e.f.g.h.i.j.mail.example.com').slice(-1)[0], 'com');
eq('8 labels → shortcut engages at x >= 8',
  D.dmarcWalkTargets('a.b.c.d.e.f.example.com').length, 8);
eq('8 labels → second target has 7',
  D.dmarcWalkTargets('a.b.c.d.e.f.example.com')[1].split('.').length, 7);
eq('7 labels → no shortcut, one label per step',
  D.dmarcWalkTargets('b.c.d.e.f.example.com'), [
    'b.c.d.e.f.example.com', 'c.d.e.f.example.com', 'd.e.f.example.com',
    'e.f.example.com', 'f.example.com', 'example.com', 'com',
  ]);
eq('7 labels → 7 queries', D.dmarcWalkTargets('b.c.d.e.f.example.com').length, 7);
eq('two labels → two queries', D.dmarcWalkTargets('example.com'), ['example.com', 'com']);
eq('a bare TLD is one query', D.dmarcWalkTargets('com'), ['com']);

const deep = await walk('a.b.c.d.e.f.g.h.i.j.mail.example.com', {
  '_dmarc.example.com TXT': txt(POLICY),
});
eq('deep walk issues exactly 8 queries', deep.queries, 8);
eq('deep walk reaches the record',       deep.applied.foundAt, 'example.com');
eq('deep walk records labelsUp',         deep.applied.labelsUp, 11);
eq('deep walk terminates at the root',   deep.terminated, 'root');

// ── Where the applied record is found ─────────────────────────────────
const own = await walk('own.example', { '_dmarc.own.example TXT': txt(POLICY) });
eq('policy at the audited name',      own.applied.foundAt, 'own.example');
eq('audited name is labelsUp 0',      own.applied.labelsUp, 0);
eq('audited name is not inherited',   own.applied.inherited, false);
eq('policyDomain aliases foundAt',    own.policyDomain, own.applied.foundAt);
eq('the walk does not stop at the first record', own.queries, 2);

const oneUp = await walk('sub.up.example', { '_dmarc.up.example TXT': txt(POLICY) });
eq('policy one level up is inherited', oneUp.applied.inherited, true);
eq('policy one level up: foundAt',     oneUp.applied.foundAt, 'up.example');
eq('policy one level up: labelsUp',    oneUp.applied.labelsUp, 1);

const several = await walk('a.b.c.deep.example', { '_dmarc.deep.example TXT': txt(POLICY) });
eq('policy several levels up: foundAt',  several.applied.foundAt, 'deep.example');
eq('policy several levels up: labelsUp', several.applied.labelsUp, 3);
eq('policy several levels up: steps',    several.steps.length, 5);

// §B.4.2: "the policy domain is the highest element in the DNS tree with a
// DMARC Policy Record". The Organizational Domain is a SEPARATE value, and
// with records at both names it is the higher one while the applied policy is
// the audited name's own.
const both = await walk('sub.both.example', {
  '_dmarc.sub.both.example TXT': txt('v=DMARC1; p=reject'),
  '_dmarc.both.example TXT': txt('v=DMARC1; p=none'),
});
eq('records at both: applied is the audited name', both.applied.foundAt, 'sub.both.example');
eq('records at both: applied is not inherited',    both.applied.inherited, false);
eq('records at both: org domain is the highest',   both.organizationalDomain, 'both.example');
eq('records at both: the walk kept going',         both.queries, 3);

const twoUp = await walk('x.mid.two.example', {
  '_dmarc.mid.two.example TXT': txt('v=DMARC1; p=none'),
  '_dmarc.two.example TXT': txt('v=DMARC1; p=reject'),
});
eq('two ancestors: the HIGHEST applies, not the nearest', twoUp.applied.foundAt, 'two.example');
eq('two ancestors: org domain matches',                   twoUp.organizationalDomain, 'two.example');
eq('two ancestors: policy comes from the highest',        D.analyzeDmarc(twoUp.applied.record).policy, 'reject');

// ── psd= as a walk terminator (§4.10 steps 2 and 6, §4.10.2 rules 1 and 2) ──
// Transcribed from RFC 9989 Appendix B.4.3, which walks all three names.
const PSD_TREE = {
  '_dmarc.giant.bank.example TXT': txt('v=DMARC1; p=reject'),
  '_dmarc.bank.example TXT': txt('v=DMARC1; p=none; psd=y'),
};
const psdAuthor = await walk('giant.bank.example', PSD_TREE);
eq('psd=y terminates the walk',           psdAuthor.terminated, 'psd-y');
eq('psd=y records the boundary',          psdAuthor.psdBoundary, 'bank.example');
eq('psd=y: walk stops, _dmarc.example unqueried', psdAuthor.queries, 2);
// B.4.3: "The Organizational Domain is 'giant.bank.example' because it is the
// domain directly below the one with 'psd=y'."
eq('psd=y: org domain is one label below', psdAuthor.organizationalDomain, 'giant.bank.example');
eq('psd=y: the author domain’s own record applies', psdAuthor.applied.foundAt, 'giant.bank.example');

const psdDkim = await walk('mail.mega.bank.example', PSD_TREE);
// B.4.3: "The Organizational Domain is 'mega.bank.example'" — a name that
// carries no DMARC record at all. This is the case a "highest record wins"
// reading of §4.10.2 gets wrong.
eq('psd=y: org domain may carry no record', psdDkim.organizationalDomain, 'mega.bank.example');
eq('psd=y: the PSD record applies when the org domain published none',
  psdDkim.applied.foundAt, 'bank.example');

// §4.10.1: "PSD policy is not used for Organizational Domains that have
// published a DMARC Policy Record." The PSD sits higher in the tree, and the
// Organizational Domain's own record still wins — which is why the applied
// record is chosen by §4.10.1's preference list rather than by height alone.
const psdBelow = await walk('x.giant.bank.example', PSD_TREE);
eq('psd=y: org domain’s record beats the PSD’s',
  psdBelow.applied.foundAt, 'giant.bank.example');
eq('psd=y: org domain below the boundary', psdBelow.organizationalDomain, 'giant.bank.example');

const psdN = await walk('sub.org.example', {
  '_dmarc.org.example TXT': txt('v=DMARC1; p=reject; psd=n'),
});
eq('psd=n terminates the walk',      psdN.terminated, 'psd-n');
eq('psd=n names the org domain',     psdN.organizationalDomain, 'org.example');
eq('psd=n leaves no psd boundary',   psdN.psdBoundary, null);
eq('psd=u does not terminate',
  (await walk('sub.u.example', { '_dmarc.u.example TXT': txt('v=DMARC1; p=reject; psd=u') })).terminated, 'root');
// §4.10 steps 2 and 6 name only `n` and `y`. Anything else — including a value
// that is not in the tag's vocabulary at all — must NOT stop the walk.
const psdJunk = await walk('x.junk.example', {
  '_dmarc.junk.example TXT': txt('v=DMARC1; p=reject; psd=maybe'),
  '_dmarc.example TXT': txt('v=DMARC1; p=none'),
});
eq('an unrecognised psd= value does not terminate', psdJunk.terminated, 'root');
eq('an unrecognised psd= value lets the walk reach the TLD',
  psdJunk.steps.slice(-1)[0].queryName, '_dmarc.example');

// §4.10.2 rule 2 excludes "the one for the domain where the Tree Walk started",
// so a psd=y on the audited name itself falls through to rule 3.
const psdSelf = await walk('self.example', {
  '_dmarc.self.example TXT': txt('v=DMARC1; p=reject; psd=y'),
});
eq('psd=y at the start still terminates the walk', psdSelf.terminated, 'psd-y');
eq('psd=y at the start is excluded from rule 2, so rule 3 applies',
  psdSelf.organizationalDomain, 'self.example');

// oneLabelBelow() takes labels from the SUBJECT rather than from the walk's
// query list, which is what lets it name a domain that carries no record — and,
// where the shortening rule skipped that depth, one that was never queried at
// all. §4.10.2 requires neither.
const psdDeep = await walk('a.b.c.d.e.f.g.h.i.j.k.example.com', {
  '_dmarc.example.com TXT': txt('v=DMARC1; p=none; psd=y'),
});
eq('a psd=y boundary reached after shortening is honoured', psdDeep.terminated, 'psd-y');
eq('the org domain is one label below it in the SUBJECT path',
  psdDeep.organizationalDomain, 'k.example.com');
eq('and that org domain carries no record of its own',
  psdDeep.steps.filter(s => s.queryName === '_dmarc.k.example.com')[0].selected, false);
eq('the PSD’s record applies because the org domain published none',
  psdDeep.applied.foundAt, 'example.com');

// ── Duplicates: discarded, walk continues (§4.10 step 2) ──────────────
const dupOnly = await walk('dup.example', {
  '_dmarc.dup.example TXT': [...txt('v=DMARC1; p=reject'), ...txt('v=DMARC1; p=none')],
});
eq('duplicates are discarded',            dupOnly.applied, null);
eq('duplicates are not a termination',    dupOnly.terminated, 'root');
eq('duplicates are recorded as evidence',
  dupOnly.observed.filter(o => o.why === 'multiple-at-step').length, 1);
// Asserted on the WALK's own output, not on analyzeDmarc('') — the latter is
// tautological once `applied` is known null, and would pass with discoverDmarc
// deleted entirely.
eq('duplicates: nothing is selected at that step',
  dupOnly.steps.filter(s => s.selected).length, 0);
eq('duplicates: the step still reports both records',
  dupOnly.steps[0].dmarcCount, 2);

const dupInherit = await walk('sub.dupup.example', {
  '_dmarc.sub.dupup.example TXT': [...txt('v=DMARC1; p=reject'), ...txt('v=DMARC1; p=none')],
  '_dmarc.dupup.example TXT': txt('v=DMARC1; p=quarantine; sp=quarantine'),
});
eq('duplicate below, record above: the record above applies',
  dupInherit.applied.foundAt, 'dupup.example');
eq('duplicate below: still recorded as evidence',
  dupInherit.observed.filter(o => o.why === 'multiple-at-step').length, 1);

// The finding stays critical either way, and must never claim that no policy
// applies when one does.
const dupFindingKeys = D.buildIssues({
  emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.applyInheritance(D.analyzeDmarc(dupInherit.applied.record, false), dupInherit, 'yes'),
  dmarcDiscovery: dupInherit, dmarcExistence: 'yes',
  hosting: 'Custom', advanced: full, domain: 'sub.dupup.example',
}).map(i => i.key);
eq('duplicate with a policy in force → the inherited key',
  dupFindingKeys.includes('dmarc-multiple-records-inherited'), true);
eq('duplicate with a policy in force → NOT the "no policy" key',
  dupFindingKeys.includes('dmarc-multiple-records'), false);
eq('duplicate with a policy in force → not reported as missing',
  dupFindingKeys.includes('dmarc-missing'), false);
eq('duplicate finding is critical',
  D.buildIssues({
    emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
    dmarcStatus: D.applyInheritance(D.analyzeDmarc(dupInherit.applied.record, false), dupInherit, 'yes'),
    dmarcDiscovery: dupInherit, dmarcExistence: 'yes',
    hosting: 'Custom', advanced: full, domain: 'sub.dupup.example',
  }).filter(i => i.key === 'dmarc-multiple-records-inherited')[0].sev, 'crit');

const dupNothing = D.buildIssues({
  emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('', false),
  dmarcDiscovery: dupOnly, dmarcExistence: 'yes',
  hosting: 'Custom', advanced: full, domain: 'dup.example',
});
eq('duplicate with nothing above → the plain key',
  dupNothing.map(i => i.key).includes('dmarc-multiple-records'), true);
eq('duplicate with nothing above → still critical',
  dupNothing.filter(i => i.key === 'dmarc-multiple-records')[0].sev, 'crit');
eq('duplicate with nothing above → not also reported as missing',
  dupNothing.map(i => i.key).includes('dmarc-missing'), false);

// ── Transient errors: unknown, never absent ───────────────────────────
const servfail = await walk('sf.example', { '_dmarc.sf.example TXT': 'servfail' });
eq('SERVFAIL terminates as error',  servfail.terminated, 'error');
eq('SERVFAIL yields no policy',     servfail.applied, null);
eq('SERVFAIL records the kind',     servfail.error, 'servfail');
eq('SERVFAIL still names an org domain', servfail.organizationalDomain, 'sf.example');

// A record collected at an ANCESTOR cannot survive: the names above it went
// unexamined, so the highest record — which is what selection needs — is not
// knowable.
const sfAbove = await walk('a.b.sfmid.example', {
  '_dmarc.b.sfmid.example TXT': txt(POLICY),
  '_dmarc.sfmid.example TXT': 'servfail',
});
eq('SERVFAIL above an inherited record → still error',   sfAbove.terminated, 'error');
eq('SERVFAIL above an inherited record → no policy',     sfAbove.applied, null);

// The Author Domain's own record DOES survive. RFC 9989 §4.10.1 settles it on
// the first query and performs the walk only "If no valid DMARC Policy Record
// is found by the first query", so nothing found higher can displace it.
const sfOwn = await walk('own.sferr.example', {
  '_dmarc.own.sferr.example TXT': txt(POLICY),
  '_dmarc.sferr.example TXT': 'servfail',
});
eq('SERVFAIL above the author domain’s own record → still error', sfOwn.terminated, 'error');
eq('SERVFAIL cannot erase the author domain’s own policy', sfOwn.applied.foundAt, 'own.sferr.example');
eq('the author domain’s own record is never inherited', sfOwn.applied.inherited, false);
eq('an errored walk falls back to the audited name as org domain',
  sfOwn.organizationalDomain, 'own.sferr.example');

// ── Nothing published anywhere ────────────────────────────────────────
const none = await walk('none.example', {});
eq('no record anywhere → root',    none.terminated, 'root');
eq('no record anywhere → null',    none.applied, null);
eq('no record anywhere → every step is a miss',
  none.steps.every(s => !s.selected && s.dmarcCount === 0), true);
eq('no record anywhere → org domain is the audited name',
  none.organizationalDomain, 'none.example');

// ── The diagnostic pass: misplaced beats absent ───────────────────────
const notFirst = await walk('nf.example', { '_dmarc.nf.example TXT': txt('p=reject; v=DMARC1') });
eq('v not first is not selected',   notFirst.applied, null);
eq('v not first is diagnosed',      notFirst.observed[0].why, 'version-not-first');

const badCase = await walk('bc.example', { '_dmarc.bc.example TXT': txt('v=dmarc1; p=reject') });
eq('miscased v is not selected',    badCase.applied, null);
eq('miscased v is diagnosed',       badCase.observed[0].why, 'version-bad-case');

const noVersion = await walk('nv.example', { '_dmarc.nv.example TXT': txt('p=reject; rua=mailto:d@nv.example') });
eq('a versionless record is diagnosed', noVersion.observed[0].why, 'version-absent');
eq('an unrelated TXT string is not diagnosed as DMARC',
  (await walk('un.example', { '_dmarc.un.example TXT': txt('v=spf1 -all') })).observed.length, 0);

// The apex TXT set costs no query — analyzeDomain already holds it.
const apex = await walk('apex.example', {}, { apexTxt: ['v=DMARC1; p=reject', 'v=spf1 -all'] });
eq('a policy at the apex is diagnosed', apex.observed[0].why, 'at-apex-not-underscore');
eq('the apex check adds no query',      apex.queries, 2);

const diagKeys = D.buildIssues({
  emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('', false), dmarcDiscovery: notFirst, dmarcExistence: 'yes',
  hosting: 'Custom', advanced: full, domain: 'nf.example',
}).map(i => i.key);
eq('a misplaced version produces a specific diagnosis, not "missing"',
  diagKeys.includes('dmarc-version-not-first'), true);
eq('a misplaced version is critical',
  D.buildIssues({
    emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
    dmarcStatus: D.analyzeDmarc('', false), dmarcDiscovery: notFirst, dmarcExistence: 'yes',
    hosting: 'Custom', advanced: full, domain: 'nf.example',
  }).filter(i => i.key === 'dmarc-version-not-first')[0].sev, 'crit');
// 'missing' is raised alongside it, and should be: no readable record exists,
// so the domain really is unprotected. The diagnosis explains WHY, it does not
// replace the verdict. Acceptance criterion 3 asks for a specific diagnosis
// rather than only "missing", which is what this pair asserts.
eq('and "missing" still stands, because no receiver can read the record',
  diagKeys.includes('dmarc-missing'), true);
// The diagnosis names the DNS name the broken record is at — the walk visits
// up to eight names and the defect may be at a parent the operator cannot edit.
eq('the diagnosis names where the broken record is',
  D.buildIssues({
    emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
    dmarcStatus: D.analyzeDmarc('', false), dmarcDiscovery: notFirst, dmarcExistence: 'yes',
    hosting: 'Custom', advanced: full, domain: 'nf.example',
  }).filter(i => i.key === 'dmarc-version-not-first')[0].args, ['_dmarc.nf.example']);

// ── Domain existence and np= (§3.2.13, Appendix A.4) ──────────────────
const npRecord = D.analyzeDmarc('v=DMARC1; p=reject; sp=quarantine; np=none');
const upTree = { applied: { record: '', foundAt: 'np.example', labelsUp: 1, inherited: true } };
eq('an existing subdomain is governed by sp',
  D.applyInheritance(npRecord, upTree, 'yes').policy, 'quarantine');
eq('a non-existent subdomain is governed by np',
  D.applyInheritance(npRecord, upTree, 'no').policy, 'none');
eq('unknown existence takes the weaker branch',
  D.applyInheritance(npRecord, upTree, 'unknown').policy, 'none');
eq('the record’s own np is still reported',
  D.applyInheritance(npRecord, upTree, 'yes').effectiveNp, 'none');
eq('inheritance records which branch was applied',
  D.applyInheritance(npRecord, upTree, 'yes').appliedBranch, 'sp');
eq('inheritance names the source',
  D.applyInheritance(npRecord, upTree, 'yes').inheritedFrom, 'np.example');
eq('inheritance returns a NEW object, leaving the parsed status intact',
  npRecord.policy, 'reject');
eq('a record at the audited name is never re-pointed at sp',
  D.applyInheritance(npRecord, { applied: { foundAt: 'x', labelsUp: 0, inherited: false } }, 'yes').policy, 'reject');

sandbox.fetch = dohFixture({ 'exists.example NS': ns('ns1.example.'), 'nodata.example NS': 'nodata' });
eq('NXDOMAIN means the name does not exist', await D.domainExists('gone.example', { retries: 0 }), 'no');
eq('NOERROR with data means it exists',      await D.domainExists('exists.example', { retries: 0 }), 'yes');
eq('NODATA means the name exists, the type does not',
  await D.domainExists('nodata.example', { retries: 0 }), 'yes');
sandbox.fetch = dohFixture({ 'flap.example NS': 'servfail' });
eq('a transient error is unknown, never "no"',
  await D.domainExists('flap.example', { retries: 0 }), 'unknown');

// ── The cache absorbs shared upper steps ──────────────────────────────
// Deliberately cached, and under a root label no other fixture touches, so the
// saving measured here is this test's own and not an artefact of an earlier one.
sandbox.fetch = dohFixture({ '_dmarc.shared.cachetld TXT': txt(POLICY) });
const first = await D.discoverDmarc('one.shared.cachetld', { retries: 0 });
const firstCalls = sandbox.fetch.calls.length;
const second = await D.discoverDmarc('two.shared.cachetld', { retries: 0 });
const secondCalls = sandbox.fetch.calls.length - firstCalls;
eq('the first walk queries every step', firstCalls, 3);
eq('a sibling subdomain reuses the cached upper steps', secondCalls, 1);
eq('the cached walk still finds the policy', second.applied.foundAt, 'shared.cachetld');
eq('both siblings agree on the org domain',
  first.organizationalDomain === second.organizationalDomain, true);

// The guarantee is over every walk in this section, not one of them.
eq('terminated is only ever one of the four defined values',
  [deep, own, oneUp, several, both, twoUp, psdAuthor, psdDkim, psdBelow, psdN,
    dupOnly, dupInherit, servfail, sfAbove, sfOwn, none, notFirst, badCase]
    .every(w => ['psd-y', 'psd-n', 'root', 'error'].includes(w.terminated)), true);
eq('a non-error walk always yields a non-null applied or an empty collection',
  [own, oneUp, several, both, twoUp, psdAuthor, psdDkim, psdBelow, psdN]
    .every(w => w.terminated === 'error' ? w.applied === null : true), true);

/* ── 29. External report authorization (RFC 9990 §4) ─────────────────── */
section('29. External report authorization after the Tree Walk (RFC 9990 §4)');

const authFor = async (map, host) => {
  sandbox.fetch = dohFixture(map);
  return (await D.checkExternalReportAuth('src.example', [host], { retries: 0 }))[0];
};

const wildcardOnly = await authFor({
  '*._report._dmarc.wc.example TXT': txt('v=DMARC1'),
}, 'wc.example');
eq('a wildcard owner authorizes via synthesis', wildcardOnly.state, 'authorized');
eq('and is answered at the constructed name', wildcardOnly.via, 'exact');

/* RFC 4592 suppresses synthesis when the queried owner exists. So a
   destination whose exact owner carries unrelated data is NOT authorized under
   RFC 9990, even though a wildcard with `v=DMARC1` sits beside it — the
   resolver never synthesizes, so a conformant receiver never sees it. The old
   second query against the literal `*` owner found that record anyway and
   authorized the arrangement, which is the verdict-changing half of the bug. */
const suppressed = await authFor({
  'src.example._report._dmarc.sup.example TXT': txt('some unrelated txt data'),
  '*._report._dmarc.sup.example TXT': txt('v=DMARC1'),
}, 'sup.example');
eq('an existing owner suppresses the wildcard → unauthorized', suppressed.state, 'unauthorized');
eq('and the unrelated data is reported as malformed', suppressed.malformed, true);

// Step 8: "If at least one TXT resource record remains in the set after
// parsing, then the external reporting arrangement was authorized." This is
// PERMISSIVE and deliberately unlike the policy duplicate rule.
const twoRecords = await authFor({
  'src.example._report._dmarc.two.example TXT': [...txt('not a dmarc record'), ...txt('v=DMARC1')],
}, 'two.example');
eq('two records, one parses → authorized', twoRecords.state, 'authorized');
eq('two records, one parses → via exact',  twoRecords.via, 'exact');

const twoValid = await authFor({
  'src.example._report._dmarc.both.example TXT': [...txt('v=DMARC1'), ...txt('v=DMARC1; rua=mailto:x@both.example')],
}, 'both.example');
eq('two records that both parse → still authorized', twoValid.state, 'authorized');
eq('two records that both parse → there is no "multiple" state', twoValid.recordCount, 2);

const neitherParses = await authFor({
  'src.example._report._dmarc.bad.example TXT': [...txt('nonsense'), ...txt('also nonsense')],
}, 'bad.example');
eq('two records, neither parses → unauthorized', neitherParses.state, 'unauthorized');
eq('two records, neither parses → flagged malformed', neitherParses.malformed, true);

// startsWithCI() accepted this; validateDmarcVersion() does not.
const almost = await authFor({
  'src.example._report._dmarc.x1.example TXT': txt('v=DMARC1x'),
}, 'x1.example');
eq('v=DMARC1x → unauthorized', almost.state, 'unauthorized');
eq('v=DMARC1x → flagged malformed', almost.malformed, true);

const notFirstAuth = await authFor({
  'src.example._report._dmarc.nf2.example TXT': txt('rua=mailto:x@nf2.example; v=DMARC1'),
}, 'nf2.example');
eq('v= not first → unauthorized (RFC 9990 §4 step 6)', notFirstAuth.state, 'unauthorized');

// NXDOMAIN at the exact name is ordinary vendor practice; NOERROR carrying
// unrelated TXT data usually means the record went to the wrong name.
const nodataMiss = await authFor({
  'src.example._report._dmarc.nd.example TXT': 'nodata',
}, 'nd.example');
eq('a NODATA miss is distinguished from NXDOMAIN', nodataMiss.exactKind, 'nodata');
eq('a NODATA miss is unauthorized, not malformed', nodataMiss.malformed, false);

/* Step 6 requires the record be parsed "as a series of tag=value pairs", not
   merely that it opens with v=DMARC1. Checking only the version tag accepted
   anything that started correctly and then said nothing meaningful. */
eq('a record with junk after v=DMARC1 does not authorize',
  (await authFor({
    'src.example._report._dmarc.junk.example TXT': txt('v=DMARC1; this-is-not-a-tag-value-pair'),
  }, 'junk.example')).state, 'unauthorized');
eq('a bare v=DMARC1 authorizes',
  (await authFor({ 'src.example._report._dmarc.bare.example TXT': txt('v=DMARC1') }, 'bare.example')).state, 'authorized');
eq('an optional trailing semicolon is allowed',
  (await authFor({ 'src.example._report._dmarc.semi.example TXT': txt('v=DMARC1;') }, 'semi.example')).state, 'authorized');
eq('an empty segment in the middle is a syntax error',
  D.parseReportAuthRecord('v=DMARC1; ; rua=mailto:x@a.example', 'a.example').valid, false);
eq('the parser names the failure reason',
  D.parseReportAuthRecord('v=DMARC1; nonsense', 'a.example').reason, 'syntax');
eq('and distinguishes it from a version failure',
  D.parseReportAuthRecord('p=reject; v=DMARC1', 'a.example').reason, 'version');
// Step 8 stays permissive: one COMPLETE record among several is enough.
eq('one complete record among malformed ones still authorizes',
  (await authFor({
    'src.example._report._dmarc.mix.example TXT': [...txt('v=DMARC1; nonsense'), ...txt('v=DMARC1; rua=mailto:r@mix.example')],
  }, 'mix.example')).state, 'authorized');

/* Step 9: the Report Consumer may override the destination, but "the
   overriding URI MUST use the same destination host from the first step". This
   tool never sends reports, so the override changes no verdict — it is
   captured because an authorized result that dropped it would be incomplete
   evidence about where reports actually go. */
const override = await authFor({
  'src.example._report._dmarc.ov.example TXT': txt('v=DMARC1; rua=mailto:reports@ov.example'),
}, 'ov.example');
eq('a same-host override is retained', override.override, 'mailto:reports@ov.example');
eq('and marked valid', override.overrideValid, true);
/* A cross-host override does not merely void itself. RFC 9990 §4: "if the
   confirming record includes a URI whose host is again different than the
   domain publishing that override, the Mail Receiver generating the report
   MUST NOT generate a report to either the original or the override URI." So
   the destination is unusable, and reporting it as `authorized` would tell the
   operator their reports are flowing when nothing is sent at all. */
const badOverride = await authFor({
  'src.example._report._dmarc.bo.example TXT': txt('v=DMARC1; rua=mailto:reports@elsewhere.example'),
}, 'bo.example');
eq('a cross-host override makes the destination unusable', badOverride.state, 'override-mismatch');
eq('it is not reported as authorized', badOverride.state === 'authorized', false);
eq('the offending override is retained as evidence', badOverride.override, 'mailto:reports@elsewhere.example');
eq('and the reason is named', badOverride.overrideReason, 'cross-host');

// §3.5 treats a malformed URI differently: "if any of the URIs are malformed,
// they SHOULD be ignored" — ignored, not escalated. The authorization stands.
const junkOverride = await authFor({
  'src.example._report._dmarc.jo.example TXT': txt('v=DMARC1; rua=not-a-uri'),
}, 'jo.example');
eq('a malformed override is ignored, not escalated', junkOverride.state, 'authorized');
eq('and is distinguished from a cross-host override', junkOverride.overrideReason, 'malformed');

/* The state has to be CONSUMED, or it is decorative. This is the regression
   that the first override fix was missing: `overrideValid: false` was set and
   nothing downstream read it, so the interface presented the destination as
   usable. */
const mismatchKeys = D.buildIssues({
  emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:d@bo.example'),
  dmarcExistence: 'yes', externalReportDestinations: ['bo.example'],
  hosting: 'Custom', advanced: Object.assign({}, full, { reportAuth: [badOverride] }),
  domain: 'src.example',
}).map(i => i.key);
eq('a cross-host override raises its own finding',
  mismatchKeys.includes('dmarc-external-override-mismatch'), true);
eq('and is not silently reported as a working destination',
  mismatchKeys.includes('dmarc-external-reporting'), false);
const okKeys = D.buildIssues({
  emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:d@jo.example'),
  dmarcExistence: 'yes', externalReportDestinations: ['jo.example'],
  hosting: 'Custom', advanced: Object.assign({}, full, { reportAuth: [junkOverride] }),
  domain: 'src.example',
}).map(i => i.key);
eq('a properly authorized destination raises no mismatch finding',
  okKeys.includes('dmarc-external-override-mismatch'), false);

sandbox.fetch = dohFixture({ 'src.example._report._dmarc.flap.example TXT': 'servfail' });
const unverifiable = (await D.checkExternalReportAuth('src.example', ['flap.example'], { retries: 0 }))[0];
eq('a DNS failure is unverifiable, not unauthorized', unverifiable.state, 'unverifiable');

// The authorization query is built from the name the APPLIED record was found
// at, not from the audited name — otherwise it asks the wrong question.
sandbox.fetch = dohFixture({
  '_dmarc.policy.example TXT': txt('v=DMARC1; p=reject; rua=mailto:r@vendor.example'),
  'vendor.example._report._dmarc.vendor.example TXT': 'nxdomain',
});
const inherited = await D.discoverDmarc('sub.policy.example', { retries: 0, noCache: true });
eq('authorization is asked of the policy domain', inherited.applied.foundAt, 'policy.example');
sandbox.fetch = dohFixture({
  'policy.example._report._dmarc.vendor.example TXT': txt('v=DMARC1'),
});
const askedAt = (await D.checkExternalReportAuth(inherited.applied.foundAt, ['vendor.example'], { retries: 0 }))[0];
eq('the query name uses foundAt, not the audited name',
  askedAt.queryName, 'policy.example._report._dmarc.vendor.example');
eq('authorization evaluated against the policy domain → authorized', askedAt.state, 'authorized');

/* One cap has to bound the WHOLE destination-driven workflow. Capping only the
   Organizational Domain walks left authorization uncapped, so the audited
   record's own text still decided how much resolver work one audit did. */
const manyDests = Array.from({ length: 20 }, (_, i) => `vendor${i}.example`);
sandbox.fetch = dohFixture({
  'big.example NS': ns('ns1.big.example.'),
  'big.example MX': mx('10 mail.big.example.'),
  'big.example TXT': txt('v=spf1 -all'),
  'big.example A': a('203.0.113.1'),
  'big.example AAAA': 'nodata',
  '_dmarc.big.example TXT': txt('v=DMARC1; p=reject; rua=' + manyDests.map(d => 'mailto:r@' + d).join(',')),
});
const big = await D.analyzeDomain('big.example', { dkim: false, advanced: true, retries: 0 });
const bigCalls = sandbox.fetch.calls;
eq('no more than ten destinations are walked',
  new Set(bigCalls.filter(c => /^_dmarc\.vendor/.test(c)).map(c => c.split(' ')[0].replace(/^_dmarc\./, ''))).size, 10);
eq('no more than ten authorization queries are issued',
  bigCalls.filter(c => c.includes('._report._dmarc.')).length, 10);
eq('one authorization query per destination, never two',
  bigCalls.filter(c => c.includes('._report._dmarc.')).length,
  new Set(bigCalls.filter(c => c.includes('._report._dmarc.')).map(c => c.split(' ')[0])).size);
// The truncation is stated, not implied away.
const bigKeys = big.issues.map(i => i.key);
eq('the audit says it stopped short', bigKeys.includes('dmarc-report-destinations-truncated'), true);
eq('and names how many of how many were checked',
  big.issues.filter(i => i.key === 'dmarc-report-destinations-truncated')[0].args.slice(0, 2), [10, 20]);
eq('a record within the cap raises no truncation notice',
  D.buildIssues({
    emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
    dmarcStatus: D.analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@v1.example'),
    dmarcExistence: 'yes', reportPlan: { external: [], total: 1, omitted: [] },
    hosting: 'Custom', advanced: full, domain: 'small.example',
  }).map(i => i.key).includes('dmarc-report-destinations-truncated'), false);

/* ── 30. PSL versus Tree Walk divergence ─────────────────────────────── */
section('30. PSL versus Tree Walk divergence');

// A future PSL refresh must not be able to change a DMARC answer. Each row
// names a domain where the vendored list and the Tree Walk disagree, and
// asserts the TREE WALK answer — so if anyone reconnects DMARC to the PSL,
// these fail rather than drifting silently.
const divergence = [
  {
    // The PSL boundary is example.com, but the DMARC boundary is one label
    // lower because that name published psd=n. §4.10.2 rule 1 wins outright.
    domain: 'a.division.example.com',
    fixtures: { '_dmarc.division.example.com TXT': txt('v=DMARC1; p=reject; psd=n') },
    psl: 'example.com',
    treeWalk: 'division.example.com',
  },
  {
    // Nothing published below the registry, so the walk keeps climbing past
    // the PSL boundary and lands on the record that genuinely governs.
    domain: 'mail.tenant.example.com',
    fixtures: { '_dmarc.example.com TXT': txt('v=DMARC1; p=reject') },
    psl: 'example.com',
    treeWalk: 'example.com',
  },
  {
    // A PSD that declares itself. The PSL calls co.uk the suffix; the walk
    // puts the Organizational Domain one label below the psd=y name, which is
    // the same answer for a different and DNS-verifiable reason.
    domain: 'mail.shop.co.uk',
    fixtures: { '_dmarc.co.uk TXT': txt('v=DMARC1; p=none; psd=y') },
    psl: 'shop.co.uk',
    treeWalk: 'shop.co.uk',
  },
  {
    // No records anywhere: §4.10.2's fallback is the initial target domain,
    // NOT the PSL's registrable domain. This is the row most likely to be
    // "fixed" back to the PSL by someone who finds it surprising.
    domain: 'orphan.example.com',
    fixtures: {},
    psl: 'example.com',
    treeWalk: 'orphan.example.com',
  },
];
for (const row of divergence) {
  const result = await walk(row.domain, row.fixtures);
  eq(`divergence: ${row.domain} → tree walk says ${row.treeWalk}`,
    result.organizationalDomain, row.treeWalk);
  eq(`divergence: ${row.domain} → PSL still says ${row.psl}`,
    D.getOrganizationalDomain(row.domain), row.psl);
}
eq('the Tree Walk and the PSL genuinely disagree on at least one row',
  divergence.some(r => r.psl !== r.treeWalk), true);

/* ── 31. Stricter tag validation (spec §5) ───────────────────────────── */
section('31. Stricter DMARC tag validation');

eq('absent sp is "absent"',      D.analyzeDmarc('v=DMARC1; p=reject').spState, 'absent');
eq('valid sp is "valid"',        D.analyzeDmarc('v=DMARC1; p=reject; sp=none').spState, 'valid');
eq('unrecognised sp is "invalid"', D.analyzeDmarc('v=DMARC1; p=reject; sp=rejcet').spState, 'invalid');
eq('an unrecognised sp still inherits p for receivers',
  D.analyzeDmarc('v=DMARC1; p=reject; sp=rejcet').effectiveSp, 'reject');
eq('an unrecognised sp keeps the raw value',
  D.analyzeDmarc('v=DMARC1; p=reject; sp=rejcet').spRaw, 'rejcet');
eq('unrecognised np is "invalid"', D.analyzeDmarc('v=DMARC1; p=reject; np=nope').npState, 'invalid');
eq('the p= raw value is retained', D.analyzeDmarc('v=DMARC1; p=rejcet').policyRaw, 'rejcet');

eq('absent adkim is "absent"',   D.analyzeDmarc('v=DMARC1; p=reject').adkimState, 'absent');
eq('adkim=r is "r"',             D.analyzeDmarc('v=DMARC1; p=reject; adkim=r').adkimState, 'r');
eq('adkim=s is "s"',             D.analyzeDmarc('v=DMARC1; p=reject; adkim=s').adkimState, 's');
eq('adkim=strict is "invalid"',  D.analyzeDmarc('v=DMARC1; p=reject; adkim=strict').adkimState, 'invalid');
eq('adkim=strict still relaxes for receivers',
  D.analyzeDmarc('v=DMARC1; p=reject; adkim=strict').adkim, 'r');
eq('aspf=loose is "invalid"',    D.analyzeDmarc('v=DMARC1; p=reject; aspf=loose').aspfState, 'invalid');

const tagKeys = rec => D.buildIssues({
  emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.analyzeDmarc(rec), dmarcExistence: 'yes',
  hosting: 'Custom', advanced: full, domain: 'example.com',
}).map(i => i.key);
eq('sp=rejcet → its own finding',   tagKeys('v=DMARC1; p=reject; sp=rejcet').includes('dmarc-bad-sp'), true);
eq('np=nope → its own finding',     tagKeys('v=DMARC1; p=reject; np=nope').includes('dmarc-bad-np'), true);
eq('adkim=strict → its own finding', tagKeys('v=DMARC1; p=reject; adkim=strict').includes('dmarc-bad-adkim'), true);
eq('aspf=loose → its own finding',  tagKeys('v=DMARC1; p=reject; aspf=loose').includes('dmarc-bad-aspf'), true);
eq('a valid record raises none of them',
  tagKeys('v=DMARC1; p=reject; sp=none; adkim=s; aspf=s; rua=mailto:d@example.com')
    .some(k => ['dmarc-bad-sp', 'dmarc-bad-np', 'dmarc-bad-adkim', 'dmarc-bad-aspf'].includes(k)), false);

const npNotApplied = D.buildIssues({
  emailProvider: 'Custom', spfStatus: spf('ok'), dkimStatus: { found: true },
  dmarcStatus: D.applyInheritance(npRecord, upTree, 'yes'),
  dmarcDiscovery: { observed: [], applied: upTree.applied }, dmarcExistence: 'yes',
  hosting: 'Custom', advanced: full, domain: 'sub.np.example',
}).map(i => i.key);
eq('np= reported but not applied on a name that exists',
  npNotApplied.includes('dmarc-np-not-applied'), true);

/* ── 32. End to end through analyzeDomain ────────────────────────────── */
section('32. Tree Walk through analyzeDomain');

const E2E = {
  'sub.e2e.example NS': ns('ns1.e2e.example.'),
  'sub.e2e.example MX': mx('10 mail.e2e.example.'),
  'sub.e2e.example TXT': txt('v=spf1 -all'),
  'sub.e2e.example A': a('203.0.113.5'),
  'sub.e2e.example AAAA': 'nodata',
  '_dmarc.e2e.example TXT': txt('v=DMARC1; p=reject; sp=quarantine; np=none; rua=mailto:d@e2e.example'),
};
sandbox.fetch = dohFixture(E2E);
const e2e = await D.analyzeDomain('sub.e2e.example', { dkim: false, retries: 0 });
eq('analyzeDomain attaches the discovery object', !!e2e.dmarcDiscovery, true);
eq('analyzeDomain finds the inherited policy',    e2e.dmarcAtDomain, 'e2e.example');
eq('dmarcAtDomain still aliases foundAt',         e2e.dmarcAtDomain, e2e.dmarcDiscovery.applied.foundAt);
eq('the audited name exists, so sp governs',      e2e.dmarcStatus.policy, 'quarantine');
eq('existence is derived without an extra query', e2e.dmarcExistence, 'yes');
eq('np is reported but not applied',              e2e.dmarcStatus.appliedBranch, 'sp');
eq('the organizational domain comes from the walk', e2e.organizationalDomain, 'e2e.example');
eq('no NS query is issued for existence beyond the first',
  sandbox.fetch.callsFor('NS').length, 1);
eq('the walk is visible as evidence',             e2e.dmarcDiscovery.steps.length, 3);
eq('the walk terminated at the root',             e2e.dmarcDiscovery.terminated, 'root');

// The gap a 1,130-assertion suite still had: section 28 tested discoverDmarc in
// isolation and section 32 tested only the happy path, so nothing asserted what
// analyzeDomain DOES with an errored walk. A transient failure on any of up to
// eight queries must never be reported as an absent record.
sandbox.fetch = dohFixture({
  'flap.example NS': ns('ns1.flap.example.'),
  'flap.example MX': mx('10 mail.flap.example.'),
  'flap.example TXT': txt('v=spf1 -all'),
  'flap.example A': a('203.0.113.9'),
  'flap.example AAAA': 'nodata',
  '_dmarc.flap.example TXT': 'servfail',
});
const flap = await D.analyzeDomain('flap.example', { dkim: false, retries: 0 });
eq('an errored walk is reported as unknown, not missing', flap.dmarcStatus.status, 'unknown');
eq('an unknown DMARC control does not wear the absent class', flap.dmarcStatus.cls, 'warn');
eq('the finding says the lookup failed, not that the record is absent',
  flap.issues.map(i => i.key).includes('dmarc-unverified'), true);
eq('an unknown control is never reported as missing',
  flap.issues.map(i => i.key).includes('dmarc-missing'), false);
eq('the finding names the failure kind',
  flap.issues.filter(i => i.key === 'dmarc-unverified')[0].args, ['servfail']);
eq('the DMARC pillar is marked unproven', flap.score.unproven.includes('dmarc'), true);
eq('an unproven DMARC pillar still scores zero',
  flap.score.breakdown.pillars.find(p => p.key === 'dmarc').pts, 0);
eq('the walk still reports how it failed', flap.dmarcDiscovery.terminated, 'error');

// The Author Domain's own record survives, so this is NOT the unknown path.
sandbox.fetch = dohFixture({
  'own.example NS': ns('ns1.own.example.'),
  'own.example MX': mx('10 mail.own.example.'),
  'own.example TXT': txt('v=spf1 -all'),
  'own.example A': a('203.0.113.9'),
  'own.example AAAA': 'nodata',
  '_dmarc.own.example TXT': txt('v=DMARC1; p=reject; rua=mailto:d@own.example'),
  '_dmarc.example TXT': 'servfail',
});
const ownErr = await D.analyzeDomain('own.example', { dkim: false, retries: 0 });
eq('an error above the domain’s own record is not unknown', ownErr.dmarcStatus.status, 'ok');
eq('the domain’s own policy still governs', ownErr.dmarcStatus.policy, 'reject');
eq('and the pillar is not marked unproven', ownErr.score.unproven.includes('dmarc'), false);

// A stray apex record ALONGSIDE a working policy is untidy, not critical — the
// same "must not lie" rule the duplicate finding follows.
sandbox.fetch = dohFixture({
  'apexok.example NS': ns('ns1.apexok.example.'),
  'apexok.example MX': mx('10 mail.apexok.example.'),
  'apexok.example TXT': [...txt('v=spf1 -all'), ...txt('v=DMARC1; p=reject')],
  'apexok.example A': a('203.0.113.9'),
  'apexok.example AAAA': 'nodata',
  '_dmarc.apexok.example TXT': txt('v=DMARC1; p=reject; rua=mailto:d@apexok.example'),
});
const apexOk = await D.analyzeDomain('apexok.example', { dkim: false, retries: 0 });
const apexOkKeys = apexOk.issues.map(i => i.key);
eq('a working policy alongside an apex stray is not critical',
  apexOkKeys.includes('dmarc-at-apex'), false);
eq('it is reported as an ignored leftover instead',
  apexOkKeys.includes('dmarc-at-apex-ignored'), true);
eq('the leftover finding names the governing policy',
  apexOk.issues.filter(i => i.key === 'dmarc-at-apex-ignored')[0].args, ['apexok.example']);
eq('and the real policy is untouched', apexOk.dmarcStatus.policy, 'reject');

// With nothing under _dmarc, the apex record IS the whole story and stays critical.
sandbox.fetch = dohFixture({
  'apexbad.example NS': ns('ns1.apexbad.example.'),
  'apexbad.example MX': mx('10 mail.apexbad.example.'),
  'apexbad.example TXT': [...txt('v=spf1 -all'), ...txt('v=DMARC1; p=reject')],
  'apexbad.example A': a('203.0.113.9'),
  'apexbad.example AAAA': 'nodata',
});
const apexBad = await D.analyzeDomain('apexbad.example', { dkim: false, retries: 0 });
eq('an apex record with nothing under _dmarc stays critical',
  apexBad.issues.filter(i => i.key === 'dmarc-at-apex')[0].sev, 'crit');

// `v=DMARC1x` is rejected on the authorization side; it must be diagnosed here too.
eq('v=DMARC1x is diagnosed rather than silently absent',
  D.diagnoseDmarcRecord('v=DMARC1x; p=reject'), 'version-bad-case');
eq('v=spf1 is still not a DMARC diagnosis', D.diagnoseDmarcRecord('v=spf1 -all'), null);

// RFC 9990 §4 step 4: an over-long constructed name cannot be determined.
sandbox.fetch = dohFixture({});
const longHost = ('a'.repeat(60) + '.').repeat(4) + 'example.com';
const tooLong = (await D.checkExternalReportAuth('src.example', [longHost], { retries: 0 }))[0];
eq('an over-long authorization name is undeterminable, not unauthorized',
  tooLong.state, 'unverifiable');
eq('and says why', tooLong.error, 'name-too-long');

/* ── 33. Transport: unsupported record types fail loudly ─────────────── */
section('33. Transport: dnsTypeNum throws instead of guessing TXT');

// The old `?? 16` made every unknown type a TXT query whose answers were then
// filtered for type 16 — so a DS lookup returned a confident empty array.
eq('SVCB throws rather than returning 16', (() => {
  try { D.dnsTypeNum('SVCB'); return 'no-throw'; } catch (e) { return e.name; }
})(), 'DnsTypeError');
eq('the message names the type', (() => {
  try { D.dnsTypeNum('SVCB'); return ''; } catch (e) { return e.message; }
})(), 'unsupported DNS type: SVCB');
eq('a prototype property name is not a type', (() => {
  try { D.dnsTypeNum('constructor'); return 'no-throw'; } catch (e) { return e.name; }
})(), 'DnsTypeError');

eq('DS is supported',     D.dnsTypeNum('DS'), 43);
eq('DNSKEY is supported', D.dnsTypeNum('DNSKEY'), 48);
eq('TLSA is supported',   D.dnsTypeNum('TLSA'), 52);
eq('PTR is supported',    D.dnsTypeNum('PTR'), 12);
eq('TXT still resolves',  D.dnsTypeNum('TXT'), 16);
eq('CAA still resolves',  D.dnsTypeNum('CAA'), 257);

// The throw has to survive the transport, or it is caught by fetchDohOnce's
// own catch and reported as 'network-error' — the same silent wrong answer in
// a different costume.
sandbox.fetch = dohFixture({});
eq('dohFetch propagates the type error', await (async () => {
  try { await D.dohFetch('example.com', 'SVCB', { retries: 0, noCache: true }); return 'no-throw'; }
  catch (e) { return e.name; }
})(), 'DnsTypeError');

// And optionalCheck must not turn a programming error into a stated unknown.
eq('optionalCheck re-throws a type error', await (async () => {
  try {
    await D.optionalCheck(() => D.dohFetch('example.com', 'SVCB', { retries: 0, noCache: true }), 'fallback');
    return 'swallowed';
  } catch (e) { return e.name; }
})(), 'DnsTypeError');
eq('optionalCheck still swallows a resolver failure', await (async () => {
  sandbox.fetch = dohFixture({ 'x.example NS': 'servfail' });
  return await D.optionalCheck(
    async () => { throw Object.assign(new Error('x'), { name: 'DnsQueryError' }); }, 'fallback');
})(), 'fallback');

/* ── 34. DKIM public key analysis (RFC 6376 §3.6.1, RFC 8463) ────────── */
section('34. DKIM public key analysis');

// Real SPKI keys, generated with openssl and pasted as static strings so the
// DER walk is exercised against genuine encodings rather than a hand-built one.
const RSA_512 = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANvwLB0jC0G5N6ooxhzJStD6NSKbEBDqdjaIG/PVtJu4Sor/279iw+pLQreH2aF9ybG9DFJYphaM5HqDteMUbFECAwEAAQ==';
const RSA_1024 = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYmA1/sNLcrMtU2cEfPrc5Gj7m1OFp23VoKeHbCMEYbMjSATLrI6YsefyW7760zWwHmb2kZ7tCAnlnLOvH75kmFdq+q6VHwaOH1MZQkB+F5VaVU2uf3iO50r23+FU5Cb6N3NuovTY8vzY/nPI2vUS/FCXuteqGUiuFKwttC8oESwIDAQAB';
const RSA_2048 = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtdBGhkB+ys0FdTPY1/X59sh1kPlfMwovaF7w0uAdPijJvb28RVHRcZW0vfp2txuyZZ3qNAV2C/2nv+zVr/bld2flVPdmnCSdAoUXi9ZQpH20zzwj8bcGrU6v/sH4xC7BLRH7P8KQ4K3suhuSLpaK0KLC+oGdD7DZ3DyeFyHeMWcR9RJin3LhZMP0rVP3e6PHNd2XwW+zPJRjuQR6yACuOLyXhBvZtD+Frs6/mtKF8HyaO9/Zs/bqrw3v5qjuC6hi2VnlUbS+zWL9fZp3xh7lf2FaztehaVHcvUO2HOGAFGWci3jtwD2owSvw/Laqq0UTInQ/vcVZf/1QNJGiZ0tEIQIDAQAB';
const RSA_4096 = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2GKwg8r1UzfnPgxUSjTck7Teu3YNAVasv1+fDj6bqNa1QAKqziKGhTUAd4NFb71ELSblrRIMmADzXEpgwEbWdGo0wMZYeXGzMATRifC1vjnBxeThGKeNtI6+wU3w3kcl+vmSVXS6oxD98bWzt2A0uqJo0uA54xnVhjoH4HG/LiKZFjLUhI6EAjjE46fmfoBGcLAOI82c7EmusMe8Xy0HcLk8Vepj3GhYO3ZS0ajgbPxNV7FjBUz9Z5wk8vdX2HFdf1/Dwfv3Kb6QOduj7MEU7RV1W4mRiYzsjZdrOqAQZSLrpxPx+Z73NRjxA0Q7t1rWCtFMP8wZ2xAK/F75FJmBi6j8urEpBt1S4xyNbaw3p/Ed7xpD4Zj3hd9vmWPGozqUP9Y9TJ3BBaR5vfDFvHl/e8ezpRcafyCH59GTmXq2j34ISjr6zRo5Y0jmdaPUXqgf2C+b8yw7Y0ut1Q3dhxQoca+Nb/REedy3tvxc2aY+uUIo80W06SoopPp3Lm8uk4u8t/t+IWjtGf7hKZgcmFPEmro1MK/1YmMnYg7ejjKEv2LBpF8m7QpZFTGEFd9/u02OkMYuM866nezPXvEKSnAkvmWDCkzwZhsBaIkihXmemKe1QhvAuk6dEVzmnHWUFAZnTErHu9TZ1Fpw6yJNw8QOkmrZ28Ji++HHu65vbzrvFWECAwEAAQ==';
const ED25519_32 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
const ED25519_31 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==';

const key = value => D.analyzeDkimKey(value);

eq('RSA-512 modulus read',   key(`v=DKIM1; k=rsa; p=${RSA_512}`).keyBits, 512);
eq('RSA-1024 modulus read',  key(`v=DKIM1; k=rsa; p=${RSA_1024}`).keyBits, 1024);
eq('RSA-2048 modulus read',  key(`v=DKIM1; k=rsa; p=${RSA_2048}`).keyBits, 2048);
eq('RSA-4096 modulus read',  key(`v=DKIM1; k=rsa; p=${RSA_4096}`).keyBits, 4096);
eq('a valid key has no errors', key(`v=DKIM1; k=rsa; p=${RSA_2048}`).errors, []);

// k= defaults to rsa when absent (RFC 6376 §3.6.1), and paypal.com publishes
// exactly this shape — no v=, no k=.
eq('k= defaults to rsa',     key(`p=${RSA_2048}`).keyType, 'rsa');
eq('v= may be omitted',      key(`p=${RSA_2048}`).version, null);
eq('and the key is still valid', key(`p=${RSA_2048}`).valid, true);
eq('v=DKIM1 is recorded',    key(`v=DKIM1; p=${RSA_2048}`).version, 'DKIM1');
eq('v=DKIM2 is invalid',     key(`v=DKIM2; p=${RSA_2048}`).valid, false);
eq('v=DKIM2 says why',       key(`v=DKIM2; p=${RSA_2048}`).errors, ['bad-version']);

// RFC 8463 §3: the value is the raw 32-byte key, not an SPKI structure, so
// there is no modulus to measure and keyBits must stay null rather than 0.
const ed = key(`v=DKIM1; k=ed25519; p=${ED25519_32}`);
eq('ed25519 detected',       ed.keyType, 'ed25519');
eq('ed25519 byte length',    ed.keyBytes, 32);
eq('ed25519 has no modulus', ed.keyBits, null);
eq('ed25519 is valid',       ed.valid, true);
eq('a 31-byte ed25519 key is flagged',
  key(`v=DKIM1; k=ed25519; p=${ED25519_31}`).errors, ['bad-ed25519-length']);

// The revocation case dkimKeyRecords() drops on the discovery side.
const revoked = key('v=DKIM1; k=rsa; p=');
eq('empty p= is revocation',        revoked.revoked, true);
eq('revocation is not a parse error', revoked.errors, []);
eq('revocation reports no size',    revoked.keyBits, null);
eq('a live key is not revoked',     key(`v=DKIM1; p=${RSA_2048}`).revoked, false);

// A p= truncated by a TXT chunking mistake is a completely silent DKIM
// failure, and it must not read as a key of whatever size the garbage implies.
eq('truncated base64 is unparseable',
  key(`v=DKIM1; k=rsa; p=${RSA_2048.slice(0, 100)}`).errors, ['unparseable-key']);
eq('and reports no size',
  key(`v=DKIM1; k=rsa; p=${RSA_2048.slice(0, 100)}`).keyBits, null);
eq('non-base64 is unparseable',
  key('v=DKIM1; k=rsa; p=not base64 at all!!').errors, ['unparseable-key']);
eq('a missing p= is named',  key('v=DKIM1; k=rsa').errors, ['missing-p']);

/* ── Both RSA envelopes are conformant ──────────────────────────────────
   RFC 6376 §3.6.1 describes the p= value as a DER-encoded RSAPublicKey, and
   the errata clarify that it MAY be wrapped in a SubjectPublicKeyInfo. So a
   bare PKCS#1 key is valid, not a curiosity — and it must not be refused just
   because crypto.subtle.importKey takes 'spki' and not 'pkcs1'. Letting an
   API's input formats decide what the protocol permits would report a
   perfectly good published key as unparseable.

   Both envelopes below are the SAME four keys, exported by openssl two ways,
   so the sizes must agree exactly across the pair.
   ───────────────────────────────────────────────────────────────────────── */
const PKCS1_512 = 'MEgCQQDb8CwdIwtBuTeqKMYcyUrQ+jUimxAQ6nY2iBvz1bSbuEqK/9u/YsPqS0K3h9mhfcmxvQxSWKYWjOR6g7XjFGxRAgMBAAE=';
const PKCS1_1024 = 'MIGJAoGBAJiYDX+w0tysy1TZwR8+tzkaPubU4WnbdWgp4dsIwRhsyNIBMusjpix5/JbvvrTNbAeZvaRnu0ICeWcs68fvmSYV2r6rpUfBo4fUxlCQH4XlVpVTa5/eI7nSvbf4VTkJvo3c26i9Njy/Nj+c8ja9RL8UJe616oZSK4UrC20LygRLAgMBAAE=';
const PKCS1_2048 = 'MIIBCgKCAQEAtdBGhkB+ys0FdTPY1/X59sh1kPlfMwovaF7w0uAdPijJvb28RVHRcZW0vfp2txuyZZ3qNAV2C/2nv+zVr/bld2flVPdmnCSdAoUXi9ZQpH20zzwj8bcGrU6v/sH4xC7BLRH7P8KQ4K3suhuSLpaK0KLC+oGdD7DZ3DyeFyHeMWcR9RJin3LhZMP0rVP3e6PHNd2XwW+zPJRjuQR6yACuOLyXhBvZtD+Frs6/mtKF8HyaO9/Zs/bqrw3v5qjuC6hi2VnlUbS+zWL9fZp3xh7lf2FaztehaVHcvUO2HOGAFGWci3jtwD2owSvw/Laqq0UTInQ/vcVZf/1QNJGiZ0tEIQIDAQAB';
const PKCS1_4096 = 'MIICCgKCAgEA2GKwg8r1UzfnPgxUSjTck7Teu3YNAVasv1+fDj6bqNa1QAKqziKGhTUAd4NFb71ELSblrRIMmADzXEpgwEbWdGo0wMZYeXGzMATRifC1vjnBxeThGKeNtI6+wU3w3kcl+vmSVXS6oxD98bWzt2A0uqJo0uA54xnVhjoH4HG/LiKZFjLUhI6EAjjE46fmfoBGcLAOI82c7EmusMe8Xy0HcLk8Vepj3GhYO3ZS0ajgbPxNV7FjBUz9Z5wk8vdX2HFdf1/Dwfv3Kb6QOduj7MEU7RV1W4mRiYzsjZdrOqAQZSLrpxPx+Z73NRjxA0Q7t1rWCtFMP8wZ2xAK/F75FJmBi6j8urEpBt1S4xyNbaw3p/Ed7xpD4Zj3hd9vmWPGozqUP9Y9TJ3BBaR5vfDFvHl/e8ezpRcafyCH59GTmXq2j34ISjr6zRo5Y0jmdaPUXqgf2C+b8yw7Y0ut1Q3dhxQoca+Nb/REedy3tvxc2aY+uUIo80W06SoopPp3Lm8uk4u8t/t+IWjtGf7hKZgcmFPEmro1MK/1YmMnYg7ejjKEv2LBpF8m7QpZFTGEFd9/u02OkMYuM866nezPXvEKSnAkvmWDCkzwZhsBaIkihXmemKe1QhvAuk6dEVzmnHWUFAZnTErHu9TZ1Fpw6yJNw8QOkmrZ28Ji++HHu65vbzrvFWECAwEAAQ==';

eq('bare PKCS#1 512 is read',   key(`v=DKIM1; k=rsa; p=${PKCS1_512}`).keyBits, 512);
eq('bare PKCS#1 1024 is read',  key(`v=DKIM1; k=rsa; p=${PKCS1_1024}`).keyBits, 1024);
eq('bare PKCS#1 2048 is read',  key(`v=DKIM1; k=rsa; p=${PKCS1_2048}`).keyBits, 2048);
eq('bare PKCS#1 4096 is read',  key(`v=DKIM1; k=rsa; p=${PKCS1_4096}`).keyBits, 4096);
eq('a bare PKCS#1 key is valid', key(`v=DKIM1; k=rsa; p=${PKCS1_2048}`).valid, true);
eq('and raises no errors',       key(`v=DKIM1; k=rsa; p=${PKCS1_2048}`).errors, []);

// The two encodings of one key must never disagree about its size.
eq('both envelopes agree on every size',
  [PKCS1_512, PKCS1_1024, PKCS1_2048, PKCS1_4096].map(p => key(`v=DKIM1; k=rsa; p=${p}`).keyBits),
  [RSA_512, RSA_1024, RSA_2048, RSA_4096].map(p => key(`v=DKIM1; k=rsa; p=${p}`).keyBits));

// The envelope is recorded as evidence — it explains why Web Crypto confirms
// one key and stays silent about the other. It is not a quality signal.
eq('SPKI is identified',   key(`v=DKIM1; k=rsa; p=${RSA_2048}`).keyEncoding, 'spki');
eq('PKCS#1 is identified', key(`v=DKIM1; k=rsa; p=${PKCS1_2048}`).keyEncoding, 'pkcs1');
eq('ed25519 has no RSA envelope', key(`v=DKIM1; k=ed25519; p=${ED25519_32}`).keyEncoding, null);

// Web Crypto is confirmation, never a downgrade. A bare key it cannot express
// comes back "not checked" — and still valid, with its size intact.
const pkcs1Validated = await D.validateDkimKeyStructure(key(`v=DKIM1; p=${PKCS1_2048}`), `v=DKIM1; p=${PKCS1_2048}`);
eq('a bare key is not sent to Web Crypto', pkcs1Validated.cryptoValidated, null);
eq('lack of confirmation leaves it valid', pkcs1Validated.valid, true);
eq('and never marks it unparseable',       pkcs1Validated.errors, []);
eq('and leaves the DER-derived size alone', pkcs1Validated.keyBits, 2048);

/* ── Malformed DER is still refused ─────────────────────────────────────
   Accepting both envelopes must not turn the walk into a shrug. These are
   built rather than pasted so the exact defect under test is visible.
   ───────────────────────────────────────────────────────────────────── */
const derTlv = (tag, content) => {
  const body = Buffer.from(content);
  if (body.length < 0x80) return Buffer.concat([Buffer.from([tag, body.length]), body]);
  const len = [];
  for (let n = body.length; n > 0; n >>= 8) len.unshift(n & 0xff);
  return Buffer.concat([Buffer.from([tag, 0x80 | len.length]), Buffer.from(len), body]);
};
const asKey = buf => key(`v=DKIM1; k=rsa; p=${Buffer.from(buf).toString('base64')}`);
// A conformant positive DER INTEGER: X.690 §8.3.2 puts the sign in the high bit
// of the first octet, so a value with that bit set needs a leading 0x00 — which
// is why a bare `0x80 …` is a NEGATIVE integer and not a 1024-bit modulus at
// all. RFC 8017 §3.1 requires `n` and `e` to be positive.
const positiveInteger = buf => ((buf[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), buf]) : buf);
// A modulus of `bytes` significant octets whose leading octet is `top`.
const modulusOf = (bytes, top) =>
  positiveInteger(Buffer.concat([Buffer.from([top]), Buffer.alloc(bytes - 1, 0xab)]));
// A well-formed modulus, for fixtures whose defect is meant to be elsewhere —
// so the assertion proves the reason under test and not an incidental one.
const wellFormedModulus = bytes => modulusOf(bytes, 0x81);

const spkiBytes = Buffer.from(RSA_2048, 'base64');
const pkcs1Bytes = Buffer.from(PKCS1_2048, 'base64');

eq('a truncated SPKI key is unparseable',
  key(`v=DKIM1; k=rsa; p=${RSA_2048.slice(0, 100)}`).errors, ['unparseable-key']);
eq('a truncated PKCS#1 key is unparseable',
  key(`v=DKIM1; k=rsa; p=${PKCS1_2048.slice(0, 100)}`).errors, ['unparseable-key']);
// A valid key with junk appended parses as far as the outer SEQUENCE, so
// without a length check it would report a confident 2048 for an unusable blob.
eq('trailing bytes after a valid SPKI key are refused',
  asKey(Buffer.concat([spkiBytes, Buffer.from([0x00])])).errors, ['unparseable-key']);
eq('trailing bytes after a valid PKCS#1 key are refused',
  asKey(Buffer.concat([pkcs1Bytes, Buffer.from([0x00])])).errors, ['unparseable-key']);
// A SEQUENCE holding one INTEGER is not an RSAPublicKey — the publicExponent
// is required, and without that check any such SEQUENCE would read as a key.
eq('a SEQUENCE with no publicExponent is refused',
  asKey(derTlv(0x30, derTlv(0x02, wellFormedModulus(256)))).errors, ['unparseable-key']);
eq('a SEQUENCE of the wrong inner type is refused',
  asKey(derTlv(0x30, derTlv(0x04, Buffer.alloc(16, 0x41)))).errors, ['unparseable-key']);
// The BIT STRING's first octet counts unused trailing bits; a key is a whole
// number of bytes, so a non-zero count means this is not the structure claimed.
const badBitString = derTlv(0x30, Buffer.concat([
  derTlv(0x30, Buffer.from([0x06, 0x01, 0x2a])),
  derTlv(0x03, Buffer.concat([Buffer.from([0x03]), derTlv(0x30, derTlv(0x02, wellFormedModulus(128)))])),
]));
eq('a BIT STRING with unused bits is refused', asKey(badBitString).errors, ['unparseable-key']);
eq('an INTEGER at the top level is not a key',
  asKey(derTlv(0x02, Buffer.alloc(8, 0x01))).errors, ['unparseable-key']);
eq('random bytes are not a key', asKey(Buffer.alloc(64, 0xab)).errors, ['unparseable-key']);
eq('a single byte is not a key', asKey(Buffer.from([0x30])).errors, ['unparseable-key']);
// An over-long DER length prefix is not something any real key carries, and
// reading it would mean trusting a length field that cannot be satisfied.
eq('an oversized length prefix is refused',
  asKey(Buffer.from([0x30, 0x85, 0x01, 0x02, 0x03, 0x04, 0x05, 0x02, 0x01, 0x01])).errors, ['unparseable-key']);

/* ── The reported size is the modulus's bit length, not its byte width ──
   These differ whenever the leading significant octet is below 0x80, and the
   difference straddles this release's own threshold: `dkim-key-weak` is
   critical below 1024 and `dkim-key-1024` is informational at exactly 1024.
   Every real RSA key has the top bit set, so the two answers agree on every key
   in the backtest sample — which is why this needs constructed keys rather than
   captured ones.
   ───────────────────────────────────────────────────────────────────── */
const EXPONENT = Buffer.from([0x01, 0x00, 0x01]);
const RSA_OID_DER = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
// modulus -> a bare PKCS#1 RSAPublicKey
const asPkcs1 = modulus => derTlv(0x30, Buffer.concat([derTlv(0x02, modulus), derTlv(0x02, EXPONENT)]));
// modulus -> the same key wrapped in a SubjectPublicKeyInfo
const asSpki = modulus => derTlv(0x30, Buffer.concat([
  derTlv(0x30, RSA_OID_DER),
  derTlv(0x03, Buffer.concat([Buffer.from([0x00]), asPkcs1(modulus)])),
]));
const bitsOf = buf => key(`v=DKIM1; k=rsa; p=${Buffer.from(buf).toString('base64')}`).keyBits;

// Immediately below, at, and above the 1024-bit boundary — both envelopes.
eq('a 1017-bit modulus reports 1017, not 1024', bitsOf(asPkcs1(modulusOf(128, 0x01))), 1017);
eq('a 1023-bit modulus reports 1023',           bitsOf(asPkcs1(modulusOf(128, 0x7f))), 1023);
eq('a 1024-bit modulus reports 1024',           bitsOf(asPkcs1(modulusOf(128, 0x80))), 1024);
eq('a 1025-bit modulus reports 1025',           bitsOf(asPkcs1(modulusOf(129, 0x01))), 1025);
eq('both envelopes agree at the boundary',
  [128, 129].flatMap(n => [0x01, 0x7f, 0x80].map(t => bitsOf(asSpki(modulusOf(n, t))))),
  [128, 129].flatMap(n => [0x01, 0x7f, 0x80].map(t => bitsOf(asPkcs1(modulusOf(n, t))))));
// The permitted sign octet is stripped rather than counted — modulusOf() emits
// it for any top octet at or above 0x80, so this is the 1024-bit case above
// seen from the encoding side.
eq('the sign octet is not counted as key material',
  [modulusOf(128, 0x80).length, bitsOf(asPkcs1(modulusOf(128, 0x80)))], [129, 1024]);

/* ── SPKI gets the same structural guards as PKCS#1 ─────────────────────
   Both envelopes go through one RSAPublicKey reader. The SPKI path used to
   check only that a modulus INTEGER existed, so a key whose exponent had been
   altered walked cleanly and returned a size — leaving Web Crypto as the only
   thing that would reject malformed DER, in a walk documented as authoritative
   without it. These are mutations of a REAL key, one byte at a time.
   ───────────────────────────────────────────────────────────────────── */
const realSpki = Buffer.from(RSA_512, 'base64');
const expAt = realSpki.lastIndexOf(Buffer.from([0x02, 0x03, 0x01, 0x00, 0x01]));
eq('the exponent was located in the real key', expAt > 0, true);
eq('the unmutated real key still parses', asKey(realSpki).keyBits, 512);

const mutate = (at, byte) => { const b = Buffer.from(realSpki); b[at] = byte; return b; };
eq('an SPKI exponent that is not an INTEGER is refused',
  asKey(mutate(expAt, 0x04)).errors, ['unparseable-key']);
eq('and reports no size',            asKey(mutate(expAt, 0x04)).keyBits, null);
// Truncating the exponent leaves trailing content inside the inner sequence.
eq('an SPKI exponent that does not end the sequence is refused',
  asKey(mutate(expAt + 1, 0x02)).errors, ['unparseable-key']);

const noExponent = derTlv(0x30, Buffer.concat([
  derTlv(0x30, RSA_OID_DER),
  derTlv(0x03, Buffer.concat([Buffer.from([0x00]), derTlv(0x30, derTlv(0x02, wellFormedModulus(64)))])),
]));
eq('an SPKI key with no publicExponent is refused', asKey(noExponent).errors, ['unparseable-key']);

// ecPublicKey, 1.2.840.10045.2.1 — a well-formed SPKI that is not an RSA key.
const ecAlgorithm = derTlv(0x30, Buffer.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]));
const notRsa = derTlv(0x30, Buffer.concat([
  ecAlgorithm,
  derTlv(0x03, Buffer.concat([Buffer.from([0x00]), asPkcs1(wellFormedModulus(64))])),
]));
eq('a non-RSA algorithm identifier is refused', asKey(notRsa).errors, ['unparseable-key']);
eq('and an RSA identifier is accepted',         asKey(asSpki(wellFormedModulus(64))).keyBits, 512);

// Trailing content at every nesting level.
eq('trailing bytes inside the BIT STRING are refused',
  asKey(derTlv(0x30, Buffer.concat([
    derTlv(0x30, RSA_OID_DER),
    derTlv(0x03, Buffer.concat([Buffer.from([0x00]), asPkcs1(wellFormedModulus(64)), Buffer.from([0x00])])),
  ]))).errors, ['unparseable-key']);
eq('trailing bytes after the BIT STRING are refused',
  asKey(Buffer.concat([
    derTlv(0x30, Buffer.concat([
      derTlv(0x30, RSA_OID_DER),
      derTlv(0x03, Buffer.concat([Buffer.from([0x00]), asPkcs1(wellFormedModulus(64))])),
      derTlv(0x05, Buffer.alloc(0)),
    ])),
  ])).errors, ['unparseable-key']);
eq('a third INTEGER in the inner sequence is refused',
  asKey(derTlv(0x30, Buffer.concat([
    derTlv(0x30, RSA_OID_DER),
    derTlv(0x03, Buffer.concat([Buffer.from([0x00]), derTlv(0x30, Buffer.concat([
      derTlv(0x02, wellFormedModulus(64)), derTlv(0x02, EXPONENT), derTlv(0x02, EXPONENT),
    ]))])),
  ]))).errors, ['unparseable-key']);

/* ── Values, not only tags and boundaries ───────────────────────────────
   A field that is tagged INTEGER is not yet a modulus, and an OID is not yet
   an AlgorithmIdentifier. RFC 8017 §3.1 makes `n` and `e` positive integers
   with `e` between 3 and n-1; RFC 3279 §2.3.1 requires rsaEncryption's
   parameters to be ASN.1 NULL. Checking only the tags accepted a negative
   modulus, an empty exponent, and an AlgorithmIdentifier carrying arbitrary
   parameters — each returning a confident size for a key no implementation
   would use.
   ───────────────────────────────────────────────────────────────────── */
const rawInteger = buf => Buffer.from(buf);   // deliberately NOT sign-corrected
const pkcs1Of = (modulus, exponent) => derTlv(0x30, Buffer.concat([
  derTlv(0x02, modulus), derTlv(0x02, exponent === undefined ? EXPONENT : exponent),
]));
const spkiOf = (algorithm, modulus, exponent) => derTlv(0x30, Buffer.concat([
  algorithm,
  derTlv(0x03, Buffer.concat([Buffer.from([0x00]), pkcs1Of(modulus, exponent)])),
]));
const GOOD_MODULUS = wellFormedModulus(128);

// The control: everything below differs from this by one deliberate defect.
eq('the control key parses', asKey(pkcs1Of(GOOD_MODULUS)).keyBits, 1024);

// Modulus values.
eq('a negative modulus is refused',
  asKey(pkcs1Of(rawInteger(Buffer.concat([Buffer.from([0x80]), Buffer.alloc(127, 0xab)])))).errors,
  ['unparseable-key']);
eq('a non-minimally encoded modulus is refused',
  asKey(pkcs1Of(rawInteger(Buffer.concat([Buffer.from([0x00, 0x01]), Buffer.alloc(126, 0xab)])))).errors,
  ['unparseable-key']);
eq('a zero modulus is refused',  asKey(pkcs1Of(Buffer.from([0x00]))).errors, ['unparseable-key']);
eq('an empty modulus is refused', asKey(pkcs1Of(Buffer.alloc(0))).errors, ['unparseable-key']);

// Exponent values.
eq('an empty exponent is refused',    asKey(pkcs1Of(GOOD_MODULUS, Buffer.alloc(0))).errors, ['unparseable-key']);
eq('a zero exponent is refused',      asKey(pkcs1Of(GOOD_MODULUS, Buffer.from([0x00]))).errors, ['unparseable-key']);
eq('an exponent of 1 is refused',     asKey(pkcs1Of(GOOD_MODULUS, Buffer.from([0x01]))).errors, ['unparseable-key']);
eq('an even exponent is refused',     asKey(pkcs1Of(GOOD_MODULUS, Buffer.from([0x04]))).errors, ['unparseable-key']);
eq('a negative exponent is refused',  asKey(pkcs1Of(GOOD_MODULUS, rawInteger(Buffer.from([0x80, 0x01])))).errors, ['unparseable-key']);
// e must be less than n; a bit-length comparison is as far as that goes without
// bignum arithmetic, and it deliberately says nothing about the factors.
eq('an exponent wider than the modulus is refused',
  asKey(pkcs1Of(Buffer.from([0x03]), wellFormedModulus(128))).errors, ['unparseable-key']);
// 3 is the smallest legal exponent and must still be accepted.
eq('an exponent of 3 is accepted', asKey(pkcs1Of(GOOD_MODULUS, Buffer.from([0x03]))).keyBits, 1024);

// RFC 8017 §3.1 is `3 <= e < n`, and the upper half needs comparing values
// rather than widths. A bit-length test accepted `e == n` and any same-width
// `e > n`; both are conformant DER and neither is a usable key. No bignum
// arithmetic is needed — strip the sign octet, compare lengths, then octets.
const SIGNIFICANT = GOOD_MODULUS.subarray(GOOD_MODULUS[0] === 0x00 ? 1 : 0);
const sameWidth = mutate => {
  const e = Buffer.from(SIGNIFICANT); mutate(e);
  return (e[0] & 0x80) ? Buffer.concat([Buffer.from([0x00]), e]) : e;
};
eq('the exponent fixture really is the same width as the modulus',
  sameWidth(() => {}).length, GOOD_MODULUS.length);
eq('an exponent equal to the modulus is refused',
  asKey(pkcs1Of(GOOD_MODULUS, sameWidth(() => {}))).errors, ['unparseable-key']);
eq('a same-width exponent greater than the modulus is refused',
  asKey(pkcs1Of(GOOD_MODULUS, sameWidth(e => { e[e.length - 1] = 0xad; }))).errors, ['unparseable-key']);
eq('a difference in the LEADING octet is caught too',
  asKey(pkcs1Of(GOOD_MODULUS, sameWidth(e => { e[0] = 0x82; }))).errors, ['unparseable-key']);
// The control: same width, strictly smaller, still odd — this one must pass, or
// the comparison is rejecting valid keys rather than invalid ones.
eq('a same-width exponent below the modulus is accepted',
  asKey(pkcs1Of(GOOD_MODULUS, sameWidth(e => { e[0] = 0x7f; }))).keyBits, 1024);
/* ── Both RSA values must be odd ────────────────────────────────────────
   RFC 8017 §3.1 makes `n` a product of distinct odd primes, so an even modulus
   is not an RSA modulus at all — and `e` must be coprime to lambda(n), which is
   even. The exponent was checked from the start; the modulus was not, two lines
   away in the same function.

   These two moduli differ in exactly one bit, so nothing but parity can explain
   a difference in the verdict.
   ───────────────────────────────────────────────────────────────────── */
const withLastOctet = (modulus, octet) => {
  const m = Buffer.from(modulus); m[m.length - 1] = octet; return m;
};
const ODD_MODULUS = withLastOctet(GOOD_MODULUS, 0xad);
const EVEN_MODULUS = withLastOctet(GOOD_MODULUS, 0xac);
eq('the two fixtures differ only in the last octet',
  [ODD_MODULUS.length, EVEN_MODULUS.length,
    ODD_MODULUS.subarray(0, -1).equals(EVEN_MODULUS.subarray(0, -1))],
  [GOOD_MODULUS.length, GOOD_MODULUS.length, true]);

eq('an odd modulus is accepted',            asKey(pkcs1Of(ODD_MODULUS)).keyBits, 1024);
eq('an even modulus is refused',            asKey(pkcs1Of(EVEN_MODULUS)).errors, ['unparseable-key']);
eq('an odd modulus inside SPKI is accepted',
  asKey(spkiOf(derTlv(0x30, RSA_OID_DER), ODD_MODULUS)).keyBits, 1024);
eq('an even modulus inside SPKI is refused',
  asKey(spkiOf(derTlv(0x30, RSA_OID_DER), EVEN_MODULUS)).errors, ['unparseable-key']);
// The smallest even value that is otherwise well-formed, so the guard is not
// relying on the modulus being large.
eq('a small even modulus is refused too',
  asKey(pkcs1Of(Buffer.from([0x04]), Buffer.from([0x03]))).errors, ['unparseable-key']);

/* ── DER length octets must be minimal, at every level ──────────────────
   X.690 §10.1: the definite length uses the FEWEST possible octets. A leading
   zero is never the fewest, and neither is the long form for a value the short
   form can express. Accepting either let BER encodings through a walk this
   release calls authoritative DER, and gave one key two valid encodings.
   ───────────────────────────────────────────────────────────────────── */
// A deliberately non-minimal encoder: `octets` length bytes, whatever the size.
const longFormTlv = (tag, content, octets) => {
  const body = Buffer.from(content);
  const len = [];
  for (let i = 0, n = body.length; i < octets; i++, n >>= 8) len.unshift(n & 0xff);
  return Buffer.concat([Buffer.from([tag, 0x80 | octets]), Buffer.from(len), body]);
};
// 129 significant octets, so its own length legitimately needs the long form.
const LONG_MODULUS = wellFormedModulus(129);
const canonicalKey = derTlv(0x30, Buffer.concat([derTlv(0x02, LONG_MODULUS), derTlv(0x02, EXPONENT)]));

// The control: the same key, canonically encoded, must parse.
eq('a canonically encoded key parses', asKey(canonicalKey).keyBits, 1032);
// ...and its modulus really does need the long form, or the fixtures below
// would not be testing what they claim.
eq('the long modulus needs long-form length', LONG_MODULUS.length >= 0x80, true);

eq('long form for a short exponent length is refused',
  asKey(derTlv(0x30, Buffer.concat([derTlv(0x02, LONG_MODULUS), longFormTlv(0x02, EXPONENT, 1)]))).errors,
  ['unparseable-key']);
eq('a leading zero length octet on the modulus is refused',
  asKey(derTlv(0x30, Buffer.concat([longFormTlv(0x02, LONG_MODULUS, 2), derTlv(0x02, EXPONENT)]))).errors,
  ['unparseable-key']);
eq('a leading zero length octet on the outer sequence is refused',
  asKey(longFormTlv(0x30, Buffer.concat([derTlv(0x02, LONG_MODULUS), derTlv(0x02, EXPONENT)]), 2)).errors,
  ['unparseable-key']);
eq('long form inside the SPKI envelope is refused too',
  asKey(derTlv(0x30, Buffer.concat([
    derTlv(0x30, RSA_OID_DER),
    derTlv(0x03, Buffer.concat([Buffer.from([0x00]),
      derTlv(0x30, Buffer.concat([derTlv(0x02, LONG_MODULUS), longFormTlv(0x02, EXPONENT, 1)]))])),
  ]))).errors, ['unparseable-key']);

// The 127/128 boundary, where the short form stops being legal. Both controls
// must PASS, or the guard is rejecting canonical encodings rather than BER.
const shortBody = wellFormedModulus(126);   // < 128 octets: short form required
eq('a value at the short-form limit parses',
  asKey(derTlv(0x30, Buffer.concat([derTlv(0x02, shortBody), derTlv(0x02, EXPONENT)]))).keyBits, 1008);
eq('the short-form fixture is genuinely under 128 octets', shortBody.length < 0x80, true);
eq('a 128-octet value uses long form and parses',
  asKey(derTlv(0x30, Buffer.concat([derTlv(0x02, wellFormedModulus(128)), derTlv(0x02, EXPONENT)]))).keyBits, 1024);

// And the same rules inside the SPKI envelope.
eq('an exponent equal to the modulus inside SPKI is refused',
  asKey(spkiOf(derTlv(0x30, RSA_OID_DER), GOOD_MODULUS, sameWidth(() => {}))).errors, ['unparseable-key']);

// AlgorithmIdentifier parameters.
const RSA_OID_ONLY = Buffer.from([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
eq('rsaEncryption with NULL parameters is accepted',
  asKey(spkiOf(derTlv(0x30, RSA_OID_DER), GOOD_MODULUS)).keyBits, 1024);
eq('an algorithm with no parameters is refused',
  asKey(spkiOf(derTlv(0x30, RSA_OID_ONLY), GOOD_MODULUS)).errors, ['unparseable-key']);
eq('an algorithm with OCTET STRING parameters is refused',
  asKey(spkiOf(derTlv(0x30, Buffer.concat([RSA_OID_ONLY, derTlv(0x04, Buffer.from([0xaa]))])), GOOD_MODULUS)).errors,
  ['unparseable-key']);
eq('an algorithm with a non-empty NULL is refused',
  asKey(spkiOf(derTlv(0x30, Buffer.concat([RSA_OID_ONLY, derTlv(0x05, Buffer.from([0x00]))])), GOOD_MODULUS)).errors,
  ['unparseable-key']);
eq('an algorithm with content after NULL is refused',
  asKey(spkiOf(derTlv(0x30, Buffer.concat([RSA_OID_DER, derTlv(0x02, Buffer.from([0x01]))])), GOOD_MODULUS)).errors,
  ['unparseable-key']);

// The same value rules apply inside the SPKI envelope, not only bare PKCS#1.
eq('a negative modulus inside SPKI is refused',
  asKey(spkiOf(derTlv(0x30, RSA_OID_DER),
    rawInteger(Buffer.concat([Buffer.from([0x80]), Buffer.alloc(127, 0xab)])))).errors, ['unparseable-key']);
eq('an empty exponent inside SPKI is refused',
  asKey(spkiOf(derTlv(0x30, RSA_OID_DER), GOOD_MODULUS, Buffer.alloc(0))).errors, ['unparseable-key']);

// Where Web Crypto exists it must now agree with the walk rather than be the
// only thing that catches these.
const walkAndCrypto = await D.validateDkimKeyStructure(
  key(`v=DKIM1; p=${RSA_512}`), `v=DKIM1; p=${RSA_512}`);
eq('a real SPKI key is confirmed by both', [walkAndCrypto.keyBits, walkAndCrypto.cryptoValidated], [512, true]);

eq('t=y is testing',         key(`v=DKIM1; t=y; p=${RSA_2048}`).testing, true);
eq('t=y:s sets both flags',  [key(`v=DKIM1; t=y:s; p=${RSA_2048}`).testing, key(`v=DKIM1; t=y:s; p=${RSA_2048}`).strictSubdomain], [true, true]);
eq('t=s alone is not testing', key(`v=DKIM1; t=s; p=${RSA_2048}`).testing, false);
eq('h= splits on colon',     key(`v=DKIM1; h=sha256:sha1; p=${RSA_2048}`).hashAlgorithms, ['sha256', 'sha1']);
eq('s= splits on colon',     key(`v=DKIM1; s=email; p=${RSA_2048}`).serviceTypes, ['email']);
eq('n= is carried through',  key(`v=DKIM1; n=rotate me; p=${RSA_2048}`).notes, 'rotate me');
eq('unknown tags are listed', key(`v=DKIM1; g=*; p=${RSA_2048}`).unknownTags, ['g']);

// Folding whitespace is legal inside p= (RFC 6376 §3.2) and destroys the
// decode if it is not stripped first.
eq('whitespace inside p= survives',
  key(`v=DKIM1; k=rsa; p=${RSA_1024.slice(0, 40)} ${RSA_1024.slice(40)}`).keyBits, 1024);

// The base64 is case-sensitive. Anything that lowercases it destroys the key,
// which is why cleanAnswerData() must not be changed to do so.
eq('case-sensitive base64 is not normalized',
  key(`v=DKIM1; k=rsa; p=${RSA_2048.toLowerCase()}`).keyBits, null);

// Web Crypto never lowers a verdict: it confirms, or it says nothing.
eq('crypto is not attempted synchronously', key(`v=DKIM1; p=${RSA_2048}`).cryptoValidated, null);
const validated = await D.validateDkimKeyStructure(key(`v=DKIM1; p=${RSA_2048}`), `v=DKIM1; p=${RSA_2048}`);
eq('crypto confirms a good key',   validated.cryptoValidated, true);
eq('and adds no errors',           validated.errors, []);
eq('and leaves the size alone',    validated.keyBits, 2048);
// A revoked key has nothing to import, and must not come back marked invalid.
const revokedValidated = await D.validateDkimKeyStructure(key('v=DKIM1; p='), 'v=DKIM1; p=');
eq('a revoked key is not sent to crypto', revokedValidated.cryptoValidated, null);
eq('and stays valid',                     revokedValidated.valid, true);

// The base64 decode is the language and nothing else. This whole file runs
// with no `atob` in the sandbox, so a decoder that reached for it would report
// every key on every domain as unparseable — an assertion about our own
// environment wearing the clothes of an assertion about the operator's DNS.
eq('the sandbox really has no atob', typeof sandbox.atob, 'undefined');
// Exact byte lengths across the three padding cases, checked against Node's
// own base64 encoder rather than against a hand-written expectation.
eq('decoded lengths round-trip for every padding case',
  [0, 1, 2, 3, 61, 62, 63, 64, 255, 256].map(n =>
    D.analyzeDkimKey(`v=DKIM1; k=ed25519; p=${Buffer.from(Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff)).toString('base64')}`).keyBytes),
  [null, 1, 2, 3, 61, 62, 63, 64, 255, 256]);
// n=0 above is null rather than 0 on purpose: an empty p= is revocation, and
// the decoder is never reached.
eq('an empty p= never reaches the decoder', D.analyzeDkimKey('v=DKIM1; p=').revoked, true);

// Multi-string TXT reassembly, through the real cleanAnswerData path.
const split = D.dkimRecordSet([{ type: 16, data: `"v=DKIM1; k=rsa; p=${RSA_2048.slice(0, 120)}" "${RSA_2048.slice(120)}"` }]);
eq('a split TXT record rejoins', split.keys.length, 1);
eq('and the rejoined key parses', key(split.keys[0]).keyBits, 2048);

// dkimRecordSet separates the two questions dkimKeyRecords conflates.
const mixedSet = D.dkimRecordSet([
  { type: 16, data: `"v=DKIM1; p=${RSA_2048}"` },
  { type: 16, data: '"v=DKIM1; p="' },
  { type: 16, data: '"verification=abc"' },
]);
eq('usable keys are separated',   mixedSet.keys.length, 1);
eq('revoked records are kept',    mixedSet.revoked.length, 1);
eq('unrelated TXT is dropped',    mixedSet.keys.length + mixedSet.revoked.length, 2);
eq('dkimKeyRecords is unchanged', D.dkimKeyRecords([{ type: 16, data: '"v=DKIM1; p="' }]).length, 0);

// The domain-level rollup: strength, not algorithm.
eq('mixed strengths detected', D.summarizeDkimKeys([
  { key: key(`v=DKIM1; p=${RSA_1024}`) }, { key: key(`v=DKIM1; p=${RSA_2048}`) },
]).mixed, true);
eq('the weakest selector sets minBits', D.summarizeDkimKeys([
  { key: key(`v=DKIM1; p=${RSA_1024}`) }, { key: key(`v=DKIM1; p=${RSA_2048}`) },
]).minBits, 1024);
eq('equal strengths are not mixed', D.summarizeDkimKeys([
  { key: key(`v=DKIM1; p=${RSA_2048}`) }, { key: key(`v=DKIM1; p=${RSA_2048}`) },
]).mixed, false);
// RFC 8463 double-signing is the recommended migration, not a weakness.
eq('ed25519 alongside RSA is not "mixed"', D.summarizeDkimKeys([
  { key: key(`v=DKIM1; k=ed25519; p=${ED25519_32}`) }, { key: key(`v=DKIM1; p=${RSA_2048}`) },
]).mixed, false);
eq('but both algorithms are recorded', D.summarizeDkimKeys([
  { key: key(`v=DKIM1; k=ed25519; p=${ED25519_32}`) }, { key: key(`v=DKIM1; p=${RSA_2048}`) },
]).algorithms, ['ed25519', 'rsa']);

/* ── 35. Structured CAA (RFC 8659, RFC 9495) ─────────────────────────── */
section('35. Structured CAA');

const caaRec = D.parseCaaRecord('0 issue "letsencrypt.org"');
eq('flags parsed',   caaRec.flags, 0);
eq('tag parsed',     caaRec.tag, 'issue');
eq('value unquoted', caaRec.value, 'letsencrypt.org');
eq('tag is known',   caaRec.known, true);
eq('record is valid', caaRec.valid, true);

eq('tag is lowercased',    D.parseCaaRecord('0 ISSUE "pki.goog"').tag, 'issue');
eq('critical bit read',    D.parseCaaRecord('128 issue "pki.goog"').critical, true);
eq('flags 0 is not critical', D.parseCaaRecord('0 issue "pki.goog"').critical, false);
eq('flags 256 is rejected', D.parseCaaRecord('256 issue "pki.goog"').errors, ['bad-flags']);
eq('an unquoted value is named', D.parseCaaRecord('0 issue pki.goog').errors, ['unquoted-value']);
eq('but is still read',    D.parseCaaRecord('0 issue pki.goog').value, 'pki.goog');
eq('an embedded semicolon survives',
  D.parseCaaRecord('0 issue "ca.example; policy=ev"').value, 'ca.example; policy=ev');
eq('an unknown tag is marked',   D.parseCaaRecord('128 unknowntag "x"').known, false);
eq('RFC 9495 tags are known',    D.parseCaaRecord('0 issuemail "ca.example"').known, true);
eq('iodef is known',             D.parseCaaRecord('0 iodef "mailto:sec@example.com"').known, true);
eq('a one-field record is unparseable', D.parseCaaRecord('issue').errors, ['unparseable-record']);

// The two semantics that are easy to get wrong.
const blocked = D.summarizeCaa(['0 issue ";"']);
eq('an issue value of ; blocks all issuance', blocked.issuanceBlocked, true);
eq('and names no issuers',                    blocked.issuers, []);
const wildBlocked = D.summarizeCaa(['0 issue "letsencrypt.org"', '0 issuewild ";"']);
eq('issuewild ; blocks wildcards only',   wildBlocked.wildcardBlocked, true);
eq('while normal issuance continues',     wildBlocked.issuanceBlocked, false);
eq('and the issuer is still listed',      wildBlocked.issuers, ['letsencrypt.org']);
// An absent issuewild set means `issue` governs wildcards — NOT that wildcards
// are unrestricted. Reading it the other way inverts the policy.
const noWild = D.summarizeCaa(['0 issue "letsencrypt.org"']);
eq('an absent issuewild set is not "blocked"',   noWild.wildcardBlocked, false);
eq('and publishes no wildcard issuers of its own', noWild.wildcardIssuers, []);

const caaFull = D.summarizeCaa([
  '0 issue "letsencrypt.org"', '0 issue "pki.goog"',
  '0 iodef "mailto:sec@example.com"', '128 weirdtag "x"', 'garbage',
]);
eq('issuers collected',        caaFull.issuers, ['letsencrypt.org', 'pki.goog']);
eq('iodef collected',          caaFull.iodef, ['mailto:sec@example.com']);
eq('unknown critical flagged', caaFull.unknownCritical, ['weirdtag']);
eq('malformed keeps the raw text', caaFull.malformed, ['garbage']);
// Parameters after the issuer name are not part of the CA identity.
eq('issuer parameters are stripped',
  D.summarizeCaa(['0 issue "letsencrypt.org; validationmethods=dns-01"']).issuers, ['letsencrypt.org']);

/* ── A known tag promises a value grammar ───────────────────────────────
   RFC 8659 §4.2 uses `%%%%%` as its own example of a malformed issue value and
   requires a CA to treat it like an absent issuer-domain-name. Reading the text
   before the first semicolon as a CA identity reported the policy backwards:
   a domain that has blocked issuance was shown as authorizing a CA called
   `%%%%%`.
   ───────────────────────────────────────────────────────────────────── */
const malformedIssue = D.summarizeCaa(['0 issue "%%%%%"']);
eq('the RFC\'s own malformed example is not an issuer', malformedIssue.issuers, []);
eq('and it blocks issuance',                             malformedIssue.issuanceBlocked, true);
eq('and it is reported malformed',                       malformedIssue.malformed, ['0 issue "%%%%%"']);
eq('the record itself is invalid',                       malformedIssue.parsed[0].valid, false);
eq('and says why',                                       malformedIssue.parsed[0].errors, ['bad-issue-value']);
// issuewild has the same grammar and the same consequence.
eq('a malformed issuewild blocks wildcards',
  D.summarizeCaa(['0 issue "pki.goog"', '0 issuewild "%%%%%"']).wildcardBlocked, true);
// RFC 9495 §3 gives issuemail the same syntax.
eq('a malformed issuemail is invalid',
  D.summarizeCaa(['0 issuemail "%%%%%"']).parsed[0].errors, ['bad-issue-value']);

// NOT overcorrected: a malformed record alongside a valid one leaves the valid
// issuer authorized, because that record still matches the grammar.
const mixedCaa = D.summarizeCaa(['0 issue "%%%%%"', '0 issue "letsencrypt.org"']);
eq('a valid issuer survives a malformed sibling', mixedCaa.issuers, ['letsencrypt.org']);
eq('and issuance is not blocked',                 mixedCaa.issuanceBlocked, false);
eq('while the malformed record is still named',   mixedCaa.malformed, ['0 issue "%%%%%"']);

// Controls that must remain valid, or the grammar is rejecting real policies.
eq('a plain LDH issuer is valid',        D.summarizeCaa(['0 issue "letsencrypt.org"']).issuers, ['letsencrypt.org']);
eq('a hyphenated label is valid',        D.summarizeCaa(['0 issue "sectigo-ca.example"']).issuers, ['sectigo-ca.example']);
eq('a digit-leading label is valid',     D.summarizeCaa(['0 issue "1trust.example"']).issuers, ['1trust.example']);
eq('parameters are accepted',
  D.summarizeCaa(['0 issue "letsencrypt.org; validationmethods=dns-01"']).issuers, ['letsencrypt.org']);
eq('multiple parameters are accepted',
  D.summarizeCaa(['0 issue "ca.example; a=1; b=2"']).parsed[0].valid, true);
eq('a trailing semicolon with no parameters is valid',
  D.summarizeCaa(['0 issue "ca.example;"']).parsed[0].valid, true);
eq('an empty value still authorizes nobody, and is not malformed',
  [D.summarizeCaa(['0 issue ""']).issuanceBlocked, D.summarizeCaa(['0 issue ""']).malformed], [true, []]);
eq('a bare ";" is still the blocking form, not a malformed one',
  [D.summarizeCaa(['0 issue ";"']).issuanceBlocked, D.summarizeCaa(['0 issue ";"']).malformed], [true, []]);
// Grammar violations that must be caught.
eq('a trailing-hyphen label is refused',   D.summarizeCaa(['0 issue "ca-.example"']).parsed[0].valid, false);
eq('a leading-hyphen label is refused',    D.summarizeCaa(['0 issue "-ca.example"']).parsed[0].valid, false);
eq('an empty label is refused',            D.summarizeCaa(['0 issue "ca..example"']).parsed[0].valid, false);
eq('a parameter without "=" is refused',   D.summarizeCaa(['0 issue "ca.example; nope"']).parsed[0].valid, false);
eq('a space inside a parameter value is refused',
  D.summarizeCaa(['0 issue "ca.example; a=b c"']).parsed[0].valid, false);

// RFC 8659 §4.4: iodef takes mailto, http or https and nothing else.
eq('an ftp iodef is refused',      D.summarizeCaa(['0 iodef "ftp://x.example"']).parsed[0].errors, ['bad-iodef-url']);
eq('a scheme-less iodef is refused', D.summarizeCaa(['0 iodef "x.example"']).parsed[0].valid, false);
eq('a mailto iodef is valid',      D.summarizeCaa(['0 iodef "mailto:sec@example.com"']).parsed[0].valid, true);
eq('an https iodef is valid',      D.summarizeCaa(['0 iodef "https://example.com/r"']).parsed[0].valid, true);
eq('an http iodef is valid',       D.summarizeCaa(['0 iodef "http://example.com/r"']).parsed[0].valid, true);
// Deliberately unvalidated — RFC 9495 §4/§5 define these loosely enough that a
// false "malformed" on a real record would be worse than no check.
eq('contactemail is not grammar-checked',  D.summarizeCaa(['0 contactemail "anything at all"']).parsed[0].valid, true);
eq('contactphone is not grammar-checked',  D.summarizeCaa(['0 contactphone "+1 555 0100"']).parsed[0].valid, true);

sandbox.fetch = dohFixture({ 'caa.example CAA': caa('0 issue "letsencrypt.org"') });
const caaWalk = await D.checkCAA('caa.example', { retries: 0, noCache: true });
eq('checkCAA keeps its original shape', [caaWalk.found, caaWalk.atDomain], [true, 'caa.example']);
eq('and gains the parsed set',          caaWalk.issuers, ['letsencrypt.org']);
eq('and the raw records still',         caaWalk.records, ['0 issue "letsencrypt.org"']);
// The climb is unchanged: RFC 8659 §3 stops at the first name with any record.
sandbox.fetch = dohFixture({ 'parent.example CAA': caa('0 issue "pki.goog"') });
const climbed = await D.checkCAA('sub.parent.example', { retries: 0, noCache: true });
eq('CAA is still inherited from the parent', climbed.atDomain, 'parent.example');
eq('and the parent policy is parsed',        climbed.issuers, ['pki.goog']);

/* ── 36. MX health (DNS only, no SMTP) ───────────────────────────────── */
section('36. MX health');

eq('an MX record splits into preference and host',
  D.parseMxRecord('10 mail.example.com.'), { preference: 10, host: 'mail.example.com' });
eq('a malformed MX record is dropped', D.parseMxRecord('mail.example.com'), null);

const MX_FIXTURE = {
  'good.example A': a('203.0.113.10'),
  'good.example AAAA': aaaa('2001:db8::10'),
  'good.example CNAME': 'nodata',
  'dead.example A': 'nxdomain',
  'dead.example AAAA': 'nxdomain',
  'dead.example CNAME': 'nxdomain',
  'aliased.example CNAME': cname('real.example.'),
  'aliased.example A': a('203.0.113.20'),
  'aliased.example AAAA': 'nodata',
};
sandbox.fetch = dohFixture(MX_FIXTURE);
const mxAudit = await D.auditMxHosts(
  ['10 good.example.', '20 dead.example.', '30 aliased.example.'],
  'example.com', { retries: 0, noCache: true });

eq('every MX host is audited',   mxAudit.hosts.length, 3);
eq('a resolving host says yes',  mxAudit.hosts[0].resolves, 'yes');
eq('a dangling host is named',   mxAudit.danglingHosts, ['dead.example']);
eq('a CNAME target is named',    mxAudit.cnameHosts, ['aliased.example']);
// RFC 2181 §10.3 forbids it, but the A record behind the alias still resolves,
// so the host is reachable and must not also be reported as dangling.
eq('a CNAME target still resolves', mxAudit.hosts[2].resolves, 'yes');
eq('IPv6 coverage is partial',   mxAudit.ipv6Coverage, 'some');
eq('three hosts is not a single point', mxAudit.singleHost, false);
eq('nothing is unknown here',    mxAudit.unknown, false);

sandbox.fetch = dohFixture({
  'only.example A': a('198.51.100.5'), 'only.example AAAA': 'nodata', 'only.example CNAME': 'nodata',
});
const single = await D.auditMxHosts(['10 only.example.'], 'example.com', { retries: 0, noCache: true });
eq('a lone MX host is a single point of failure', single.singleHost, true);
eq('and IPv4-only reads as no IPv6',              single.ipv6Coverage, 'none');

// Concentration: three hosts, one /24. The prefix label is what the operator
// has to go and look at, so it is reported rather than a bare count.
sandbox.fetch = dohFixture({
  'a.example A': a('203.0.113.10'), 'a.example AAAA': 'nodata', 'a.example CNAME': 'nodata',
  'b.example A': a('203.0.113.11'), 'b.example AAAA': 'nodata', 'b.example CNAME': 'nodata',
  'c.example A': a('198.51.100.9'), 'c.example AAAA': 'nodata', 'c.example CNAME': 'nodata',
});
const prefixes = await D.auditMxHosts(
  ['10 a.example.', '20 b.example.', '30 c.example.'], 'example.com', { retries: 0, noCache: true });
eq('one shared /24 is reported', prefixes.sharedPrefixes.length, 1);
eq('the prefix is named',        prefixes.sharedPrefixes[0].prefix, '203.0.113.0/24');
eq('with the hosts inside it',   prefixes.sharedPrefixes[0].hosts, ['a.example', 'b.example']);
// The host in a different /24 is not swept into the group.
eq('an unrelated host is left out', prefixes.sharedPrefixes[0].hosts.includes('c.example'), false);

sandbox.fetch = dohFixture({
  'p1.example A': a('203.0.113.10'), 'p1.example AAAA': 'nodata', 'p1.example CNAME': 'nodata',
  'p2.example A': a('198.51.100.10'), 'p2.example AAAA': 'nodata', 'p2.example CNAME': 'nodata',
});
const dupes = await D.auditMxHosts(['10 p1.example.', '10 p2.example.'], 'example.com', { retries: 0, noCache: true });
eq('duplicate preferences are reported', dupes.duplicatePreferences, [10]);

// A SERVFAIL on one host must degrade that host and leave the others intact —
// and must never let an unchecked host be counted as dangling.
sandbox.fetch = dohFixture({
  'ok.example A': a('203.0.113.10'), 'ok.example AAAA': 'nodata', 'ok.example CNAME': 'nodata',
  'flaky.example A': 'servfail', 'flaky.example AAAA': 'servfail', 'flaky.example CNAME': 'servfail',
});
const flakyMx = await D.auditMxHosts(['10 ok.example.', '20 flaky.example.'], 'example.com', { retries: 0, noCache: true });
eq('the healthy host still reports',      flakyMx.hosts[0].resolves, 'yes');
eq('the failed host is unknown',          flakyMx.hosts[1].resolves, 'unknown');
eq('an unknown host is NOT dangling',     flakyMx.danglingHosts, []);
eq('and the audit says it is incomplete', flakyMx.unknown, true);

// Two MX records naming the same exchange are ONE delivery target: one point
// of failure, one set of lookups, one row. Mapping records straight to audits
// queried it twice, counted it twice, and suppressed `mx-single-host` on a
// domain that has exactly one host.
sandbox.fetch = dohFixture({
  'dup.example A': a('203.0.113.10'), 'dup.example AAAA': 'nodata', 'dup.example CNAME': 'nodata',
});
const dupTarget = await D.auditMxHosts(
  ['10 dup.example.', '20 dup.example.'], 'example.com', { retries: 0, noCache: true });
eq('one exchange at two preferences is one host',  dupTarget.hosts.length, 1);
eq('and is still a single point of failure',       dupTarget.singleHost, true);
eq('and both preferences survive as evidence',     dupTarget.hosts[0].preferences, [10, 20]);
eq('and the host is described by the preferred one', dupTarget.hosts[0].preference, 10);
eq('and it is queried once per type, not twice',   sandbox.fetch.calls.length, 3);
eq('the finding names the single host',
  D.buildIssues({ emailProvider: 'X', spfStatus: { status: 'ok', warnings: [] },
    dkimStatus: { found: false, selectors: [], confidence: 'observed' },
    dmarcStatus: { status: 'ok', policy: 'reject', warnings: [] }, reportPlan: { external: [] },
    externalReportDestinations: [], advanced: { mxHealth: dupTarget }, domain: 'example.com',
  }).filter(i => i.key === 'mx-single-host').length, 1);
// Trailing-dot and case differences are the same name, so they are one target.
sandbox.fetch = dohFixture({
  'mixed.example A': a('203.0.113.11'), 'mixed.example AAAA': 'nodata', 'mixed.example CNAME': 'nodata',
});
eq('case and trailing dot do not split a target',
  (await D.auditMxHosts(['10 Mixed.Example.', '20 mixed.example'], 'example.com',
    { retries: 0, noCache: true })).hosts.length, 1);
// Two genuinely different hosts stay two, or the deduplication is too eager.
sandbox.fetch = dohFixture({
  'x1.example A': a('203.0.113.20'), 'x1.example AAAA': 'nodata', 'x1.example CNAME': 'nodata',
  'x2.example A': a('198.51.100.20'), 'x2.example AAAA': 'nodata', 'x2.example CNAME': 'nodata',
});
const twoTargets = await D.auditMxHosts(
  ['10 x1.example.', '20 x2.example.'], 'example.com', { retries: 0, noCache: true });
eq('two distinct hosts remain two',       twoTargets.hosts.length, 2);
eq('and are not a single point',          twoTargets.singleHost, false);
eq('and each carries one preference',
  twoTargets.hosts.map(h => h.preferences), [[10], [20]]);
// Duplicate PREFERENCES are about the records, not the targets, so a repeated
// host at one preference is still reported as a duplicate preference.
sandbox.fetch = dohFixture({
  'same.example A': a('203.0.113.30'), 'same.example AAAA': 'nodata', 'same.example CNAME': 'nodata',
});
eq('duplicate preferences are still counted from the records',
  (await D.auditMxHosts(['10 same.example.', '10 same.example.'], 'example.com',
    { retries: 0, noCache: true })).duplicatePreferences, [10]);

// A null MX never reaches this function, but an empty list must not throw.
eq('no MX records is not an error', (await D.auditMxHosts([], 'example.com', { retries: 0, noCache: true })).hosts, []);

/* ── 37. TLSA and DANE (RFC 6698, RFC 7671) ──────────────────────────── */
section('37. TLSA published, not yet qualified');

// The parenthesised uppercase shape the resolver actually returns. A parser
// written for the DS shape splits this to ['3','1','1','('] and reads the
// association data as an empty string, raising no error at all.
const tlsaRec = D.parseTlsaRecord('3 1 1 ( 13815B2C03F7BD63C54869706428442EDAB706D5B018A27575CA989129A196D5 )');
eq('usage parsed',         tlsaRec.usage, 3);
eq('selector parsed',      tlsaRec.selector, 1);
eq('matching type parsed', tlsaRec.matchingType, 1);
eq('parentheses stripped', tlsaRec.data, '13815b2c03f7bd63c54869706428442edab706d5b018a27575ca989129a196d5');
eq('the digest is 32 bytes', tlsaRec.data.length / 2, 32);
eq('the record is valid',  tlsaRec.valid, true);

// The same record without parentheses, as DS would come back. Both must work,
// because nothing guarantees the resolver keeps its current formatting.
eq('an unparenthesised record parses too',
  D.parseTlsaRecord('3 1 1 13815B2C03F7BD63C54869706428442EDAB706D5B018A27575CA989129A196D5').data,
  tlsaRec.data);
eq('a 3 0 1 record parses', D.parseTlsaRecord('3 0 1 ( ' + 'AB'.repeat(32) + ' )').valid, true);
eq('SHA-512 wants 64 bytes', D.parseTlsaRecord('3 1 2 ( ' + 'AB'.repeat(64) + ' )').valid, true);
eq('a short SHA-256 digest is flagged',
  D.parseTlsaRecord('3 1 1 ( ABCD )').errors, ['bad-digest-length']);
// Matching type 0 is the full certificate, of no fixed length.
eq('matching type 0 accepts any length',
  D.parseTlsaRecord('3 1 0 ( ' + 'AB'.repeat(200) + ' )').valid, true);
eq('usage 4 is out of range',    D.parseTlsaRecord('4 1 1 ( ' + 'AB'.repeat(32) + ' )').errors, ['bad-usage']);
eq('selector 2 is out of range', D.parseTlsaRecord('3 2 1 ( ' + 'AB'.repeat(32) + ' )').errors, ['bad-selector']);
eq('matching type 3 is out of range',
  D.parseTlsaRecord('3 1 3 ( ' + 'AB'.repeat(32) + ' )').errors, ['bad-matching-type']);
eq('non-hex data is flagged',
  D.parseTlsaRecord('3 1 1 ( ZZZZ )').errors, ['bad-association-data']);
eq('an empty record is unparseable', D.parseTlsaRecord('').errors, ['unparseable-record']);

// The wrapper is either absent or one balanced pair. Stripping each side
// independently accepted both halves of a broken record, which defeats the
// syntactic contract of a parser written for exactly this presentation form.
eq('an opening parenthesis with no close is refused',
  D.parseTlsaRecord('3 1 1 ( ' + 'AB'.repeat(32)).errors, ['unbalanced-parentheses']);
eq('a closing parenthesis with no open is refused',
  D.parseTlsaRecord('3 1 1 ' + 'AB'.repeat(32) + ' )').errors, ['unbalanced-parentheses']);
eq('an unbalanced record reports no digest',
  D.parseTlsaRecord('3 1 1 ( ' + 'AB'.repeat(32)).data, '');
eq('a lone opening parenthesis is refused',
  D.parseTlsaRecord('3 1 1 (').errors, ['unbalanced-parentheses']);
// Both controls must still pass, or the check is rejecting real records.
eq('a balanced pair is still accepted',
  D.parseTlsaRecord('3 1 1 ( ' + 'AB'.repeat(32) + ' )').valid, true);
eq('no parentheses at all is still accepted',
  D.parseTlsaRecord('3 1 1 ' + 'AB'.repeat(32)).valid, true);
eq('an empty balanced pair fails on its data, not its wrapper',
  D.parseTlsaRecord('3 1 1 ( )').errors, ['bad-association-data']);

const DIGEST = 'A6EB48052B5A83AA9D40E71CEAA20F6818C3A632D3B182A6246501B64D63724D';
sandbox.fetch = dohFixture({
  '_25._tcp.signed.example TLSA': { answers: tlsa(`3 1 1 ( ${DIGEST} )`), ad: true },
  '_25._tcp.unsigned.example TLSA': { answers: tlsa(`3 1 1 ( ${DIGEST} )`), ad: false },
  '_25._tcp.bare.example TLSA': 'nxdomain',
});
const tlsaResult = await D.checkTlsa(
  ['signed.example', 'unsigned.example', 'bare.example'], { retries: 0, noCache: true });
eq('TLSA is found where published',   tlsaResult.hosts[0].present, true);
eq('and the digest survives the query', tlsaResult.hosts[0].records[0].data, DIGEST.toLowerCase());
eq('a signed answer is authenticated', tlsaResult.hosts[0].authenticated, true);
eq('an unsigned answer is not',        tlsaResult.hosts[1].authenticated, false);
eq('a host without TLSA is absent',    tlsaResult.hosts[2].present, false);
eq('anyPresent is true',               tlsaResult.anyPresent, true);
eq('unauthenticated hosts are named',  tlsaResult.unauthenticatedHosts, ['unsigned.example']);
// Acceptance criterion 4: nothing in this release may claim DANE is active.
eq('qualified is false even when every host is signed', tlsaResult.qualified, false);
eq('and stays false with a fully signed set',
  (await D.checkTlsa(['signed.example'], { retries: 0, noCache: true })).qualified, false);
eq('a fully signed set is recorded as such',
  (await D.checkTlsa(['signed.example'], { retries: 0, noCache: true })).allAuthenticated, true);

// A TLSA query commonly returns a CNAME alongside the records — pointing
// _25._tcp.<host> at a shared _dane.<zone> name is ordinary practice. Handing
// that CNAME to the record parser reports a malformed TLSA on a healthy host.
sandbox.fetch = dohFixture({
  '_25._tcp.dane.example TLSA': {
    answers: [...cname('_dane.example.'), ...tlsa(`3 1 1 ( ${DIGEST} )`)], ad: true,
  },
});
const withCname = await D.checkTlsa(['dane.example'], { retries: 0, noCache: true });
eq('the CNAME in the answer set is filtered out', withCname.hosts[0].records.length, 1);
eq('and nothing is reported malformed',
  withCname.hosts[0].records.every(r => r.valid), true);

sandbox.fetch = dohFixture({ '_25._tcp.flaky.example TLSA': 'servfail' });
const tlsaFlaky = await D.checkTlsa(['flaky.example'], { retries: 0, noCache: true });
eq('a failed TLSA lookup is unknown',    tlsaFlaky.hosts[0].unknown, true);
eq('and is never reported as absent',    tlsaFlaky.hosts[0].authenticated, null);
eq('and the result says so',             tlsaFlaky.unknown, true);

/* ── 38. The findings these analyzers produce ────────────────────────── */
section('38. Advisory findings from the new analyzers');

const findings = (parts) => D.buildIssues(Object.assign({
  emailProvider: 'Google Workspace',
  spfStatus: { status: 'ok', cls: 'ok', warnings: [] },
  dkimStatus: { found: true, selectors: [], testedSelectors: ['s1'], failedSelectors: [], duplicated: [], revokedSelectors: [], confidence: 'observed' },
  dmarcStatus: { status: 'ok', cls: 'ok', policy: 'reject', warnings: [] },
  dmarcDiscovery: null, dmarcExistence: 'yes', externalReportDestinations: [],
  reportPlan: { external: [] }, wildcardApex: false, wildcardDkim: false,
  hosting: '@custom', advanced: {}, domain: 'example.com',
}, parts));
const keysOf = (parts) => findings(parts).map(i => i.key);
const sevOf = (parts, k) => (findings(parts).find(i => i.key === k) || {}).sev;

const sel = (name, value) => ({ sel: name, key: key(value) });
const dkimWith = (...selectors) => ({
  dkimStatus: {
    found: true, selectors, testedSelectors: [], failedSelectors: [], duplicated: [],
    revokedSelectors: [], confidence: 'observed', keyProfile: D.summarizeDkimKeys(selectors),
  },
});

eq('a sub-1024 key is critical', sevOf(dkimWith(sel('s1', `v=DKIM1; p=${RSA_512}`)), 'dkim-key-weak'), 'crit');
eq('and names the selector and size',
  findings(dkimWith(sel('s1', `v=DKIM1; p=${RSA_512}`))).find(i => i.key === 'dkim-key-weak').args, ['s1 (512)']);
// OQ-DEPTH-05: 53% of real keys are RSA-1024, so a warning here would fire on
// most audited domains and teach people to ignore the critical line above.
eq('a 1024-bit key is informational, not a warning',
  sevOf(dkimWith(sel('s1', `v=DKIM1; p=${RSA_1024}`)), 'dkim-key-1024'), 'info');
// The size fix carried into the findings: `dkim-key-weak` is critical below
// 1024 and `dkim-key-1024` is informational at exactly 1024, so a modulus
// reported by byte width rather than bit length crossed the boundary the wrong
// way. Helpers come from section 34.
const bitsFinding = buf => keysOf(dkimWith(sel('s1', `v=DKIM1; k=rsa; p=${Buffer.from(buf).toString('base64')}`)))
  .filter(k => k === 'dkim-key-weak' || k === 'dkim-key-1024');
eq('a 1017-bit key is critical, not informational', bitsFinding(asPkcs1(modulusOf(128, 0x01))), ['dkim-key-weak']);
eq('a 1023-bit key is critical too',                bitsFinding(asPkcs1(modulusOf(128, 0x7f))), ['dkim-key-weak']);
eq('a 1024-bit key is informational',               bitsFinding(asPkcs1(modulusOf(128, 0x80))), ['dkim-key-1024']);
eq('the same holds through the SPKI envelope',      bitsFinding(asSpki(modulusOf(128, 0x01))), ['dkim-key-weak']);

eq('a 2048-bit key raises nothing',
  keysOf(dkimWith(sel('s1', `v=DKIM1; p=${RSA_2048}`))).filter(k => k.startsWith('dkim-key')), []);
eq('selectors are grouped onto one line',
  findings(dkimWith(sel('a', `v=DKIM1; p=${RSA_1024}`), sel('b', `v=DKIM1; p=${RSA_1024}`)))
    .filter(i => i.key === 'dkim-key-1024').length, 1);
eq('mixed strengths are reported with both sizes',
  findings(dkimWith(sel('a', `v=DKIM1; p=${RSA_1024}`), sel('b', `v=DKIM1; p=${RSA_2048}`)))
    .find(i => i.key === 'dkim-key-mixed').args, [1024, 2048]);
eq('a testing key is informational', sevOf(dkimWith(sel('s1', `v=DKIM1; t=y; p=${RSA_2048}`)), 'dkim-key-testing'), 'info');
eq('an unparseable key warns', sevOf(dkimWith(sel('s1', `v=DKIM1; p=${RSA_2048.slice(0, 100)}`)), 'dkim-key-unparseable'), 'warn');
eq('h=sha1 alone warns', sevOf(dkimWith(sel('s1', `v=DKIM1; h=sha1; p=${RSA_2048}`)), 'dkim-key-sha1'), 'warn');
// A verifier offered both can pick SHA-256, so the list is not a finding.
eq('h=sha256:sha1 does not warn',
  keysOf(dkimWith(sel('s1', `v=DKIM1; h=sha256:sha1; p=${RSA_2048}`))).includes('dkim-key-sha1'), false);
eq('a revoked selector warns', sevOf({
  dkimStatus: { found: true, selectors: [], testedSelectors: [], failedSelectors: [], duplicated: [], confidence: 'observed', revokedSelectors: [{ sel: 'old', queryName: 'old._domainkey.example.com', value: 'v=DKIM1; p=' }] },
}, 'dkim-key-revoked'), 'warn');
// A browser without Web Crypto has said nothing about the key. It must never
// end up in the unparseable line.
const uncheckable = key(`v=DKIM1; p=${RSA_2048}`);
eq('an unvalidated key is not reported broken',
  keysOf(dkimWith({ sel: 's1', key: uncheckable })).includes('dkim-key-unparseable'), false);

const caaAdv = summary => ({ advanced: { caa: Object.assign({ found: true, atDomain: 'example.com', records: [] }, summary) } });
eq('blocked issuance warns',
  sevOf(caaAdv(D.summarizeCaa(['0 issue ";"'])), 'caa-blocks-all-issuance'), 'warn');
eq('an unknown critical tag warns',
  sevOf(caaAdv(D.summarizeCaa(['0 issue "pki.goog"', '128 weird "x"'])), 'caa-unknown-critical-tag'), 'warn');
eq('a malformed record warns',
  sevOf(caaAdv(D.summarizeCaa(['0 issue "pki.goog"', 'garbage'])), 'caa-malformed'), 'warn');
eq('a missing iodef is informational',
  sevOf(caaAdv(D.summarizeCaa(['0 issue "pki.goog"'])), 'caa-no-iodef'), 'info');
eq('a single issuer is informational',
  sevOf(caaAdv(D.summarizeCaa(['0 issue "pki.goog"'])), 'caa-single-issuer'), 'info');
// issue + issuewild for the same CA is one issuer, not two.
eq('issue and issuewild for one CA is still a single issuer',
  keysOf(caaAdv(D.summarizeCaa(['0 issue "pki.goog"', '0 issuewild "pki.goog"']))).includes('caa-single-issuer'), true);
eq('two issuers raise nothing',
  keysOf(caaAdv(D.summarizeCaa(['0 issue "pki.goog"', '0 issue "letsencrypt.org"']))).includes('caa-single-issuer'), false);
eq('a blocked policy is not also "single issuer"',
  keysOf(caaAdv(D.summarizeCaa(['0 issue ";"']))).includes('caa-single-issuer'), false);
// No CAA at all is a suggestion, not a policy finding.
eq('an absent CAA set raises no policy findings',
  keysOf({ advanced: { caa: { found: false, records: [], atDomain: null } } }).filter(k => k.startsWith('caa-')), []);

const mxAdv = health => ({ advanced: { mxHealth: health } });
eq('a dangling MX host is critical', sevOf(mxAdv(mxAudit), 'mx-dangling'), 'crit');
eq('and names the host',            findings(mxAdv(mxAudit)).find(i => i.key === 'mx-dangling').args, ['dead.example']);
eq('a CNAME MX target warns',       sevOf(mxAdv(mxAudit), 'mx-cname-target'), 'warn');
eq('a single MX host is informational', sevOf(mxAdv(single), 'mx-single-host'), 'info');
eq('no IPv6 is informational',      sevOf(mxAdv(single), 'mx-no-ipv6'), 'info');
eq('a shared prefix is informational', sevOf(mxAdv(prefixes), 'mx-same-prefix'), 'info');
eq('and names the prefix',          findings(mxAdv(prefixes)).find(i => i.key === 'mx-same-prefix').args[0], '203.0.113.0/24');
eq('duplicate preferences are informational', sevOf(mxAdv(dupes), 'mx-duplicate-preference'), 'info');
// The whole point of the resilience work: a host we could not check must never
// be reported as an outage.
eq('an unchecked host raises no dangling finding',
  keysOf(mxAdv(flakyMx)).includes('mx-dangling'), false);
eq('but the audit says which check was incomplete',
  findings(mxAdv(flakyMx)).find(i => i.key === 'checks-unverified').args, ['MX']);

eq('an unsigned TLSA record warns', sevOf({ advanced: { tlsa: tlsaResult } }, 'tlsa-published-unsigned'), 'warn');
eq('and names only the unsigned host',
  findings({ advanced: { tlsa: tlsaResult } }).find(i => i.key === 'tlsa-published-unsigned').args, ['unsigned.example']);
// The finding that would have shipped wrong: gating on `qualified` alone fires
// on every domain, telling a correctly signed zone its DANE is unprotected.
eq('a fully signed TLSA set raises no unsigned warning',
  keysOf({ advanced: { tlsa: await D.checkTlsa(['signed.example'], { retries: 0, noCache: true }) } })
    .includes('tlsa-published-unsigned'), false);
eq('partial coverage is informational',
  sevOf({ advanced: { tlsa: tlsaResult } }, 'tlsa-partial-coverage'), 'info');
eq('and counts only the hosts checked',
  findings({ advanced: { tlsa: tlsaResult } }).find(i => i.key === 'tlsa-partial-coverage').args, [2, 3]);

sandbox.fetch = dohFixture({
  '_25._tcp.bad.example TLSA': { answers: tlsa('3 1 1 ( ABCD )'), ad: true },
});
eq('a malformed TLSA record warns',
  sevOf({ advanced: { tlsa: await D.checkTlsa(['bad.example'], { retries: 0, noCache: true }) } }, 'tlsa-malformed'), 'warn');

/* ── 39. Deep checks through analyzeDomain ───────────────────────────── */
section('39. Deep protocol checks through analyzeDomain');

const DEEP = {
  'depth.example NS': ns('ns1.depth.example.'),
  'depth.example MX': mx('10 mail.depth.example.', '20 dead.depth.example.'),
  'depth.example TXT': txt('v=spf1 -all'),
  'depth.example A': a('203.0.113.5'),
  'depth.example AAAA': 'nodata',
  'depth.example CAA': caa('0 issue "letsencrypt.org"'),
  '_dmarc.depth.example TXT': txt('v=DMARC1; p=reject; rua=mailto:d@depth.example'),
  'mail.depth.example A': a('203.0.113.25'),
  'mail.depth.example AAAA': 'nodata',
  'mail.depth.example CNAME': 'nodata',
  'dead.depth.example A': 'nxdomain',
  'dead.depth.example AAAA': 'nxdomain',
  'dead.depth.example CNAME': 'nxdomain',
  '_25._tcp.mail.depth.example TLSA': { answers: tlsa(`3 1 1 ( ${DIGEST} )`), ad: true },
};

// One fixture across both runs, so the second audit's query count is measured
// on the same `calls` array — and, because dohFetch's cache is module-level and
// already warm from the first run, what it counts is exactly the queries the
// toggle adds. That number is what PRIVACY.md has to state.
sandbox.fetch = dohFixture(DEEP);
const deepOff = await D.analyzeDomain('depth.example', { dkim: false, advanced: true, retries: 0 });
eq('deep checks are off unless asked for', deepOff.advanced.mxHealth, null);
eq('and TLSA is not queried at all',       deepOff.advanced.tlsa, null);
eq('no TLSA query is issued',              sandbox.fetch.callsFor('TLSA').length, 0);
// CAA parsing is free — it reads records the audit already fetched — so it
// must work with the deep checks switched off.
eq('CAA is still parsed with deep checks off', deepOff.advanced.caa.issuers, ['letsencrypt.org']);

const queriesWithout = sandbox.fetch.calls.length;
const deepOn = await D.analyzeDomain('depth.example', { dkim: false, advanced: true, deepChecks: true, retries: 0 });
eq('MX health runs',                deepOn.advanced.mxHealth.hosts.length, 2);
eq('the dead MX host is found',     deepOn.advanced.mxHealth.danglingHosts, ['dead.depth.example']);
eq('and reported as critical',      deepOn.issues.find(i => i.key === 'mx-dangling').sev, 'crit');
eq('TLSA runs for every MX host',   deepOn.advanced.tlsa.hosts.length, 2);
eq('and finds the published record', deepOn.advanced.tlsa.anyPresent, true);
eq('DANE is never called qualified', deepOn.advanced.tlsa.qualified, false);
// The measured cost of the toggle, which PRIVACY.md has to state.
eq('deep checks cost 3 queries per MX host plus 1 TLSA each',
  sandbox.fetch.calls.length - queriesWithout, 8);

// A null MX has declared it accepts no mail: there is no host to resolve.
sandbox.fetch = dohFixture({
  'nomail.example NS': ns('ns1.nomail.example.'),
  'nomail.example MX': mx('0 .'),
  'nomail.example TXT': txt('v=spf1 -all'),
  'nomail.example A': a('203.0.113.5'),
  'nomail.example AAAA': 'nodata',
});
const nullMx = await D.analyzeDomain('nomail.example', { dkim: false, advanced: true, deepChecks: true, retries: 0 });
eq('a null MX skips the deep checks', nullMx.advanced.mxHealth, null);
eq('and issues no TLSA query',        sandbox.fetch.callsFor('TLSA').length, 0);

// Acceptance criterion 5: nothing here may move a grade.
eq('the deep checks change no score', deepOn.score.total, deepOff.score.total);
eq('and no grade',                    deepOn.score.grade, deepOff.score.grade);

// Every finding this release can emit must have English text behind it. The
// guard in section 22 only walks DMARC-shaped records, so the DKIM key, CAA,
// MX and TLSA findings would have slipped past it — a finding with no locale
// entry renders as its own key, which is how a 124-key gap once survived for
// months.
sandbox.fetch = dohFixture({
  '_25._tcp.bad.example TLSA': { answers: tlsa('3 1 1 ( ABCD )'), ad: true },
});
const malformedTlsaResult = await D.checkTlsa(['bad.example'], { retries: 0, noCache: true });
const depthEmitted = new Set([
  ...keysOf(dkimWith(sel('a', `v=DKIM1; p=${RSA_512}`), sel('b', `v=DKIM1; t=y; h=sha1; p=${RSA_1024}`))),
  ...keysOf(dkimWith(sel('c', `v=DKIM1; p=${RSA_2048.slice(0, 100)}`))),
  ...keysOf({ dkimStatus: { found: true, selectors: [], testedSelectors: [], failedSelectors: [], duplicated: [], confidence: 'observed', revokedSelectors: [{ sel: 'old', queryName: 'old._domainkey.example.com', value: 'v=DKIM1; p=' }] } }),
  ...keysOf(caaAdv(D.summarizeCaa(['0 issue ";"', '128 weird "x"', 'garbage']))),
  ...keysOf(caaAdv(D.summarizeCaa(['0 issue "pki.goog"']))),
  ...keysOf(mxAdv(mxAudit)), ...keysOf(mxAdv(single)),
  ...keysOf(mxAdv(prefixes)), ...keysOf(mxAdv(dupes)), ...keysOf(mxAdv(flakyMx)),
  ...keysOf({ advanced: { tlsa: tlsaResult } }),
  ...keysOf({ advanced: { tlsa: malformedTlsaResult } }),
]);
eq('every finding in this release has English text',
  [...depthEmitted].filter(k => !enIssues[k]), []);
// And the set actually covers what was built, rather than passing by emitting
// nothing at all.
eq('the guard exercises all 21 new findings',
  [...depthEmitted].filter(k => /^(dkim-key|caa-|mx-|tlsa-)/.test(k)).length, 21);

/* ── 40. Conflicting SPF records keep their evidence ─────────────────── */
section('40. Multiple SPF records are reported WITH the records');

// Reported from the field against splunk.com, which really does publish two
// v=spf1 records. The permerror was correct; the panel beside it showed one
// perfectly valid record, because every match after the first was discarded
// here and existed nowhere in the result. A critical finding with its evidence
// withheld reads as a bug in this tool — which is exactly how it was reported.
const SPF_A = 'v=spf1 include:_spf.google.com include:_spf.xactlycorp.com ~all';
const SPF_B = 'v=spf1 include:mktomail.com include:stspg-customer.com ~all';

sandbox.fetch = dohFixture({
  'twospf.example NS': ns('ns1.twospf.example.'),
  'twospf.example MX': mx('10 mail.twospf.example.'),
  'twospf.example TXT': [...txt(SPF_A), ...txt(SPF_B)],
  'twospf.example A': a('203.0.113.5'),
  'twospf.example AAAA': 'nodata',
  '_dmarc.twospf.example TXT': txt('v=DMARC1; p=reject; rua=mailto:d@twospf.example'),
});
const twoSpf = await D.analyzeDomain('twospf.example', { dkim: false, retries: 0 });
eq('two records is still a permerror',   twoSpf.spfStatus.status, 'permerror');
eq('and still critical',                 twoSpf.spfStatus.cls, 'crit');
eq('every conflicting record is kept',   twoSpf.spfRecords, [SPF_A, SPF_B]);
eq('spfRecord still names the first',    twoSpf.spfRecord, SPF_A);
// The finding evidences itself at row level too, the way dkim-multiple-records
// already names its selectors.
eq('the finding counts the records',
  twoSpf.issues.find(i => i.key === 'spf-multiple-records').args, [2]);
// Nothing in the record contents may be judged: no record applies at all, so a
// warning about `~all` or a missing provider include would be about a record
// receivers never reach.
eq('no content warning is drawn from a record that does not apply',
  twoSpf.spfStatus.warnings, ['spf-multiple-records']);

sandbox.fetch = dohFixture({
  'threespf.example NS': ns('ns1.threespf.example.'),
  'threespf.example MX': mx('10 mail.threespf.example.'),
  'threespf.example TXT': [...txt(SPF_A), ...txt(SPF_B), ...txt('v=spf1 -all')],
  'threespf.example A': a('203.0.113.5'),
  'threespf.example AAAA': 'nodata',
});
const threeSpf = await D.analyzeDomain('threespf.example', { dkim: false, retries: 0 });
eq('three records are all kept',   threeSpf.spfRecords.length, 3);
eq('and the count says three',
  threeSpf.issues.find(i => i.key === 'spf-multiple-records').args, [3]);

// The single-record path is untouched: one record, no finding, no behaviour
// change for the overwhelming majority of domains.
sandbox.fetch = dohFixture({
  'onespf.example NS': ns('ns1.onespf.example.'),
  'onespf.example MX': mx('10 mail.onespf.example.'),
  'onespf.example TXT': txt(SPF_A),
  'onespf.example A': a('203.0.113.5'),
  'onespf.example AAAA': 'nodata',
});
const oneSpf = await D.analyzeDomain('onespf.example', { dkim: false, retries: 0 });
eq('one record is not a permerror',  oneSpf.spfStatus.status !== 'permerror', true);
eq('and spfRecords holds just it',   oneSpf.spfRecords, [SPF_A]);
eq('and raises no multiple finding',
  oneSpf.issues.map(i => i.key).includes('spf-multiple-records'), false);

// A domain with no SPF at all must not report an empty record as a conflict.
sandbox.fetch = dohFixture({
  'nospf.example NS': ns('ns1.nospf.example.'),
  'nospf.example MX': mx('10 mail.nospf.example.'),
  'nospf.example TXT': txt('google-site-verification=abc'),
  'nospf.example A': a('203.0.113.5'),
  'nospf.example AAAA': 'nodata',
});
const noSpf = await D.analyzeDomain('nospf.example', { dkim: false, retries: 0 });
eq('no SPF means an empty record list', noSpf.spfRecords, []);
eq('and the status is missing, not permerror', noSpf.spfStatus.status, 'missing');

/* ── 41. A recognized field name promises a value grammar ────────────── */
section('41. Registered value grammars: DKIM applicability, MTA-STS, TLS-RPT, BIMI');

// ── DKIM: published key-shaped record vs. usable for THIS domain's email ──
// `k=bogus` and `s=tlsrpt` are conformant records that RFC 6376 §3.6.1 tells a
// verifier to ignore for email. Counting them satisfied DKIM discovery and
// reported a signing key where none applies.
const appliesToEmail = tags => D.analyzeDkimKey(`${tags}p=${RSA_2048}`).appliesToEmail;
const discovered = tags => D.dkimRecordSet([{ type: 16, data: `"${tags}p=${RSA_2048}"` }]).keys.length > 0;

eq('an unrecognized k= does not apply to email', appliesToEmail('k=bogus; '), false);
eq('and does not satisfy discovery',             discovered('k=bogus; '), false);
eq('but is not called malformed',                D.analyzeDkimKey(`k=bogus; p=${RSA_2048}`).errors, []);
eq('it is recorded as a restriction instead',
  D.analyzeDkimKey(`k=bogus; p=${RSA_2048}`).restrictions, ['unsupported-key-type']);

eq('s=tlsrpt does not apply to email',  appliesToEmail('s=tlsrpt; '), false);
eq('and does not satisfy discovery',    discovered('s=tlsrpt; '), false);
eq('and is a restriction, not an error',
  D.analyzeDkimKey(`s=tlsrpt; p=${RSA_2048}`).restrictions, ['service-not-email']);

// Controls that must all still apply to email.
eq('s=email applies',            appliesToEmail('s=email; '), true);
eq('s=* applies',                appliesToEmail('s=*; '), true);
eq('an absent s= defaults to *', appliesToEmail(''), true);
eq('s=email:tlsrpt applies',     appliesToEmail('s=email:tlsrpt; '), true);
eq('and all four satisfy discovery',
  ['s=email; ', 's=*; ', '', 's=email:tlsrpt; '].map(discovered), [true, true, true, true]);

// h=: an unknown hash name is an extension, not a defect — but a list offering
// no hash this verifier knows is a key it cannot use.
eq('h=sha999 alone does not apply',      appliesToEmail('h=sha999; '), false);
eq('and is a restriction, not an error',
  D.analyzeDkimKey(`h=sha999; p=${RSA_2048}`).restrictions, ['no-supported-hash']);
eq('h=sha999:sha256 applies',            appliesToEmail('h=sha999:sha256; '), true);
eq('and keeps the extension token',
  D.analyzeDkimKey(`h=sha999:sha256; p=${RSA_2048}`).hashAlgorithms, ['sha999', 'sha256']);
eq('an unknown t= flag is kept as an extension',
  D.analyzeDkimKey(`t=y:custom; p=${RSA_2048}`).flags, ['y', 'custom']);

// A PRESENT list tag may not be empty; an ABSENT one is a different thing.
eq('an empty h= is malformed',  D.analyzeDkimKey(`h=; p=${RSA_2048}`).errors, ['invalid-tag-list']);
eq('an empty s= is malformed',  D.analyzeDkimKey(`s=; p=${RSA_2048}`).errors, ['invalid-tag-list']);
eq('an empty t= is malformed',  D.analyzeDkimKey(`t=; p=${RSA_2048}`).errors, ['invalid-tag-list']);
eq('an absent h= is not malformed', D.analyzeDkimKey(`p=${RSA_2048}`).errors, []);
eq('and reports no hash list',      D.analyzeDkimKey(`p=${RSA_2048}`).hashAlgorithms, []);

// The line this fix must NOT cross: a key meant for email that happens to be
// broken still counts as found, so `dkim-key-unparseable` keeps firing. Turning
// a warning about a broken key into "no DKIM at all" is a worse answer.
eq('an unparseable key still applies to email', D.analyzeDkimKey('p=notbase64!!').appliesToEmail, true);
eq('and still satisfies discovery',
  D.dkimRecordSet([{ type: 16, data: '"v=DKIM1; p=notbase64!!"' }]).keys.length, 1);
eq('a revoked key applies to nothing', D.analyzeDkimKey('v=DKIM1; p=').appliesToEmail, false);

// The unusable records are surfaced, not silently dropped.
sandbox.fetch = dohFixture({
  'tlsrpt._domainkey.svc.example TXT': txt(`v=DKIM1; k=rsa; s=tlsrpt; p=${RSA_2048}`),
});
const scoped = await D.checkDKIM('svc.example', false, ['tlsrpt'], '@custom-unknown', false, '', { retries: 0, noCache: true });
eq('a scoped-only domain reports no email DKIM', scoped.found, false);
// A record exists at that name, so "No Domain Key Found" would contradict the
// finding that describes it.
eq('but the selector is not reported missing',   scoped.missingSelectors.length, 0);
// The same applies to a selector holding only a revocation.
sandbox.fetch = dohFixture({ 'old._domainkey.rev.example TXT': txt('v=DKIM1; p=') });
const revokedOnly = await D.checkDKIM('rev.example', false, ['old'], '@custom-unknown', false, '', { retries: 0, noCache: true });
eq('a revoked-only selector is not reported missing either', revokedOnly.missingSelectors.length, 0);
eq('it is reported as revoked',                              revokedOnly.revokedSelectors.map(r => r.sel), ['old']);
// ...but a selector with genuinely nothing at it is still reported missing.
sandbox.fetch = dohFixture({});
eq('an empty selector is still reported missing',
  (await D.checkDKIM('none.example', false, ['ghost'], '@custom-unknown', false, '', { retries: 0, noCache: true }))
    .missingSelectors.map(m => m.sel), ['ghost']);
eq('it is reported as inapplicable instead',
  scoped.unusableSelectors.map(u => u.sel), ['tlsrpt']);
eq('and the finding says so',
  D.buildIssues({ emailProvider: 'X', spfStatus: { status: 'ok', warnings: [] }, dkimStatus: scoped,
    dmarcStatus: { status: 'ok', policy: 'reject', warnings: [] }, reportPlan: { external: [] },
    externalReportDestinations: [], advanced: {}, domain: 'svc.example',
  }).filter(i => i.key === 'dkim-key-not-email').map(i => i.args), [['tlsrpt']]);

// ── MTA-STS (RFC 8461 §3.1) ──
const sts = r => D.validateMtaStsRecord(r).valid;
eq('a canonical MTA-STS record is valid',   sts('v=STSv1; id=20260817'), true);
eq('a trailing delimiter is permitted',     sts('v=STSv1; id=abc;'), true);
eq('a valid extension is permitted',        sts('v=STSv1; id=abc; ext_1=ok'), true);
eq('the version must come first',           sts('id=abc; v=STSv1'), false);
eq('the version is case-sensitive',         sts('v=stsv1; id=abc'), false);
eq('an id with a hyphen is refused',        sts('v=STSv1; id=has-hyphen'), false);
eq('a 33-character id is refused',          sts(`v=STSv1; id=${'a'.repeat(33)}`), false);
eq('a 32-character id is accepted',         sts(`v=STSv1; id=${'a'.repeat(32)}`), true);
eq('a bare fragment is not an extension',   sts('v=STSv1; id=abc; garbage'), false);
eq('a missing id is still refused',         sts('v=STSv1'), false);
// A bare fragment is rejected for having no "=" at all, which never reaches
// the extension grammar. These do reach it: a well-formed field whose NAME or
// VALUE breaks the ABNF.
eq('an extension name with a space is refused',  sts('v=STSv1; id=abc; bad name=x'), false);
eq('an extension value with a space is refused', sts('v=STSv1; id=abc; ext=has space'), false);
eq('an empty extension value is refused',        sts('v=STSv1; id=abc; ext='), false);
eq('an over-long extension name is refused',     sts(`v=STSv1; id=abc; ${'e'.repeat(33)}=x`), false);
eq('a dotted extension name is accepted',        sts('v=STSv1; id=abc; a.b-c_d=x'), true);

// ── TLS-RPT (RFC 8460 §3) ──
const rpt = r => D.validateTlsRptRecord(r).valid;
eq('a canonical TLS-RPT record is valid',   rpt('v=TLSRPTv1; rua=mailto:tls@example.com'), true);
eq('an https destination is valid',         rpt('v=TLSRPTv1; rua=https://example.com/r'), true);
eq('a comma-separated pair is valid',       rpt('v=TLSRPTv1; rua=mailto:a@e.example,https://e.example/r'), true);
eq('the version must come first',           rpt('rua=mailto:a@example.com; v=TLSRPTv1'), false);
eq('the version is case-sensitive',         rpt('v=tlsrptv1; rua=mailto:a@e.example'), false);
eq('a scheme prefix is not a URI',          rpt('v=TLSRPTv1; rua=mailto:not an address'), false);
eq('a bare fragment is not an extension',   rpt('v=TLSRPTv1; rua=https://example.com/x; garbage'), false);
eq('a missing rua is still refused',        rpt('v=TLSRPTv1'), false);
eq('an extension value with a space is refused',
  rpt('v=TLSRPTv1; rua=mailto:a@e.example; ext=has space'), false);
eq('a valid extension is accepted',
  rpt('v=TLSRPTv1; rua=mailto:a@e.example; ext_1=ok'), true);

// ── BIMI (draft-brand-indicators-for-message-identification §4.3) ──
const bimi = r => D.validateBimiRecord(r);
eq('an active BIMI record is valid',        bimi('v=BIMI1; l=https://logo.example/x.svg').valid, true);
eq('and is not a declination',              bimi('v=BIMI1; l=https://logo.example/x.svg').declined, false);
// The draft's explicit "we publish no indicator" — a conformant record that
// was previously reported invalid.
eq('an empty l= is a valid declination',    bimi('v=BIMI1; l=').valid, true);
eq('and is flagged as declined',            bimi('v=BIMI1; l=').declined, true);
eq('an absent l= is still invalid',         bimi('v=BIMI1').valid, false);
eq('the version is case-sensitive',         bimi('v=bimi1; l=https://logo.example/x.svg').valid, false);
eq('the version must come first',           bimi('l=https://logo.example/x.svg; v=BIMI1').valid, false);
eq('a scheme with no host is refused',      bimi('v=BIMI1; l=https://').valid, false);
eq('a PNG indicator is refused',            bimi('v=BIMI1; l=https://logo.example/x.png').valid, false);
eq('an SVGZ indicator is accepted',         bimi('v=BIMI1; l=https://logo.example/x.svgz').valid, true);
eq('an https authority is accepted',
  bimi('v=BIMI1; l=https://l.example/x.svg; a=https://a.example/c.pem').valid, true);
eq('an http logo is still refused',         bimi('v=BIMI1; l=http://logo.example/x.svg').valid, false);
eq('an extension value with a space is refused',
  bimi('v=BIMI1; l=https://l.example/x.svg; ext=has space').valid, false);
eq('a valid extension is accepted',
  bimi('v=BIMI1; l=https://l.example/x.svg; ext_1=ok').valid, true);
eq('a malformed authority URL is refused',
  bimi('v=BIMI1; l=https://l.example/x.svg; a=https://').valid, false);

// A declination is neither "present" nor "invalid" once it reaches the result.
const bimiDeclined = { advertised: true, present: false, declined: true, multiple: false, unknown: false };
eq('a declination raises no bimi-invalid finding',
  D.buildIssues({ emailProvider: 'X', spfStatus: { status: 'ok', warnings: [] },
    dkimStatus: { found: true, selectors: [], confidence: 'observed' },
    dmarcStatus: { status: 'ok', policy: 'reject', warnings: [] }, reportPlan: { external: [] },
    externalReportDestinations: [], advanced: { bimi: bimiDeclined }, domain: 'e.example',
  }).map(i => i.key).includes('bimi-invalid'), false);
eq('and is not sold BIMI in the suggestions',
  D.buildSuggestions({ emailProvider: 'X', spfStatus: { status: 'ok' },
    dkimStatus: { found: true }, dmarcStatus: { status: 'ok', policy: 'reject' },
    advanced: { bimi: bimiDeclined },
  }).map(t => t.key).some(k => k.startsWith('bimi')), false);

// ── CAA iodef is a URL, not a prefix ──
const iodef = v => D.summarizeCaa([`0 iodef "${v}"`]).parsed[0].valid;
eq('a scheme prefix with prose is refused', iodef('mailto:not an address'), false);
eq('a bare scheme is refused',              iodef('https://'), false);
// CAA §4.4 asks for a URL and adds no FQDN rule of its own — that constraint
// belongs to BIMI, which states it. RFC 6068 permits a bare reg-name here.
eq('a single-label host is accepted',       iodef('mailto:a@b'), true);
eq('an encoded quoted local part is accepted',
  iodef('mailto:%22not%40me%22@example.org'), true);
eq('an encoded domain literal is accepted', iodef('mailto:user@%5B192.0.2.1%5D'), true);
eq('an IPv6 literal authority is accepted', iodef('https://[2001:db8::1]/r'), true);
eq('a malformed percent escape is refused', iodef('https://example.com/%ZZ'), false);
eq('a real mailto is accepted',             iodef('mailto:sec@example.com'), true);
eq('a real https URL is accepted',          iodef('https://example.com/report'), true);
eq('a real http URL is accepted',           iodef('http://example.com/report'), true);
eq('ftp is still refused',                  iodef('ftp://x.example'), false);

/* ── 42. Repetition, field ABNF, URI profiles, and malformed evidence ─── */
section('42. Conforming records must not be rejected, malformed ones must not vanish');

// ── Repetition semantics are per-protocol, not a blanket duplicate rule ──
// RFC 8461 §3.1: "If any non-repeated field is duplicated, all entries except
// for the first SHALL be ignored" — and that sentence is explicitly about TXT
// records. A blanket rejection called a conformant record invalid AND reported
// the last id as effective, which is the one every sender discards.
const stsDup = D.validateMtaStsRecord('v=STSv1; id=first; id=second');
eq('a repeated MTA-STS id is still valid', stsDup.valid, true);
eq('and the FIRST id is effective',        stsDup.id, 'first');
// RFC 8460 §3: `1*(field-delim tlsrpt-field)` where a field may be a rua, so
// more than one rua is grammatical. Rejecting it also threw away evidence.
const rptDup = D.validateTlsRptRecord('v=TLSRPTv1; rua=mailto:a@example.com; rua=https://example.com/r');
eq('repeated TLS-RPT rua fields are valid', rptDup.valid, true);
eq('and every destination is kept',
  rptDup.destinations, ['mailto:a@example.com', 'https://example.com/r']);
eq('a repeated version field is ignored, not fatal',
  D.validateMtaStsRecord('v=STSv1; id=abc; v=STSv1').valid, true);

// ── Field ABNF: WSP belongs to the delimiter, and '=' is not a value char ──
// `sts-version = %s"v=STSv1"` and `sts-id = %s"id="` are single literals.
eq('whitespace inside an MTA-STS field is refused', D.validateMtaStsRecord('v = STSv1; id = abc').valid, false);
eq('whitespace inside a TLS-RPT field is refused',
  D.validateTlsRptRecord('v = TLSRPTv1; rua = mailto:a@e.example').valid, false);
// ...but `field-delim = *WSP ";" *WSP` means it does surround the delimiter.
eq('whitespace around the delimiter is permitted', D.validateMtaStsRecord('v=STSv1 ;  id=abc').valid, true);
eq('and for TLS-RPT too',
  D.validateTlsRptRecord('v=TLSRPTv1 ;  rua=mailto:a@e.example').valid, true);
// sts-ext-value / tlsrpt-ext-value = 1*(%x21-3A / %x3C / %x3E-7E): no '='.
eq('an "=" in an MTA-STS extension value is refused', D.validateMtaStsRecord('v=STSv1; id=abc; ext=a=b').valid, false);
eq('an "=" in a TLS-RPT extension value is refused',
  D.validateTlsRptRecord('v=TLSRPTv1; rua=mailto:a@e.example; ext=a=b').valid, false);
// BIMI's pinned grammar carries no such exclusion, so it must not inherit one.
eq('BIMI does not inherit the "=" exclusion',
  D.validateBimiRecord('v=BIMI1; l=https://l.example/x.svg; ext=a=b').valid, true);

// ── URI profiles: the consuming protocol adds the extra constraints ──
eq('an IPv6 literal is a valid TLS-RPT destination',
  D.validateTlsRptRecord('v=TLSRPTv1; rua=https://[2001:db8::1]/r').valid, true);
eq('a malformed percent escape is refused',
  D.validateTlsRptRecord('v=TLSRPTv1; rua=https://example.com/%ZZ').valid, false);
eq('an encoded quoted local part is accepted',
  D.validateTlsRptRecord('v=TLSRPTv1; rua=mailto:%22not%40me%22@example.org').valid, true);
// BIMI is the protocol that adds HTTPS and FQDN, so it keeps rejecting these.
eq('BIMI still refuses a single-label host',
  D.validateBimiRecord('v=BIMI1; l=https://localhost/logo.svg').valid, false);
eq('BIMI still refuses http',
  D.validateBimiRecord('v=BIMI1; l=http://logo.example/x.svg').valid, false);

// ── A malformed candidate is evidence, not an absence ──
// A sender discards a record that does not begin with the version field. An
// auditor that also discards it reports "nothing published" at an owner name
// dedicated to the protocol, and withholds the reason senders ignore it.
const ORDER = {
  'order.example NS': ns('ns1.order.example.'),
  'order.example MX': mx('10 mail.order.example.'),
  'order.example TXT': txt('v=spf1 -all'),
  'order.example A': a('203.0.113.5'),
  'order.example AAAA': 'nodata',
  'default._bimi.order.example TXT': txt('l=https://logo.example/logo.svg; v=BIMI1'),
  '_mta-sts.order.example TXT': txt('id=abc; v=STSv1'),
  '_smtp._tls.order.example TXT': txt('rua=mailto:a@example.com; v=TLSRPTv1'),
};
sandbox.fetch = dohFixture(ORDER);
const wrongOrder = await D.analyzeDomain('order.example', { dkim: false, advanced: true, retries: 0 });
const orderKeys = wrongOrder.issues.map(i => i.key);
eq('a wrong-order BIMI record is advertised',    wrongOrder.advanced.bimi.advertised, true);
eq('but not present',                            wrongOrder.advanced.bimi.present, false);
eq('and raises bimi-invalid',                    orderKeys.includes('bimi-invalid'), true);
eq('and the record is kept as evidence',
  wrongOrder.advanced.bimi.record, 'l=https://logo.example/logo.svg; v=BIMI1');
eq('a wrong-order MTA-STS record raises mta-sts-invalid', orderKeys.includes('mta-sts-invalid'), true);
eq('and keeps its record',                       wrongOrder.advanced.mtaSts.record, 'id=abc; v=STSv1');
eq('a wrong-order TLS-RPT record raises tls-rpt-invalid',  orderKeys.includes('tls-rpt-invalid'), true);
eq('and keeps its record',                       wrongOrder.advanced.tlsRpt.record, 'rua=mailto:a@example.com; v=TLSRPTv1');
// An owner with genuinely nothing at it must still read as absent.
sandbox.fetch = dohFixture({
  'bare42.example NS': ns('ns1.bare42.example.'), 'bare42.example MX': mx('10 mail.bare42.example.'),
  'bare42.example TXT': txt('v=spf1 -all'), 'bare42.example A': a('203.0.113.5'), 'bare42.example AAAA': 'nodata',
});
const bare42 = await D.analyzeDomain('bare42.example', { dkim: false, advanced: true, retries: 0 });
eq('an empty owner is not advertised',  bare42.advanced.bimi.advertised, false);
eq('and raises no invalid finding',     bare42.issues.map(i => i.key).includes('bimi-invalid'), false);

// ── A malformed DKIM key record must not pass in silence ──
const ED25519_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
const malformedRecord = `v=DKIM1; k=ed25519; h=; p=${ED25519_KEY}`;
eq('an empty h= makes the record invalid', D.analyzeDkimKey(malformedRecord).valid, false);
eq('but it still applies to email',        D.analyzeDkimKey(malformedRecord).appliesToEmail, true);
eq('so it still satisfies discovery',
  D.dkimRecordSet([{ type: 16, data: `"${malformedRecord}"` }]).keys.length, 1);
// ...and the silence is what had to end.
const malformedFindings = tags => keysOf(dkimWith(sel('s1', `${tags}p=${RSA_2048}`)))
  .filter(k => k === 'dkim-key-malformed' || k === 'dkim-key-unparseable');
eq('an empty h= raises the malformed finding',  malformedFindings('v=DKIM1; h=; '), ['dkim-key-malformed']);
eq('an empty s= raises it too',                 malformedFindings('v=DKIM1; s=; '), ['dkim-key-malformed']);
eq('an empty t= raises it too',                 malformedFindings('v=DKIM1; t=; '), ['dkim-key-malformed']);
eq('a duplicated tag raises it',                malformedFindings('v=DKIM1; t=y; t=s; '), ['dkim-key-malformed']);
eq('a bad version raises it',                   malformedFindings('v=DKIM2; '), ['dkim-key-malformed']);
// The two findings are disjoint: a decode failure is not also "malformed".
eq('a decode failure raises only the decode finding',
  keysOf(dkimWith(sel('s1', 'v=DKIM1; p=notbase64!!')))
    .filter(k => k === 'dkim-key-malformed' || k === 'dkim-key-unparseable'), ['dkim-key-unparseable']);
eq('and a clean key raises neither',            malformedFindings('v=DKIM1; h=sha256; s=email; '), []);

/* ── 43. Full grammar and candidate-state regression matrix ─────────── */
section('43. Full DKIM/URI grammar and sender-effective candidate state');

// Candidate evidence and sender-effective multiplicity are different axes.
// A malformed record that senders discard cannot disable the valid record
// beside it or make the UI claim the control is inactive.
const MIXED_CANDIDATES = {
  'mixed43.example NS': ns('ns1.mixed43.example.'),
  'mixed43.example MX': mx('10 mail.mixed43.example.'),
  'mixed43.example TXT': txt('v=spf1 -all'),
  'mixed43.example A': a('203.0.113.5'),
  'mixed43.example AAAA': 'nodata',
  'default._bimi.mixed43.example TXT': txt(
    'v=BIMI1 ; l=https://logo.example/logo.svg',
    'l=https://old.example/old.svg; v=BIMI1'),
  '_mta-sts.mixed43.example TXT': txt(
    'v=STSv1 ; id=good',
    'id=discarded; v=STSv1'),
  '_smtp._tls.mixed43.example TXT': txt(
    'v=TLSRPTv1\t; rua=mailto:good@example.com',
    'rua=mailto:discarded@example.com; v=TLSRPTv1'),
};
sandbox.fetch = dohFixture(MIXED_CANDIDATES);
const mixed43 = await D.analyzeDomain('mixed43.example', { dkim: false, advanced: true, retries: 0 });
const mixed43Keys = mixed43.issues.map(i => i.key);
['bimi', 'mtaSts', 'tlsRpt'].forEach(name => {
  eq(`${name}: the valid sender-compatible record remains present`, mixed43.advanced[name].present, true);
  eq(`${name}: malformed evidence does not become effective multiplicity`, mixed43.advanced[name].multiple, false);
  eq(`${name}: configuration at the owner is advertised`, mixed43.advanced[name].advertised, true);
  eq(`${name}: both raw candidates are retained`, mixed43.advanced[name].candidates.length, 2);
});
eq('no false BIMI multiple-record verdict', mixed43Keys.includes('bimi-multiple-records'), false);
eq('no false MTA-STS multiple-record verdict', mixed43Keys.includes('mta-sts-multiple-records'), false);
eq('no false TLS-RPT multiple-record verdict', mixed43Keys.includes('tls-rpt-multiple-records'), false);

// The complete DKIM tag-list grammar reaches the malformed finding. These
// are not merely unknown extensions: each violates a production RFC 6376
// requires a verifier to enforce.
const grammarFinding = record => {
  const analyzed = D.analyzeDkimKey(record);
  return {
    valid: analyzed.valid,
    findings: keysOf(dkimWith(sel('s1', record)))
      .filter(k => k === 'dkim-key-malformed' || k === 'dkim-key-unparseable'),
  };
};
const ED43 = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
[
  ['v= is not first', `k=ed25519; p=${ED43}; v=DKIM1`],
  ['k= is empty', `v=DKIM1; k=; p=${ED43}`],
  ['k= is not a hyphenated-word', `v=DKIM1; k=not a token; p=${ED43}`],
  ['a bare fragment occurs', `v=DKIM1; garbage; k=ed25519; p=${ED43}`],
  ['a tag name is malformed', `v=DKIM1; bad name=x; k=ed25519; p=${ED43}`],
  ['an empty middle tag occurs', `v=DKIM1;; k=ed25519; p=${ED43}`],
  ['n= contains a bad quoted-printable escape', `v=DKIM1; n=bad=zz; k=ed25519; p=${ED43}`],
].forEach(([label, record]) => {
  const result = grammarFinding(record);
  eq(`${label}: invalid`, result.valid, false);
  eq(`${label}: reported`, result.findings, ['dkim-key-malformed']);
});
eq('a well-formed unknown key type remains a restriction, not malformed',
  D.analyzeDkimKey(`v=DKIM1; k=future-alg; p=${ED43}`).errors, []);
eq('a syntactically valid unknown tag remains allowed',
  D.analyzeDkimKey(`v=DKIM1; future_tag=x; k=ed25519; p=${ED43}`).valid, true);
eq('legal folded whitespace inside p= remains accepted',
  D.analyzeDkimKey(`v=DKIM1; k=ed25519; p=${ED43.slice(0, 8)}\r\n ${ED43.slice(8)}`).valid, true);
['\n', '\v', '\f'].forEach((space, i) => {
  eq(`non-FWS base64 whitespace ${i + 1} is refused`,
    D.analyzeDkimKey(`v=DKIM1; k=ed25519; p=${ED43.slice(0, 8)}${space}${ED43.slice(8)}`).valid, false);
});
// Non-zero unused padding bits are not a canonical base64 encoding.
eq('non-canonical base64 pad bits are refused',
  D.analyzeDkimKey('v=DKIM1; k=ed25519; p=AB==').errors.includes('unparseable-key'), true);

// A recognizable key candidate with no p= must reach the analyzer rather than
// becoming a contradictory "nothing at this selector" result.
eq('a missing-p candidate is retained as malformed evidence',
  D.dkimRecordSet([{ type: 16, data: '"v=DKIM1; k=rsa"' }]).malformed,
  ['v=DKIM1; k=rsa']);
eq('an explicitly different protocol with p= is not a DKIM candidate',
  D.dkimRecordSet([{ type: 16, data: '"v=DMARC1; p=reject"' }]),
  { keys: [], revoked: [], unusable: [], malformed: [] });
eq('a malformed DKIM-family version remains diagnosable',
  D.dkimRecordSet([{ type: 16, data: `"v=DKIM2; k=ed25519; p=${ED43}"` }]).keys.length, 1);
sandbox.fetch = dohFixture({
  'broken._domainkey.missingp.example TXT': txt('v=DKIM1; k=rsa'),
});
const missingP43 = await D.checkDKIM('missingp.example', false, ['broken'], '@custom-unknown', false, '', { retries: 0, noCache: true });
eq('a missing-p candidate does not claim the selector is empty', missingP43.missingSelectors.length, 0);
eq('a missing-p candidate has its own evidence channel', missingP43.malformedSelectors.map(r => r.sel), ['broken']);
eq('a missing-p candidate raises the malformed finding',
  D.buildIssues({ emailProvider: 'X', spfStatus: { status: 'ok', warnings: [] },
    dkimStatus: missingP43, dmarcStatus: { status: 'ok', policy: 'reject', warnings: [] },
    reportPlan: { external: [] }, externalReportDestinations: [], advanced: {}, domain: 'missingp.example',
  }).map(i => i.key).includes('dkim-key-malformed'), true);

// The same grammar finding must not vanish merely because the key is revoked
// or deliberately scoped away from ordinary email.
const nonSigningEvidence = {
  found: false, selectors: [], missingSelectors: [], testedSelectors: [], failedSelectors: [],
  duplicated: [], keyProfile: {}, confidence: 'sampled',
  revokedSelectors: [{ sel: 'old', key: D.analyzeDkimKey('v=DKIM1; h=; p=') }],
  unusableSelectors: [{ sel: 'rpt', key: D.analyzeDkimKey(`v=DKIM1; s=tlsrpt; h=; k=ed25519; p=${ED43}`) }],
  malformedSelectors: [],
};
eq('revoked and scoped malformed records both reach the finding',
  D.buildIssues({ emailProvider: 'X', spfStatus: { status: 'ok', warnings: [] },
    dkimStatus: nonSigningEvidence, dmarcStatus: { status: 'ok', policy: 'reject', warnings: [] },
    reportPlan: { external: [] }, externalReportDestinations: [], advanced: {}, domain: 'e.example',
  }).filter(i => i.key === 'dkim-key-malformed').map(i => i.args), [['rpt, old']]);

const rpt43 = record => D.validateTlsRptRecord(record).valid;
// RFC 3986 IP-literal boundaries and component characters.
['::1', '2001:db8::1', '1:2:3:4:5:6:7:8', '::ffff:192.0.2.1'].forEach(ip => {
  eq(`valid IPv6 literal ${ip}`, rpt43(`v=TLSRPTv1; rua=https://[${ip}]/r`), true);
});
[':::', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', '12345::1', '::ffff:999.0.2.1', '192.0.2.1::'].forEach(ip => {
  eq(`invalid IPv6 literal ${ip}`, rpt43(`v=TLSRPTv1; rua=https://[${ip}]/r`), false);
});
eq('IPvFuture is accepted by the imported URI grammar',
  rpt43('v=TLSRPTv1; rua=https://[v1.foo]/r'), true);
eq('IPvFuture requires a hexadecimal version',
  rpt43('v=TLSRPTv1; rua=https://[v.foo]/r'), false);
eq('valid path/query/fragment characters are accepted',
  rpt43('v=TLSRPTv1; rua=https://example.com/a:@%21$&\'()*+%2C%3B=/%20?q=/?:@#ok'), true);
['<bad>', '{bad}', '"bad"'].forEach(path => {
  eq(`illegal URI path ${path}`, rpt43(`v=TLSRPTv1; rua=https://example.com/${path}`), false);
});

// RFC 6068 addr-spec and hfield structure, including its own published
// examples rather than an invented approximation.
eq('encoded quoted local part remains accepted',
  rpt43('v=TLSRPTv1; rua=mailto:%22not%40me%22@example.org'), true);
eq('encoded multiple-recipient mailto is accepted',
  rpt43('v=TLSRPTv1; rua=mailto:a@example.com%2Cb@example.com'), true);
eq('valid mailto header fields are accepted',
  rpt43('v=TLSRPTv1; rua=mailto:a@example.com?subject=hello%20world&body=ok'), true);
eq('RFC 6068 UTF-8 domain example is accepted',
  rpt43('v=TLSRPTv1; rua=mailto:user@%E7%B4%8D%E8%B1%86.example.org'), true);
['a..b@example.com', '.a@example.com', 'a.@example.com', 'a=b@example.com'].forEach(address => {
  eq(`invalid addr-spec ${address}`, rpt43(`v=TLSRPTv1; rua=mailto:${address}`), false);
});
eq('a mailto query must contain hfield syntax',
  rpt43('v=TLSRPTv1; rua=mailto:a@example.com?garbage'), false);
eq('an invalid percent-encoded UTF-8 sequence is refused',
  rpt43('v=TLSRPTv1; rua=mailto:a@%FF.example'), false);

const longLabel = 'a'.repeat(64);
eq('BIMI refuses a DNS-impossible 64-octet FQDN label',
  D.validateBimiRecord(`v=BIMI1; l=https://${longLabel}.example/logo.svg`).valid, false);

/* ── 44. The fixture harness and the transport agree on record types ──
   Groundwork for dnssec-evidence (0.5.0). Two type maps now describe the same
   thing — DNS_TYPES in js/dns.js, which decides what can be queried, and
   TYPE_NUM in tools/lib/doh-fixture.mjs, which decides what a fixture key
   resolves to. Nothing forced them to agree, and a divergence is silent in
   both directions: a fixture written for a type the transport cannot query is
   simply unreachable, and a transport type the harness does not know falls
   through TYPE_NAME to 'TXT' and answers the wrong fixture entry. That is the
   same silent-wrong-type failure dnsTypeNum() was changed to throw on,
   relocated into the tests that are supposed to catch it.
   ──────────────────────────────────────────────────────────────────────── */
section('44. The fixture harness and the transport agree on record types');

// dnsTypeNum() throws on a type it does not know, which is the whole point of
// it — but a guard that propagates that throw takes the rest of the suite with
// it, and a drift check whose failure mode is "no results at all" is worse
// than the drift. Resolve to a value first, then assert on it.
const transportType = type => {
  try { return D.dnsTypeNum(type); } catch (e) { return e.name; }
};
Object.keys(TYPE_NUM).forEach(type => {
  eq(`harness ${type} matches the transport`, transportType(type), TYPE_NUM[type]);
});
eq('the harness knows every type the transport can query',
  Object.keys(D.DNS_TYPES).filter(type => TYPE_NUM[type] === undefined), []);
eq('the harness claims no type the transport rejects',
  Object.keys(TYPE_NUM).filter(type => D.DNS_TYPES[type] === undefined), []);

// The builders write the resolver's presentation form verbatim. A DS digest is
// lowercase hex and a DNSKEY key is case-sensitive base64 with '+', '/' and
// '=' in it; a builder that normalized either would hide the parser defect
// most likely to ship in 0.5.0.
eq('ds() emits type 43 untouched',
  ds('2371 13 2 b1ae88aff068ddec3f7ff662f47d6599c74134425c67106e6c203942d6227ea4'),
  [{ type: 43, data: '2371 13 2 b1ae88aff068ddec3f7ff662f47d6599c74134425c67106e6c203942d6227ea4' }]);
eq('dnskey() preserves base64 case and symbols',
  dnskey('257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=='),
  [{ type: 48, data: '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==' }]);
eq('rrsig() emits type 46', rrsig('DS 8 2 3600 1788794710 1786976710 44925 org. mcMQ').map(r => r.type), [46]);

// A do=1 answer carries the RRSIG beside the record it signs. The fixture has
// to be able to reproduce that, or no test can prove the type filter exists.
sandbox.fetch = dohFixture({
  'signed.example DS': { ad: true, answers: [
    ...ds('2371 13 2 b1ae88aff068ddec3f7ff662f47d6599c74134425c67106e6c203942d6227ea4'),
    ...rrsig('DS 8 2 3600 1788794710 1786976710 44925 example. mcMQJv3yllXqZPW2kGss3W8bJWnjdtMYYe0bY9T0U2zQ'),
  ] },
  'signed.example DNSKEY': { ad: true, answers: [
    ...dnskey('256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=='),
    ...dnskey('257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=='),
    ...rrsig('DNSKEY 13 2 3600 1792128637 1786858237 2371 example. k4KjRHaTjZno4j69wB4L/tVnR55KUxIIlOR6Lb4FWII'),
  ] },
});

const dsAnswer = await D.dohFetch('signed.example', 'DS', { retries: 0, noCache: true });
eq('the DS answer carries its RRSIG', dsAnswer.answers.map(r => r.type), [43, 46]);
eq('the DS AD flag survives the transport', dsAnswer.ad, true);
eq('filtering on 43 leaves exactly the DS record',
  dsAnswer.answers.filter(r => r.type === 43).length, 1);

const keyAnswer = await D.dohFetch('signed.example', 'DNSKEY', { retries: 0, noCache: true });
eq('the DNSKEY answer carries its RRSIG', keyAnswer.answers.map(r => r.type), [48, 48, 46]);
eq('the key field reaches the caller byte-identical',
  keyAnswer.answers.filter(r => r.type === 48)[1].data.split(' ')[3],
  'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==');

// cleanAnswerData()'s non-TXT branch strips surrounding quotes and trims; the
// 0.4.0 capture concluded it needs no change for these types. Asserted rather
// than assumed, because every digest match in 0.5.0 depends on it.
eq('a DNSKEY survives the shared answer cleaner',
  (await D.dohFetch('signed.example', 'DNSKEY', { retries: 0, noCache: true }))
    .answers.filter(r => r.type === 48).map(r => r.data.split(' ').length), [4, 4]);

/* ── 45. DNSSEC record parsing and the RFC 4034 key tag ────────────────
   The load-bearing tests of dnssec-evidence (0.5.0). The key tag is what links
   a DS to a DNSKEY, and an off-by-one in it does not fail loudly — it reports
   a spurious mismatch on a healthy zone, which the spec calls the most
   damaging defect this project could ship. So the reference vectors come from
   the RFCs themselves and from answers captured off the live resolver, never
   from this implementation's own output.
   ──────────────────────────────────────────────────────────────────────── */
section('45. DNSSEC record parsing and the RFC 4034 key tag');

// RFC 4034 §5.4's worked example. The RFC states the key tag as 60485, and
// RFC 4509 §2.3 publishes the SHA-256 DS for the same key — so this one key
// anchors the tag arithmetic here and the digest matcher in the next section.
const RFC4034_KEY = '256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==';
const rfcKey = D.parseDnskey(RFC4034_KEY);
eq('RFC 4034 §5.4 key tag is the RFC\'s stated 60485', rfcKey.keyTag, 60485);
eq('and it parses as RSASHA1', [rfcKey.algorithm, rfcKey.algorithmName], [5, 'RSASHA1']);
eq('RSASHA1 is deprecated per RFC 9905 §3.1', rfcKey.deprecated, true);
eq('a 256-flag key has the zone bit and not SEP', [rfcKey.hasZoneFlag, rfcKey.hasSep], [true, false]);
eq('and its RSA key material is structurally possible', rfcKey.keyStructure, 'valid');

// Live keys, captured before the parser existed. The tags below were computed
// independently of this code and cross-checked against the DS records the
// parents actually publish — cloudflare.com and ietf.org both anchor tag 2371.
const LIVE = {
  zsk13: '256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==',
  ksk13: '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==',
  zsk8:  '256 3 8 AwEAAd0QrBPRbxNYnFgWuM4MagnO2sYGEOgRJMN47TcPPd/RfeKt3MSoYnemjW1PjQvI61fagfUvI/lfse6f2ZpDVHwOS+iO/zKY25eH+PazhEVleydA618j/ZSZxNd91OBqRIdBjusdsEL8TjyiND2+7TNfB44NX9HjdyBaVaTen0BV',
};
eq('live ECDSAP256SHA256 ZSK tag', D.parseDnskey(LIVE.zsk13).keyTag, 34505);
eq('live ECDSAP256SHA256 KSK tag', D.parseDnskey(LIVE.ksk13).keyTag, 2371);
eq('live RSASHA256 ZSK tag',       D.parseDnskey(LIVE.zsk8).keyTag, 61291);
eq('a 257-flag key has the SEP bit', D.parseDnskey(LIVE.ksk13).hasSep, true);
eq('RSA-1024 decodes to 132 RDATA key bytes', D.parseDnskey(LIVE.zsk8).keyBytes, 132);
eq('ECDSA P-256 decodes to 64',    D.parseDnskey(LIVE.zsk13).keyBytes, 64);

// The defect this parser is written to avoid. Base64 is case-carrying; folding
// it destroys the key, every digest then fails, and a healthy zone is reported
// as a broken chain.
eq('the public key survives byte-identical', D.parseDnskey(LIVE.ksk13).publicKey,
  'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==');
eq('a key differing only in case parses to a different tag',
  D.parseDnskey(LIVE.ksk13).keyTag === D.parseDnskey(LIVE.ksk13.toLowerCase()).keyTag, false);

// Algorithm 1 has its own rule, and RFC 4034 Appendix B.1 states it WRONG.
// RFC 6840 §5.5 is the normative text: B.1 correctly says the tag is the most
// significant 16 of the least significant 24 bits of the modulus, then names
// the "fourth-to-last and third-to-last" octets for it, where §5.5 corrects
// that to the third-to-last and second-to-last. The vector below separates
// all three readings — the general formula gives 44837, the erroneous appendix
// gives 52242, and the corrected rule gives 4660 — so this assertion fails if
// the implementation follows the appendix as literally written.
eq('RSAMD5 follows the RFC 6840 §5.5 correction, not Appendix B.1 as written',
  D.parseDnskey('256 3 1 qrvMEjRW').keyTag, 4660);
eq('RSAMD5 is deprecated',              D.parseDnskey('256 3 1 qrvMEjRW').deprecated, true);

// RFC 4034 §2.1.2: the protocol field MUST be 3; anything else is invalid.
eq('protocol 4 is refused', D.parseDnskey('256 4 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==').errors, ['bad-protocol']);
eq('an invalid key computes no tag',  D.parseDnskey('256 4 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==').keyTag, null);

// Every flag is reported as the bit it is, never as the role it suggests.
// RFC 5011 §2.1 makes a key revoked when a resolver sees it in a SELF-SIGNED
// RRset with the bit set; this release does not validate RRSIGs, so it holds
// one half of that proof and the field is named for the half it holds.
const revokedKey = D.parseDnskey('385 3 13 ' + LIVE.zsk13.split(' ')[3]);
eq('the REVOKE bit is reported as a flag, not as a revocation', revokedKey.hasRevokeFlag, true);
eq('a REVOKE flag does not make the record unparseable', revokedKey.valid, true);
eq('no field claims the key is revoked', 'isRevoked' in revokedKey, false);

// RFC 6840 §6.2: the SEP bit "has no effect on how a DNSKEY may be used" and
// validation is prohibited from consulting it, so nothing here may call a SEP
// key the KSK.
eq('no field claims a key is the KSK', 'isKsk' in D.parseDnskey(LIVE.ksk13), false);

// RFC 4034 §2.1.1: a key without the zone bit MUST NOT verify RRsets. Reported
// here; applied where matching happens.
const nonZone = D.parseDnskey('1 3 13 ' + LIVE.zsk13.split(' ')[3]);
eq('a key with the zone bit clear is reported, not rejected',
  [nonZone.hasZoneFlag, nonZone.valid], [false, true]);

// Reserved flag bits are ignored on receipt (RFC 4034 §2.1.1), so a record
// carrying one still parses.
eq('a reserved flag bit does not invalidate the record',
  D.parseDnskey('1280 3 13 ' + LIVE.zsk13.split(' ')[3]).valid, true);

// The registry grows. An algorithm this build has never heard of is reported
// as its number with no name, not as a broken record.
const future = D.parseDnskey('257 3 250 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==');
eq('an unregistered algorithm keeps its number',
  [future.algorithm, future.algorithmName, future.algorithmEligibility, future.valid],
  [250, null, 'unknown', true]);

eq('a non-record is unparseable',       D.parseDnskey('not a dnskey').errors, ['unparseable-record']);
eq('an empty string is unparseable',    D.parseDnskey('').errors, ['unparseable-record']);
eq('an empty key field is caught',      D.parseDnskey('256 3 13 ').errors, ['unparseable-record']);
eq('non-base64 key material is caught', D.parseDnskey('256 3 13 not!base64!').errors, ['bad-key-encoding']);
eq('a half-open parenthesis is refused', D.parseDnskey('256 3 13 ( oJMRESz5E4g').errors, ['unbalanced-parentheses']);
eq('a balanced pair is accepted', D.parseDnskey(`256 3 13 ( ${LIVE.zsk13.split(' ')[3]} )`).keyTag, 34505);

/* ── DS ──────────────────────────────────────────────────────────────── */

// RFC 4034 §5.4 and RFC 4509 §2.3 publish both digests for the same key.
eq('the RFC 4034 SHA-1 DS parses', (() => {
  const d = D.parseDs('60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118');
  return [d.keyTag, d.algorithm, d.digestType, d.digestName, d.deprecated, d.valid];
})(), [60485, 5, 1, 'SHA-1', true, true]);
eq('the RFC 4509 SHA-256 DS parses', (() => {
  const d = D.parseDs('60485 5 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A');
  return [d.digestType, d.digestName, d.deprecated, d.valid];
})(), [2, 'SHA-256', false, true]);

// Cloudflare returns the digest lowercase and dns.google returns it uppercase.
// The comparison this feeds is a string equality, so the case is folded — the
// opposite decision from DNSKEY, and safe here because the field is hex.
eq('an uppercase digest is folded to lowercase',
  D.parseDs('60485 5 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A').digest,
  'd4b7d520e7bb5f0f67674a0cceb1e3e0614b93c4f9e99b8383f6a1e4469da50a');
eq('the two resolvers\' spellings parse identically',
  D.parseDs('2371 13 2 B1AE88AFF068DDEC3F7FF662F47D6599C74134425C67106E6C203942D6227EA4').digest,
  D.parseDs('2371 13 2 b1ae88aff068ddec3f7ff662f47d6599c74134425c67106e6c203942d6227ea4').digest);

// A digest of the wrong length for its type is the shape of a truncated
// record, and it must not reach the matcher and be reported as a mismatch.
eq('a short SHA-256 digest is refused',  D.parseDs('60485 5 2 D4B7D5').errors, ['bad-digest-length']);
eq('a SHA-1-length digest labelled SHA-256 is refused',
  D.parseDs('60485 5 2 2BB183AF5F22588179A53B0A98631FAD1A292118').errors, ['bad-digest-length']);
eq('an odd number of hex digits is refused', D.parseDs('60485 5 2 abc').errors, ['bad-digest']);
eq('non-hex digest material is refused',     D.parseDs('60485 5 2 ' + 'z'.repeat(64)).errors, ['bad-digest']);
eq('SHA-384 length is accepted',             D.parseDs('60485 5 4 ' + 'ab'.repeat(48)).valid, true);
eq('SHA-384 at SHA-256 length is refused',   D.parseDs('60485 5 4 ' + 'ab'.repeat(32)).errors, ['bad-digest-length']);

// An unregistered digest type has no length to check against. Inventing one
// would reject a record written to a specification newer than this build.
const futureDigest = D.parseDs('60485 5 99 ' + 'ab'.repeat(19));
eq('an unregistered digest type is carried, not judged',
  [futureDigest.digestType, futureDigest.digestName, futureDigest.valid], [99, null, true]);

eq('a parenthesised DS is unwrapped',
  D.parseDs('2371 13 2 ( b1ae88aff068ddec3f7ff662f47d6599c74134425c67106e6c203942d6227ea4 )').valid, true);
eq('a DS half-open parenthesis is refused', D.parseDs('2371 13 2 ( b1ae88').errors, ['unbalanced-parentheses']);
eq('an RRSIG is not a DS record', D.parseDs('DS 8 2 3600 1788794710 1786976710 44925 org. mcMQJv3yl').errors, ['unparseable-record']);
eq('an RRSIG is not a DNSKEY',    D.parseDnskey('DNSKEY 13 2 3600 1792128637 1786858237 2371 ietf.org. k4KjRHaT').errors, ['unparseable-record']);

// Every error branch above is reachable, and each is asserted so none of them
// is quietly dead. A validator with an unreachable rejection reads as stricter
// than it is.
eq('a flags value over 16 bits is refused',   D.parseDnskey('999999 3 13 ' + LIVE.zsk13.split(' ')[3]).errors, ['bad-flags']);
eq('an algorithm over 8 bits is refused',     D.parseDnskey('256 3 999 ' + LIVE.zsk13.split(' ')[3]).errors, ['bad-algorithm']);
eq('an empty parenthesised key is refused',   D.parseDnskey('256 3 13 ()').errors, ['empty-key']);
eq('a key tag over 16 bits is refused',       D.parseDs('99999999 5 2 ' + 'ab'.repeat(32)).errors, ['bad-key-tag']);
eq('a DS algorithm over 8 bits is refused',   D.parseDs('60485 999 2 ' + 'ab'.repeat(32)).errors, ['bad-algorithm']);
eq('a digest type over 8 bits is refused',    D.parseDs('60485 5 999 ' + 'ab'.repeat(32)).errors, ['bad-digest-type']);
eq('an empty parenthesised digest is refused', D.parseDs('60485 5 2 ()').errors, ['empty-digest']);

/* ── Key material structure (F2) ─────────────────────────────────────
   `valid` is a statement about the RECORD. Whether the key material is even
   structurally possible for the algorithm it declares is a separate fact, and
   collapsing the two is how a recognized name gets accepted without its
   registered value grammar — the failure 0.4.0 removed from CAA, MTA-STS and
   DKIM in three separate rounds.

   Only 'invalid' disqualifies. 'unknown' must never be read as a fault: a DS
   digest is computed over the raw RDATA, so a parent and child can agree
   perfectly about a key whose internals nothing here can parse.
   ──────────────────────────────────────────────────────────────────────── */
const keyOf = (alg, bytes) => D.parseDnskey(`257 3 ${alg} ${Buffer.alloc(bytes, 0xab).toString('base64')}`);

// RFC 6605 §4: ECDSA Q is the uncompressed point x|y — 64 octets for P-256,
// 96 for P-384. RFC 8080 §3: Ed25519 is 32 octets, Ed448 is 57.
eq('ECDSA P-256 at 64 octets is structurally valid', keyOf(13, 64).keyStructure, 'valid');
eq('ECDSA P-256 at 1 octet is impossible',           keyOf(13, 1).keyStructure, 'invalid');
eq('ECDSA P-384 at 96 octets is structurally valid', keyOf(14, 96).keyStructure, 'valid');
eq('ECDSA P-384 carrying a P-256 key is impossible', keyOf(14, 64).keyStructure, 'invalid');
eq('Ed25519 at 32 octets is structurally valid',     keyOf(15, 32).keyStructure, 'valid');
eq('Ed25519 at 1 octet is impossible',               keyOf(15, 1).keyStructure, 'invalid');
eq('Ed448 at 57 octets is structurally valid',       keyOf(16, 57).keyStructure, 'valid');
eq('Ed448 one octet short is impossible',            keyOf(16, 56).keyStructure, 'invalid');

// A malformed key still parses as a record, and still computes a key tag. That
// is deliberate: the tag is arithmetic over the RDATA and does not depend on
// the material meaning anything. What must not happen is the two facts being
// confused.
eq('impossible key material still yields a parseable record', keyOf(15, 1).valid, true);
eq('and it is not silently reported as fine',
  [keyOf(15, 1).valid, keyOf(15, 1).keyStructure], [true, 'invalid']);

// RFC 3110 §2: exponent length (1 or 3 octets), exponent, then modulus. The
// long form is canonical only above 255 octets, neither integer may have a
// leading zero, and each is capped at 4096 bits. Section 3 sets the modulus
// protocol range to 512–4096 bits.
const rsa = bytes => D.parseDnskey('257 3 8 ' + Buffer.from(bytes).toString('base64')).keyStructure;
const rsaExponent = [0x03, 1, 0, 1];
eq('a canonical RSA key at the 512-bit modulus floor is valid',
  rsa([...rsaExponent, ...Buffer.alloc(64, 0xab)]), 'valid');
eq('an RSA key that is only a length octet is impossible', rsa([0x00]), 'invalid');
eq('an RSA exponent longer than the key is impossible',    rsa([0x05, 1, 2]), 'invalid');
eq('an RSA key with no modulus left is impossible',        rsa([0x03, 1, 0, 1]), 'invalid');
eq('a zero-length RSA exponent is impossible',             rsa([0x00, 0x00, 0x00, 0xab]), 'invalid');
eq('the extended exponent length is noncanonical at 255 octets or fewer',
  rsa([0x00, 0x00, 0x03, 1, 0, 1, ...Buffer.alloc(64, 0xab)]), 'invalid');
eq('an RSA exponent may not have a leading zero',
  rsa([0x03, 0, 1, 1, ...Buffer.alloc(64, 0xab)]), 'invalid');
eq('an RSA modulus may not have a leading zero',
  rsa([...rsaExponent, 0, ...Buffer.alloc(63, 0xab)]), 'invalid');
eq('an RSA modulus below 512 bits is outside the protocol range',
  rsa([...rsaExponent, ...Buffer.alloc(63, 0xab)]), 'invalid');
eq('an RSA modulus above 4096 bits is outside the protocol range',
  rsa([...rsaExponent, ...Buffer.alloc(513, 0xab)]), 'invalid');

// The modulus floor is per-algorithm, not shared. RFC 3110 §3 sets 512 bits
// for the RSA/SHA-1 family and RFC 5702 §2.1 repeats it for RSA/SHA-256, but
// **§2.2 raises RSA/SHA-512 to 1024 bits**. A single shared minimum drops that
// constraint silently — permissive, so it breaks no real zone, and still a
// recognized algorithm accepted without the limit its own RFC states.
const rsaAlg = (algorithm, modulusBytes) =>
  D.parseDnskey(`257 3 ${algorithm} ` + Buffer.from(
    [...rsaExponent, ...Buffer.alloc(modulusBytes, 0xab)]).toString('base64')).keyStructure;
eq('RSA/SHA-256 accepts the RFC 5702 §2.1 floor of 512 bits', rsaAlg(8, 64), 'valid');
eq('RSA/SHA-1 accepts the RFC 3110 §3 floor of 512 bits',     rsaAlg(5, 64), 'valid');
eq('RSA/SHA-512 refuses 512 bits — RFC 5702 §2.2 requires 1024', rsaAlg(10, 64), 'invalid');
eq('RSA/SHA-512 refuses one octet below its floor',           rsaAlg(10, 127), 'invalid');
eq('RSA/SHA-512 accepts its 1024-bit floor',                  rsaAlg(10, 128), 'valid');
eq('RSA/SHA-512 still refuses above 4096 bits',               rsaAlg(10, 513), 'invalid');
eq('an RSA exponent above 4096 bits is outside the protocol range',
  rsa([0x00, 0x02, 0x01, ...Buffer.alloc(513, 0xab), ...Buffer.alloc(64, 0xab)]), 'invalid');
eq('the extended exponent form is accepted when the exponent exceeds 255 octets',
  rsa([0x00, 0x01, 0x00, ...Buffer.alloc(256, 0xab), ...Buffer.alloc(64, 0xab)]), 'valid');

// Algorithms whose key grammar this build does not implement. Reporting
// 'unknown' is the honest answer; rejecting them would refuse zones signed to
// a specification newer than this build.
eq('DSA key grammar is not implemented here',   keyOf(3, 20).keyStructure, 'unknown');
eq('SM2SM3 key grammar is not implemented',     keyOf(17, 64).keyStructure, 'unknown');
eq('ML-DSA-44 key grammar is not implemented',  keyOf(18, 1312).keyStructure, 'unknown');
eq('an unassigned algorithm is unknown, not invalid', keyOf(99, 10).keyStructure, 'unknown');

// The live keys must all pass, or the check is too strict to ship.
eq('every live key is structurally valid',
  [LIVE.zsk13, LIVE.ksk13, LIVE.zsk8, RFC4034_KEY].map(r => D.parseDnskey(r).keyStructure),
  ['valid', 'valid', 'valid', 'valid']);

/* ── Registry currency (F4) ──────────────────────────────────────────── */

// IANA DNS Security Algorithm Numbers, checked 2026-08-26. 17 is RFC 9563,
// 23 is RFC 9558, and 18 is an early allocation held by an Internet-Draft.
eq('SM2SM3 is named',     D.DNSSEC_ALGORITHMS[17], 'SM2SM3');
eq('MLDSA44 is named',    D.DNSSEC_ALGORITHMS[18], 'MLDSA44');
eq('ECC-GOST12 is named', D.DNSSEC_ALGORITHMS[23], 'ECC-GOST12');
eq('ECC-GOST12 is a replacement, not a deprecation',
  D.parseDnskey('257 3 23 ' + Buffer.alloc(64, 0xab).toString('base64')).deprecated, false);
eq('ECC-GOST (12) is deprecated by RFC 9906',
  D.parseDnskey('257 3 12 ' + Buffer.alloc(64, 0xab).toString('base64')).deprecated, true);

// The IANA Zone Signing column is eligibility evidence, not a synonym for a
// known mnemonic or a key grammar this build happens to implement. DELETE,
// RSAMD5, DH and INDIRECT are named but explicitly not zone-signing algorithms.
eq('the full named registry carries its Zone Signing classification',
  Object.entries(D.DNSSEC_ALGORITHMS).map(([algorithm]) =>
    [Number(algorithm), D.dnssecAlgorithmEligibility(Number(algorithm))]),
  [[0, 'ineligible'], [1, 'ineligible'], [2, 'ineligible'], [3, 'eligible'],
   [5, 'eligible'], [6, 'eligible'], [7, 'eligible'], [8, 'eligible'],
   [10, 'eligible'], [12, 'eligible'], [13, 'eligible'], [14, 'eligible'],
   [15, 'eligible'], [16, 'eligible'], [17, 'eligible'], [18, 'eligible'],
   [23, 'eligible'], [252, 'ineligible'], [253, 'eligible'], [254, 'eligible']]);
eq('a recognized non-zone-signing DNSKEY is explicitly ineligible',
  D.parseDnskey('257 3 1 qrvMEjRW').algorithmEligibility, 'ineligible');
eq('a DS carries the same algorithm eligibility fact',
  D.parseDs('1 1 2 ' + 'ab'.repeat(32)).algorithmEligibility, 'ineligible');
eq('an unassigned DS algorithm remains unknown rather than ineligible',
  D.parseDs('1 99 2 ' + 'ab'.repeat(32)).algorithmEligibility, 'unknown');

// Digest types 5 and 6 are registered. Without their lengths, a one-octet
// digest declaring type 6 was accepted as a valid unnamed record — a
// registered grammar going unchecked, which is not forward compatibility.
eq('GOST R 34.11-2012 is named',   D.DNSSEC_DIGESTS[5], 'GOST-R-34.11-2012');
eq('SM3 is named',                 D.DNSSEC_DIGESTS[6], 'SM3');
eq('a one-octet SM3 digest is refused',  D.parseDs('1 17 6 ab').errors, ['bad-digest-length']);
eq('a one-octet GOST-2012 digest is refused', D.parseDs('1 23 5 ab').errors, ['bad-digest-length']);
eq('a 32-octet SM3 digest is accepted',       D.parseDs('1 17 6 ' + 'ab'.repeat(32)).valid, true);
eq('a 32-octet GOST-2012 digest is accepted', D.parseDs('1 23 5 ' + 'ab'.repeat(32)).valid, true);
eq('GOST R 34.11-94 stays deprecated',        D.parseDs('1 12 3 ' + 'ab'.repeat(32)).deprecated, true);
eq('GOST R 34.11-2012 is not deprecated',     D.parseDs('1 23 5 ' + 'ab'.repeat(32)).deprecated, false);
eq('SHA-1 is deprecated for delegation',      D.parseDs('1 8 1 ' + 'ab'.repeat(20)).deprecated, true);

// Only a genuinely unassigned or private-use digest type is carried unjudged.
const unassignedDigest = D.parseDs('60485 5 99 ' + 'ab'.repeat(19));
eq('an unassigned digest type is carried, not judged',
  [unassignedDigest.digestType, unassignedDigest.digestName, unassignedDigest.valid], [99, null, true]);

/* ── Canonical owner name (RFC 4034 §5.1.4) ──────────────────────────── */

const wire = name => Array.from(D.dnsWireName(name) || []);
eq('dskey.example.com encodes per the RFC example', wire('dskey.example.com'),
  [5, 100, 115, 107, 101, 121, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0]);
eq('an uppercase label is lowercased before hashing',
  wire('DSKEY.Example.COM'), wire('dskey.example.com'));
eq('a trailing dot is not an extra label', wire('example.com.'), wire('example.com'));
eq('a four-label name encodes every label', wire('a.b.c.example.com').length, 2 + 2 + 2 + 8 + 4 + 1);
eq('the root is a single zero octet', wire(''), [0]);

// Returns null rather than writing wrong bytes. A digest built on a bad
// encoding would be a mismatch verdict about the operator's zone that is
// really a statement about our own encoder.
eq('a 64-octet label cannot be encoded', D.dnsWireName('a'.repeat(64) + '.example.com'), null);
eq('a 63-octet label can',                D.dnsWireName('a'.repeat(63) + '.example.com') === null, false);
eq('an over-long name cannot be encoded',
  D.dnsWireName(new Array(52).join('abcd.') + 'example.com'), null);
eq('a non-ASCII label cannot be encoded',  D.dnsWireName('münchen.example.com'), null);

// The order of the ASCII check and the case fold is load-bearing, and this is
// the fixture that proves it. JavaScript's toLowerCase() is Unicode case
// conversion, not the ASCII-only folding RFC 4034 §6.2 defines: U+212A KELVIN
// SIGN folds to a plain 'k'. Checking ASCII second therefore turned a name
// this function must refuse into one it accepted, and computed a digest for
// `k.example` when the caller asked about `K.example` — a different owner
// name, which is a different zone.
eq('U+212A KELVIN SIGN is refused, not folded to ASCII k', D.dnsWireName('\u212A.example'), null);
eq('while the ASCII name it folds to encodes normally — so the refusal above is a refusal, not a blanket null',
  [D.dnsWireName('\u212A.example'), wire('k.example')], [null, [1, 107, 7, 101, 120, 97, 109, 112, 108, 101, 0]]);
eq('U+017F LATIN SMALL LETTER LONG S is refused too', D.dnsWireName('\u017F.example'), null);
eq('an ASCII uppercase name is still folded normally', wire('K.EXAMPLE'), wire('k.example'));
eq('an empty label cannot be encoded',     D.dnsWireName('a..example.com'), null);

// RFC 4034 §2.1: flags(2) || protocol(1) || algorithm(1) || public key.
eq('RDATA is four octets plus the key', D.dnskeyRdata(rfcKey).length, 134);
eq('RDATA opens with the flags, protocol and algorithm',
  Array.from(D.dnskeyRdata(rfcKey).slice(0, 4)), [1, 0, 3, 5]);
eq('an invalid key yields no RDATA', D.dnskeyRdata(D.parseDnskey('256 4 13 abcd')), null);

/* ── 46. Local DS-to-DNSKEY digest matching (RFC 4034 §5.1.4) ─────────
   Step 3. The only part of this release that computes rather than reports.
   Its reference vectors are RFC 4034 §5.4's example key with RFC 4509 §2.3's
   SHA-256 DS for that same key, so the digest input, the canonical owner name
   and the RDATA reconstruction are all checked against published values
   rather than against this implementation's own output.

   The governing rule is that every failure path lands on `unverifiable` and
   never on `digest-mismatch`. A mismatch tells an operator their DNSSEC is
   broken; only arithmetic that actually ran is entitled to say so.
   ──────────────────────────────────────────────────────────────────────── */
section('46. Local DS-to-DNSKEY digest matching');

// Block-scoped: this section declares a lot of locals and the file is one
// long module. Top-level await is legal inside a block in an ES module.
{

const OWNER = 'dskey.example.com';
const rfcKeySet = [D.parseDnskey(RFC4034_KEY)];
const RFC4509_DS = '60485 5 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A';
const RFC4034_DS = '60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118';
const matchOne = async (dsText, keys = rfcKeySet, owner = OWNER) =>
  D.matchDsToDnskeys(D.parseDs(dsText), keys, owner);

eq('the RFC 4509 §2.3 SHA-256 DS confirms the RFC 4034 §5.4 key',
  (await matchOne(RFC4509_DS)).match, 'confirmed');
eq('and it names the key tag it matched', (await matchOne(RFC4509_DS)).matchedKeyTag, 60485);
eq('and points at which key in the set supplied it', (await matchOne(RFC4509_DS)).matchedKeyIndex, 0);
eq('a confirmed match carries no unverifiable reason',
  (await matchOne(RFC4509_DS)).unverifiableReason, null);
eq('the match is attributed to local computation',
  (await matchOne(RFC4509_DS)).computedLocally, true);

// Acceptance criterion 5, as amended at 1.1. SHA-1 is a registered Web Crypto
// digest and is computed; it is never a mismatch BECAUSE of its digest type.
eq('the RFC 4034 §5.4 SHA-1 DS is computed, not declined',
  (await matchOne(RFC4034_DS)).match, 'confirmed');
eq('and the DS still reports the digest type as deprecated',
  D.parseDs(RFC4034_DS).deprecated, true);

eq('a right tag with a wrong digest is a mismatch',
  (await matchOne('60485 5 2 ' + 'ab'.repeat(32))).match, 'digest-mismatch');
eq('a tag no DNSKEY carries has no matching key',
  (await matchOne('11111 5 2 ' + 'ab'.repeat(32))).match, 'no-matching-key');
eq('an algorithm no DNSKEY carries has no matching key',
  (await matchOne('60485 8 2 ' + 'ab'.repeat(32))).match, 'no-matching-key');
eq('an empty DNSKEY set has no matching key',
  (await matchOne(RFC4509_DS, [])).match, 'no-matching-key');

/* ── The digest binds the owner name ─────────────────────────────────── */

eq('an uppercase owner folds to the same canonical form',
  (await matchOne(RFC4509_DS, rfcKeySet, 'DSKEY.EXAMPLE.COM')).match, 'confirmed');
eq('the same DS under a different owner does not confirm',
  (await matchOne(RFC4509_DS, rfcKeySet, 'other.example.com')).match, 'digest-mismatch');
// An owner name the encoder refuses is a statement about our input, not about
// the zone, so it must not reach the alarming verdict.
eq('an owner name the encoder refuses is unverifiable, never a mismatch',
  (await matchOne(RFC4509_DS, rfcKeySet, 'K.example')).match, 'unverifiable');

/* ── Uncomputable and unparseable both land on unverifiable ──────────── */

// GOST-94, GOST-2012 and SM3 are registered digest types that Web Crypto does
// not implement. Digest type 0 is reserved by RFC 3658 — named so it does not
// read as an unassigned future type, and not rejected, because RFC 3658
// reserves the value without saying a DS carrying it is invalid.
for (const [digestType, label] of [[3, 'GOST R 34.11-94'], [5, 'GOST R 34.11-2012'], [6, 'SM3'], [0, 'the reserved type']]) {
  eq(`${label} cannot be computed and says so`,
    (await matchOne(`60485 5 ${digestType} ` + 'ab'.repeat(32))).match, 'unverifiable-digest-type');
}
eq('the reserved digest type is named, not left null', D.parseDs('60485 5 0 ab').digestName, 'RESERVED');
eq('a DS that did not parse is unverifiable', (await matchOne('not a ds record')).match, 'unverifiable');
eq('a DS with a bad digest length is unverifiable, never a mismatch',
  (await matchOne('60485 5 2 D4B7D5')).match, 'unverifiable');

/* ── The runtime is never allowed to accuse the operator ─────────────── */

// Capability is tested by executing. A runtime with no crypto.subtle, or one
// that rejects an algorithm it advertised, produces `unverifiable` — "our
// environment could not hash this" and "your zone is broken" are different
// sentences and only one of them is ours to say.
const realCrypto = sandbox.crypto;
sandbox.crypto = undefined;
eq('no crypto.subtle at all is unverifiable, never a mismatch',
  (await matchOne(RFC4509_DS)).match, 'unverifiable');
sandbox.crypto = { subtle: { digest: async () => { throw Object.assign(new Error('nope'), { name: 'NotSupportedError' }); } } };
eq('a runtime rejecting the algorithm is unverifiable, never a mismatch',
  (await matchOne(RFC4509_DS)).match, 'unverifiable');
sandbox.crypto = realCrypto;
eq('and the real runtime still confirms once restored',
  (await matchOne(RFC4509_DS)).match, 'confirmed');

/* ── Key tag collisions ──────────────────────────────────────────────── */

// A key tag is not unique. Every DNSKEY sharing the tag and algorithm is
// tried, and the DS confirms if any of them hashes correctly.
const decoy = D.parseDnskey('256 3 5 ' + Buffer.concat([
  Buffer.from([0x03, 1, 0, 1]), Buffer.alloc(128, 0xab)]).toString('base64'));
decoy.keyTag = 60485;   // force the collision the real world produces by chance
eq('a colliding decoy ahead of the real key still confirms',
  (await matchOne(RFC4509_DS, [decoy, ...rfcKeySet])).match, 'confirmed');
// The tag cannot identify WHICH candidate was selected — every key in a
// collision set shares it by definition, and RFC 4034 Appendix B says so. The
// index is the fact that distinguishes them, and asserting on the tag alone
// proved nothing at all.
eq('the tag alone cannot distinguish collision candidates',
  [decoy.keyTag, rfcKeySet[0].keyTag], [60485, 60485]);
eq('so the match points at the key that actually hashed, by index',
  (await matchOne(RFC4509_DS, [decoy, ...rfcKeySet])).matchedKeyIndex, 1);
eq('and with the real key first, at index 0',
  (await matchOne(RFC4509_DS, [...rfcKeySet, decoy])).matchedKeyIndex, 0);

/* ── Eligibility sits beside the match, never inside it ──────────────── */

const eligibilityOf = async keyText => {
  const key = D.parseDnskey(keyText);
  const ds = D.parseDs(`${key.keyTag} ${key.algorithm} 2 ` + await sha256Of(key));
  return D.matchDsSet([ds], [key], OWNER);
};
// Build the true DS for an arbitrary key so each case differs only in the flag
// or algorithm under test, never in whether the digest is right.
async function sha256Of(key) {
  const owner = D.dnsWireName(OWNER);
  const rdata = D.dnskeyRdata(key);
  const input = new Uint8Array(owner.length + rdata.length);
  input.set(owner, 0); input.set(rdata, owner.length);
  return Buffer.from(await crypto.subtle.digest('SHA-256', input)).toString('hex');
}
const KEY_BODY = RFC4034_KEY.split(' ').slice(3).join(' ');

// Zone bit clear: RFC 4034 §2.1.1 forbids the key verifying RRsets.
const nonZoneSet = await eligibilityOf(`1 3 5 ${KEY_BODY}`);
eq('a DS confirming a zone-bit-clear key still confirms the digest',
  nonZoneSet.ds[0].match, 'confirmed');
eq('but that key cannot anchor the delegation', nonZoneSet.anchorConfirmed, false);

// IANA Zone Signing: N. RSAMD5 is named and parseable and still ineligible.
const ineligibleSet = await eligibilityOf('256 3 1 qrvMEjRW');
eq('a DS confirming a non-zone-signing algorithm still confirms the digest',
  ineligibleSet.ds[0].match, 'confirmed');
eq('but an ineligible algorithm cannot anchor', ineligibleSet.anchorConfirmed, false);
eq('and the reason is carried beside the match',
  ineligibleSet.ds[0].matchedKeyAlgorithmEligibility, 'ineligible');

// Impossible key material cannot be usable anchoring evidence.
const malformedSet = await eligibilityOf('257 3 15 AA==');
eq('a DS confirming structurally impossible material still confirms the digest',
  malformedSet.ds[0].match, 'confirmed');
eq('but invalid key structure cannot anchor', malformedSet.anchorConfirmed, false);

// The REVOKE flag is the one that concludes nothing. RFC 5011 §2.1 needs a
// validated self-signature this release does not compute, so the flag is
// reported and the key still anchors.
const revokedSet = await eligibilityOf(`385 3 5 ${KEY_BODY}`);
eq('a REVOKE flag is reported', revokedSet.ds[0].matchedKeyHasRevokeFlag, true);
eq('and it does NOT stop the key anchoring — the proof is incomplete, not negative',
  revokedSet.anchorConfirmed, true);

// SEP is advisory (RFC 6840 §6.2) and must never be required by the matcher.
const noSepSet = await eligibilityOf(`256 3 5 ${KEY_BODY}`);
eq('a key without the SEP bit anchors perfectly well', noSepSet.anchorConfirmed, true);

/* ── Published ECDSA vectors, RFC 6605 §§6.1–6.2 (R4-F5) ─────────────
   Spec 1.3's fixture table requires "SHA-384 DS → confirmed via SHA-384", and
   section 46 tested only SHA-1 and SHA-256. These are the RFC's own examples,
   so digest type 4 and the two ECDSA curves are verified against published
   numbers rather than against this implementation's output.
   ──────────────────────────────────────────────────────────────────────── */

const RFC6605_P256_KEY = '257 3 13 GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==';
const RFC6605_P256_DS = '55648 13 2 b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17';
const RFC6605_P384_KEY = '257 3 14 xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40';
const RFC6605_P384_DS = '10771 14 4 72d7b62976ce06438e9c0bf319013cf801f09ecc84b8d7e9495f27e305c6a9b0563a9b5f4d288405c3008a946df983d6';

eq('RFC 6605 §6.1 P-256 key tag is the RFC\'s stated 55648',
  D.parseDnskey(RFC6605_P256_KEY).keyTag, 55648);
eq('RFC 6605 §6.2 P-384 key tag is the RFC\'s stated 10771',
  D.parseDnskey(RFC6605_P384_KEY).keyTag, 10771);
eq('and both are structurally valid at their curve lengths',
  [D.parseDnskey(RFC6605_P256_KEY).keyBytes, D.parseDnskey(RFC6605_P384_KEY).keyBytes], [64, 96]);
eq('the RFC 6605 §6.1 SHA-256 DS confirms its P-256 key',
  (await matchOne(RFC6605_P256_DS, [D.parseDnskey(RFC6605_P256_KEY)], 'example.net')).match, 'confirmed');
eq('the RFC 6605 §6.2 SHA-384 DS confirms its P-384 key',
  (await matchOne(RFC6605_P384_DS, [D.parseDnskey(RFC6605_P384_KEY)], 'example.net')).match, 'confirmed');
eq('and SHA-384 is genuinely the digest that ran',
  D.parseDs(RFC6605_P384_DS).digestName, 'SHA-384');
eq('the P-384 DS under the P-256 key does not confirm',
  (await matchOne(RFC6605_P384_DS, [D.parseDnskey(RFC6605_P256_KEY)], 'example.net')).match, 'no-matching-key');

/* ── Precedence and reasons (R4-F1, R4-F2, R4-F4) ────────────────────── */

// A completed proof cannot be revoked by failing to inspect another candidate.
// Before this the verdict depended on array order.
const flaky = onFirst => ({ subtle: { digest: async (alg, data) => {
  if (onFirst-- > 0) return realCrypto.subtle.digest(alg, data);
  throw Object.assign(new Error('transient'), { name: 'OperationError' });
} } });
sandbox.crypto = flaky(1);
eq('a confirmation survives a later candidate failing to hash',
  (await matchOne(RFC4509_DS, [...rfcKeySet, decoy])).match, 'confirmed');
sandbox.crypto = flaky(0);
eq('but with nothing confirmed, a failure is unverifiable and says why',
  [(await matchOne(RFC4509_DS)).match, (await matchOne(RFC4509_DS)).unverifiableReason],
  ['unverifiable', 'runtime-unavailable']);
sandbox.crypto = realCrypto;

// "No key carries that tag and algorithm" needs no hashing to establish, so it
// must not hide behind a digest this build cannot compute — that made an
// absent key change verdict according to which hashes are implemented, and
// dropped the DS out of `orphanDs` entirely.
eq('an orphan DS with an uncomputable digest is still an orphan',
  (await matchOne('11111 5 3 ' + 'ab'.repeat(32))).match, 'no-matching-key');
eq('and it reaches orphanDs',
  (await D.matchDsSet([D.parseDs('11111 5 3 ' + 'ab'.repeat(32))], rfcKeySet, OWNER)).orphanDs, [11111]);
eq('while an uncomputable digest WITH a candidate is a digest-type problem',
  (await matchOne('60485 5 3 ' + 'ab'.repeat(32))).match, 'unverifiable-digest-type');

// Four different failures shared one token; a detail panel could not tell an
// operator which had happened.
eq('each unverifiable outcome carries its own reason', [
  (await matchOne('not a ds record')).unverifiableReason,
  (await matchOne(RFC4509_DS, rfcKeySet, '\u212A.example')).unverifiableReason,
  (await matchOne(RFC4509_DS, [{
    valid: true, keyTag: 60485, algorithm: 5, protocol: 3, flags: 256,
    publicKey: 'not!base64!', algorithmEligibility: 'eligible',
    hasZoneFlag: true, keyStructure: 'valid', hasRevokeFlag: false,
  }])).unverifiableReason,
], ['invalid-ds', 'invalid-owner', 'unbuildable-key']);
eq('and an uncomputable digest type is its own verdict, not a reason',
  [(await matchOne('60485 5 3 ' + 'ab'.repeat(32))).match,
   (await matchOne('60485 5 3 ' + 'ab'.repeat(32))).unverifiableReason],
  ['unverifiable-digest-type', null]);

/* ── Digest registry eligibility (R4-F3) ─────────────────────────────── */

// The IANA "Use for DNSSEC Validation" column, which is the applicable one:
// this tool inspects delegations that exist rather than creating them. The two
// columns disagree, and reading the delegation column would mark every SHA-1
// anchor in use as prohibited.
eq('SHA-1 is permitted for validation even though delegation forbids it',
  D.dnssecDigestEligibility(1), 'eligible');
eq('the reserved type 0 is affirmatively prohibited', D.dnssecDigestEligibility(0), 'ineligible');
eq('GOST R 34.11-94 is affirmatively prohibited',     D.dnssecDigestEligibility(3), 'ineligible');
eq('SHA-256 and SHA-384 are permitted',
  [D.dnssecDigestEligibility(2), D.dnssecDigestEligibility(4)], ['eligible', 'eligible']);
eq('MAY-strength digests are permitted, not merely tolerated',
  [D.dnssecDigestEligibility(5), D.dnssecDigestEligibility(6)], ['eligible', 'eligible']);
eq('unassigned, reserved and private-use ranges make no claim',
  [D.dnssecDigestEligibility(7), D.dnssecDigestEligibility(200), D.dnssecDigestEligibility(253), D.dnssecDigestEligibility(255)],
  ['unknown', 'unknown', 'unknown', 'unknown']);

// Named so a reserved or private-use value cannot read as a future assignment.
eq('the registry ranges are named distinguishably',
  [D.dnssecDigestName(0), D.dnssecDigestName(200), D.dnssecDigestName(253), D.dnssecDigestName(7), D.dnssecDigestName(255)],
  ['RESERVED', 'RESERVED', 'PRIVATE-USE', null, null]);
eq('a DS carries the registry determination beside the digest',
  [D.parseDs('1 8 3 ' + 'ab'.repeat(32)).digestEligibility,
   D.parseDs('1 8 2 ' + 'ab'.repeat(32)).digestEligibility],
  ['ineligible', 'eligible']);
// An affirmative prohibition is not the same statement as "we lack the code".
eq('a prohibited digest and an unimplemented one are distinguishable',
  [(await matchOne('60485 5 3 ' + 'ab'.repeat(32))).digestEligibility,
   (await matchOne('60485 5 5 ' + 'ab'.repeat(32))).digestEligibility],
  ['ineligible', 'eligible']);

/* ── The set, and the paypal.com shape ───────────────────────────────── */

// RFC 6840 §5.11: where several DS records exist for keys of one algorithm,
// "any subset of those may appear in the DNSKEY RRset". One confirming DS
// beside one orphan is a healthy zone, and this is the exact shape paypal.com
// publishes — the case that overturned the 1.0 design.
const anchorKey = rfcKeySet[0];
const trueDs = D.parseDs(RFC4509_DS);
const orphanDs = D.parseDs('34800 5 2 ' + 'cd'.repeat(32));
const mixed = await D.matchDsSet([trueDs, orphanDs], rfcKeySet, OWNER);
eq('a confirming DS beside an orphan still anchors', mixed.anchorConfirmed, true);
eq('and the orphan is reported by key tag', mixed.orphanDs, [34800]);
eq('order does not matter',
  (await D.matchDsSet([orphanDs, trueDs], rfcKeySet, OWNER)).anchorConfirmed, true);

eq('an empty DS set anchors nothing and reports no orphan',
  await D.matchDsSet([], rfcKeySet, OWNER), { ds: [], anchorConfirmed: false, orphanDs: [] });
eq('a DS set that only mismatches anchors nothing',
  (await D.matchDsSet([D.parseDs('60485 5 2 ' + 'ab'.repeat(32))], rfcKeySet, OWNER)).anchorConfirmed, false);
eq('and a mismatch is not reported as an orphan',
  (await D.matchDsSet([D.parseDs('60485 5 2 ' + 'ab'.repeat(32))], rfcKeySet, OWNER)).orphanDs, []);

// Candidates that exist but cannot be hashed must not become a verdict. A key
// object claiming to be valid whose material will not decode is skipped, and
// skipping every candidate has to land on `unverifiable` — reporting
// `digest-mismatch` there announces a broken chain from arithmetic that never
// ran. parseDnskey() cannot produce such a key today; a saved report from
// another release or a caller building key objects by hand can.
const undecodable = {
  valid: true, keyTag: 60485, algorithm: 5, protocol: 3, flags: 256,
  publicKey: 'not!base64!', algorithmEligibility: 'eligible',
  hasZoneFlag: true, keyStructure: 'valid', hasRevokeFlag: false,
};
eq('a candidate whose RDATA cannot be rebuilt yields no RDATA', D.dnskeyRdata(undecodable), null);
eq('and skipping every candidate is unverifiable, never a mismatch',
  (await matchOne(RFC4509_DS, [undecodable])).match, 'unverifiable');
eq('one good key beside an unhashable one still confirms',
  (await matchOne(RFC4509_DS, [undecodable, ...rfcKeySet])).match, 'confirmed');

/* ── matchConfirmsAnchor, directly ───────────────────────────────────── */

// The digest-eligibility half of the anchoring rule is unreachable through the
// matcher today: the only affirmatively prohibited digest types, 0 and 3, are
// also ones Web Crypto cannot compute, so they never reach `confirmed`. That
// makes it exactly the kind of guard which reads as protection and is never
// exercised — mutating it away failed nothing. Reached here directly, because
// the pairing is not guaranteed to hold: a future registry entry can be both
// computable and prohibited, and this is the rule that would catch it.
const confirmedMatch = extra => Object.assign({
  match: 'confirmed',
  digestEligibility: 'eligible',
  matchedKeyAlgorithmEligibility: 'eligible',
  matchedKeyHasZoneFlag: true,
  matchedKeyStructure: 'valid',
}, extra);

eq('a fully eligible confirmed match anchors', D.matchConfirmsAnchor(confirmedMatch()), true);
eq('a prohibited digest type does not anchor even when it confirms',
  D.matchConfirmsAnchor(confirmedMatch({ digestEligibility: 'ineligible' })), false);
eq('an unknown digest type still anchors — no determination is not a prohibition',
  D.matchConfirmsAnchor(confirmedMatch({ digestEligibility: 'unknown' })), true);
eq('a verdict other than confirmed never anchors',
  ['digest-mismatch', 'no-matching-key', 'unverifiable', 'unverifiable-digest-type']
    .map(match => D.matchConfirmsAnchor(confirmedMatch({ match }))),
  [false, false, false, false]);
eq('the key half of the rule still applies here',
  [D.matchConfirmsAnchor(confirmedMatch({ matchedKeyHasZoneFlag: false })),
   D.matchConfirmsAnchor(confirmedMatch({ matchedKeyAlgorithmEligibility: 'ineligible' })),
   D.matchConfirmsAnchor(confirmedMatch({ matchedKeyStructure: 'invalid' }))],
  [false, false, false]);
eq('and nothing anchors on a missing match', D.matchConfirmsAnchor(null), false);

/* ── dnskeyCanAnchor, directly ───────────────────────────────────────── */

eq('the anchoring predicate needs all three affirmative facts',
  [D.dnskeyCanAnchor(anchorKey),
   D.dnskeyCanAnchor(Object.assign({}, anchorKey, { hasZoneFlag: false })),
   D.dnskeyCanAnchor(Object.assign({}, anchorKey, { algorithmEligibility: 'unknown' })),
   D.dnskeyCanAnchor(Object.assign({}, anchorKey, { keyStructure: 'invalid' })),
   D.dnskeyCanAnchor(Object.assign({}, anchorKey, { hasRevokeFlag: true })),
   D.dnskeyCanAnchor(null)],
  [true, false, false, false, true, false]);

// The rule lives in one place. `dnskeyCanAnchor()` reads it off a key object
// and `matchDsSet()` reads it off the published match fields, and both defer
// to `anchorFactsUsable()` — stated twice they drift, and a mutation that
// wrongly disqualified a REVOKE-flagged key was caught by only one of the two
// before they were joined.
eq('both anchoring paths agree across the whole fact space', await (async () => {
  const disagreements = [];
  for (const eligibility of ['eligible', 'ineligible', 'unknown']) {
    for (const hasZoneFlag of [true, false]) {
      for (const keyStructure of ['valid', 'invalid', 'unknown']) {
        const viaKey = D.dnskeyCanAnchor({ algorithmEligibility: eligibility, hasZoneFlag, keyStructure });
        const viaFacts = D.anchorFactsUsable(eligibility, hasZoneFlag, keyStructure);
        if (viaKey !== viaFacts) disagreements.push([eligibility, hasZoneFlag, keyStructure]);
      }
    }
  }
  return disagreements;
})(), []);
}

/* ── 47. The DNSSEC state classifier (spec §4) ────────────────────────
   Step 4. The classifier is ORDERED and the order is normative:
   dnssec-failed.org satisfies three of its rules at once. Rules 4 and 5 also
   require the lookups they reason about to have completed, which is what stops
   a failed DS query reading as "no DS published".

   The invariant these fixtures exist to protect: rules 4, 5 and 6 are
   reachable only when AD is false, and `signed === (state === 'secure')`, so
   `signed` is identical to 0.4.0 by construction. Measured against the real
   released v0.4.0 function across 49 live domains: zero differences.
   ──────────────────────────────────────────────────────────────────────── */
section('47. The DNSSEC state classifier');
{
const OWNER = 'dskey.example.com';
const KEY = '256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==';
const TRUE_DS = '60485 5 2 D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A';
const WRONG_DS = '60485 5 2 ' + 'ab'.repeat(32);
const ORPHAN_DS = '11111 5 2 ' + 'cd'.repeat(32);

const chain = async map => {
  sandbox.fetch = dohFixture(map);
  return D.checkDNSSEC(OWNER, { retries: 0, noCache: true });
};
const signedNs = { ad: true, answers: ns('a.example') };
const unsignedNs = { ad: false, answers: ns('a.example') };

/* ── Rule 3: the resolver's verdict is the only route to `secure` ────── */

const secure = await chain({
  [`${OWNER} NS`]: signedNs,
  [`${OWNER} DNSKEY`]: dnskey(KEY),
  [`${OWNER} DS`]: ds(TRUE_DS),
});
eq('AD true is secure', [secure.state, secure.signed], ['secure', true]);
eq('and the local evidence confirms alongside it', secure.anchorConfirmed, true);

// servfail.nl, in fixture form: every local fact agrees and the zone is bogus.
// Local evidence must never assemble a `secure` claim on its own.
const bogusButConfirming = await chain({
  [`${OWNER} NS`]: 'servfail',
  [`${OWNER} NS cd`]: signedNs,     // answers with checking disabled → bogus
  [`${OWNER} DNSKEY`]: dnskey(KEY),
  [`${OWNER} DS`]: ds(TRUE_DS),
});
eq('a bogus zone whose DS confirms locally is still bogus',
  [bogusButConfirming.state, bogusButConfirming.signed], ['bogus', false]);
eq('and the confirmation is still reported as evidence',
  bogusButConfirming.anchorConfirmed, true);

/* ── Rule 1 outranks everything below it ─────────────────────────────── */

// dnssec-failed.org satisfies rules 1, 2 and 5 simultaneously.
const bogus = await chain({
  [`${OWNER} NS`]: 'servfail',
  [`${OWNER} NS cd`]: signedNs,
  [`${OWNER} DNSKEY`]: 'servfail',
  [`${OWNER} DS`]: ds(TRUE_DS),
});
eq('SERVFAIL that answers with cd=1 is bogus, not indeterminate or mismatch',
  bogus.state, 'bogus');

// A SERVFAIL that stays a SERVFAIL with checking disabled is not bogus — the
// resolver never gave a usable answer either way.
sandbox.fetch = dohFixture({ [`${OWNER}`]: 'servfail' });
eq('SERVFAIL both ways is indeterminate',
  (await D.checkDNSSEC(OWNER, { retries: 0, noCache: true })).state, 'indeterminate');

/* ── Rule 2, and the NXDOMAIN boundary inherited from 0.4.0 ──────────── */

const timedOut = await chain({ [`${OWNER} NS`]: 'http-error', [`${OWNER} DNSKEY`]: dnskey(KEY), [`${OWNER} DS`]: 'nodata' });
eq('an NS probe that did not complete is indeterminate', timedOut.state, 'indeterminate');
eq('and it carries the reason', timedOut.error, 'http-error');
// 0.4.0 treated NXDOMAIN on the NS probe as indeterminate rather than
// insecure. Both score zero, but only `indeterminate` marks the pillar
// unproven, so moving it would change what the interface reports.
eq('NXDOMAIN on the NS probe stays indeterminate, as at 0.4.0',
  (await chain({ [`${OWNER} NS`]: 'nxdomain', [`${OWNER} DNSKEY`]: 'nodata', [`${OWNER} DS`]: 'nodata' })).state,
  'indeterminate');

/* ── Rule 4: unanchored, and the failed-lookup precondition ──────────── */

const unanchored = await chain({
  [`${OWNER} NS`]: unsignedNs,
  [`${OWNER} DNSKEY`]: dnskey(KEY),
  [`${OWNER} DS`]: 'nodata',
});
eq('DNSKEY published with a completed DS lookup returning nothing is unanchored',
  unanchored.state, 'unanchored');
eq('and it is still unsigned, so no grade can move', unanchored.signed, false);

// The defect this precondition exists to stop: a failed DS lookup leaves the
// same empty array as a completed one that found nothing.
const dsFailed = await chain({
  [`${OWNER} NS`]: unsignedNs,
  [`${OWNER} DNSKEY`]: dnskey(KEY),
  [`${OWNER} DS`]: 'servfail',
});
eq('a FAILED DS lookup is never unanchored', dsFailed.state, 'insecure');
eq('and the missing evidence is stated rather than inferred',
  [dsFailed.lookups.ds.completed, dsFailed.lookups.ds.kind, dsFailed.evidence],
  [false, 'servfail', 'partial']);

/* ── Rule 5: mismatch needs positive local proof ─────────────────────── */

eq('a DS that hashes to something else is a mismatch',
  (await chain({ [`${OWNER} NS`]: unsignedNs, [`${OWNER} DNSKEY`]: dnskey(KEY), [`${OWNER} DS`]: ds(WRONG_DS) })).state,
  'mismatch');
eq('a DS pointing at a key the child does not publish is a mismatch',
  (await chain({ [`${OWNER} NS`]: unsignedNs, [`${OWNER} DNSKEY`]: dnskey(KEY), [`${OWNER} DS`]: ds(ORPHAN_DS) })).state,
  'mismatch');

// Never on evidence that could not be gathered.
eq('a failed DNSKEY lookup is never a mismatch',
  (await chain({ [`${OWNER} NS`]: unsignedNs, [`${OWNER} DNSKEY`]: 'servfail', [`${OWNER} DS`]: ds(WRONG_DS) })).state,
  'insecure');
eq('an uncomputable digest is never a mismatch',
  (await chain({ [`${OWNER} NS`]: unsignedNs, [`${OWNER} DNSKEY`]: dnskey(KEY), [`${OWNER} DS`]: ds('60485 5 3 ' + 'ab'.repeat(32)) })).state,
  'insecure');
// §3: a DS confirming only a key that cannot anchor falls to the residual,
// because a critical alarm on a mid-rollover zone is the paypal.com failure.
// The DS has to be computed over THIS key's RDATA — the flags are part of the
// hashed material, so reusing the DS for the flags-256 key would merely be a
// digest mismatch and would test rule 5 instead of the residual.
const nonZoneKey = D.parseDnskey(`1 3 5 ${KEY.split(' ').slice(3).join(' ')}`);
const nonZoneOwner = D.dnsWireName(OWNER);
const nonZoneRdata = D.dnskeyRdata(nonZoneKey);
const nonZoneInput = new Uint8Array(nonZoneOwner.length + nonZoneRdata.length);
nonZoneInput.set(nonZoneOwner, 0); nonZoneInput.set(nonZoneRdata, nonZoneOwner.length);
const nonZoneDs = `${nonZoneKey.keyTag} 5 2 ` +
  Buffer.from(await crypto.subtle.digest('SHA-256', nonZoneInput)).toString('hex');
const ineligible = await chain({
  [`${OWNER} NS`]: unsignedNs,
  [`${OWNER} DNSKEY`]: dnskey(`1 3 5 ${KEY.split(' ').slice(3).join(' ')}`),
  [`${OWNER} DS`]: ds(nonZoneDs),
});
eq('the DS genuinely confirms that key', ineligible.ds[0].match, 'confirmed');
eq('but the key cannot anchor, so nothing is anchored', ineligible.anchorConfirmed, false);
eq('and a DS confirming only an ineligible key falls to the residual, not mismatch',
  ineligible.state, 'insecure');

/* ── Rule 6 residual, and the evidence summary ───────────────────────── */

const insecure = await chain({ [`${OWNER} NS`]: unsignedNs, [`${OWNER} DNSKEY`]: 'nodata', [`${OWNER} DS`]: 'nodata' });
eq('nothing published anywhere is insecure', insecure.state, 'insecure');
eq('and both lookups completed, so the absence is evidence',
  [insecure.lookups.ds.completed, insecure.lookups.dnskey.completed, insecure.evidence],
  [true, true, 'complete']);
eq('neither lookup completing reports no evidence at all',
  (await chain({ [`${OWNER} NS`]: unsignedNs, [`${OWNER} DNSKEY`]: 'servfail', [`${OWNER} DS`]: 'servfail' })).evidence,
  'none');

/* ── A partial lookup never demotes a validated zone ─────────────────── */

const secureDespiteGap = await chain({
  [`${OWNER} NS`]: signedNs,
  [`${OWNER} DNSKEY`]: 'servfail',
  [`${OWNER} DS`]: ds(TRUE_DS),
});
eq('a failed DNSKEY lookup on an AD-true zone is still secure',
  [secureDespiteGap.state, secureDespiteGap.signed], ['secure', true]);
eq('and the gap is recorded rather than scored', secureDespiteGap.evidence, 'partial');

/* ── RRSIG companions are ignored (spec §1) ──────────────────────────── */

const withRrsig = await chain({
  [`${OWNER} NS`]: signedNs,
  [`${OWNER} DNSKEY`]: [...dnskey(KEY), ...rrsig('DNSKEY 5 3 3600 1792128637 1786858237 60485 dskey.example.com. abcd')],
  [`${OWNER} DS`]: [...ds(TRUE_DS), ...rrsig('DS 5 2 3600 1792128637 1786858237 60485 example.com. abcd')],
});
eq('an RRSIG beside the records is not parsed as one',
  [withRrsig.keys.length, withRrsig.ds.length], [1, 1]);
eq('and the real records still confirm', withRrsig.anchorConfirmed, true);

/* ── Attribution (acceptance criteria 1 and 2) ───────────────────────── */

eq('every chain entry is attributed to the resolver or to local computation',
  secure.chain.filter(c => c.source !== 'resolver' && c.source !== 'local'), []);
eq('the resolver AD flag is attributed to the resolver',
  secure.chain.some(c => c.claim === 'resolver-ad' && c.source === 'resolver'), true);
eq('the digest match is attributed to local computation',
  secure.chain.some(c => c.claim === 'ds-confirms-dnskey' && c.source === 'local'), true);
// OQ-SEC9-03: showing one link without naming it implies a completeness this
// release does not have.
eq('the chain states which link was checked',
  secure.chain.filter(c => c.claim === 'link-checked')
    .map(c => [c.source, c.detail.link]),
  [['local', 'child-dnskey-to-parent-ds']]);
eq('an incomplete lookup appears in the chain',
  dsFailed.chain.filter(c => c.claim === 'lookup-incomplete').map(c => c.detail.query), ['ds']);

/* ── Deprecation reporting ───────────────────────────────────────────── */

eq('a deprecated algorithm is reported from the key set',
  secure.deprecatedAlgorithms, [5]);
eq('a SHA-1 DS reports the deprecated digest type',
  (await chain({ [`${OWNER} NS`]: signedNs, [`${OWNER} DNSKEY`]: dnskey(KEY),
    [`${OWNER} DS`]: ds('60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118') })).deprecatedDigests,
  [1]);

/* ── The invariant, stated as a test ─────────────────────────────────── */

// `signed` must equal `state === 'secure'` for every state the classifier can
// produce, which is what makes "no grade moves" a property of the table rather
// than a hope about the fixtures.
eq('signed is exactly state === secure, in every state',
  [secure, bogus, timedOut, unanchored, dsFailed, insecure, secureDespiteGap]
    .map(r => r.signed === (r.state === 'secure')),
  [true, true, true, true, true, true, true]);
eq('and only AD true ever produces secure',
  [secure, secureDespiteGap, bogusButConfirming, unanchored, insecure]
    .map(r => [r.state === 'secure', r.resolverValidated]),
  [[true, true], [true, true], [false, false], [false, false], [false, false]]);
}

/* ── Summary ─────────────────────────────────────────────────────────── */
console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
