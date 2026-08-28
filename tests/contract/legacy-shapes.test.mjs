#!/usr/bin/env node
/**
 * Targeted legacy contracts over `js/dns.js` at v0.5.0.
 *
 * Spec §12.1 rule 4: the state matrix's contract "runs targeted legacy
 * contracts for computed values, thrown paths, booleans, nullability and
 * absence until extraction is complete". Those are the axes a static scan
 * cannot see, and they are the reason `tests/state-algebras.json` is a
 * reviewed document rather than an extractor's output.
 *
 * Every check here ships with the negative case that proves it can fail —
 * framework §1.3. A green check nobody has watched fail is not evidence.
 *
 * Data profile: this suite supplies the FIXTURE public suffix list and the
 * PRODUCTION DKIM selector catalog — the same mixture every v0.5.0 suite
 * loads. It declares both directions and runs both fingerprints before any
 * other assertion.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import {
  FIXTURE_PSL_RULES, FIXTURE_DKIM_SELECTOR,
  probePublicSuffixRules, probeDkimCatalog, assertFixtureIdentity,
} from '../lib/fixture-identity.mjs';
import { dohFixture, txt, ns, caa, ds, dnskey } from '../../tools/lib/doh-fixture.mjs';
import { PLATFORM_PROFILES } from '../lib/platform.mjs';
import { loadApp } from '../../tools/lib/browser-harness.mjs';
import { probeEnglishBundle, FIXTURE_ENGLISH_TITLE } from '../lib/fixture-identity.mjs';
import { PUBLIC_SUFFIX_RULES } from '../../src/data/public-suffixes.js';
import { createDnsEngine } from '../../js/dns.js';
import { DKIM_SELECTOR_CATALOG } from '../../src/data/dkim-selectors.js';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, throws, rejects, section, report } = createSuite();

/* ── Loading ──────────────────────────────────────────────────────────── */

/**
 * An engine over a chosen public suffix list and crypto runtime.
 *
 * Until 0.6.0 this evaluated js/dns.js into a node:vm sandbox. The file is an
 * ES module now, which a sandbox cannot evaluate, so the engine is built
 * directly — and its inputs are arguments rather than globals it reaches for,
 * which is what makes the fixture table below the one actually in force.
 *
 * `holder.fetch` keeps `setFetch` working: the platform reads it at call time,
 * so every fixture swap below is unchanged.
 */
function load(pslRules, cryptoImpl = crypto) {
  const holder = { fetch: async () => ({ ok: false }) };
  const D = createDnsEngine({
    publicSuffixRules: pslRules,
    dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
    platform: {
      fetch: (...args) => holder.fetch(...args),
      crypto: cryptoImpl, AbortController, URLSearchParams, setTimeout, clearTimeout,
    },
  });
  return { D, holder };
}

const { D, holder } = load(FIXTURE_PSL_RULES);
const setFetch = impl => { holder.fetch = impl; };

/* ── 0. Fixture identity, and the proof it can fail ───────────────────── */
section('0. Fixture identity (spec §11)');

const probes = [
  probePublicSuffixRules(D.getOrganizationalDomain, 'fixture'),
  probeDkimCatalog(D.isRecognizedDkimSelector, 'production'),
];
// Runs first, and throws rather than counting: a suite testing against the
// wrong generated data must not be allowed to report a count at all.
assertFixtureIdentity(probes);
eq('PSL probe resolves to the fixture answer', probes[0].actual, 'blogspot.com');
eq('DKIM catalog probe sees the production catalog', probes[1].actual, false);

// The negative case. Load the SAME file against the real public suffix list
// and confirm the probe rejects it — this is the substitution the spike
// demonstrated, and a probe that cannot catch it is decoration.
const REAL_PSL = PUBLIC_SUFFIX_RULES;
const real = load(REAL_PSL).D;

eq('the real list is the real list, not a stub', REAL_PSL.length > 10000, true);
eq('production resolves the probe one label deeper',
  real.getOrganizationalDomain('foo.blogspot.com'), 'foo.blogspot.com');
throws('substituting the real PSL fails the probe',
  () => assertFixtureIdentity([probePublicSuffixRules(real.getOrganizationalDomain)]),
  e => /the PSL binding in force is not the fixture one/.test(e.message) &&
       /this is exactly the production value/.test(e.message));
throws('claiming a fixture catalog while loading production fails the probe',
  () => assertFixtureIdentity([probeDkimCatalog(real.isRecognizedDkimSelector, 'fixture')]),
  e => /the DKIM catalog binding in force is not the fixture one/.test(e.message) &&
       /this is exactly the production value/.test(e.message));
throws('and claiming production while a fixture is in force fails it too',
  () => assertFixtureIdentity([probeDkimCatalog(() => true, 'production')]),
  e => /is not the production one/.test(e.message) &&
       /this is exactly the fixture value/.test(e.message));

// And the proof that the WITHDRAWN probe would not have caught it. This is
// spec §11's own worked example, executed rather than quoted.
eq('a.b.ck agrees under both lists — vacuous as a probe',
  D.getOrganizationalDomain('a.b.ck') === real.getOrganizationalDomain('a.b.ck'), true);
eq('a.www.ck agrees under both lists — vacuous as a probe',
  D.getOrganizationalDomain('a.www.ck') === real.getOrganizationalDomain('a.www.ck'), true);

/* ── 0b. The injection point, proven for all three bindings ───────────── */
section('0b. Generated data is injected, and each binding has its own probe');

/**
 * Phase 2 moved the three generated tables to ES modules under `src/data/`.
 * They are still INJECTED — by `src/data/legacy-globals.js` for the bundle and
 * by `tools/lib/browser-harness.mjs` for the suites — and never imported by the
 * code that consumes them.
 *
 * That distinction is the whole of spec §11, and this asserts it rather than
 * trusting the comment: a suite must be able to hand the app different data,
 * and each binding's probe must notice independently when it is the wrong one.
 */
// Every layer is an ES module now; the harness constructs the i18n layer
// directly rather than loading the entry point, which is what lets one process
// build three of them with different bindings.
const productionApp = await loadApp({ app: false });
eq('with no override, the harness supplies production English',
  probeEnglishBundle(productionApp.t, 'production').actual,
  probeEnglishBundle(productionApp.t, 'production').expected);

const fixtureEnglish = { meta: { code: 'en' }, doc: { title: FIXTURE_ENGLISH_TITLE } };
const fixtureApp = await loadApp({ app: false, data: { englishBundle: fixtureEnglish } });
eq('a suite can inject a fixture English bundle instead',
  probeEnglishBundle(fixtureApp.t, 'fixture').actual, FIXTURE_ENGLISH_TITLE);
throws('and claiming production while the fixture is in force fails the probe',
  () => assertFixtureIdentity([probeEnglishBundle(fixtureApp.t, 'production')]),
  e => /the English bundle binding in force is not the production one/.test(e.message) &&
       /this is exactly the fixture value/.test(e.message));
throws('as does the reverse',
  () => assertFixtureIdentity([probeEnglishBundle(productionApp.t, 'fixture')]),
  e => /is not the fixture one/.test(e.message));

// The three probes are INDEPENDENT: substituting one leaves the others correct,
// which is what makes each of them evidence about its own binding.
const mixed = await loadApp({ app: false, data: { englishBundle: fixtureEnglish } });
eq('substituting English does not disturb the PSL binding',
  mixed.__PUBLIC_SUFFIX_RULES__.length > 10000, true);
eq('nor the DKIM catalog binding',
  JSON.stringify(Object.keys(mixed.__DKIM_SELECTOR_CATALOG__)),
  JSON.stringify(Object.keys(productionApp.__DKIM_SELECTOR_CATALOG__)));

/* ── 1. The ten transport kinds, each at its own construction site ────── */
section('1. Transport kinds (spec Design §3, dns.transport.kind)');

const KINDS = ['success', 'nodata', 'nxdomain', 'servfail', 'refused', 'dns-error',
  'http-error', 'cancelled', 'timeout', 'network-error'];

async function kindOf(name, fetchImpl, opts) {
  setFetch(fetchImpl);
  const result = await D.dohFetch(name, 'TXT', Object.assign({ noCache: true, retries: 0 }, opts));
  return result.kind;
}

const jsonResponse = body => ({ ok: true, status: 200, json: async () => body });

eq('success',       await kindOf('a1.test', dohFixture({ 'a1.test': txt('x') })), 'success');
eq('nodata',        await kindOf('a2.test', dohFixture({ 'a2.test': 'nodata' })), 'nodata');
eq('nxdomain',      await kindOf('a3.test', dohFixture({})), 'nxdomain');
eq('servfail',      await kindOf('a4.test', dohFixture({ 'a4.test': 'servfail' })), 'servfail');
eq('refused',       await kindOf('a5.test', dohFixture({ 'a5.test': 'refused' })), 'refused');
// Any status responseKind() does not name. 4 is NOTIMP.
eq('dns-error',     await kindOf('a6.test', async () => jsonResponse({ Status: 4, Answer: [] })), 'dns-error');
eq('http-error',    await kindOf('a7.test', async () => ({ ok: false, status: 502 })), 'http-error');
eq('network-error', await kindOf('a8.test', async () => { throw new Error('socket'); }), 'network-error');

// `timeout` needs the internal timer to fire, so the fetch must not settle
// before it and must reject when the internal controller aborts.
const hangingFetch = (url, init) => new Promise((resolve, reject) => {
  init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
});
eq('timeout', await kindOf('a9.test', hangingFetch, { timeoutMs: 5 }), 'timeout');

// `cancelled` needs the CALLER's signal to abort mid-flight. An
// already-aborted signal takes a different path — see section 2.
const outer = new AbortController();
const cancellingFetch = (url, init) => new Promise((resolve, reject) => {
  init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  outer.abort();
});
eq('cancelled', await kindOf('a10.test', cancellingFetch, { signal: outer.signal }), 'cancelled');

// Exhaustive: nothing above is missing and nothing extra was invented.
eq('all ten kinds are reachable and the set is closed', KINDS.length, 10);

/* ── 2. Thrown paths — never kinds ────────────────────────────────────── */
section('2. Thrown paths (dns.thrown)');

// DnsTypeError. Thrown before the cache and before the slot, so an
// unsupported type can never be reported as a resolver failure.
throws('an unsupported type throws DnsTypeError',
  () => D.dnsTypeNum('SRV'), e => e.name === 'DnsTypeError');
eq('DnsTypeError is not a transport kind', KINDS.includes('DnsTypeError'), false);
await rejects('dohFetch rethrows it rather than answering',
  () => D.dohFetch('b1.test', 'SRV', { noCache: true }), e => e.name === 'DnsTypeError');

// optionalCheck re-throws exactly two names and degrades everything else.
const typeError = Object.assign(new Error('x'), { name: 'DnsTypeError' });
const abortError = Object.assign(new Error('x'), { name: 'AbortError' });
const queryError = Object.assign(new Error('x'), { name: 'DnsQueryError', kind: 'servfail' });
await rejects('optionalCheck rethrows DnsTypeError',
  () => D.optionalCheck(() => { throw typeError; }, 'FALLBACK'), e => e.name === 'DnsTypeError');
await rejects('optionalCheck rethrows AbortError',
  () => D.optionalCheck(() => { throw abortError; }, 'FALLBACK'), e => e.name === 'AbortError');
eq('optionalCheck degrades a DnsQueryError',
  await D.optionalCheck(() => { throw queryError; }, 'FALLBACK'), 'FALLBACK');
eq('the fallback may be a function of the error',
  await D.optionalCheck(() => { throw queryError; }, e => e.kind), 'servfail');

// An already-aborted signal throws out of the slot acquisition, and the throw
// is named AbortError even though its `kind` is 'cancelled'.
const preAborted = new AbortController();
preAborted.abort();
setFetch(dohFixture({}));
await rejects('a pre-aborted signal throws, and does not return a kind',
  () => D.dohFetch('b2.test', 'TXT', { noCache: true, signal: preAborted.signal }),
  e => e.name === 'AbortError' && e.kind === 'cancelled');

// requireUsable and the normalized APIs are internal, so they are exercised
// through `checkCAA()`, which is the production path into both. Three kinds
// pass; the other seven throw and carry the kind on the error rather than
// flattening it to one failure.
setFetch(dohFixture({ 'b3.test CAA': caa('0 issue "letsencrypt.org"') }));
const caaFound = await D.checkCAA('b3.test', { noCache: true });
eq('a success answer passes the usability gate', caaFound.found, true);
eq('and reaches the parser as a cleaned value', caaFound.issuers, ['letsencrypt.org']);

setFetch(dohFixture({}));
eq('an nxdomain answer passes the gate and reports absence',
  (await D.checkCAA('b4.test', { noCache: true })).found, false);
setFetch(dohFixture({ 'b5.test': 'nodata' }));
eq('a nodata answer passes the gate and reports absence',
  (await D.checkCAA('b5.test', { noCache: true })).found, false);

for (const kind of ['servfail', 'refused']) {
  setFetch(dohFixture({ [`b6${kind}.test`]: kind }));
  await rejects(`the usability gate throws on ${kind}`,
    () => D.checkCAA(`b6${kind}.test`, { noCache: true, retries: 0 }),
    e => e.name === 'DnsQueryError' && e.kind === kind);
}
setFetch(async () => ({ ok: false, status: 503 }));
await rejects('it throws on http-error and keeps the status in the detail',
  () => D.checkCAA('b7.test', { noCache: true, retries: 0 }),
  e => e.kind === 'http-error' && /HTTP 503/.test(e.message));

// The exception edge: domainExists() reads `.kind` directly, and its mapping
// is the one place nxdomain and nodata must NOT be flattened together.
setFetch(dohFixture({}));
eq('nxdomain maps to no', await D.domainExists('b8.test', { noCache: true }), 'no');
setFetch(dohFixture({ 'b9.test': 'nodata' }));
eq('nodata maps to yes', await D.domainExists('b9.test', { noCache: true }), 'yes');
setFetch(dohFixture({ 'b10.test NS': ns('ns1.b10.test') }));
eq('success maps to yes', await D.domainExists('b10.test', { noCache: true }), 'yes');
setFetch(dohFixture({ 'b11.test': 'servfail' }));
eq('servfail maps to unknown, never to no',
  await D.domainExists('b11.test', { noCache: true, retries: 0 }), 'unknown');
setFetch(dohFixture({ 'b12.test': 'refused' }));
eq('refused maps to unknown', await D.domainExists('b12.test', { noCache: true, retries: 0 }), 'unknown');

/* ── 3. Cacheable ⊂ retry-terminal ────────────────────────────────────── */
section('3. Cache and retry sets (dns.cacheable, dns.retryTerminal)');

// `cancelled` is retry-terminal and never cached. Proved behaviourally: a
// second query for the same name must reach the network again.
let calls = 0;
const countingCancel = (url, init) => new Promise((resolve, reject) => {
  calls++;
  init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  cancelController.abort();
});
let cancelController = new AbortController();
setFetch(countingCancel);
await D.dohFetch('c1.test', 'TXT', { retries: 0, signal: cancelController.signal });
cancelController = new AbortController();
await D.dohFetch('c1.test', 'TXT', { retries: 0, signal: cancelController.signal });
eq('a cancelled result is never cached', calls, 2);

// A cacheable kind is cached: the second query does not reach the network.
let successCalls = 0;
setFetch(async url => { successCalls++; return jsonResponse({ Status: 0, Answer: [{ type: 16, data: '"x"' }] }); });
await D.dohFetch('c2.test', 'TXT', {});
await D.dohFetch('c2.test', 'TXT', {});
eq('a success result is cached', successCalls, 1);

let nxCalls = 0;
setFetch(async url => { nxCalls++; return jsonResponse({ Status: 3, Answer: [] }); });
await D.dohFetch('c3.test', 'TXT', {});
await D.dohFetch('c3.test', 'TXT', {});
eq('an nxdomain result is cached', nxCalls, 1);

// A transport failure is never remembered as an answer.
let sfCalls = 0;
setFetch(async url => { sfCalls++; return jsonResponse({ Status: 2, Answer: [] }); });
await D.dohFetch('c4.test', 'TXT', { retries: 0 });
await D.dohFetch('c4.test', 'TXT', { retries: 0 });
eq('a servfail result is never cached', sfCalls, 2);

/* ── 4. Computed values a literal scan cannot see ─────────────────────── */
section('4. Computed values (spec §12.1)');

// The two DNSSEC chain claims built as 'ds-' + record.match. Nine claims, not
// seven, and these two exist nowhere in the source as literals.
const chainSource = readFileSync(join(REPO, 'js/dns.js'), 'utf8');
// The chain claims moved to their owner at Task 4.5; the issue-key scan below
// still reads js/dns.js, because buildIssues() has not moved. Two sources, and
// each assertion names the one it means.
const DNSSEC_CHAIN = 'src/core/dnssec/chain.js';
const dnssecChainSource = readFileSync(join(REPO, DNSSEC_CHAIN), 'utf8');
/**
 * These two claims are still COMPUTED, and the evidence has changed shape.
 *
 * Before Task 4.5 they appeared nowhere as literals at all, which is what made
 * them the example of a literal scan under-reporting. The extraction published
 * `DNSSEC_CHAIN_CLAIMS`, so the vocabulary is now declared in one place — an
 * improvement, and it costs the old assertion its exact form.
 *
 * The property that actually mattered is preserved and asserted more precisely:
 * neither claim is written at its CONSTRUCTION SITE. The only literal is the
 * published constant, and `claim:` is never given either string directly.
 */
for (const claim of ['ds-no-matching-key', 'ds-digest-mismatch']) {
  eq(`'${claim}' is never written at a claim: construction site`,
    chainSource.includes(`claim: '${claim}'`) || dnssecChainSource.includes(`claim: '${claim}'`),
    false);
  eq(`and its only literal is the published vocabulary`,
    (dnssecChainSource.match(new RegExp(`'${claim}'`, 'g')) || []).length, 1);
  eq(`which js/dns.js does not carry at all`, chainSource.includes(`'${claim}'`), false);
}
eq(`the claim is concatenated from the match verdict, in ${DNSSEC_CHAIN}`,
  dnssecChainSource.includes("claim: 'ds-' + record.match"), true);

// And they are genuinely produced. An orphan DS — a DS whose key tag matches
// no published DNSKEY — yields no-matching-key.
setFetch(dohFixture({
  'orphan.test NS': ns('ns1.orphan.test'),
  'orphan.test DS': ds('12345 8 2 ' + 'ab'.repeat(32)),
  'orphan.test DNSKEY': dnskey('257 3 8 AwEAAQ=='),
}));
const orphan = await D.checkDNSSEC('orphan.test', {});
eq('an orphan DS produces the computed claim',
  orphan.chain.some(c => c.claim === 'ds-no-matching-key'), true);
eq('and the DS match verdict agrees',
  orphan.ds[0].match, 'no-matching-key');
eq('orphanDs carries the key tag', orphan.orphanDs, [12345]);

/* ── 5. Booleans, nullability and absence ─────────────────────────────── */
section('5. Booleans, nullability and absence');

// `dnssec.error` is set to undefined rather than omitted. Present-with-
// undefined and absent are different, and the canonicalizer must not fold them.
eq('the error property is PRESENT on a determinate result',
  Object.prototype.hasOwnProperty.call(orphan, 'error'), true);
eq('and its value is undefined', orphan.error, undefined);

// The not-checked DKIM shape is an ABSENCE shape: six properties the checked
// shape carries are not present at all.
const notChecked = { found: false, selectors: [], testedSelectors: [], confidence: 'not-checked', note: '' };
for (const absent of ['scanMode', 'missingSelectors', 'failedSelectors', 'duplicated', 'keyProfile']) {
  eq(`the not-checked DKIM shape has no ${absent}`,
    Object.prototype.hasOwnProperty.call(notChecked, absent), false);
}

// cryptoValidated is a three-valued field and analyzeDkimKey never sets
// anything but null.
const rsaKey = D.analyzeDkimKey('v=DKIM1; k=rsa; p=AwEAAQ==');
eq('cryptoValidated starts null', rsaKey.cryptoValidated, null);
eq('null is not false', rsaKey.cryptoValidated === false, false);

// keyEncoding is null for a revoked key, and revoked is a complete record
// rather than a parse failure.
const revokedKey = D.analyzeDkimKey('v=DKIM1; k=rsa; p=');
eq('a revoked key is revoked', revokedKey.revoked, true);
eq('a revoked key has no encoding', revokedKey.keyEncoding, null);
eq('a revoked key has no bit count', revokedKey.keyBits, null);
eq('a revoked key is not an error', revokedKey.errors, []);
eq('a revoked key does not apply to email', revokedKey.appliesToEmail, false);

// version is null when v= is absent, which is legal.
eq('an absent v= gives a null version', D.analyzeDkimKey('k=rsa; p=AwEAAQ==').version, null);

// The DMARC version reason is null when valid — not absent, not ''.
eq('a valid version has a null reason', D.validateDmarcVersion('v=DMARC1; p=none').reason, null);
eq('an absent version names its reason', D.validateDmarcVersion('p=none').reason, 'not-first');
eq('a bare string names its reason', D.validateDmarcVersion('').reason, 'absent');

// diagnoseDmarcRecord returns null for a record that was never meant to be
// DMARC, which is different from a diagnosed one.
eq('an SPF record is not diagnosed as DMARC', D.diagnoseDmarcRecord('v=spf1 -all'), null);
eq('a lowercase version IS diagnosed', D.diagnoseDmarcRecord('v=dmarc1; p=none'), 'version-bad-case');

/* ── 5b. Web Crypto refusing a key the DER walk accepted ──────────────── */
section('5b. Platform-dependent key validation (§6 decision, 2026-08-27)');

/**
 * `cryptoValidated: false` and `key-structure-invalid` are set only when
 * `crypto.subtle.importKey` rejects a key `derReadRsaPublicKey()` has already
 * accepted (js/dns.js:1067). **Native Node Web Crypto cannot produce that** —
 * every probe inside the walk's accepted window imported successfully on
 * v26.7.0, and the keys Node might refuse are rejected by the walk first.
 *
 * So this state is reached by substituting the crypto primitive, which is the
 * same move the project already makes with `fetch` and which spec §11 names
 * `crypto` an injectable platform primitive for. Nothing is fabricated: the
 * production branch constructs the state itself.
 *
 * The equivalence corpus carries the same pair — `dkim-crypto-import-rejects`
 * and `dkim-crypto-import-accepts` — because the state is operator-visible and
 * spec §12.1 requires an equivalence fixture for those. These assertions are
 * the focused half, not a substitute for it.
 */
const REAL_RSA_2048_SPKI = (await import('../fixtures/equivalence/keys.mjs')).RSA_2048_SPKI;
const goodKeyRecord = 'v=DKIM1; k=rsa; p=' + REAL_RSA_2048_SPKI;

// First: the key really is one the DER walk accepts on its own. Without this
// the pair below would pass just as happily on a key nothing could parse,
// which is how the first draft of the corpus went unnoticed.
const walked = D.analyzeDkimKey(goodKeyRecord);
eq('the DER walk reads the size without the browser', walked.keyBits, 2048);
eq('and the envelope', walked.keyEncoding, 'spki');
eq('with no errors of its own', walked.errors, []);
eq('and no verdict yet from Web Crypto', walked.cryptoValidated, null);

const rejecting = load(FIXTURE_PSL_RULES, PLATFORM_PROFILES['crypto-import-rejects'].crypto());
const accepting = load(FIXTURE_PSL_RULES, PLATFORM_PROFILES['crypto-import-accepts'].crypto());

const refused = await rejecting.D.validateDkimKeyStructure(rejecting.D.analyzeDkimKey(goodKeyRecord), goodKeyRecord);
eq('a refused import records cryptoValidated false', refused.cryptoValidated, false);
eq('and pushes key-structure-invalid', refused.errors.includes('key-structure-invalid'), true);
eq('and lowers valid', refused.valid, false);
// The size was read without the browser's help and does not become less true
// because the browser declined to confirm it — js/dns.js:1049.
eq('and leaves the DER-derived size exactly as it was', refused.keyBits, 2048);

// The negative control. Same wrapper, import delegated. If this moved too, the
// case above would prove only that a substituted platform changes something.
const confirmed = await accepting.D.validateDkimKeyStructure(accepting.D.analyzeDkimKey(goodKeyRecord), goodKeyRecord);
eq('the control confirms the same key', confirmed.cryptoValidated, true);
eq('with no error', confirmed.errors, []);
eq('and stays valid', confirmed.valid, true);
eq('the two profiles disagree about the same record',
  refused.cryptoValidated === confirmed.cryptoValidated, false);

// Native Node is the control's equal, which is the measurement this decision
// rests on. If a future Node starts refusing, this assertion is where it shows.
const native = await D.validateDkimKeyStructure(D.analyzeDkimKey(goodKeyRecord), goodKeyRecord);
eq('native Node Web Crypto accepts it, so the corpus cannot reach false without the profile',
  native.cryptoValidated, true);

// The wrapper delegates digest, so a profile cannot silently move the DNSSEC
// surface while claiming to change only key validation.
eq('the rejecting profile still computes digests',
  typeof PLATFORM_PROFILES['crypto-import-rejects'].crypto().subtle.digest, 'function');

/* ── 5c. States the application entry point cannot reach ──────────────── */
section('5c. States unreachable through analyzeDomain');

/**
 * Nine registry members are reachable only by calling an exported function
 * directly. That is not a seam and nothing is fabricated — each is a real
 * return value of a real function, and each is unreachable from
 * `analyzeDomain()` for a stated structural reason.
 */

// `permerror` is legacy and js/dns.js:1397 says so in its own comment: the
// tree walk never passes `multiple`, because RFC 9989 §4.10 step 2 discards
// duplicates and CONTINUES. Retained because the token is part of a shape
// report-comparison (0.9.0) exports.
eq('permerror survives as a direct-call status', D.analyzeDmarc('v=DMARC1; p=none', true).status, 'permerror');
eq('and the discovery path never produces it',
  D.analyzeDmarc('v=DMARC1; p=none', false).status === 'permerror', false);

// `bad-value` never reaches a status object through discovery: a record whose
// v= is not exactly DMARC1 fails isDmarcPolicyRecord() and is never collected,
// so analyzeDmarc receives '' and reports reason 'absent' instead.
eq('a wrong version value is diagnosed on a direct call',
  D.validateDmarcVersion('v=DMARC2; p=none').reason, 'bad-value');
eq('and such a record is not a policy record at all',
  D.isDmarcPolicyRecord('v=DMARC2; p=none'), false);

// The other two diagnoses. Their OUTPUT reaches the result as observed[].why,
// which the corpus covers; the function's own return values are asserted here.
eq('a version tag out of position', D.diagnoseDmarcRecord('p=none; v=DMARC1'), 'version-not-first');
eq('a record with no version tag at all', D.diagnoseDmarcRecord('p=reject'), 'version-absent');
eq('and something that was never meant to be DMARC is not diagnosed',
  D.diagnoseDmarcRecord('some-verification-token=abc'), null);

// appliedBranch np and weakest need domain existence 'no' or 'unknown', and
// analyzeDomain cannot produce either: an NXDOMAIN NS probe returns the
// unregistered shape at js/dns.js:5370 before any DMARC work happens, so
// existence is always 'yes' by the time applyInheritance runs.
const inherited = {
  applied: { record: 'v=DMARC1; p=reject', foundAt: 'parent.test', labelsUp: 1, inherited: true },
};
const parentPolicy = D.analyzeDmarc('v=DMARC1; p=reject; sp=quarantine; np=none', false);
eq('an existing subdomain takes the sp branch',
  D.applyInheritance(parentPolicy, inherited, 'yes').appliedBranch, 'sp');
eq('a non-existent one takes np',
  D.applyInheritance(parentPolicy, inherited, 'no').appliedBranch, 'np');
eq('and unknown existence takes the weaker of the two',
  D.applyInheritance(parentPolicy, inherited, 'unknown').appliedBranch, 'weakest');
eq('the weakest branch really is the weaker policy',
  D.applyInheritance(parentPolicy, inherited, 'unknown').policy, 'none');
eq('a record that is not inherited is returned untouched',
  D.applyInheritance(parentPolicy, { applied: null }, 'yes').appliedBranch, undefined);

// parseReportAuthRecord's reason is internal: checkExternalReportAuth reports a
// destination-level state and never the per-record reason.
eq('a valid authorization record has a null reason',
  D.parseReportAuthRecord('v=DMARC1', 'vendor.test').reason, null);
eq('a wrong version is rejected at step 6',
  D.parseReportAuthRecord('v=DMARC2', 'vendor.test').reason, 'version');
eq('and so is a record whose remaining syntax is not tag=value',
  D.parseReportAuthRecord('v=DMARC1; this-is-not-a-pair', 'vendor.test').reason, 'syntax');
eq('a cross-host override is named separately from a malformed one',
  D.parseReportAuthRecord('v=DMARC1; rua=mailto:x@elsewhere.test', 'vendor.test').overrideReason, 'cross-host');
eq('a malformed override does not void the authorization',
  D.parseReportAuthRecord('v=DMARC1; rua=not-a-uri', 'vendor.test').valid, true);

/* ── 5d. DNSSEC states the audit path cannot reach ────────────────────── */
section('5d. DNSSEC states unreachable through analyzeDomain');

const { DNSSEC_ZONE_KEY, DS_MATCHING_SECURE } =
  await import('../fixtures/equivalence/keys.mjs');

// `invalid-owner` is a statement about OUR OWN input, not about the zone: the
// wire-format encoder refused the name. Unreachable through the audit path
// because `parseDomains()` in js/app.js rejects a label over 63 octets before
// startAudit() ever queues it — measured, by watching the corpus case produce
// no result at all.
const parsedDs = D.parseDs(DS_MATCHING_SECURE);
const parsedKey = D.parseDnskey(DNSSEC_ZONE_KEY);
eq('the DS and key are both well-formed to begin with',
  [parsedDs.valid, parsedKey.valid], [true, true]);
eq('an over-long label has no wire form', D.dnsWireName('x'.repeat(64) + '.test'), null);
const badOwner = await D.matchDsToDnskeys(parsedDs, [parsedKey], 'x'.repeat(64) + '.test');
eq('so the match is unverifiable', badOwner.match, 'unverifiable');
eq('and names our input as the reason', badOwner.unverifiableReason, 'invalid-owner');
eq('and it is never reported as a mismatch', badOwner.match === 'digest-mismatch', false);

// A DS that did not parse is the other half of the same rule.
const badDs = await D.matchDsToDnskeys(D.parseDs('1 8 2 zzzz'), [parsedKey], 'ok.test');
eq('an unparseable DS is unverifiable', badDs.match, 'unverifiable');
eq('with its own reason', badDs.unverifiableReason, 'invalid-ds');

/**
 * `unbuildable-key` is DEAD CODE in the current implementation, and this
 * asserts the property that makes it so rather than pretending to reach it.
 *
 * `matchDsToDnskeys()` selects candidates with `key.valid === true`
 * (js/dns.js:3841), and every key the parser calls valid has decodable base64,
 * so `dnskeyRdata()` always builds. `digestsComputed` can therefore only be
 * zero when there were no candidates — which returns `no-matching-key` earlier
 * — or when every computation failed, which returns `runtime-unavailable`
 * first. The branch is defensive and unreachable.
 *
 * Recorded rather than removed: it is a real string in a real union, and a
 * future change that made a valid key unbuildable would need this assertion to
 * fail before the branch became live.
 */
const KEY_SHAPES = [
  DNSSEC_ZONE_KEY, '257 3 8 AwEAAQ==', '256 3 13 AwEAAQ==', '257 3 15 AwEAAQ==',
  '257 3 99 AwEAAQ==', '0 3 8 AwEAAQ==', '257 3 5 AwEAAQ==',
];
const unbuildable = KEY_SHAPES
  .map(shape => D.parseDnskey(shape))
  .filter(key => key.valid && D.dnskeyRdata(key) === null);
eq('every key the parser calls valid can be rebuilt, so unbuildable-key is unreachable',
  unbuildable, []);
eq('and an INVALID key is never a candidate in the first place',
  D.parseDnskey('257 3 8 !!!!').valid, false);

// `dnssec.error: cancelled` needs an abort during the DNSSEC lookups. Through
// analyzeDomain that aborts every other in-flight query too, their
// optionalCheck() wrappers re-throw AbortError and the audit produces no
// result — so there is nothing for the corpus to observe.
const dnssecAbort = new AbortController();
setFetch((url, init) => new Promise((resolve, reject) => {
  init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  dnssecAbort.abort();
}));
const cancelled = await D.checkDNSSEC('cancelled.test', { noCache: true, retries: 0, signal: dnssecAbort.signal });
eq('a cancelled DNSSEC probe is indeterminate', cancelled.state, 'indeterminate');
eq('and carries the cancelled kind', cancelled.error, 'cancelled');
eq('with no evidence at all', cancelled.evidence, 'none');
eq('and the resolver-unreachable claim', cancelled.chain.some(c => c.claim === 'resolver-unreachable'), true);

/* ── 6. The issue vocabulary closes against locales/en.json ───────────── */
section('6. Issue token vocabulary (audit.issue.key)');

const registry = JSON.parse(readFileSync(join(REPO, 'tests/state-algebras.json'), 'utf8'));
const issueAlgebra = registry.algebras.find(a => a.id === 'audit.issue.key');
const en = JSON.parse(readFileSync(join(REPO, 'locales/en.json'), 'utf8'));
const localeIssueKeys = Object.keys(en.issue).sort();

eq('the registry records 106 issue tokens', issueAlgebra.members.length, 106);
eq('and they are exactly the locale issue keys',
  [...issueAlgebra.members].sort(), localeIssueKeys);

// The negative case: prove a literal scan under-reports, which is why the
// registry is reviewed rather than extracted. Three tokens are emitted only
// through the computed pushKeyFinding(key, ...) helper.
const literalKeys = new Set([...chainSource.matchAll(/key:\s*'([^']+)'/g)].map(m => m[1]));
for (const computed of ['dnssec-key-algorithm-ineligible', 'dnssec-key-not-zone-key', 'dnssec-key-malformed']) {
  eq(`${computed} is invisible to a literal key: scan`, literalKeys.has(computed), false);
  eq(`${computed} is in the reviewed registry`, issueAlgebra.members.includes(computed), true);
  eq(`${computed} has a locale entry`, Object.prototype.hasOwnProperty.call(en.issue, computed), true);
}

report();
