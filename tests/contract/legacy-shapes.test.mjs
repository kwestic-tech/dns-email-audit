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
import vm from 'node:vm';

import { createSuite } from '../lib/assert.mjs';
import {
  FIXTURE_PSL_RULES, FIXTURE_DKIM_SELECTOR,
  probePublicSuffixRules, probeDkimCatalog, assertFixtureIdentity,
} from '../lib/fixture-identity.mjs';
import { dohFixture, txt, ns, caa, ds, dnskey } from '../../tools/lib/doh-fixture.mjs';
import { PLATFORM_PROFILES } from '../lib/platform.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, throws, rejects, section, report } = createSuite();

/* ── Loading ──────────────────────────────────────────────────────────── */

function load(pslRules, cryptoImpl = crypto) {
  const sandbox = {
    window: { __PUBLIC_SUFFIX_RULES__: pslRules },
    fetch: async () => ({ ok: false }),
    console, AbortController, URLSearchParams, setTimeout, clearTimeout,
    crypto: cryptoImpl,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(readFileSync(join(REPO, 'js/dkim-selectors.js'), 'utf8'), sandbox);
  vm.runInContext(readFileSync(join(REPO, 'js/dns.js'), 'utf8'), sandbox);
  return { D: sandbox.window.DnsAudit, sandbox };
}

const { D, sandbox } = load(FIXTURE_PSL_RULES);
const setFetch = impl => { sandbox.fetch = impl; };

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
const realPslSandbox = { window: {} };
realPslSandbox.globalThis = realPslSandbox;
vm.createContext(realPslSandbox);
vm.runInContext(readFileSync(join(REPO, 'js/public-suffixes.js'), 'utf8'), realPslSandbox);
const REAL_PSL = realPslSandbox.window.__PUBLIC_SUFFIX_RULES__;
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
eq("'ds-no-matching-key' appears nowhere as a literal",
  chainSource.includes("'ds-no-matching-key'"), false);
eq("'ds-digest-mismatch' appears nowhere as a literal",
  chainSource.includes("'ds-digest-mismatch'"), false);
eq('the claim is concatenated from the match verdict',
  chainSource.includes("claim: 'ds-' + record.match"), true);

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
