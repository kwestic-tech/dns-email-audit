#!/usr/bin/env node
/**
 * DKIM: selector discovery, the catalog, and key decoding. Task 4.7.
 *
 * The properties held still here are the ones where a wrong answer is
 * confident rather than absent:
 *
 *  - `cryptoValidated` is `null` / `true` / `false`, and each is asserted by
 *    identity. `null` is "we could not check" — no implementation, or a format
 *    `importKey` has no name for. `false` is "Web Crypto rejected an SPKI key
 *    it should have read", which DOES claim structural invalidity. Collapsing
 *    either into the other says something the code does not.
 *  - a revoked key (`p=`) is a FINDING, not an absent key.
 *  - `DKIM_SCAN_BATCH_SIZE` is 24 — it bounds concurrency, not the query
 *    count, and Phase 4 forbids concurrency changes.
 *
 * Everything runs against a fake transport, a substitute catalog and, where it
 * matters, a runtime with no `crypto.subtle` at all.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { requireUsable, cleanAnswerData } from '../dns/resolver.js';
import {
  createDkimCheck, analyzeDkimKey, parseDkimKeyTagList, validDkimSelector,
  DKIM_SELECTORS, DKIM_SCAN_BATCH_SIZE,
} from './dkim.js';

const { eq, section, report } = createSuite();

/**
 * A REAL 2048-bit RSA SubjectPublicKeyInfo, generated once and pinned.
 *
 * `analyzeDkimKey()` walks the DER — it reads the algorithm identifier, the
 * modulus and the exponent — so a plausible-looking byte string is not a key
 * and every assertion written against one tests the failure path by accident.
 */
const RSA_SPKI = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsEn+FiV0as8YjqEqqzxxRFM2CUDD+ZpfZwRruPe0nA/6GFizMTX6yb2JQ6KN3WUUkV9qeKja7W5xUFY2VIpmL1HuD0Wm/TE60Qc7eft4E0n1CvpxrDuDEwirisxFRYC/QQe+dZTYteRGoB6dnNBpaUyhP7Hx6kyabuP/PlDaH5uSEtvaXEF2bQwpCbMeLMl8Z8K0QdrgHbMlwV6sO/pA9VLHS67Z77trboOuloLaDtcPLoMwf0ibYz2vtq32BygauvOG7kZ+BlEpMUiwWbYUWCmFrbE2CN4kxx30+nxjH61p8yzAuZTjqvULWozMNV0eAJsM2MSeNnrxKjqGbIXoBwIDAQAB';
const rsaKey = () => RSA_SPKI;

/* ── 1. The published constants ───────────────────────────────────────── */
section('1. Constants');

eq('the scan batch is 24, unchanged', DKIM_SCAN_BATCH_SIZE, 24);
eq('the base selector list is the ten v0.5.0 tried',
  [...DKIM_SELECTORS],
  ['google', 'default', 'mail', 's1', 's2', 'selector1', 'selector2', 'dkim', 'sig1', 'odoo']);

eq('a normal selector is valid', validDkimSelector('selector1'), true);
eq('underscores and hyphens are allowed', validDkimSelector('a_b-c'), true);
eq('a leading hyphen is not', validDkimSelector('-bad'), false);
eq('an uppercase selector is not', validDkimSelector('Google'), false);
eq('an over-long selector is not', validDkimSelector('a'.repeat(64)), false);
eq('an empty selector is not', validDkimSelector(''), false);

/* ── 2. The key tag list ──────────────────────────────────────────────── */
section('2. parseDkimKeyTagList');

eq('tags are read', parseDkimKeyTagList('v=DKIM1; k=rsa; p=abc').tags.k, 'rsa');
// Tag names are kept as published. DKIM tag names ARE case-sensitive
// (RFC 6376 §3.2), unlike DMARC's, which is why this parser is not
// `core/dmarc/record.js`'s `parseTagList()`.
eq('names are NOT lowercased — DKIM tag names are case-sensitive',
  parseDkimKeyTagList('V=DKIM1; K=rsa').tags, { V: 'DKIM1', K: 'rsa' });
eq('and the published order is kept',
  parseDkimKeyTagList('k=rsa; v=DKIM1').order, ['k', 'v']);
eq('an unknown tag is not the tag parser\'s complaint',
  parseDkimKeyTagList('v=DKIM1; zz=1').errors, []);
eq('the key analyzer is what names it',
  analyzeDkimKey(`v=DKIM1; k=rsa; zz=1; p=${rsaKey()}`).unknownTags, ['zz']);
eq('a duplicated tag is reported', parseDkimKeyTagList('k=rsa; k=ed25519').duplicates, ['k']);

/* ── 3. Key analysis, and the three-valued crypto answer ──────────────── */
section('3. analyzeDkimKey');

const good = analyzeDkimKey(`v=DKIM1; k=rsa; p=${rsaKey()}`);
eq('a well-formed RSA key is valid', good.valid, true);
eq('its type is read', good.keyType, 'rsa');
eq('its size is derived without the browser', good.keyBits, 2048);
eq('and its encoding is recognized', good.keyEncoding, 'spki');
// The whole point of the third value: nothing has asked Web Crypto yet.
eq('cryptoValidated starts null — nothing has checked', good.cryptoValidated, null);
eq('and it applies to email', good.appliesToEmail, true);

// A revoked key is an empty p=, and it is a FINDING rather than an absence.
const revoked = analyzeDkimKey('v=DKIM1; k=rsa; p=');
eq('an empty p= is revoked', revoked.revoked, true);
// The record is still VALID: revocation is a published fact, not a parse
// failure, and collapsing the two would turn a deliberate revocation into
// "no DKIM at all" — a worse answer and the loss of an existing finding.
eq('and the record is still valid', revoked.valid, true);
eq('but a revoked key does not apply to email', revoked.appliesToEmail, false);
eq('and it carries no size', revoked.keyBits, null);

eq('an unparseable key is not valid', analyzeDkimKey('v=DKIM1; k=rsa; p=!!!').valid, false);
eq('and a plausible byte string that is not DER is not a key either',
  analyzeDkimKey(`v=DKIM1; k=rsa; p=${Buffer.alloc(256, 0xab).toString('base64')}`).valid, false);
eq('an empty record is not a key', analyzeDkimKey('').valid, false);
// `s=` scoped elsewhere is a good record that is simply not for this purpose.
eq('a key scoped to another service does not apply to email',
  analyzeDkimKey(`v=DKIM1; k=rsa; s=other; p=${rsaKey()}`).appliesToEmail, false);
eq('while s=email does', analyzeDkimKey(`v=DKIM1; k=rsa; s=email; p=${rsaKey()}`).appliesToEmail, true);

/* ── 4. The factory, its catalog and its crypto ───────────────────────── */
section('4. createDkimCheck');

/**
 * A substitute catalog keyed the way the real one is. `catalogSelectors()`
 * reaches it through `DKIM_PROVIDER_CATALOG_KEYS`, which maps the detected
 * provider NAME to the catalog key — the two are not the same string, and a
 * fixture keyed by the provider name finds nothing.
 */
/** No vendors named. The shape the four selector members now take. */
const NO_KEYS = new Set();

const CATALOG = {
  providers: { 'Twilio SendGrid': ['acme1', 'acme2'] },
  generic: ['generic1'], temporal: [], prefixes: [], excluded: [],
};
// `subtle` rather than `crypto` throughout: an ambient name in this file reads
// to `platform.test.mjs`'s lexical scan as a bare reach, and the scan's limits
// are asserted rather than worked around.
function build({ table = {}, catalog = CATALOG, subtle = undefined } = {}) {
  const asked = [];
  const dohFetch = async (name, type) => {
    asked.push(`${name}/${type}`);
    const spec = table[name];
    if (!spec) return { kind: 'nodata', answers: [] };
    return { kind: 'success', answers: spec };
  };
  return {
    asked,
    ...createDkimCheck({
      dohFetch, requireUsable, cleanAnswerData, crypto: subtle,
      dkimSelectorCatalog: catalog,
    }),
  };
}

const api = build();
// The factory's product, counted rather than trusted to a doc comment.
eq('the factory returns ten members',
  Object.keys(api).filter(k => k !== 'asked').sort(),
  ['buildDkimSelectorList', 'catalogSelectors', 'checkDKIM', 'dkimKeyRecords',
    'dkimRecordSet', 'inspectDkimSelector', 'isRecognizedDkimSelector',
    'spfSelectorSources', 'summarizeDkimKeys', 'validateDkimKeyStructure']);
eq('the base list is always tried',
  DKIM_SELECTORS.every(s => api.buildDkimSelectorList([], '@none', false, NO_KEYS).includes(s)), true);
eq('a provider adds its catalog selectors',
  api.catalogSelectors('SendGrid', false, NO_KEYS).includes('acme1'), true);
// The indirection is real: the provider name is not the catalog key.
eq('and an unmapped provider name finds nothing',
  api.catalogSelectors('Twilio SendGrid', false, NO_KEYS), []);
eq('comprehensive mode adds the generic list',
  api.catalogSelectors('@none', true, NO_KEYS).includes('generic1'), true);
// Absent is the same as empty, which is what the retired collaborator returned
// for a missing record and what the legacy wrapper still produces.
eq('and a missing key set is the same as an empty one',
  api.catalogSelectors('SendGrid', false, undefined), api.catalogSelectors('SendGrid', false, NO_KEYS));
eq('a catalog selector is recognized', api.isRecognizedDkimSelector('acme1'), true);
eq('an arbitrary one is not', api.isRecognizedDkimSelector('zzz'), false);

// The catalog is INJECTED: a different catalog gives a different answer, which
// is what the fixture-identity probes depend on.
const other = build({ catalog: { providers: { 'Twilio SendGrid': ['different'] }, generic: [], temporal: [], prefixes: [], excluded: [] } });
eq('two factories over two catalogs disagree',
  [api.catalogSelectors('SendGrid', false, NO_KEYS)[0], other.catalogSelectors('SendGrid', false, NO_KEYS)[0]],
  ['acme1', 'different']);

/**
 * The SPF collaborator, RETIRED at Task 5.2.
 *
 * This module no longer takes SPF's derivation as a capability and no longer
 * sees an SPF record at all: `src/audit/` parses the references with the
 * SPF-owned helper and passes the derived catalog KEYS. Task 4.0's ruling is
 * still what forbids the alternative — importing `core/spf/` or copying its
 * grammar — and this is the arrangement that satisfies it without a debt.
 *
 * The keys are supplied here as a plain Set, which is the whole point: no SPF
 * text reaches this file, so nothing here can grow an opinion about it.
 */
const ACME_KEYS = new Set(['Twilio SendGrid']);
eq('SPF-named vendors widen the scan',
  api.catalogSelectors('@none', false, ACME_KEYS).includes('acme1'), true);
eq('and a record naming nobody does not',
  api.catalogSelectors('@none', false, NO_KEYS), []);
// The retirement itself: the factory no longer accepts the collaborator, and a
// module built with one supplied would ignore it. Asserted so the parameter
// cannot quietly come back.
const withStrayCapability = createDkimCheck({
  dohFetch: async () => ({ kind: 'nodata', answers: [] }),
  requireUsable, cleanAnswerData, crypto: undefined, dkimSelectorCatalog: CATALOG,
  spfReferencedCatalogKeys: () => new Set(['Twilio SendGrid']),
});
eq('a supplied SPF derivation is ignored — the capability is gone',
  withStrayCapability.catalogSelectors('@none', false, NO_KEYS), []);
/**
 * Attribution is a Map from selector to the catalog key that explains it, and
 * a selector the baseline would have supplied ANYWAY is deliberately absent:
 * it needed no explaining. `acme1` is passed in explicitly here, so it is
 * baseline and drops out; `acme2` is the one SPF actually adds.
 */
const sources = api.spfSelectorSources(['acme1'], '@none', false, ACME_KEYS);
eq('the SPF-explained selector is attributed to its vendor',
  [...sources], [['acme2', 'Twilio SendGrid']]);
eq('and a selector the baseline already supplies is not', sources.has('acme1'), false);
eq('nor is one from the base list', sources.has('google'), false);
// Comprehensive mode already covers every vendor, so nothing needs explaining.
eq('comprehensive mode attributes nothing',
  [...api.spfSelectorSources([], '@none', true, ACME_KEYS)], []);

/* ── 5. Optional Web Crypto validation ────────────────────────────────── */
section('5. cryptoValidated is three answers');

const key = analyzeDkimKey(`v=DKIM1; k=rsa; p=${rsaKey()}`);

// No crypto at all: silence, never a failure verdict.
const noCrypto = build({ subtle: undefined });
const unchecked = await noCrypto.validateDkimKeyStructure({ ...key }, `v=DKIM1; k=rsa; p=${rsaKey()}`);
eq('with no subtle implementation the answer stays null', unchecked.cryptoValidated, null);
eq('and the DER-derived size is untouched', unchecked.keyBits, key.keyBits);
eq('and the key is still valid', unchecked.valid, key.valid);

/**
 * An SPKI key Web Crypto REJECTS. This is the `false` case, and it is a real
 * claim of structural invalidity — not the same as a missing API or a format
 * `importKey` has no name for, both of which stay `null`.
 *
 * Asserted exactly, because an assertion that accepts `false || null` here
 * would pass whichever value the implementation produced and prove neither.
 */
const refuses = build({ subtle: { subtle: { importKey: async () => { throw new Error('nope'); } } } });
const declined = await refuses.validateDkimKeyStructure({ ...key }, `v=DKIM1; k=rsa; p=${rsaKey()}`);
eq('a rejected SPKI import is false, not null', declined.cryptoValidated, false);
eq('and it invalidates the key', declined.valid, false);
eq('naming the reason', declined.errors.includes('key-structure-invalid'), true);
// The size was read from the DER without the browser's help and does not
// become less true because the browser declined to confirm it.
eq('while the DER-derived size is unchanged', declined.keyBits, key.keyBits);
eq('which was 2048 before the attempt', key.keyBits, 2048);

// A runtime that accepts: the confirmation is recorded.
const accepts = build({ subtle: { subtle: { importKey: async () => ({}) } } });
const confirmed = await accepts.validateDkimKeyStructure({ ...key }, `v=DKIM1; k=rsa; p=${rsaKey()}`);
eq('an accepted import confirms', confirmed.cryptoValidated, true);

/* ── 6. Discovery ─────────────────────────────────────────────────────── */
section('6. checkDKIM');

const txt = value => [{ type: 16, data: `"${value}"` }];
const found = build({
  table: { 'google._domainkey.example.test': txt(`v=DKIM1; k=rsa; p=${rsaKey()}`) },
});
const result = await found.checkDKIM('example.test', false, [], '@none', false, NO_KEYS, {});
eq('a published selector is found', result.found, true);
eq('and it is named', result.selectors.some(s => s.sel === 'google'), true);
eq('a domain publishing nothing is not found',
  (await build().checkDKIM('example.test', false, [], '@none', false, NO_KEYS, {})).found, false);

/**
 * The batch bounds CONCURRENCY, not the query count. `checkDKIM()` slices the
 * same selector list either way, so a batch of 1 and a batch of 24 ask exactly
 * the same questions — they differ only in how many are in flight. Asserted,
 * because "fan-out figure" was the wrong reason to preserve 24 and the right
 * reason is that Phase 4 forbids concurrency changes and the equivalence trace
 * watches this directly.
 */
// A list deliberately longer than one batch, so the loop runs more than once.
const extra = Array.from({ length: 40 }, (_, i) => `x${i}`);
const wide = build();
await wide.checkDKIM('example.test', false, extra, '@none', false, NO_KEYS, {});
const distinct = new Set(wide.asked.map(q => q.split('/')[0]));
eq('every selector in the list is queried, across as many batches as it takes',
  extra.every(sel => distinct.has(`${sel}._domainkey.example.test`)), true);
eq('and the list is longer than one batch, so the loop really ran twice',
  extra.length > DKIM_SCAN_BATCH_SIZE, true);

report();
