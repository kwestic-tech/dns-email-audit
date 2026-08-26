# Spec: DNS-only protocol depth for DKIM, CAA, MX and TLSA

| Field | Value |
| --- | --- |
| Spec version | 1.2 (Implemented) |
| Target release | 0.4.0 |
| Status | Implemented and released |
| Released in | `v0.4.0`, 2026-08-25 |
| Pull request | [#22](https://github.com/kwestic-tech/dns-email-audit/pull/22) |
| Merge commit | `9bda3ad` (squashed) |
| Depends on | [rendering-and-robustness](rendering-and-robustness.md) for rendering, [dmarcbis-tree-walk](dmarcbis-tree-walk.md) for the fixture-resolver test harness |
| Blocks | [dnssec-evidence](dnssec-evidence.md), which reviewed this release's `qualified` flag and **retired** it — see the 1.2 row in Revision history |
| Slug for open questions | `DEPTH` |
| Last updated | 2026-08-26 |

## Problem

The application discovers a great deal and analyzes comparatively little. It
finds DKIM selectors well, and since 0.2.2 it finds selectors named indirectly
through the domain's own SPF record, but a found selector produces only the raw
TXT string. Nobody is told whether the key is RSA-1024, RSA-2048, Ed25519, or
revoked. That is the single most actionable fact about a DKIM key and it is
sitting decoded-but-unread in `s.value`.

CAA is reduced to a boolean. `checkCAA()` at [`js/dns.js:1555`](../../../js/dns.js)
walks up the tree, returns `found`, the raw record strings, and the name they
were found at, and nothing parses them. A domain with
`0 issue ";"` has locked out every certificate authority, and a domain with
`0 issuewild ";"` has locked out wildcards only; the interface shows both as a
green dot.

MX records are read for provider detection at
[`js/dns.js:336`](../../../js/dns.js) and never validated. An MX pointing at a
hostname that does not resolve is a total mail outage and reads today as a
normal configured mail domain. Single-MX setups, MX targets that are CNAMEs,
and MX hosts that all sit in one address block are equally invisible.

TLSA is not queried at all, so DANE for SMTP is entirely unrepresented. That
also means the transport layer cannot currently ask for it:
`dnsTypeNum()` at [`js/dns.js:94`](../../../js/dns.js) knows seven record types and
silently returns 16, the TXT type number, for anything else. A caller asking for
`DS` today would issue a TXT query, filter the answers for type 16, and receive a
plausible-looking empty array.

## Scope

1. Fix `dnsTypeNum()` to fail loudly on unknown types, and add `PTR`, `DS`,
   `DNSKEY` and `TLSA`.
2. Decode DKIM public keys: algorithm, RSA modulus size, Ed25519 detection,
   revocation, and the `h=`, `s=`, `t=`, `n=` service tags.
3. Parse CAA into structured fields with wildcard authorization semantics and
   malformed-record findings.
4. Resolve MX targets and report dangling hosts, CNAME targets, redundancy, and
   preference layout.
5. Add TLSA lookup and syntax validation, labelled explicitly as unqualified
   until 0.5.0 supplies DNSSEC evidence.
6. Ship every new observation as advisory. No scoring weight changes in this
   release.

## Non-goals

- **No SMTP.** Nothing connects to port 25, ever. MX health is inferred from DNS
  alone.
- **No certificate retrieval.** A TLSA record is compared against nothing. The
  tool reports what is published and whether it is well-formed.
- **No DKIM key age.** Key rotation age cannot be inferred from DNS and the tool
  must not imply it can. A selector name containing a year, such as `s2024`, is
  a naming convention and not evidence of anything.
- **No scoring changes.** Weights in `WEIGHTS` at
  [`js/dns.js:1987`](../../../js/dns.js) are untouched. See `OQ-DEPTH-06`.

## Design

### 1. Transport: additional record types

```js
var DNS_TYPES = { A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16,
                  AAAA: 28, DS: 43, DNSKEY: 48, TLSA: 52, CAA: 257 };

function dnsTypeNum(type) {
  var num = DNS_TYPES[type];
  if (num === undefined) throw new Error('unsupported DNS type: ' + type);
  return num;
}
```

The silent TXT fallback is removed. It exists to make the function total, and the
cost of totality here is that a typo produces a confidently wrong empty answer
rather than a stack trace. Every current call site passes a supported literal, so
this change is behavior-preserving for existing code and fail-fast for new code.

The exact resolver output for these three types was captured before any parser
was designed and is recorded in
[`fixtures/doh-shapes-0.4.0.md`](fixtures/doh-shapes-0.4.0.md). **Write the
parsers against that file, not against the shape you expect**, because the three
types come back in three different shapes from the same resolver:

| Type | Observed `data` | Note |
| --- | --- | --- |
| `DS` | `2371 13 2 32996839a6d8…` | four plain fields, **lowercase** hex |
| `DNSKEY` | `256 3 13 oJMRESz5E4gY…` | four plain fields, **case-sensitive** base64 |
| `TLSA` | `3 1 1 ( 87D109DD0286… )` | **parenthesised**, **uppercase** hex |

The `TLSA` parentheses are the trap `OQ-DEPTH-01` existed to catch. A parser
written for the `DS` shape and reused for `TLSA` splits to `['3','1','1','(']`
and reads the association data as an empty string, raising no error. Strip the
parentheses and normalise hex case before comparing anything.

A `TLSA` query may also return a `CNAME` in the same answer set — pointing
`_25._tcp.<host>` at a shared `_dane.<zone>` name is ordinary DANE practice — so
the TLSA path filters on `a.type === 52`. `dohQuery()` already does; `dohAll()`
does not and must not be used here.

`cleanAnswerData()` at [`js/dns.js:220`](../../../js/dns.js) needs **no change**.
Its non-TXT branch strips surrounding quotes and trims, and does not lowercase,
so the case-sensitive `DNSKEY` base64 survives intact and the quote-stripping is
a no-op for all three types. No CAA-style bypass is required.

### 2. DKIM key analysis

New pure function, exported for testing, no DNS access:

```js
function analyzeDkimKey(txtValue) → {
  valid: boolean,
  version: 'DKIM1' | null,        // v= absent is legal and means DKIM1
  keyType: 'rsa' | 'ed25519' | 'unknown',   // k=, default rsa
  revoked: boolean,               // p= present and empty (RFC 6376 §3.6.1)
  keyBits: number | null,         // RSA modulus size; null for ed25519/unknown
  keyBytes: number | null,        // decoded p= length
  hashAlgorithms: string[],       // h=, split on ':'
  serviceTypes: string[],         // s=, split on ':'; '*' means any
  flags: string[],                // t=, split on ':'; 'y' testing, 's' strict
  testing: boolean,               // t= contains 'y'
  strictSubdomain: boolean,       // t= contains 's'
  notes: string,                  // n=, human note from the key publisher
  unknownTags: string[],
  errors: string[],               // token list, never English
}
```

Key size determination for RSA does **both**, per `OQ-DEPTH-02`: a DER length
walk establishes the modulus size synchronously and everywhere, and Web Crypto
validates the structure when it is available. The size is the actionable fact and
must not depend on a secure context; structural validation is a bonus that
degrades to an explicit unknown rather than to a false negative.

The DER walk reads the SPKI structure to the modulus INTEGER and takes its
length. Web Crypto, where `crypto.subtle` exists, additionally confirms the key
imports:

> **Amended at 1.1 — see [As implemented](#as-implemented) item 1.** "the SPKI
> structure" is too narrow. RFC 6376 §3.6.1 describes the `p=` value as a
> DER-encoded `RSAPublicKey`, and the errata clarify that it MAY be wrapped in a
> `SubjectPublicKeyInfo` — so a bare PKCS#1 key is conformant too, and the walk
> accepts both. Web Crypto's `importKey` takes `spki` and not `pkcs1`, and as
> written this paragraph would have let that API's input formats decide which
> published keys are valid.



```js
const der = base64ToBytes(tags.p);
const key = await crypto.subtle.importKey(
  'spki', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
const jwk = await crypto.subtle.exportKey('jwk', key);
const keyBits = base64UrlToBytes(jwk.n).length * 8;   // 1024, 2048, 4096
```

A key that fails the DER walk is `errors: ['unparseable-key']`, which is itself a
useful finding: a truncated `p=` value from a TXT record split across strings is
a common and completely silent DKIM failure. A key that walks but fails
`importKey` is `errors: ['key-structure-invalid']` — the size is still reported,
because it was read without Web Crypto. Where `crypto.subtle` is absent
altogether the analysis records `cryptoValidated: false` and reports the size
regardless; it never reports a key as bad because the browser could not check it.

> **Amended at 1.1 — see [As implemented](#as-implemented) item 1.**
> `cryptoValidated` is `null`, not `false`, when nothing was checked. The final
> sentence is the binding rule and it needs three states to hold: `true`
> confirmed, `false` attempted and rejected, `null` not attempted. `false` for
> "absent" would have collapsed "we did not look" into "it failed", which is the
> false negative the same sentence forbids. A bare PKCS#1 key is also `null` —
> Web Crypto cannot express it, so there is nothing to confirm it with.

Because the DER walk is synchronous, `analyzeDkimKey()` stays synchronous and
returns the sizes directly. Only the optional Web Crypto validation is async, and
it is attached separately inside `inspectDkimSelector()` at
[`js/dns.js:500`](../../../js/dns.js) where each selector's records are already in
hand.

Ed25519 keys are not SPKI. RFC 8463 defines the `p=` value for `k=ed25519` as
the raw 32-byte public key, base64-encoded. Detection is therefore
`keyType === 'ed25519' && keyBytes === 32`, and a length other than 32 is
`errors: ['bad-ed25519-length']`.

`dkimKeyRecords()` at [`js/dns.js:412`](../../../js/dns.js) currently filters out
records whose `p=` is empty, which discards exactly the revoked keys this release
wants to report. Split it: keep the strict filter for the "is there a usable key
here" question, and return the discarded records separately so a revoked key is
reported as revoked rather than as absent.

Advisory findings produced:

| Finding | Condition | Severity |
| --- | --- | --- |
| `dkim-key-weak` | RSA modulus under 1024 bits | crit |
| `dkim-key-1024` | RSA modulus exactly 1024 bits | **info** (see `OQ-DEPTH-05`) |
| `dkim-key-revoked` | `p=` present and empty | warn |
| `dkim-key-unparseable` | `p=` fails to decode or import | warn |
| `dkim-key-testing` | `t=y` | info |
| `dkim-key-mixed` | Selectors on one domain use different key strengths | info |
| `dkim-key-sha1` | `h=sha1` only | warn |

`dkim-key-mixed` is a cross-selector observation and belongs to the findings
engine in 0.6.0. In this release it is computed and reported flat, and it moves
into the structured engine later.

### 3. Structured CAA

```js
function parseCaaRecord(presentationString) → {
  flags: number,          // 0-255
  critical: boolean,      // flags & 0x80
  tag: string,            // lowercased
  value: string,          // unquoted
  known: boolean,         // tag in the RFC 8659 / RFC 9495 registry
  valid: boolean,
  errors: string[],
}
```

Recognized tags: `issue`, `issuewild`, `iodef`, `issuemail`, `contactemail`,
`contactphone`. An unknown tag with the critical bit set means a conformant
certificate authority must refuse to issue, which is a materially different
situation from an unknown tag without it and must be reported as such.

`checkCAA()` returns the parsed set plus derived posture:

```js
{
  found, atDomain, records,          // unchanged, kept for compatibility
  parsed: [ …parseCaaRecord results… ],
  issuers: string[],                 // non-empty issue values
  wildcardIssuers: string[],         // issuewild values; empty means issue governs
  issuanceBlocked: boolean,          // an issue value of ';' with no others
  wildcardBlocked: boolean,          // an issuewild value of ';'
  iodef: string[],
  unknownCritical: string[],
  malformed: string[],
}
```

Two semantics that are easy to get wrong and must be encoded explicitly. An
`issue` value of `;` forbids all issuance. An absent `issuewild` set means
wildcard issuance is governed by the `issue` set, not that wildcards are
unrestricted. `checkCAA()` already walks up the tree correctly and returns at the
first name with any CAA record, which matches RFC 8659 climbing; that behavior is
preserved.

Advisory findings: `caa-blocks-all-issuance`, `caa-unknown-critical-tag`,
`caa-malformed`, `caa-no-iodef`, `caa-single-issuer` (informational, a note that
CA migration will require a record change).

### 4. MX health

New function, DNS only:

```js
async function auditMxHosts(mx, domain, queryOpts) → {
  hosts: [{
    host, preference,
    addresses: string[],
    v4Count, v6Count,
    resolves: 'yes' | 'no' | 'unknown',
    isCname: boolean,
    inAudited: boolean,        // host is at or under the audited domain
  }],
  danglingHosts: string[],
  cnameHosts: string[],
  duplicatePreferences: number[],
  singleHost: boolean,
  ipv6Coverage: 'all' | 'some' | 'none',
  sharedPrefixes: [{ prefix, hosts }],   // /24 for v4, /48 for v6
  unknown: boolean,
}
```

`isNullMx()` at [`js/dns.js:330`](../../../js/dns.js) already detects the RFC 7505
null MX and that path short-circuits before this function runs.

An MX target that is a CNAME violates RFC 2181 §10.3 and RFC 5321 §5.1. It
frequently works anyway, which is why it survives in the wild, and it breaks in
specific and hard-to-diagnose ways. It is reported as a warning, not an error.

`sharedPrefixes` uses the CIDR helpers already present for the SPF subnet audit:
`parseIpCidr()`, `cidrContains()` and `ipv4ToBigInt()` / `ipv6ToBigInt()` at
[`js/dns.js:1782`](../../../js/dns.js) onward. No new IP arithmetic is needed.

The whole function is wrapped in `optionalCheck()` so a resolver failure on one
MX target degrades that host to `resolves: 'unknown'` rather than discarding the
audit, following the pattern documented at [`js/dns.js:206`](../../../js/dns.js).

Query cost: one A and one AAAA per MX host, plus one CNAME probe per host. A
five-MX domain adds fifteen queries. See `OQ-DEPTH-03`.

Advisory findings: `mx-dangling` (crit), `mx-cname-target` (warn),
`mx-single-host` (info), `mx-no-ipv6` (info), `mx-same-prefix` (info),
`mx-duplicate-preference` (info).

### 5. TLSA and DANE

```js
async function checkTlsa(mxHosts, queryOpts) → {
  hosts: [{
    host,
    queryName,                  // _25._tcp.<host>
    records: [{ usage, selector, matchingType, data, valid, errors }],
    present: boolean,
    unknown: boolean,
  }],
  anyPresent: boolean,
  qualified: false,             // always false in 0.4.0, see below
}
```

Validation is syntactic only: usage in 0 to 3, selector in 0 to 1, matching type
in 0 to 2, and association data of the length the matching type implies, 32 bytes
for SHA-256 and 64 for SHA-512, with matching type 0 accepting a full
certificate of any length.

The critical labelling rule: **DANE is only meaningful when the TLSA record is
protected by a validated DNSSEC chain.** An unsigned TLSA record can be stripped
or replaced by anyone on the path, so publishing one without DNSSEC provides no
security at all while looking like it does. This release does not yet have chain
evidence, so `qualified` is hardcoded `false` and the interface must say
"published, not yet qualified" rather than anything resembling "DANE enabled".
0.5.0 supplies the evidence that lets `qualified` become meaningful.

Advisory findings: `tlsa-published-unsigned` (warn, and it is a warning precisely
because it looks like protection), `tlsa-malformed` (warn),
`tlsa-partial-coverage` (info, some MX hosts have TLSA and some do not).

### 6. Forward-confirmed reverse DNS

`PTR` support is added to the transport. Whether it is used is `OQ-DEPTH-04`.
The check, if implemented: for each MX host address, query the reverse name,
then forward-resolve the PTR answer and confirm it returns the original address.
Failure is `fcrdns-mismatch` at informational severity, because many perfectly
functioning mail systems fail it and it is a deliverability signal rather than a
security one.

### 7. Result surface

```js
advanced: {
  …existing fields…,
  mxHealth: { …section 4… },
  tlsa: { …section 5… },
},
dkimStatus: {
  …existing fields…,
  selectors: [{ …existing…, key: { …analyzeDkimKey result… } }],
  revokedSelectors: [{ sel, queryName, value }],
  keyProfile: { minBits, maxBits, algorithms: string[], mixed: boolean },
}
```

CSV columns are appended, never inserted, per the positional-header backfill at
[`js/app.js:1079`](../../../js/app.js): `dkim_key_type`, `dkim_key_bits`,
`dkim_revoked`, `caa_issuers`, `caa_wildcard_issuers`, `mx_dangling`,
`mx_host_count`, `tlsa_present`.

The detail panel gains a key line under each DKIM selector at
[`js/app.js:666`](../../../js/app.js), a parsed CAA block, and an MX health block
replacing the plain `r.mx.join('\n')` at [`js/app.js:782`](../../../js/app.js).

## Localization impact

Substantial. Roughly 40 to 60 new keys: `issue.<key>.msg`, `.what`, `.fix` and
optional `.fixCode` for each of the roughly fifteen new findings, plus detail
labels for key type, key size, CAA fields, MX health and TLSA.

All thirteen locales translated in the same change. Never translated: `RSA`,
`Ed25519`, `SHA-256`, `SHA-512`, `TLSA`, `DANE`, `CAA`, `PTR`, `_25._tcp`,
`issue`, `issuewild`, `iodef`, and the tag letters `k`, `p`, `h`, `s`, `t`, `n`.
Always translated: "key size", "revoked", "testing mode", "certificate
authority", "mail host", "unreachable".

## Testing

`analyzeDkimKey()` and `parseCaaRecord()` are pure and test directly in the
existing `node:vm` sandbox with no DOM and no network. Note that
`crypto.subtle` must be added to the sandbox globals in
[`tools/scoring.test.mjs:16`](../../../tools/scoring.test.mjs), which currently
provides only `fetch`, `console`, `AbortController`, `URLSearchParams`,
`setTimeout` and `clearTimeout`.

DKIM key fixtures, using real published keys captured as static strings:

| Fixture | Expectation |
| --- | --- |
| RSA-1024 key | `keyBits: 1024`, `dkim-key-1024` warn |
| RSA-2048 key | `keyBits: 2048`, no finding |
| RSA-4096 key | `keyBits: 4096`, no finding |
| RSA-512 key | `keyBits: 512`, `dkim-key-weak` crit |
| Ed25519 key | `keyType: 'ed25519'`, `keyBytes: 32`, `keyBits: null` |
| `k=ed25519` with 31 bytes | `bad-ed25519-length` |
| `p=` empty | `revoked: true` |
| `p=` truncated mid-base64 | `unparseable-key` |
| Multi-string TXT reassembled | Parses correctly; `cleanAnswerData()` already joins chunks |
| `v=DKIM1` absent | Legal, `version: null`, still valid |
| `v=DKIM2` | Invalid |
| `t=y:s` | `testing: true`, `strictSubdomain: true` |
| `h=sha256:sha1` | Both listed, no finding; `h=sha1` alone warns |

CAA fixtures: `0 issue "letsencrypt.org"`, `0 issue ";"`,
`0 issuewild ";"` alongside a permissive `issue`, `128 unknowntag "x"`,
`0 iodef "mailto:sec@example.com"`, a value with an embedded semicolon, an
unquoted value, and a flags value of 256.

MX and TLSA fixtures use the programmable resolver from
[dmarcbis-tree-walk](dmarcbis-tree-walk.md) `OQ-DMARC-03`: dangling target,
CNAME target, single host, IPv4-only, all hosts in one `/24`, duplicate
preferences, TLSA present on some hosts, malformed TLSA, and a SERVFAIL on one
host asserting the other hosts still report.

Transport fixture: `dnsTypeNum('SVCB')` throws rather than returning 16.

## Acceptance criteria

1. Every new observation retains the raw DNS evidence that produced it, and no
   claim in the interface requires SMTP, certificate, or third-party network
   access.
2. `dnsTypeNum()` throws on an unknown type.
3. No DKIM key age claim appears anywhere in the code, the locale files, or the
   documentation.
4. TLSA is never presented as active protection while `qualified` is false.
5. `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` are byte-identical to
   0.3.0, and `node tools/backtest.mjs --json` shows zero grade movement.
6. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

## Risks

**Query volume.** MX resolution, TLSA and optional PTR meaningfully increase the
per-domain fan-out that `PRIVACY.md` documents. A 200-domain audit is already
around 6,000 queries. Mitigation: measure with the backtest, put MX and TLSA
depth behind the existing options row alongside the DKIM and wildcard toggles,
and update `PRIVACY.md` with the measured number. See `OQ-DEPTH-03`.

**Web Crypto availability.** `crypto.subtle` requires a secure context. The app
is served over HTTPS in production, but `file://` is not a secure context in all
browsers, and `README.md` advertises that opening `index.html` from disk works.
Mitigation: feature-detect and degrade DKIM key analysis to
`errors: ['crypto-unavailable']` with an explicit unknown, never a false
negative.

**Advisory findings crowd the interface.** Fifteen new findings on a domain that
was previously clean will read as a regression to the user. Mitigation: new
informational findings render in the suggestions section rather than the issues
section, and `CHANGELOG.md` says plainly that the domain did not get worse, the
tool got more thorough.

## Open questions

None. All seven were resolved on 2026-08-25 — see **Resolved questions** below.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| OQ-DEPTH-01 | What exactly does the resolver return for `DS`, `DNSKEY` and `TLSA` in JSON? | **Captured, not assumed.** Real responses were fetched from `cloudflare-dns.com` on 2026-08-25 and are recorded in [`fixtures/doh-shapes-0.4.0.md`](fixtures/doh-shapes-0.4.0.md). The three types come back in **three different shapes from the same resolver**: `DS` as four plain fields with lowercase hex, `DNSKEY` as four plain fields with case-sensitive base64, and `TLSA` **parenthesised with uppercase hex** (`3 1 1 ( 87D1… )`). A parser written for the `DS` shape and reused for `TLSA` splits to `['3','1','1','(']` and reads the digest as an empty string with no error — precisely the failure this question existed to prevent. Two further findings: a `TLSA` query can return a `CNAME` alongside the `TLSA` (shared `_dane.<zone>` names are ordinary practice), so the path must filter on `a.type === 52`; and `cleanAnswerData()` needs no change, because it does not lowercase and none of these types are quoted. | 1.0 |
| OQ-DEPTH-02 | Is Web Crypto the right tool for RSA key size, or a plain DER walk? | **Both — the draft's third option.** A synchronous DER length walk establishes the modulus size, and Web Crypto validates the structure where `crypto.subtle` exists. The size is the actionable fact and must not depend on a secure context; validation is a bonus that degrades to an explicit unknown. This also keeps `analyzeDkimKey()` synchronous and therefore trivially testable in the `node:vm` sandbox. **Note for implementation:** whether `file://` is a secure context was *not* established — the available browser surface loads local files as `data:` URLs, so the obvious probe measures the sandbox rather than `file://`. Confirm it against a real browser if it ever matters; under this resolution it does not, because the size never depends on it. | 1.0 |
| OQ-DEPTH-03 | Are MX health and TLSA on by default, or behind a checkbox? | **A single "deep protocol checks" toggle, defaulted on, automatically disabled above 50 domains.** Approved by Ian 2026-08-25, with four riders: the interface shows a clear notice when the auto-disable fires; the user can re-enable manually; that explicit choice is remembered **for the browser tab's session only**; and the real fan-out is measured, published in `PRIVACY.md`, and the 50-domain threshold revisited after release. The session-scoped memory is deliberate and was confirmed explicitly: persisting it would need a second `localStorage` key, and `PRIVACY.md` states the app writes "exactly one value" and calls that "the entire footprint". **No new storage key, and no change to `PRIVACY.md`'s storage table.** A reload restores the default. | 1.0 |
| OQ-DEPTH-04 | Do we implement forward-confirmed reverse DNS at all? | **No.** `PTR` is added to the transport, because `dnssec-evidence` (0.5.0) and `report-comparison` (0.8.0) may want it and adding a type is free; the FCrDNS check itself is not shipped. It is a deliverability signal rather than a security control, most large providers pass it trivially, it costs two queries per MX address, and it does not fit the tool's stated subject. Agreeing with the draft's own recommendation. | 1.0 |
| OQ-DEPTH-05 | What is the threshold for a weak DKIM key? | **Sub-1024 is critical; exactly 1024 is *informational*, not a warning.** The draft asked whether warning on 1024 would generate noise on a majority of domains. It would, and this was measured rather than argued: across the 40-domain backtest sample, 66 keys were found on 27 domains — **35 of them (53%) are RSA-1024**, on 21 of those 27 domains, including Microsoft, GitHub, Apple, PayPal, Stripe, NASA, Harvard, Mozilla and the EFF. A warning firing on roughly 78% of domains that publish DKIM at all is not a signal. RFC 8301's floor still deserves saying, so it is said at informational severity, in the suggestions section this release's own risk note reserves for exactly this. **Zero sub-1024 keys were found**, which is the other half of the answer: `dkim-key-weak` stays critical and stays meaningful precisely because it will almost never fire. No Ed25519 keys were found either, so that path has fixture coverage only and no real-world sample. | 1.0 |
| OQ-DEPTH-06 | When do these checks enter the score, and what gives way? | **Refine existing pillars; the 100-point total is a contract.** Approved by Ian 2026-08-25. DKIM key strength eventually refines the existing DKIM pillar, CAA quality refines the CAA pillar, and DANE refines the transport-security pillar — read here as **MTA-STS**, the pillar that already scores authenticated SMTP transport, with DNSSEC remaining separate as the prerequisite that *qualifies* DANE rather than as its host. **MX health never scores**: availability and operational hygiene are not email-security signals and must not distort the score. Weighting *within* that contract is revisited in `findings-and-remediation` (0.6.0); the 100-point total and the pillar set are not. Nothing changes in 0.4.0 — this is recorded so the advisory findings are shaped to feed it. Score continuity across releases is the reason, and it is what makes `report-comparison` (0.8.0) able to diff grades at all. | 1.0 |
| OQ-DEPTH-07 | Does an unsigned TLSA record deserve a warning or an informational finding? | **Warning.** The draft asked what the user should do differently in each case, and the answer is concrete: an unsigned TLSA record can be stripped or rewritten by anyone on the path, so it provides no protection while creating a strong appearance of it — and the operator's action is real, which is to sign the zone or stop advertising DANE. That is the same reasoning that makes `dmarc-at-apex` critical when nothing else governs: a control that looks active and is not is worse than one that is plainly absent. It stays a warning rather than critical because nothing is broken by it. | 1.0 |

**Note on the DANE pillar reading.** `OQ-DEPTH-06`'s answer named "the relevant
transport-security pillar" without naming it. This spec reads that as MTA-STS,
on the grounds that MTA-STS and DANE are the two mechanisms for authenticated
SMTP transport and belong in one place. If 0.6.0 disagrees, this is the sentence
to change, and nothing in 0.4.0 depends on it — no scoring code is written here.

## As implemented

**1. The DER walk accepts both RSA encodings, and Web Crypto confirms only the
one it can express.** The 1.0 text said the walk "reads the SPKI structure", and
the first implementation refused a bare PKCS#1 `RSAPublicKey` on the reasoning
that the walk and Web Crypto must never disagree about a size. That has the
dependency backwards. RFC 6376 §3.6.1 describes the `p=` value as a DER-encoded
`RSAPublicKey`, and the errata clarify that it MAY be wrapped in a
`SubjectPublicKeyInfo`; both are therefore conformant DKIM key encodings.
`crypto.subtle.importKey` accepts `'spki'` and not `'pkcs1'`, so refusing the
bare form let one API's input formats decide which published keys are valid —
and would have reported a working key as `unparseable-key`, which is exactly the
class of confident-but-unsupported verdict this release was written to avoid.

`rsaPublicKeyShape()` reads both and returns the envelope alongside the size, so
`analyzeDkimKey()` gains a `keyEncoding: 'pkcs1' | 'spki' | null` field. The
DER-derived size is authoritative in both cases. `validateDkimKeyStructure()`
returns early for a bare key, leaving `cryptoValidated: null` and no error, so a
lack of confirmation never makes a valid key look broken.

Accepting a second envelope tightened the walk rather than loosening it, because
a shape check that accepts more must discriminate better: a top-level DER value
must now consume the whole buffer, and a PKCS#1 `SEQUENCE` must carry a
`publicExponent` that ends it. Both guards are mutation-tested — removing either
one fails assertions that otherwise pass.

Bare PKCS#1 has fixture coverage and no real-world sample: all 39 keys found
across a 15-domain slice, Microsoft, Apple, PayPal, Stripe, NASA, Harvard,
Mozilla and the EFF among them, are SPKI. That is the argument for accepting it
rather than against — a conformant encoding rare enough that nothing in the
sample would have caught the misreport.

**2. `tlsa-published-unsigned` is gated on the resolver's AD bit, not on
`qualified`.** Section 5 hardcodes `qualified: false` for the whole release,
which is right, and `OQ-DEPTH-07` makes the unsigned record a warning, which is
also right. Firing the finding on `qualified` alone joins the two into something
neither says: it would warn on **every** domain that publishes TLSA, including a
correctly signed zone, announcing "DANE offers no protection here" on the
strength of a check this release had simply not made. That is the release's own
headline failure mode — an unknown presented as an absent.

The evidence was available for nothing: the TLSA query is issued anyway, so it
carries `do=1` and the answer's AD bit is recorded per host as `authenticated`.
It is read for the MX host's own name rather than for the audited domain,
because an MX host usually lives in someone else's zone and the audited domain's
DNSSEC state says nothing about it. The finding fires only on hosts where
`authenticated === false`. Verified against live zones: posteo.de and ietf.org
publish authenticated TLSA and correctly raise nothing.

`authenticated` and `qualified` are deliberately separate and both are kept.
The AD bit is a validating resolver's assertion; `qualified` is the stronger
claim that the chain was walked and verified, which
[dnssec-evidence](dnssec-evidence.md) supplies. Nothing in this release calls
DANE active, and the interface's first line stays "published, not yet
qualified" — acceptance criterion 4 holds at the surface the user actually
reads, not only in the data model.

**3. Base64 is decoded in-file rather than with `atob`.** The spec's pseudocode
calls `base64ToBytes(tags.p)` without saying where that comes from. Reaching for
the `atob` global would have meant that in any environment lacking it — the
test sandbox and `tools/backtest.mjs` both lack it — the decode throws, the
caller reads a throw as "this key does not decode", and **every key on every
domain** is reported unparseable. That is an assertion about our own runtime
wearing the clothes of an assertion about the operator's DNS. Twelve lines of
arithmetic buy an answer that cannot depend on what the host provides. The test
sandbox deliberately supplies no `atob`, which is what proves the DER walk needs
nothing but the language; the decoder is fuzzed against Node's own encoder for
every length from 1 to 300.

**4. The renderer is hardened against partial result shapes.** The detail-panel
blocks were written against the result shape section 7 defines, and a fixture
carrying `caa.found` without the parsed fields threw — taking down not just the
block but the entire table row, since one thrown render aborts the row. A saved
report from an earlier release has exactly that shape. `caaDetail()` now returns
nothing when `parsed` is absent, and the MX, TLSA and DKIM-key blocks default
their collections, so an unrecognized shape renders less rather than failing.
The rule this encodes: a renderer may say less than it hoped to, and may never
take the page down to say it.

**5. CSV column order is asserted by index, not by tail.** Section 7 says the
new columns are appended and never inserted. The 0.3.0 export tests pinned the
*last* columns of the header row, so appending fired them — the rule working,
not breaking. They are re-anchored to fixed indices, with an added assertion
that no pre-0.4.0 column moved, so the next release's append moves nothing here.

Two cells needed a decision the spec did not cover. With the deep checks off,
`MX Dangling`, `MX Host Count` and `TLSA Present` say `Unknown` rather than
`No`: a domain whose MX hosts were never resolved has no dangling hosts
*reported*, which is not the same as having none. And an absent `issuewild` set
is named as governed by `issue` rather than left blank, because a blank cell
reads as "wildcards unrestricted" — the inverse of the policy the domain
published, and the same inversion section 3 calls out for the interface.

**6. `optionalCheck()` re-throws the unsupported-type error.** Section 1 and
acceptance criterion 2 require `dnsTypeNum()` to throw, and on its own that is
not enough to make an unsupported type fail loudly. Two layers would have
swallowed it: `fetchDohOnce()`'s catch turns every throw into `network-error`,
and `optionalCheck()` turns everything except an abort into a stated "unknown".
Either one restores the silent wrong answer the throw exists to prevent, in a
different costume. The type is now resolved before the concurrency slot and
before the try, and `optionalCheck()` re-throws `DnsTypeError` alongside
`AbortError` — a query for a type the transport does not know is a bug in
`js/dns.js`, not a resolver hiccup, and must not be reported as one.

**7. Twenty-three findings, not the fifteen estimated.** The Localization impact
section estimated "roughly fifteen new findings" and 40 to 60 locale keys; the
implemented set is 23 findings and 81 keys, plus 29 more for the interface and
the CSV headers — 110 keys, translated into all thirteen locales in the same
change. The count rose because several conditions the design describes in prose
turned out to deserve their own line rather than sharing one: `caa-single-issuer`
and `caa-no-iodef` split from the CAA block, and the MX findings separated
concentration from redundancy. No finding was added that the design did not
already describe.

**9. What review changed, and what that says about the design.** This release
went through **eight** review rounds after the implementation was "done" — 0.3.0
took four — and every one found something real. The detail lives in the
untracked `CODEX review for PR#22.md` decision log; what belongs here is the
shape, because it is a property of the spec and not of the session.

**Six of the eight were in the DER key walk**, each sitting underneath a
boundary the previous round had drawn:

| Round | Found | Underneath |
| --- | --- | --- |
| 1 | byte width reported as bit length | accepting both envelopes |
| 1 | SPKI missing the PKCS#1 guards | accepting both envelopes |
| 2 | tags checked, values not | the strict structure guards |
| 3 | `e < n` compared by width, not value | the strict value guards |
| 4 | non-minimal DER lengths accepted | the exact value comparison |
| 5 | modulus parity unchecked | the canonical-encoding guards |

Rounds 6 to 8 moved outward from DER to the other parsers and found the same
pattern in a different costume: **a recognized name accepted without its
registered value grammar.** CAA read `%%%%%` as a certificate authority where
RFC 8659 §4.2 uses that exact string as its example of a value that BLOCKS
issuance — the policy reported inverted. MTA-STS and TLS-RPT were tag-bag
lookups that could not express "the version field comes first", so
`id=abc; v=STSv1` validated. DKIM counted `s=tlsrpt` keys as email signing keys.

**Three rounds found the opposite failure**, which is the one to expect when
tightening: validators rejecting *conforming* records. A blanket duplicate-field
rule contradicted RFC 8461 §3.1 and RFC 8460 §3; an FQDN-only URI check refused
`https://[2001:db8::1]/r`. Both were settled by reading the RFC text — one of
them after a reply declining the finding had already been drafted from memory.

**The design lesson, for `dnssec-evidence` and anything else parsing records
here:** a structural check that is locally consistent is not finished. Validate
the encoding, then the values, then the relationships between them — and when a
field name is recognized, validate what its specification says the value may be.
"A key is published" and "that key signs your mail" are different claims, and
only the second answers the question this audit asks.

**8. Verification.** `npm test` passes 1,813 assertions across the five suites,
up from 1,189 at 0.3.0; `npm run locale:gate` passes 13/13 at 724/724 keys. The
backtest shows **zero grade movement and zero score movement** against `v0.3.0`
on the 40-domain sample, with the deep checks both off and on, and `WEIGHTS`,
`PARKED_WEIGHTS` and `GRADE_THRESHOLDS` byte-identical — acceptance criterion 5.
Fan-out is about 32 queries per domain with the deep checks off, unchanged from
0.3.0 (`cloudflare.com` issues exactly 43 on both releases), and about 39 with
them on, where the same domain issues 59; `PRIVACY.md` carries both numbers and its storage table is untouched,
because the toggle's session memory is a module variable and not a second
`localStorage` key.

The final review also exercised the candidate/effective-state boundary, the
complete DKIM tag-list and base64 grammar, and the imported URI productions.
The live gate caught a wildcard-specific false positive that fixtures had not:
`gov.uk` synthesized `v=DMARC1; p=reject` at every tested DKIM selector, and an
intermediate implementation treated the DMARC `p=` tag as a public key. The
candidate filter now retains malformed DKIM-family records as evidence while
ignoring records that explicitly declare another protocol. A three-way live
comparison of all 40 sampled domains — v0.3.0, 0.4.0 with deep checks off, and
0.4.0 with them on — reports zero per-domain score or grade movement.

The interface was exercised against live domains through the running app: the
toggle's default, its auto-disable above 50 domains, the notice text, manual
re-enable, all four detail blocks, a 40-column CSV export, and a non-English
locale rendering the new strings with DNS terms correctly left in Latin script.
That verification was done by reading the rendered DOM text rather than from
screenshots — the browser pane returned blank captures for scrolled content, so
the detail panel could not be photographed. It is not treated as a gap: the
renderer tests cover the same nodes deterministically, and the live DOM read
confirms them against real DNS.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
| 1.2 | 2026-08-26 | No implementation change. Recorded because **As implemented** item 2 makes a forward statement that is no longer true: it says `qualified` is "the stronger claim that the chain was walked and verified, which dnssec-evidence supplies". The 0.5.0 spec review concluded the opposite and retired the field. Two reasons, and item 2 had already established the first: a TLSA record lives at `_25._tcp.<mx-host>`, usually in a zone unrelated to the audited domain, so the audited domain's chain evidence says nothing about it — and local DS-to-DNSKEY matching never validates RRSIGs, so it can never exceed the resolver's per-host AD verdict that this release already records. The per-host `authenticated` field item 2 introduced is therefore the honest ceiling, and it stands unchanged. Everything item 2 says about *this* release remains correct; only its expectation of 0.5.0 was wrong. See `OQ-SEC9-07` in [dnssec-evidence](dnssec-evidence.md). |
| 1.1 | 2026-08-25 | Implemented, then hardened across eight review rounds — see **As implemented** item 9 for what they found and why the shape matters. Two spec amendments, both in the same direction — the spec had let an implementation's capabilities stand in for the protocol's rules. The DER walk was written as SPKI-only, which would have reported a conformant bare PKCS#1 key as unparseable because `crypto.subtle.importKey` does not accept that encoding; and `cryptoValidated: false` for an absent Web Crypto collapsed "not checked" into "failed", contradicting the same paragraph's own rule. Three further notes recorded: the `tlsa-published-unsigned` finding is gated on the resolver's AD bit rather than on `qualified`, which would otherwise have fired on every domain in the release; base64 is decoded in-file rather than with `atob`; and the renderer was hardened against partial result shapes. See **As implemented**. |
| 1.0 | 2026-08-25 | Final. Resolved all seven open questions. Two were settled with measurement rather than argument: `OQ-DEPTH-01`'s resolver shapes were captured before any parser was designed, and immediately found that `TLSA` comes back parenthesised where `DS` does not — a difference that would have produced a silently empty digest; and `OQ-DEPTH-05`'s 1024-bit threshold was decided by counting real keys, which showed 53% of keys on the sample are RSA-1024, so a warning would fire on most audited domains and the finding drops to informational. `OQ-DEPTH-02` takes the draft's third option, a DER walk for size with Web Crypto validation where available, which also keeps the analysis synchronous. `OQ-DEPTH-03` and `OQ-DEPTH-06` were decided by Ian; the former's "remember the user's choice" is explicitly session-scoped, because persisting it would need a second `localStorage` key and falsify `PRIVACY.md`'s "exactly one value" claim. Every code reference in the draft was re-pointed — all fifteen were stale, the spec having been written against 0.2.2 — and each referenced function was confirmed to still exist. |
