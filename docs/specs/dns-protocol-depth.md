# Spec: DNS-only protocol depth for DKIM, CAA, MX and TLSA

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | 0.4.0 |
| Status | Awaiting review |
| Depends on | [rendering-and-robustness](rendering-and-robustness.md) for rendering, [dmarcbis-tree-walk](dmarcbis-tree-walk.md) for the fixture-resolver test harness |
| Blocks | [dnssec-evidence](dnssec-evidence.md), which qualifies the DANE conclusions this release produces |
| Slug for open questions | `DEPTH` |
| Last updated | 2026-08-20 |

## Problem

The application discovers a great deal and analyzes comparatively little. It
finds DKIM selectors well, and since 0.2.2 it finds selectors named indirectly
through the domain's own SPF record, but a found selector produces only the raw
TXT string. Nobody is told whether the key is RSA-1024, RSA-2048, Ed25519, or
revoked. That is the single most actionable fact about a DKIM key and it is
sitting decoded-but-unread in `s.value`.

CAA is reduced to a boolean. `checkCAA()` at [`js/dns.js:868`](../../js/dns.js)
walks up the tree, returns `found`, the raw record strings, and the name they
were found at, and nothing parses them. A domain with
`0 issue ";"` has locked out every certificate authority, and a domain with
`0 issuewild ";"` has locked out wildcards only; the interface shows both as a
green dot.

MX records are read for provider detection at
[`js/dns.js:303`](../../js/dns.js) and never validated. An MX pointing at a
hostname that does not resolve is a total mail outage and reads today as a
normal configured mail domain. Single-MX setups, MX targets that are CNAMEs,
and MX hosts that all sit in one address block are equally invisible.

TLSA is not queried at all, so DANE for SMTP is entirely unrepresented. That
also means the transport layer cannot currently ask for it:
`dnsTypeNum()` at [`js/dns.js:71`](../../js/dns.js) knows seven record types and
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
  [`js/dns.js:1300`](../../js/dns.js) are untouched. See `OQ-DEPTH-06`.

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

`cleanAnswerData()` at [`js/dns.js:194`](../../js/dns.js) strips surrounding
quotes for non-TXT types. `DS`, `DNSKEY` and `TLSA` come back from the resolver
as space-separated presentation-format strings that must not be quote-stripped or
lowercased before parsing. Confirm the exact shape returned by the resolver
before writing the parsers; see `OQ-DEPTH-01`.

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

Key size determination for RSA uses Web Crypto rather than a hand-rolled DER
walk, because `importKey` validates the structure as a side effect:

```js
const der = base64ToBytes(tags.p);
const key = await crypto.subtle.importKey(
  'spki', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
const jwk = await crypto.subtle.exportKey('jwk', key);
const keyBits = base64UrlToBytes(jwk.n).length * 8;   // 1024, 2048, 4096
```

A key that fails `importKey` is `errors: ['unparseable-key']`, which is itself a
useful finding: a truncated `p=` value from a TXT record split across strings is
a common and completely silent DKIM failure.

Ed25519 keys are not SPKI. RFC 8463 defines the `p=` value for `k=ed25519` as
the raw 32-byte public key, base64-encoded. Detection is therefore
`keyType === 'ed25519' && keyBytes === 32`, and a length other than 32 is
`errors: ['bad-ed25519-length']`.

Because `importKey` is asynchronous, `analyzeDkimKey` is async. `checkDKIM()` at
[`js/dns.js:494`](../../js/dns.js) already awaits per-selector work, so the
analysis attaches inside `inspectDkimSelector()` at
[`js/dns.js:467`](../../js/dns.js) where each selector's records are already in
hand.

`dkimKeyRecords()` at [`js/dns.js:379`](../../js/dns.js) currently filters out
records whose `p=` is empty, which discards exactly the revoked keys this release
wants to report. Split it: keep the strict filter for the "is there a usable key
here" question, and return the discarded records separately so a revoked key is
reported as revoked rather than as absent.

Advisory findings produced:

| Finding | Condition | Severity |
| --- | --- | --- |
| `dkim-key-weak` | RSA modulus under 1024 bits | crit |
| `dkim-key-1024` | RSA modulus exactly 1024 bits | warn |
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

`isNullMx()` at [`js/dns.js:297`](../../js/dns.js) already detects the RFC 7505
null MX and that path short-circuits before this function runs.

An MX target that is a CNAME violates RFC 2181 §10.3 and RFC 5321 §5.1. It
frequently works anyway, which is why it survives in the wild, and it breaks in
specific and hard-to-diagnose ways. It is reported as a warning, not an error.

`sharedPrefixes` uses the CIDR helpers already present for the SPF subnet audit:
`parseIpCidr()`, `cidrContains()` and `ipv4ToBigInt()` / `ipv6ToBigInt()` at
[`js/dns.js:1033`](../../js/dns.js) onward. No new IP arithmetic is needed.

The whole function is wrapped in `optionalCheck()` so a resolver failure on one
MX target degrades that host to `resolves: 'unknown'` rather than discarding the
audit, following the pattern documented at [`js/dns.js:162`](../../js/dns.js).

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
[`js/app.js:744`](../../js/app.js): `dkim_key_type`, `dkim_key_bits`,
`dkim_revoked`, `caa_issuers`, `caa_wildcard_issuers`, `mx_dangling`,
`mx_host_count`, `tlsa_present`.

The detail panel gains a key line under each DKIM selector at
[`js/app.js:425`](../../js/app.js), a parsed CAA block, and an MX health block
replacing the plain `r.mx.join('\n')` at [`js/app.js:489`](../../js/app.js).

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
[`tools/scoring.test.mjs:15`](../../tools/scoring.test.mjs), which currently
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

**OQ-DEPTH-01: What exactly does the resolver return for DS, DNSKEY and TLSA in
JSON?**
The DoH JSON `data` field for these types may be presentation format, or it may
be an escaped or hex-encoded generic form for types the resolver does not
specifically format. The parsers must be written against observed output, not
assumed output. Someone needs to capture real responses for a signed domain and
a DANE-enabled mail host and attach them to this spec before implementation. Note
that `cleanAnswerData()` quote-strips and the CAA path deliberately bypasses it;
the same decision is needed for these three types.

**OQ-DEPTH-02: Is Web Crypto the right tool for RSA key size, or a plain DER
walk?**
`importKey` gives structural validation for free and is honest about malformed
keys, at the cost of making the analysis asynchronous and dependent on a secure
context. A 30-line DER length parser is synchronous, works everywhere including
`file://`, and would accept some structurally invalid keys that Web Crypto
rejects. A third option is to do both: DER walk for the size, Web Crypto for
validation when available. Which?

**OQ-DEPTH-03: Are MX health and TLSA on by default, or behind a checkbox?**
The options row already carries four toggles and a text field, and adding more
makes the default path less informative for the majority of users who never
change defaults. Against that, this is a privacy-conscious tool whose selling
point is that it makes few queries, and MX plus TLSA plus PTR could double the
fan-out. Options: on by default with the cost documented; a single "deep
protocol checks" toggle covering all three; on by default but skipped
automatically when the run exceeds some domain count. This draft prefers the
single combined toggle, defaulted on, automatically disabled above 50 domains.

**OQ-DEPTH-04: Do we implement forward-confirmed reverse DNS at all?**
FCrDNS is a deliverability signal rather than a security control, most large
providers pass it trivially, and it costs two queries per MX address. It also
does not fit the tool's stated subject, which is DNS and email *security*.
Recommendation in this draft is to add `PTR` to the transport, because 0.5.0 and
0.8.0 may want it, and to not ship the check. Agree, or is FCrDNS worth having?

**OQ-DEPTH-05: What is the threshold for a weak DKIM key?**
RFC 8301 sets the floor at 1024 bits and recommends 2048. Real-world practice
splits: many large senders still publish 1024-bit keys because some receivers
historically rejected keys over 2048 bits in a single TXT string. This draft
treats sub-1024 as critical and exactly 1024 as a warning, and does not flag 2048
at all. Is flagging 1024 as a warning going to generate noise on a majority of
audited domains, and if so is that a reason to soften it or a reason it is worth
saying?

**OQ-DEPTH-06: When do these checks enter the score, and what gives way?**
The rubric currently totals 100 across eight pillars. Adding DKIM key strength,
CAA quality, MX health and DANE means either taking weight from existing pillars
or expanding the total and rescaling. Neither happens in 0.4.0. The question for
review is what the intended end state is, so that the advisory findings are
designed with it in mind: does DKIM key strength modify the existing DKIM pillar,
or become its own? Does MX health belong in a security score at all?

**OQ-DEPTH-07: Does an unsigned TLSA record deserve a warning or an informational
finding?**
Publishing TLSA without DNSSEC provides no protection while creating a strong
appearance of protection, which argues for a warning. It also breaks nothing and
harms nobody, which argues for informational. This draft warns. Reviewers who
disagree should say what the user is supposed to do differently in each case.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
