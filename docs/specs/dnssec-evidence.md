# Spec: DNSSEC chain evidence

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Final) |
| Target release | 0.5.0 |
| Status | Final — implementation may begin |
| Depends on | [dns-protocol-depth](implemented/dns-protocol-depth.md) for `DS`, `DNSKEY` and `TLSA` transport support, the `DnsTypeError` re-throw in `optionalCheck()`, and the per-host `authenticated` field on `checkTlsa()` |
| Blocks | [findings-and-remediation](findings-and-remediation.md), which uses chain state to qualify DANE findings |
| Slug for open questions | `SEC9` |
| Evidence | [fixtures/dnssec-live-states-0.5.0.md](fixtures/dnssec-live-states-0.5.0.md) |
| Last updated | 2026-08-25 |

## Problem

DNSSEC carries 15 of the 100 available points on an active mail domain and 25
of 100 on a parked one, and it gates the entire A tier. A domain cannot reach
`A`, `A+` or `A++` without it, per `requiresDnssec` in `GRADE_THRESHOLDS` at
[`js/dns.js:3615`](../../js/dns.js). That is a defensible weighting, because an
unsigned zone means every record the tool just examined can be forged in
transit.

The evidence behind that decision is one bit. `checkDNSSEC()` at
[`js/dns.js:3244`](../../js/dns.js) issues an NS query with `do=1`, reads the AD
flag from the resolver's response, and returns `secure` or `insecure`. On
SERVFAIL it re-queries with `cd=1`, and a success there means the chain is bogus
rather than merely unsigned. That is a clever and correct use of the resolver,
and it is the whole implementation.

The problem is not that the AD flag is wrong. Cloudflare is a validating
resolver and its AD flag is trustworthy. The problem is that the user gets a
verdict with no evidence, from a third party, with no way to tell a
never-signed zone from a zone that is signed but has no DS record at its parent,
or from a zone whose DS and DNSKEY have drifted apart during a key rollover.
Those three states all render as one grey dot, and the remediation for each is
completely different.

`quad9.net` and `fsf.org` are both signed and both publish no DS at their
parent. The tool tells their operators, today, that they have not enabled
DNSSEC.

There is also a forward dependency. [dns-protocol-depth](implemented/dns-protocol-depth.md)
adds TLSA records but hardcodes `qualified: false`, because a TLSA record
without a validated chain above it provides no protection. `OQ-SEC9-07` settles
what becomes of that flag, and the answer is not the one the draft assumed.

## Scope

1. Query the child's `DNSKEY` set and the parent's `DS` set, and display them.
2. Parse algorithm, digest type, key tag and flags from both.
3. Match DS digests against DNSKEY material locally using Web Crypto.
4. Replace the four-state model with a six-state model that distinguishes the
   materially different failure modes, on an axis that cannot move a grade.
5. Report the local DS-to-DNSKEY evidence as its own axis, separate from the
   state.
6. Attribute every conclusion to either the resolver or local computation,
   visibly, in the interface.
7. Flag deprecated algorithms and digest types.
8. Retire `checkTlsa()`'s `qualified` flag, which this release cannot honestly
   make true. See `OQ-SEC9-07`.

## Non-goals

- **No signature validation.** The tool does not verify RRSIG records. Doing so
  requires canonical wire-format reconstruction of RRsets from presentation-format
  JSON, and getting it subtly wrong would produce false "bogus" verdicts, which
  is a worse outcome than not claiming it. See `OQ-SEC9-02`.
- **No independent validating resolver.** The browser is not one and must not be
  described as one. The resolver's AD flag remains the validation signal.
- **No trust anchor handling.** The root KSK is not embedded and the chain is not
  walked to the root. See `OQ-SEC9-03`.
- **No chain evidence for MX host zones.** This release gathers DS and DNSKEY
  for the audited domain only. A TLSA record lives at `_25._tcp.<mx-host>`,
  usually in an unrelated zone, and nothing here says anything about it. See
  `OQ-SEC9-07`.
- **No scoring change.** The weights and the A-tier gate stay exactly as they
  are. New states report; they do not rescore. See `OQ-SEC9-05`, and the
  invariant in Design §4 that makes this provable rather than hoped for.

## Design

### 1. Query plan

Three queries per audited domain, all through the existing `dohFetch()` cache and
concurrency limiter. Two of them are new; the NS probe already exists.

| Query | Purpose |
| --- | --- |
| `<domain>` `DNSKEY` with `do=1` | The child's published keys |
| `<domain>` `DS` with `do=1` | The delegation signer records, served by the parent zone |
| `<domain>` `NS` with `do=1` | The existing AD-flag probe, unchanged |

The `DS` record is owned by the child name but served authoritatively by the
parent zone, so a single query at the child name is the correct and only lookup
needed.

The existing SERVFAIL-then-`cd=1` bogus probe is retained unchanged.

**Two transport rules, both learned the hard way in 0.4.0.**

*Filter on the numeric type.* A `do=1` answer carries the `RRSIG` alongside the
record it signs — `Answer: [43, 46]` for DS, `[48, 48, 46]` for DNSKEY. An
unfiltered parser reads the RRSIG presentation string `DS 8 2 3600 1788794710 …`
as a DS record with key tag `NaN` and digest `3600…`. That is not an error. It
is a plausible-looking DS record that matches no DNSKEY, and it would raise a
`mismatch` verdict on **every signed domain audited**. Filter `a.type === 43`
and `a.type === 48`, exactly as `checkTlsa()` filters `52` to survive the shared
`_dane` CNAME.

*`checkDNSSEC()` must stay unable to throw.* It is the only entry in the
`Promise.all` at [`js/dns.js:4544`](../../js/dns.js) with no `optionalCheck()`
wrapper, and that is safe today only because it reads `dohFetch()`'s `.kind`
and never calls `requireUsable()`. The new queries follow the same discipline:
read `.kind`, never `requireUsable()`. If that ever becomes inconvenient, add
the wrapper rather than the throw — `optionalCheck()` re-throws `DnsTypeError`,
so a typo in a record type still fails loudly either way.

### 2. Record parsing

```js
function parseDnskey(presentationString) → {
  flags: number,          // 256 ZSK, 257 KSK (SEP bit 0x0001)
  protocol: number,       // must be 3
  algorithm: number,
  algorithmName: string,  // token, not English
  publicKey: Uint8Array,
  keyTag: number,         // computed per RFC 4034 Appendix B
  isKsk: boolean,         // SEP bit set
  isRevoked: boolean,     // REVOKE bit 0x0080
  deprecated: boolean,
  valid: boolean,
  errors: string[],
}

function parseDs(presentationString) → {
  keyTag: number,
  algorithm: number,
  digestType: number,     // 1 SHA-1, 2 SHA-256, 4 SHA-384
  digest: string,         // lowercase hex
  deprecated: boolean,    // digestType 1
  valid: boolean,
  errors: string[],
}
```

**`parseDs()` may reuse `parseTlsaRecord()`'s normalization. `parseDnskey()` may
not.** The idiom at [`js/dns.js:2660`](../../js/dns.js) is
`body.replace(/\s+/g, '').toLowerCase()`, which is right for a hex digest and
fatal for base64: the DNSKEY key field is case-sensitive and contains `+`, `/`
and `=`. Lowercasing it destroys the key, every digest then fails to match, and
the output is a `mismatch` verdict on a healthy zone — the exact defect the
Risks section calls the worst this project could ship. Strip whitespace and
balanced parentheses; change no case.

Measured shapes are in
[fixtures/dnssec-live-states-0.5.0.md](fixtures/dnssec-live-states-0.5.0.md) and
[implemented/fixtures/doh-shapes-0.4.0.md](implemented/fixtures/doh-shapes-0.4.0.md):
`DS` is four whitespace-separated fields with lowercase unparenthesised hex;
`DNSKEY` is four fields with contiguous case-sensitive base64, unwrapped at
every observed length including 2048-bit RSA. Parentheses are handled defensively
anyway, using the balanced-pair rule already written for TLSA — accepting `( X`
or `X )` alone defeats the point of a parser written for a presentation form.

The key tag computation in RFC 4034 Appendix B is a fixed 15-line algorithm over
the DNSKEY RDATA, with a special case for algorithm 1. It must be implemented
exactly, because the key tag is what links a DS to a DNSKEY and an off-by-one
produces a spurious mismatch verdict on a perfectly healthy zone. It was
implemented during this review and run against seven live zones; the computed
KSK tag for `ietf.org` and `cloudflare.com` is 2371, matching the DS key tag
captured independently in 0.4.0.

Algorithm and digest tokens are emitted as identifiers, translated in
`js/app.js`. Deprecated set: algorithms 5 and 7 (RSASHA1 family, deprecated by
RFC 8624), algorithms 3 and 6 (DSA family), and digest type 1 (SHA-1).

### 3. Local DS-to-DNSKEY matching

For each DS record, find the DNSKEYs whose computed key tag and algorithm match,
then recompute the digest and compare:

```
digest_input  = canonical_owner_name_wire_format || DNSKEY_RDATA
DNSKEY_RDATA  = flags(2) || protocol(1) || algorithm(1) || public_key
computed      = SHA-256(digest_input)   // or SHA-384 for digestType 4
```

`crypto.subtle.digest('SHA-256', input)` handles the hashing. The canonical owner
name is the domain in DNS wire format: each label prefixed by its length byte,
lowercased, terminated by a zero byte. Both sides of the comparison are
normalized to lowercase hex — Cloudflare returns lowercase and `dns.google`
returns uppercase, and a case-sensitive compare would report mismatch on every
domain if the resolver were ever changed.

SHA-1 digests, digest type 1, cannot be computed with Web Crypto in all browsers
and are reported as `unverifiable-digest-type` rather than as a mismatch. That is
the correct outcome anyway, since SHA-1 DS records are deprecated and a domain
still using one should be told so rather than told its chain is broken.

Result per DS:

```js
{ keyTag, algorithm, digestType,
  matchedKey: keyTag | null,
  match: 'confirmed' | 'no-matching-key' | 'digest-mismatch'
       | 'unverifiable-digest-type' | 'unverifiable',
  computedLocally: true }
```

`digest-mismatch` means a DNSKEY with the right key tag and algorithm exists but
hashes to something else, which is the classic signature of a half-completed key
rollover. `unverifiable` is the conservative fallback for any parse failure.

Derived from the set:

```js
anchorConfirmed = ds.some(d => d.match === 'confirmed')
orphanDs        = ds.filter(d => d.match === 'no-matching-key').map(d => d.keyTag)
```

**`anchorConfirmed` is existential, and this matters.** `paypal.com` publishes
two DS records: key tag 7037 confirms its KSK, and key tag 34800 matches
nothing. The zone validates, mail is delivered, and nothing is wrong with it —
one good DS beside one orphan is the ordinary appearance of a key rollover or a
stale registrar record. A rule that fires on "a DS that does not match" rather
than on "no DS that does" reports one of the internet's most security-conscious
operators as broken. An orphan DS beside a confirmed one is informational, and
nothing more.

### 4. The state model, and why it cannot move a grade

The draft of this spec defined `secure` as "resolver AD is true **and** at least
one DS confirms a DNSKEY locally". That conjunction is the defect this revision
exists to remove. It lets local evidence demote a zone the resolver validated,
and on `paypal.com` — a domain in the project's own backtest sample — it costs
15 points and the A tier.

The two things are independent axes and are modelled as such.

**Axis A, `state`.** Derived from the resolver's verdict and from what is
published. Never from digest arithmetic. The classifier is **ordered**, and the
order is part of the specification — `dnssec-failed.org` satisfies three of the
draft's conditions at once and the draft says nothing about which wins:

| # | Condition | State |
| --- | --- | --- |
| 1 | NS probe SERVFAILs and the `cd=1` re-query succeeds | `bogus` |
| 2 | NS probe did not complete | `indeterminate` |
| 3 | NS probe returned AD true | `secure` |
| 4 | AD false, DNSKEY present, no DS published | `unanchored` |
| 5 | AD false, DS published, DNSKEY published, at least one DS was verifiable, and none confirms | `mismatch` |
| 6 | Anything else | `insecure` |

Rule 5 requires *positive local proof*: at least one DS whose digest type could
actually be computed, and no confirmation from any of them. A SHA-1-only DS set
is not verifiable, so it can never reach `mismatch` — acceptance criterion 5. A
DS set present with a failed DNSKEY lookup is not verifiable either, so a
resolver hiccup can never produce the alarm.

Rule 6 is the residual, and it covers one case worth naming: AD false with local
evidence that does not explain why. The resolver's verdict stands, the
contradiction is recorded in `chain`, and the tool declines to invent a
diagnosis it cannot support.

**The invariant.** Rules 4, 5 and 6 are reachable only when AD is false, and
`signed = (state === 'secure')`, and `secure` holds exactly when AD is true. So
`signed` is byte-identical to 0.4.0 for every domain, by construction rather
than by measurement, and `state === 'indeterminate'` marks the same set of
pillars unproven at [`js/dns.js:4327`](../../js/dns.js). `calcScore()` at
[`js/dns.js:4335`](../../js/dns.js), `gradeFor()` at
[`js/dns.js:3697`](../../js/dns.js) and `unprovenPillars()` at
[`js/dns.js:4319`](../../js/dns.js) need no change. Acceptance criterion 6 is a
theorem about this table, and the backtest confirms it rather than establishing
it.

`unanchored` and `mismatch` are the two states this release exists to expose.
Both currently render as `insecure`, which tells a domain owner who has signed
their zone that they have not.

**Axis B, `dsMatch`.** The per-DS verdicts of §3, computed whenever the evidence
is available, regardless of state, feeding findings only. This is where
`paypal.com`'s orphan is reported, and where a `secure` zone can carry a
non-fatal observation without its grade moving.

### 5. Attribution

Every conclusion carries its source, and the interface shows it:

```js
dnssec: {
  signed, state,
  resolverValidated: boolean,     // the AD flag on the NS probe, from Cloudflare
  keys: [ …parseDnskey results… ],
  ds: [ …parseDs results with match verdicts… ],
  anchorConfirmed: boolean,
  orphanDs: number[],
  chain: [{ claim, source: 'resolver' | 'local', detail }],
  deprecatedAlgorithms: number[],
  deprecatedDigests: number[],
  evidence: 'complete' | 'partial' | 'none',
  error,
}
```

`evidence` states whether the DNSKEY and DS lookups completed. It is what keeps
rule 6 honest: an `insecure` proved by two empty answers and an `insecure` where
neither query returned are the same verdict from different amounts of evidence,
and the display rule in [`README.md`](README.md) — unknown is not absent —
requires the difference to be visible. It carries no scoring meaning;
`unprovenPillars()` continues to key on `state === 'indeterminate'`, which is
why the draft's `unknown` boolean is dropped rather than added: nothing would
have read it.

`dsAuthenticated` is dropped too, and the reason is measurement rather than
taste. It was proposed to separate a parent that authoritatively denies a DS
from a lookup that established nothing. Cloudflare returns `AD: false` on
`amazon.com`'s DS response even though the NSEC3 authenticated denial is right
there in the Authority section, because the answer describes an insecure
delegation. The flag is therefore false in both cases and separates nothing.
The evidence that would separate them lives in the Authority section, which
`fetchDohOnce()` at [`js/dns.js:170`](../../js/dns.js) does not return.
Surfacing it is a transport change with one consumer, and it is not made here.

The `chain` array is the honesty mechanism. It reads, in the interface, as a
short list along the lines of "Cloudflare reports this answer as authenticated"
attributed to the resolver, and "DS key tag 12345 matches DNSKEY 12345 by SHA-256
digest" attributed to local computation. A reviewer or a user can then see
exactly which part of the verdict came from a third party. It must also state
which link was checked, so that showing one link does not imply the tool walked
the chain to the root — `OQ-SEC9-03`.

The interface must never assemble a `secure` claim out of local evidence alone.
This is not a hypothetical. `servfail.nl` publishes a DS that **confirms** its
KSK by SHA-256, publishes its DNSKEY set, and returns AD true on both — and the
zone is bogus. Every piece of local evidence agrees on a broken zone. The AD flag
is what covers the gap, and the tool says so.

### 6. DANE: `qualified` is retired

`checkTlsa()`'s `qualified` flag is removed rather than made true, and each host
reports `authenticated: true | false | null` as 0.4.0 already computes it.

The draft proposed `qualified = dnssec.state === 'secure' && dnssec.resolverValidated`.
That is wrong twice over. The conjunction is redundant, since `secure` holds
exactly when AD is true. More seriously, it applies the *audited domain's* chain
state to a record at `_25._tcp.<mx-host>`, and 0.4.0's **As implemented** item 2
established that an MX host usually lives in someone else's zone, so the audited
domain's DNSSEC state says nothing about whether that record is protected. It
would call TLSA on `mx.example.net` qualified because `example.com` is signed —
reintroducing, in the release meant to fix it, the confident-but-unsupported
verdict 0.4.0 removed.

The deeper reason it cannot be rescued: local DS-to-DNSKEY matching does not
validate RRSIGs, so it is **never stronger evidence than the resolver's AD
verdict**, for the audited domain or for anything else. `servfail.nl` is the
proof. There is therefore no arrangement of this release's evidence under which
`qualified` means more than `authenticated` already means, and keeping a second
field that can only ever equal the first is how a distinction becomes a claim.

`tlsa.publishedNotQualified` is rewritten accordingly; its current text is
scoped to "this release does not verify", which stops being true in a way the
string does not capture. Per host: `tlsa.authenticated` and
`tlsa.unauthenticated` already exist and carry the meaning. The
`tlsa-published-unsigned` finding keeps firing on `authenticated === false`,
exactly as 0.4.0 shipped it.

### 7. Findings

| Finding | Condition | Severity |
| --- | --- | --- |
| `dnssec-unanchored` | `state === 'unanchored'` | warn |
| `dnssec-mismatch` | `state === 'mismatch'` | crit |
| `dnssec-ds-orphan` | `anchorConfirmed` and `orphanDs.length` | info |
| `dnssec-deprecated-algorithm` | any key on a deprecated algorithm | warn |
| `dnssec-deprecated-digest` | any DS on digest type 1 | info |
| `dnssec-key-revoked` | REVOKE bit set on a published key | info |
| `dnssec-bogus`, `dnssec-indeterminate` | unchanged from 0.4.0 | crit, warn |

`dnssec-unanchored` is a warning, not a critical. A zone signed with no DS gets
no protection, but that does not prove breakage — it is also the legitimate
intermediate state of a careful rollout that signs first and publishes the DS
after a soak period, and nothing in DNS distinguishes the two. Critical stays
reserved for demonstrably broken validation: `mismatch` and `bogus`
(`OQ-SEC9-01`).

### 8. Interface

The DNSSEC dot in the advanced strip at [`js/app.js:398`](../../js/app.js) and
[`js/app.js:444`](../../js/app.js) gains an amber state for `unanchored` and
`mismatch`, using the existing `partial` field that already drives the amber
treatment for duplicated records at [`js/app.js:402`](../../js/app.js) and
[`js/app.js:450`](../../js/app.js). The `done/5` count is unchanged: amber is not
configured. Everything else — keys, DS records, match verdicts, the chain array
— lives in the detail panel (`OQ-SEC9-06`).

The CSV cell at [`js/app.js:1365`](../../js/app.js) already emits
`dnssec.state` as a token when the domain is not signed, so `unanchored` and
`mismatch` appear there without a schema change. That is a behaviour change for
anything consuming the column and it is deliberate: tokens, not prose, is the
established rule for that export.

Renderers default their collections and return nothing on an unrecognized
shape, per 0.4.0's **As implemented** item 4. A saved report from an earlier
release has no `keys` or `ds` array, and must render less rather than taking the
row down.

## Localization impact

Roughly 60 to 90 new keys: six state descriptions, five DS match verdicts,
algorithm and digest names, `issue.<key>.msg` / `.what` / `.fix` and where
useful `.fixCode` for the six new findings, the chain attribution labels, and
detail panel headings.

The draft estimated 25 to 35. That estimate is raised deliberately: 0.4.0
estimated "roughly fifteen new findings" and 40 to 60 keys and shipped 23
findings and 110 keys, and the same pressure applies here — conditions that read
as one line in a design turn into their own line once an operator has to act on
them.

**Two existing keys change**, which the draft did not account for. Editing an
English string marks it `kwestic:stale` in all thirteen locales and requires
re-translation in the same change:

- `tlsa.publishedNotQualified` — rewritten or removed with `qualified` (§6).
- `adv.tip.dnssecOff` — currently "Not detected", which is now wrong for four of
  the six states.

Never translated: `DNSSEC`, `DNSKEY`, `DS`, `RRSIG`, `TLSA`, `DANE`, `KSK`,
`ZSK`, `SEP`, `AD`, `SHA-1`, `SHA-256`, `SHA-384`, `RSASHA256`, `ECDSAP256SHA256`,
`ED25519`, and numeric algorithm and digest identifiers. Always translated: "key
tag", "signed", "unsigned", "not anchored", "mismatch", "deprecated",
"validated by the resolver", "computed locally".

All thirteen locales in the same change.

## Testing

`parseDnskey()`, `parseDs()`, the key tag algorithm and the digest matcher are
pure and test in the existing `node:vm` sandbox. `crypto` is **already** a
sandbox global — 0.4.0 added it at
[`tools/scoring.test.mjs:21`](../../tools/scoring.test.mjs) for the DKIM key
work — so no harness change is needed. `atob` is still deliberately absent, and
the base64 decoder written in-file for 0.4.0 is reused rather than reaching for
it.

Key tag fixtures must include the published examples from RFC 4034 Appendix B
plus at least one real key per algorithm family, because the key tag algorithm is
the single most error-prone piece of this release.

| Fixture | Expectation |
| --- | --- |
| RFC 4034 Appendix B example key | Key tag matches the RFC's stated value |
| Real RSASHA256 KSK with matching DS | `match: 'confirmed'` |
| DS with correct key tag, wrong digest | `digest-mismatch` |
| DS with a key tag no DNSKEY carries | `no-matching-key` |
| SHA-1 DS | `unverifiable-digest-type`, `deprecated: true`, never `mismatch` |
| SHA-384 DS | Confirmed via SHA-384 |
| One confirming DS beside one orphan | `state: 'secure'`, `anchorConfirmed: true`, `dnssec-ds-orphan` at info |
| DNSKEY set with no DS, AD false | `state: 'unanchored'` |
| No DNSKEY, no DS | `state: 'insecure'`, `evidence: 'complete'` |
| DS present, DNSKEY lookup fails | `state: 'insecure'`, `evidence: 'partial'`, never `mismatch` |
| SERVFAIL then `cd=1` success | `state: 'bogus'`, taking precedence over DS and DNSKEY evidence |
| Timeout on the NS probe | `state: 'indeterminate'`, pillar unproven |
| Timeout on the DNSKEY query only, AD true | `state: 'secure'`, `evidence: 'partial'` — **not** indeterminate |
| Answer containing an RRSIG beside the record | RRSIG ignored, no spurious DS or key |
| DNSKEY base64 containing `+`, `/`, mixed case | Parsed byte-identical; digest confirms |
| Revoked key, REVOKE bit set | Reported, not counted as anchoring |
| Algorithm 5 (RSASHA1) | `deprecatedAlgorithms: [5]` |
| Key tag collision, two keys same tag | Both tried, match if either confirms |
| Owner name with an uppercase label | Canonical form lowercases before hashing |
| Owner name at a deep subdomain | Wire-format encoding correct for 4+ labels |
| A pre-0.5.0 saved report with no `keys`/`ds` | Detail panel renders less; the row survives |

The "timeout on the DNSKEY query" row is a corrected expectation. The draft
required `state: 'indeterminate'` there, which would have zeroed the DNSSEC
pillar on a domain the resolver had just validated — a grade movement produced
by a lookup that has no bearing on the verdict.

**Live coverage** is a new `--dnssec-states` mode in
[`tools/backtest.mjs`](../../tools/backtest.mjs), carrying the named domains
below. The 40-domain `SAMPLE` is **not** modified: it is a longitudinal score
baseline compared release to release, and mixing deliberately-broken test zones
into it would change what its histogram means. The two lists are complementary —
fixtures cover the state logic exhaustively and deterministically, and the live
mode is what catches a real zone or resolver changing behaviour under us, the
way `gov.uk`'s synthesized wildcard did in 0.4.0.

| State | Domains |
| --- | --- |
| `secure` | `cloudflare.com`, `ietf.org`, `gov.uk`, `verisigninc.com` |
| `insecure` | `amazon.com`, `godaddy.com`, `python.org` |
| `unanchored` | `quad9.net`, `fsf.org` |
| orphan DS beside a confirmed one | `paypal.com` |
| `bogus` | `dnssec-failed.org`, `servfail.nl` |

Only 11 of the 40 sample domains are signed at all, so the ordinary backtest
exercises none of this release's new paths and cannot be read as a guard on
them. It remains the guard on the invariant in §4: `dnssec.signed` and the grade
for all 40 must be identical to `v0.4.0`.

## Acceptance criteria

1. The interface never labels a chain `secure` on the basis of DNSKEY records
   existing, or on any local evidence without the resolver's AD flag.
2. Every claim in the `chain` array is attributed to `resolver` or `local`, the
   attribution is visible to the user, and it states which link was checked.
3. `unanchored` and `mismatch` are distinguished from `insecure`, each with its
   own remediation text.
4. Key tag computation matches the RFC 4034 Appendix B reference values.
5. A SHA-1 DS is reported as unverifiable and deprecated, never as a mismatch.
6. `dnssec.signed` and the grade are unchanged for every backtest domain against
   `v0.4.0`, including `paypal.com`, and `WEIGHTS`, `PARKED_WEIGHTS` and
   `GRADE_THRESHOLDS` are byte-identical.
7. Local evidence never appears in the `state` classifier except through rule 5,
   which requires positive proof and is reachable only when AD is already false.
8. `qualified` no longer appears in `checkTlsa()`'s result or anywhere in
   `js/app.js`, and no string implies the tool verified DANE for an MX host.
9. `PRIVACY.md`'s fan-out figures are **re-measured**, not adjusted by
   arithmetic. Two queries per domain are added, and the document states 39 for
   a typical domain, 59 for `cloudflare.com`, and 32 and 43 with the deep checks
   off — all four measured at `v0.4.0` and all four now stale.
10. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

## Risks

**Key tag errors produce alarming false positives.** A `mismatch` verdict tells a
domain owner their DNSSEC is broken. Mitigation: RFC reference vectors in the
test suite; a conservative fallback where any parse failure produces
`unverifiable` rather than `mismatch`; and structurally, §4 rule 5, which makes
`mismatch` unreachable without positive local proof and unreachable at all on a
zone the resolver validated. The arithmetic was verified against seven live
zones during review.

**A parser that lowercases the DNSKEY key field.** Silent, total, and it
presents as a mismatch on healthy zones. Mitigation: stated as a rule in §2, and
a fixture whose base64 contains mixed case and `+`/`/`.

**RRSIG records parsed as DS or DNSKEY records.** Would raise `mismatch` on
every signed domain. Mitigation: the type filter in §1, and a fixture whose
answer array carries an RRSIG.

**Presentation-format variance.** Largely discharged. The draft deferred to
`OQ-DEPTH-01`, which captured the shapes in
[implemented/fixtures/doh-shapes-0.4.0.md](implemented/fixtures/doh-shapes-0.4.0.md);
this review extended the capture to 2048-bit RSA keys and to the RRSIG
companions. Residual: only Cloudflare has been observed, which is what
`OQ-SEC9-04` keeps fixed, and the parsers reject unexpected shapes with an error
token rather than guessing.

**Query cost on large runs.** Two additional queries per domain, 400 on a
200-domain audit. Modest relative to the existing fan-out of roughly 39, and no
cache benefit is assumed since DNSKEY and DS answers are per-name. The figures
in `PRIVACY.md` are measured claims and criterion 9 requires re-measuring them.

## Resolved questions

**OQ-SEC9-01: Is `unanchored` a warning or a critical finding?**
*Warning.* Resolved at 1.0 by Ian. `unanchored` means zero DNSSEC protection but
does not prove breakage: it is also the legitimate pre-DS state of a careful
rollout, and the draft's own sub-question — whether DNS alone can tell the two
apart — is answered no. Critical stays reserved for demonstrably broken
validation, `mismatch` and `bogus`. An escalation to critical when the domain
also publishes TLSA was considered and rejected: TLSA normally belongs to each
MX host's zone, so the audited domain being unanchored does not necessarily
weaken it, and the per-host `authenticated` field already captures the condition
that matters.

**OQ-SEC9-02: Do we ever attempt RRSIG validation?**
*Not in this release, and not on the roadmap.* If it is ever attempted it is a
separate release with its own spec, and it must report `unverifiable` on any
reconstruction ambiguity. The argument for it — detecting an expired RRSIG
before the AD flag reports it as bogus — is real but narrow, and the failure
mode of getting canonical RRset reconstruction subtly wrong is a false "your
DNSSEC is broken" alarm on a working zone. §6 records the consequence that
matters here: because RRSIGs are not validated, local evidence is never stronger
than the resolver's verdict, which is what retires `qualified`.

**OQ-SEC9-03: Do we walk the chain to the root?**
*One link, and the interface says so.* Validating that `example.com`'s DS is
itself signed by `com`, and `com`'s by the root, needs an embedded root trust
anchor with its own rotation problem, and the resolver already does it. The
draft's worry — that showing one link implies a completeness the tool does not
have — is answered in the `chain` array rather than by walking further:
criterion 2 requires each entry to state which link was checked.

**OQ-SEC9-04: Should the resolver be configurable?**
*Settled: it stays fixed.* A user-chosen DoH endpoint would require a CSP
change, break the "one destination, documented" property in `PRIVACY.md`, and
let a user point the tool at a hostile resolver. One supporting datum from this
review: `dns.google` returns DS digests in uppercase hex where Cloudflare
returns lowercase, so a configurable resolver would have needed case
normalization the draft did not specify. §3 normalizes regardless.

**OQ-SEC9-05: Do deprecated algorithms affect the score?**
*No. Finding only.* A zone signed with RSASHA1 is signed and the resolver
validates it, so it is `secure` and earns its points. Reducing its score is a
scoring change, which this release does not make. Whether 0.6.0 introduces a
partial-credit DNSSEC pillar is deferred to
[findings-and-remediation](findings-and-remediation.md), which is where severity
and confidence get a model.

**OQ-SEC9-06: How much belongs in the collapsed row versus the detail panel?**
*Amber in the dot, everything else in the panel.* Consistent with the
duplicate-record precedent, and it needs no new rendering concept: the existing
`partial` field already drives amber at [`js/app.js:402`](../../js/app.js) and
[`js/app.js:450`](../../js/app.js). See §8.

**OQ-SEC9-07: What becomes of `checkTlsa()`'s `qualified` flag?**
*It is retired.* Raised during the 1.0 review; resolved by Ian. The draft's §6
would have qualified an MX host's TLSA record from the audited domain's chain
state, which 0.4.0's **As implemented** item 2 had already established says
nothing about it. Two alternatives were considered and rejected: restricting
`qualified` to MX hosts within the audited zone, using the `inAudited` flag
0.4.0 computes, and walking the chain per distinct MX host zone. Both fail on
the same fact — local DS-to-DNSKEY matching does not validate RRSIGs, so it is
never stronger than the AD bit the host already reports, and a second field that
can only equal the first is a claim rather than a distinction. Each TLSA host
reports `authenticated: true | false | null` and nothing more. See §6.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
| 1.0 | 2026-08-25 | Final. The state model was rebuilt: the draft defined `secure` as AD true **and** a local DS confirmation, which let local evidence demote a zone the resolver had validated. Measured against live DNS, that flips `paypal.com` — already in the backtest sample, validating, delivering mail — to `mismatch`, costing 15 points and the A tier, and so failed the draft's own acceptance criterion 6. `state` and local `dsMatch` are now separate axes, the classifier is ordered rather than a table of independent conditions (`dnssec-failed.org` satisfied three of them at once), `mismatch` requires positive proof and is reachable only when AD is already false, and the resulting invariant makes "no grade moves" a theorem rather than a hope. `OQ-SEC9-07` was raised and retires `qualified` outright: §6 would have qualified an MX host's TLSA record from the audited domain's chain state, undoing 0.4.0's **As implemented** item 2, and no arrangement of this release's evidence can make the field mean more than the per-host AD bit, because local matching never validates RRSIGs. `dsAuthenticated` and `unknown` are dropped — the first because Cloudflare returns AD false on an authenticated denial of DS, measured on `amazon.com`, so it separates nothing; the second because nothing would have read it. Three transport and parsing rules added from live capture: filter answers on the numeric type or every signed domain reports `mismatch` from its own RRSIG; never lowercase the DNSKEY base64; keep `checkDNSSEC()` unable to throw, since it is the only unwrapped entry in its `Promise.all`. Live domains were found for every state, so the draft's "if one can be found" is replaced by a named `--dnssec-states` backtest mode that leaves the longitudinal `SAMPLE` untouched. All six code references were re-pointed — all six were stale, the draft having been written against 0.2.2 — the Problem section corrected to state DNSSEC's 25-point weight on parked domains, the sandbox no longer asked to add a `crypto` global that 0.4.0 already added, the localization estimate raised from 25–35 to 60–90 keys with two existing keys marked for rewrite, and `PRIVACY.md`'s four measured fan-out figures added to the acceptance criteria. Evidence: [fixtures/dnssec-live-states-0.5.0.md](fixtures/dnssec-live-states-0.5.0.md). |
