# Spec: DNSSEC chain evidence

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | 0.5.0 |
| Status | Awaiting review |
| Depends on | [dns-protocol-depth](implemented/dns-protocol-depth.md) for `DS`, `DNSKEY` and `TLSA` transport support |
| Blocks | [findings-and-remediation](findings-and-remediation.md), which uses chain state to qualify DANE findings |
| Slug for open questions | `SEC9` |
| Last updated | 2026-08-20 |

## Problem

DNSSEC carries 15 of the 100 available points and gates the entire A tier. A
domain cannot reach `A`, `A+` or `A++` without it, per `requiresDnssec` in
`GRADE_THRESHOLDS` at [`js/dns.js:1310`](../../js/dns.js). That is a defensible
weighting, because an unsigned zone means every record the tool just examined can
be forged in transit.

The evidence behind that 15-point decision is one bit. `checkDNSSEC()` at
[`js/dns.js:939`](../../js/dns.js) issues an NS query with `do=1`, reads the AD
flag from the resolver's response, and returns `secure` or `insecure`. On
SERVFAIL it re-queries with `cd=1`, and a success there means the chain is bogus
rather than merely unsigned. That is a clever and correct use of the resolver,
and it is the whole implementation.

The problem is not that the AD flag is wrong. Cloudflare is a validating
resolver and its AD flag is trustworthy. The problem is that the user gets a
verdict with no evidence, from a third party, with no way to tell a
never-signed zone from a zone that is signed but has no DS record at its parent,
or from a zone whose DS and DNSKEY have drifted apart during a key rollover. Those
three states all render as one grey dot, and the remediation for each is
completely different.

There is also a forward dependency. [dns-protocol-depth](implemented/dns-protocol-depth.md)
adds TLSA records but hardcodes `qualified: false`, because a TLSA record without
a validated chain above it provides no protection. That flag cannot become
meaningful until this release exists.

## Scope

1. Query the child's `DNSKEY` set and the parent's `DS` set, and display them.
2. Parse algorithm, digest type, key tag and flags from both.
3. Match DS digests against DNSKEY material locally using Web Crypto.
4. Replace the four-state model with a six-state model that distinguishes the
   materially different failure modes.
5. Connect chain state to the DANE conclusions from 0.4.0.
6. Attribute every conclusion to either the resolver or local computation,
   visibly, in the interface.
7. Flag deprecated algorithms and digest types.

## Non-goals

- **No signature validation.** The tool does not verify RRSIG records. Doing so
  requires canonical wire-format reconstruction of RRsets from presentation-format
  JSON, and getting it subtly wrong would produce false "bogus" verdicts, which
  is a worse outcome than not claiming it. See `OQ-SEC9-02`.
- **No independent validating resolver.** The browser is not one and must not be
  described as one. The resolver's AD flag remains the validation signal.
- **No trust anchor handling.** The root KSK is not embedded and the chain is not
  walked to the root. See `OQ-SEC9-03`.
- **No scoring change.** The 15 points and the A-tier gate stay exactly as they
  are. New states report; they do not rescore. See `OQ-SEC9-05`.

## Design

### 1. Query plan

Three queries per audited domain, all through the existing `dohFetch()` cache and
concurrency limiter:

| Query | Purpose |
| --- | --- |
| `<domain>` `DNSKEY` with `do=1` | The child's published keys |
| `<domain>` `DS` with `do=1` | The delegation signer records, served by the parent zone |
| `<domain>` `NS` with `do=1` | The existing AD-flag probe, unchanged |

The `DS` record is owned by the child name but served authoritatively by the
parent zone, so a single query at the child name is the correct and only lookup
needed. The AD flag on the DS response matters independently: an unauthenticated
DS response cannot anchor anything, so the tool records whether the DS answer was
itself validated.

The existing SERVFAIL-then-`cd=1` bogus probe is retained unchanged.

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
  digest: Uint8Array,
  deprecated: boolean,    // digestType 1
  valid: boolean,
  errors: string[],
}
```

The key tag computation in RFC 4034 Appendix B is a fixed 15-line algorithm over
the DNSKEY RDATA, with a special case for algorithm 1. It must be implemented
exactly, because the key tag is what links a DS to a DNSKEY and an off-by-one
produces a spurious mismatch verdict on a perfectly healthy zone.

Algorithm and digest tokens are emitted as identifiers, translated in
`js/app.js`. Deprecated set: algorithms 5 and 7 (RSASHA1 family, deprecated by
RFC 8624), algorithm 3 and 6 (DSA family), and digest type 1 (SHA-1).

### 3. Local DS-to-DNSKEY matching

For each DS record, find the DNSKEY whose computed key tag and algorithm match,
then recompute the digest and compare:

```
digest_input  = canonical_owner_name_wire_format || DNSKEY_RDATA
DNSKEY_RDATA  = flags(2) || protocol(1) || algorithm(1) || public_key
computed      = SHA-256(digest_input)   // or SHA-384 for digestType 4
```

`crypto.subtle.digest('SHA-256', input)` handles the hashing. The canonical owner
name is the domain in DNS wire format: each label prefixed by its length byte,
lowercased, terminated by a zero byte. SHA-1 digests, digest type 1, cannot be
computed with Web Crypto in all browsers and are reported as
`unverifiable-digest-type` rather than as a mismatch. That is the correct
outcome anyway, since SHA-1 DS records are deprecated and a domain still using
one should be told so rather than told its chain is broken.

Result per DS:

```js
{ keyTag, algorithm, digestType,
  matchedKey: keyTag | null,
  match: 'confirmed' | 'no-matching-key' | 'digest-mismatch' | 'unverifiable',
  computedLocally: true }
```

`digest-mismatch` means a DNSKEY with the right key tag and algorithm exists but
hashes to something else, which is the classic signature of a half-completed key
rollover.

### 4. Six-state model

`checkDNSSEC()` returns a state token. The current four are `secure`,
`insecure`, `bogus`, `indeterminate`. The new set:

| State | Condition | What the operator should do |
| --- | --- | --- |
| `secure` | Resolver AD is true and at least one DS confirms a DNSKEY locally | Nothing |
| `insecure` | No DS at the parent and no DNSKEY at the child | Sign the zone and publish a DS |
| `unanchored` | DNSKEY present, no DS at the parent | Publish the DS at the registrar; the zone is signed and unprotected |
| `mismatch` | DS present, no matching DNSKEY or a digest mismatch | Finish or roll back the key rollover |
| `bogus` | SERVFAIL that resolves with `cd=1` | Validation is failing; mail and web may already be broken for validating users |
| `indeterminate` | Any transport failure | Unknown, not absent; re-run |

`unanchored` and `mismatch` are the two states this release exists to expose.
Both currently render as `insecure`, which tells a domain owner who has signed
their zone that they have not.

`signed` stays a boolean derived from `state === 'secure'`, so
`calcScore()` at [`js/dns.js:1742`](../../js/dns.js), `gradeFor()` and the
`unprovenPillars()` logic at [`js/dns.js:1725`](../../js/dns.js) need no change.
`indeterminate` continues to mark the DNSSEC pillar unproven.

### 5. Attribution

Every conclusion carries its source, and the interface shows it:

```js
dnssec: {
  signed, state,
  resolverValidated: boolean,     // the AD flag, from Cloudflare
  dsAuthenticated: boolean,       // AD flag on the DS response specifically
  keys: [ …parseDnskey results… ],
  ds: [ …parseDs results with match verdicts… ],
  chain: [{ claim, source: 'resolver' | 'local', detail }],
  deprecatedAlgorithms: number[],
  deprecatedDigests: number[],
  unknown: boolean,
}
```

The `chain` array is the honesty mechanism. It reads, in the interface, as a
short list along the lines of "Cloudflare reports this answer as authenticated"
attributed to the resolver, and "DS key tag 12345 matches DNSKEY 12345 by SHA-256
digest" attributed to local computation. A reviewer or a user can then see
exactly which part of the verdict came from a third party.

The interface must never assemble a `secure` claim out of local evidence alone.
DNSKEY records existing, and even a DS digest matching, does not prove the zone's
signatures validate. Both facts together are consistent with a correctly signed
zone and also with a zone whose RRSIGs have all expired. The AD flag is what
covers the gap, and the tool says so.

### 6. DANE qualification

`checkTlsa()` from 0.4.0 gains its qualification input:

```js
qualified = dnssec.state === 'secure' && dnssec.resolverValidated
```

A TLSA record on an `unanchored`, `mismatch`, `insecure` or `bogus` zone is
reported as published and unprotected. The `tlsa-published-unsigned` finding from
0.4.0 gets its precise condition here.

## Localization impact

Roughly 25 to 35 new keys: six state descriptions, DS match verdicts, algorithm
and digest names, deprecation findings, the chain attribution labels, and detail
panel headings.

Never translated: `DNSSEC`, `DNSKEY`, `DS`, `RRSIG`, `TLSA`, `DANE`, `KSK`,
`ZSK`, `SEP`, `AD`, `SHA-1`, `SHA-256`, `SHA-384`, `RSASHA256`, `ECDSAP256SHA256`,
`ED25519`, and numeric algorithm and digest identifiers. Always translated: "key
tag", "signed", "unsigned", "not anchored", "mismatch", "deprecated",
"validated by the resolver", "computed locally".

All thirteen locales in the same change.

## Testing

`parseDnskey()`, `parseDs()`, the key tag algorithm and the digest matcher are
pure and test in the existing sandbox, with `crypto.subtle` added to the sandbox
globals.

Key tag fixtures must include the published examples from RFC 4034 Appendix B
plus at least one real key per algorithm family, because the key tag algorithm is
the single most error-prone piece of this release.

| Fixture | Expectation |
| --- | --- |
| RFC 4034 Appendix B example key | Key tag matches the RFC's stated value |
| Real RSASHA256 KSK with matching DS | `match: 'confirmed'` |
| DS with correct key tag, wrong digest | `digest-mismatch` |
| DS with a key tag no DNSKEY carries | `no-matching-key` |
| SHA-1 DS | `unverifiable`, `deprecated: true`, not a mismatch |
| SHA-384 DS | Confirmed via SHA-384 |
| DNSKEY set with no DS | `state: 'unanchored'` |
| No DNSKEY, no DS | `state: 'insecure'` |
| SERVFAIL then `cd=1` success | `state: 'bogus'` |
| Timeout on the DNSKEY query | `state: 'indeterminate'`, `unknown: true` |
| Revoked key, REVOKE bit set | Reported, not counted as anchoring |
| Algorithm 5 (RSASHA1) | `deprecatedAlgorithms: [5]` |
| Key tag collision, two keys same tag | Both tried, match if either confirms |
| Owner name with an uppercase label | Canonical form lowercases before hashing |
| Owner name at a deep subdomain | Wire-format encoding correct for 4+ labels |

Cross-check the six-state classifier against a live list of known-state domains
in the backtest, including at least one domain in each of `unanchored` and
`mismatch` if one can be found, since those are the states with no existing
coverage.

Assert that `dnssec.signed` for every backtest domain is identical to 0.4.0, so
no grade moves.

## Acceptance criteria

1. The interface never labels a chain `secure` on the basis of DNSKEY records
   existing, or on any local evidence without the resolver's AD flag.
2. Every claim in the `chain` array is attributed to `resolver` or `local`, and
   the attribution is visible to the user.
3. `unanchored` and `mismatch` are distinguished from `insecure`, each with its
   own remediation text.
4. Key tag computation matches the RFC 4034 Appendix B reference values.
5. A SHA-1 DS is reported as unverifiable and deprecated, never as a mismatch.
6. `dnssec.signed` is unchanged for every backtest domain against 0.4.0, and no
   grade moves.
7. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

## Risks

**Key tag errors produce alarming false positives.** A `mismatch` verdict tells a
domain owner their DNSSEC is broken. Getting that wrong through an off-by-one in
a 15-line algorithm would be the most damaging defect this project could ship.
Mitigation: RFC reference vectors in the test suite, and a conservative fallback
where any parse failure produces `unverifiable` rather than `mismatch`.

**Presentation-format variance.** DNSKEY and DS `data` strings from the DoH JSON
endpoint may not be in the format the parsers expect, and may differ between
resolvers if the resolver is ever made configurable. Mitigation: `OQ-DEPTH-01`
in the 0.4.0 spec requires capturing real responses first; the parsers reject
unexpected shapes with an error token rather than guessing.

**Query cost on large runs.** Two additional queries per domain, 400 on a
200-domain audit. Mitigation: modest relative to the existing fan-out, and the
DNSKEY and DS answers for a shared parent are not shared, so no cache benefit is
assumed.

## Open questions

**OQ-SEC9-01: Is `unanchored` a warning or a critical finding?**
A zone that is signed with no DS at the parent gets no protection at all, and the
operator almost certainly believes it is protected, which argues for critical. It
is also a common intermediate state during a deliberate, careful DNSSEC rollout,
where the operator is signing first and publishing the DS after a soak period,
which argues for a warning. Is there a way to tell the two apart from DNS alone?
This draft says no, and warns.

**OQ-SEC9-02: Do we ever attempt RRSIG validation?**
Not in this release. The question is whether it is on the long-term roadmap at
all. Arguments for: it would make the tool genuinely independent of the resolver
and would let it detect an expired RRSIG, which is a real and common outage cause
that the AD flag only reports as bogus after it has already broken. Arguments
against: canonical RRset reconstruction from JSON presentation format is
error-prone, the failure mode is a false "your DNSSEC is broken" alarm, and the
DoH JSON API may not return RRSIG records in a form that round-trips to wire
format reliably. If it is ever attempted, it should be a separate release with
its own spec and it must report `unverifiable` on any reconstruction ambiguity.

**OQ-SEC9-03: Do we walk the chain to the root?**
Validating that `example.com`'s DS is itself signed by `com`, and `com`'s by the
root, would require DNSKEY and DS queries at every level plus an embedded root
trust anchor with its own rotation problem. The resolver already does this, and
its AD flag is the report. This draft checks exactly one link, child DNSKEY
against parent DS, and relies on the resolver for the rest. Is one link the right
amount of evidence, or does showing one link imply a completeness the tool does
not have?

**OQ-SEC9-04: Should the resolver be configurable?**
Everything in this release is framed around trusting Cloudflare's AD flag.
`PRIVACY.md` documents Cloudflare as the sole destination, and the CSP
`connect-src` enforces it. A user who does not want to trust Cloudflare's
validation has no alternative. Allowing a user-chosen DoH endpoint would require
a CSP change, would break the "one destination, documented" privacy property, and
would let a user point the tool at a hostile resolver. This draft keeps it fixed.
Worth revisiting, or settled?

**OQ-SEC9-05: Do deprecated algorithms affect the score?**
A zone signed with RSASHA1 is signed, and the resolver validates it, so it is
`secure` and earns 15 points. It is also using an algorithm the community has
deprecated. Reducing its score would be defensible and would be a scoring change,
which this release does not make. Should 0.6.0 introduce a partial-credit DNSSEC
pillar, or should algorithm deprecation stay a finding that never touches the
number?

**OQ-SEC9-06: How much of this belongs in the collapsed row versus the detail
panel?**
The DNSSEC dot in the advanced strip at [`js/app.js:296`](../../js/app.js) is
currently binary, green or grey. Six states do not fit in a dot. Options: add an
amber state for `unanchored` and `mismatch`, matching the existing treatment of
duplicated records at [`js/app.js:260`](../../js/app.js); keep the dot binary and
put everything in the detail panel; or replace the dot with a short state label
for DNSSEC only. This draft uses amber, consistent with the duplicate-record
precedent.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
