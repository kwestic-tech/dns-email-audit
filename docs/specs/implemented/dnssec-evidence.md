# Spec: DNSSEC chain evidence

| Field | Value |
| --- | --- |
| Spec version | 1.4 (Implemented) |
| Target release | 0.5.0 |
| Status | Implemented and released |
| Released in | `v0.5.0`, 2026-08-26 |
| Pull request | _filled at merge_ |
| Merge commit | _filled at merge_ |
| Depends on | [dns-protocol-depth](dns-protocol-depth.md) for `DS`, `DNSKEY` and `TLSA` transport support, the `DnsTypeError` re-throw in `optionalCheck()`, and the per-host `authenticated` field on `checkTlsa()` |
| Blocks | [findings-and-remediation](../findings-and-remediation.md), whose DANE conditions read `checkTlsa()`'s per-host `authenticated` evidence. **Not** the audited domain's chain state — see `OQ-SEC9-07`. |
| Slug for open questions | `SEC9` |
| Evidence | [fixtures/dnssec-live-states-0.5.0.md](fixtures/dnssec-live-states-0.5.0.md) |
| Last updated | 2026-08-26 |

## Problem

DNSSEC carries 15 of the 100 available points on an active mail domain and 25
of 100 on a parked one, and it gates the entire A tier. A domain cannot reach
`A`, `A+` or `A++` without it, per `requiresDnssec` in `GRADE_THRESHOLDS` at
[`js/dns.js:3615`](../../../js/dns.js). That is a defensible weighting, because an
unsigned zone means every record the tool just examined can be forged in
transit.

The evidence behind that decision is one bit. `checkDNSSEC()` at
[`js/dns.js:3244`](../../../js/dns.js) issues an NS query with `do=1`, reads the AD
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

There is also a forward dependency. [dns-protocol-depth](dns-protocol-depth.md)
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
`Promise.all` at [`js/dns.js:4544`](../../../js/dns.js) with no `optionalCheck()`
wrapper, and that is safe today only because it reads `dohFetch()`'s `.kind`
and never calls `requireUsable()`. The new queries follow the same discipline:
read `.kind`, never `requireUsable()`. If that ever becomes inconvenient, add
the wrapper rather than the throw — `optionalCheck()` re-throws `DnsTypeError`,
so a typo in a record type still fails loudly either way.

### 2. Record parsing

```js
function parseDnskey(presentationString) → {
  flags: number,          // raw bits; Zone 0x0100, REVOKE 0x0080, SEP 0x0001
  protocol: number,       // must be 3
  algorithm: number,
  algorithmName: string,  // token, not English
  algorithmEligibility: 'eligible' | 'ineligible' | 'unknown',
  publicKey: string,      // base64 as published — see below
  keyBytes: number,
  keyTag: number,         // RFC 4034 Appendix B; RFC 6840 §5.5 for algorithm 1
  keyStructure: 'valid' | 'invalid' | 'unknown',
  hasSep: boolean,        // SEP bit 0x0001 — advisory, RFC 6840 §6.2
  hasZoneFlag: boolean,   // zone bit 0x0100 — RFC 4034 §2.1.1
  hasRevokeFlag: boolean, // REVOKE bit 0x0080 — half of RFC 5011 §2.1's proof
  deprecated: boolean,
  valid: boolean,         // the RECORD parsed. NOT "the key is usable".
  errors: string[],
}

function parseDs(presentationString) → {
  keyTag: number,
  algorithm: number,
  algorithmName: string,
  algorithmEligibility: 'eligible' | 'ineligible' | 'unknown',
  digestType: number,
  digestName: string,
  digestEligibility: 'eligible' | 'ineligible' | 'unknown',
  digest: string,         // lowercase hex
  deprecated: boolean,
  valid: boolean,
  errors: string[],
}
```

**Every flag is named for the bit it is, never for the role it suggests.**

- `hasSep` is not `isKsk`. RFC 6840 §6.2: the SEP bit "has no effect on how a
  DNSKEY may be used", and validation is *prohibited* from consulting it. A key
  without SEP may be the only secure entry point a zone has, so the matcher
  must never require it and the interface must not call a SEP key "the KSK".
- `hasRevokeFlag` is not `isRevoked`. RFC 5011 §2.1 makes a key revoked when a
  resolver sees it **in a self-signed RRset** with the bit set. This release
  does not validate RRSIGs, so it holds one half of a two-part proof. The
  interface says "REVOKE flag set", never "key revoked".
- `hasZoneFlag` is the one flag with a normative consequence — RFC 4034 §2.1.1
  says a key without it MUST NOT verify RRsets — and it is still reported here
  and applied where matching happens, not folded in at parse time.

**`valid` is a statement about the record, not about the key.** Whether the key
material is even structurally possible for its declared algorithm is
`keyStructure`:

| Value | Meaning |
| --- | --- |
| `valid` | The material fits the algorithm's registered key format |
| `invalid` | A recognized algorithm carrying material it cannot possibly be |
| `unknown` | This build does not implement that algorithm's key grammar |

Checked: ECDSA P-256 and P-384 at 64 and 96 octets (RFC 6605 §4 — Q is the
uncompressed point `x|y`), Ed25519 at 32 and Ed448 at 57 (RFC 8080 §3), and the
RSA family's canonical exponent-and-modulus encoding (RFC 3110 §§2–3),
including its length form, prohibition on leading zero octets and 4096-bit
limits. DSA, GOST, SM2 and ML-DSA are `unknown`.

**The RSA modulus floor is per-algorithm.** RFC 3110 §3 sets 512 bits for the
RSA/SHA-1 family and RFC 5702 §2.1 repeats it for RSA/SHA-256, but **§2.2
raises RSA/SHA-512 to 1024 bits**. A single shared minimum drops that
constraint — permissively, so it breaks no zone, and still a recognized
algorithm accepted without the limit its own specification states.

**Structure and algorithm eligibility are independent.** An `invalid` structure
disqualifies. An `unknown` structure must never be read as a fault: a DS digest
is computed over the raw RDATA, so a parent and child can agree perfectly about
a key whose internals nothing here can parse. Separately, the IANA registry's
Zone Signing column gives `algorithmEligibility`: `eligible` for an affirmative
`Y`, `ineligible` for an affirmative `N`, and `unknown` for an unassigned number
this build cannot judge. Only affirmative `eligible` may contribute to
`anchorConfirmed`; `unknown` produces neither confirmation nor mismatch.
Algorithms 0 (DELETE), 1 (RSAMD5), 2 (DH), and 252 (INDIRECT) are named but
explicitly ineligible. Recognition, structural parsing, deprecation, and zone-
signing eligibility remain four separate facts.

Collapsing these facts into one boolean is how a recognized name gets accepted
without its registered value grammar, the failure 0.4.0 removed from CAA,
MTA-STS and DKIM in three separate rounds. Before the split, `257 3 15 AA==` —
a one-octet Ed25519 key — parsed as `valid: true` and computed a key tag.

**`parseDs()` may reuse `parseTlsaRecord()`'s normalization. `parseDnskey()` may
not.** The idiom at [`js/dns.js:2660`](../../../js/dns.js) is
`body.replace(/\s+/g, '').toLowerCase()`, which is right for a hex digest and
fatal for base64: the DNSKEY key field is case-sensitive and contains `+`, `/`
and `=`. Lowercasing it destroys the key, every digest then fails to match, and
the output is a `mismatch` verdict on a healthy zone — the exact defect the
Risks section calls the worst this project could ship. Strip whitespace and
balanced parentheses; change no case.

**Scope of the presentation grammar.** These parsers read the numeric form this
project's one resolver returns. RFC 4034 also permits algorithm mnemonics in
zone-file presentation format; Cloudflare's JSON never emits them, and rather
than accept a grammar nothing here can produce, an alphabetic algorithm field is
reported as unparseable. That is a deliberate statement of scope, and it is the
first thing to revisit if `OQ-SEC9-04` is ever reopened.

Measured shapes are in
[fixtures/dnssec-live-states-0.5.0.md](fixtures/dnssec-live-states-0.5.0.md) and
[implemented/fixtures/doh-shapes-0.4.0.md](fixtures/doh-shapes-0.4.0.md):
`DS` is four whitespace-separated fields with lowercase unparenthesised hex;
`DNSKEY` is four fields with contiguous case-sensitive base64, unwrapped at
every observed length including 2048-bit RSA. Parentheses are handled defensively
anyway, using the balanced-pair rule already written for TLSA — accepting `( X`
or `X )` alone defeats the point of a parser written for a presentation form.

**The canonical owner name checks ASCII before folding case, and the order is
load-bearing.** JavaScript's `toLowerCase()` is Unicode case conversion, not the
ASCII-only folding RFC 4034 §6.2 defines: U+212A KELVIN SIGN folds to a plain
`k`. Folding first turned a name the encoder must refuse into one it accepted,
and computed a digest for `k.example` when the caller asked about `K.example` —
a different owner name, which is a different zone.

The key tag computation in RFC 4034 Appendix B is a fixed 15-line algorithm over
the DNSKEY RDATA, with a special case for algorithm 1. It must be implemented
exactly, because the key tag is what links a DS to a DNSKEY and an off-by-one
produces a spurious mismatch verdict on a perfectly healthy zone. It was
implemented during this review and run against seven live zones; the computed
KSK tag for `ietf.org` and `cloudflare.com` is 2371, matching the DS key tag
captured independently in 0.4.0.

**The key tag for algorithm 1 does not follow RFC 4034 Appendix B.1, because
Appendix B.1 is wrong.** RFC 6840 §5.5 is the normative text: B.1 correctly
says the tag is the most significant 16 of the least significant 24 bits of the
modulus, then names the "fourth-to-last and third-to-last" octets for it, where
§5.5 corrects that to the third-to-last and second-to-last. Implementing the
appendix as literally written puts every RSAMD5 tag one octet out, which is a
mismatch verdict on every zone still using one.

Algorithm and digest tokens are emitted as identifiers and rendered by
`js/app.js` inside localized surrounding prose; the identifiers themselves are
never translated. Both registries are carried in full, current as of 2026-08-26,
including **algorithm 17** (SM2SM3, RFC 9563), **18** (ML-DSA-44, an early
allocation held by an Internet-Draft), **23** (ECC-GOST12, RFC 9558) and
**digest types 5 and 6** (GOST R 34.11-2012 and SM3, both 32 octets). Every
registered digest type has its length checked, including the two this build
cannot compute — a registered type parsed without its registered grammar is a
gap, not forward compatibility. Only a genuinely unassigned or private-use
value is carried unjudged.

Reserved and private-use digest ranges are **named**, not left null, so a value
from them cannot read as a possible future assignment: RFC 9904 reserves
128–252 and sets 253–254 aside for private use, while 7–127 and 255 are
genuinely unassigned and are the only values that get no name.

Deprecated set, per **RFC 9905 §3.1 and RFC 9906**, which obsolete RFC 8624's
tables: algorithms 1 (RSAMD5), 3 and 6 (DSA family), 5 and 7 (RSASHA1 family)
and 12 (ECC-GOST); digest types 1 (SHA-1, "deprecated for delegation" — it must
not be used for new delegations but remains required for validating existing
ones) and 3 (GOST R 34.11-94). Algorithm 23 is **not** deprecated: RFC 9558
registers it as the replacement for 12.

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

**SHA-1 is computed, not declined.** The 1.0 text said digest type 1 "cannot be
computed with Web Crypto in all browsers". That is false — SHA-1 is a registered
`SubtleCrypto.digest` algorithm and is available in every current engine; the
withdrawals of SHA-1 support were in signature and HMAC operations. Reporting
"we could not verify this" about something the runtime verifies perfectly well
is an unknown presented where a known was available, which is the precise
failure this release exists to remove — and it would have shipped inside the
honesty mechanism itself.

A SHA-1 DS is therefore `confirmed` or `digest-mismatch` on its merits, and
carries `deprecated: true` separately. The digest type that genuinely cannot be
computed is **3**, GOST R 34.11-94, which returns `NotSupportedError`.

Capability is tested at execution and never denied in advance: if a runtime
does reject an algorithm, that rejection becomes `unverifiable`, never
`mismatch`. Acceptance criterion 5 — a SHA-1 DS is never reported as a
mismatch *because of its digest type* — still holds.

Result per DS:

```js
{ keyTag, algorithm, digestType, digestEligibility,
  matchedKeyTag: number | null,
  matchedKeyIndex: number | null,   // WHICH candidate; the tag cannot say
  match: 'confirmed' | 'no-matching-key' | 'digest-mismatch'
       | 'unverifiable-digest-type' | 'unverifiable',
  unverifiableReason: 'invalid-ds' | 'invalid-owner'
       | 'runtime-unavailable' | 'unbuildable-key' | null,
  // Facts about the key the digest matched, kept beside the match and never
  // folded into it.
  matchedKeyAlgorithmEligibility: 'eligible' | 'ineligible' | 'unknown' | null,
  matchedKeyHasZoneFlag: boolean | null,
  matchedKeyStructure: 'valid' | 'invalid' | 'unknown' | null,
  matchedKeyHasRevokeFlag: boolean | null,
  computedLocally: true }
```

`digest-mismatch` means a DNSKEY with the right key tag and algorithm exists but
hashes to something else, which is the classic signature of a half-completed key
rollover.

**`matchedKeyTag` cannot identify a candidate, and does not claim to.** Every
key in a collision set shares the tag by definition — RFC 4034 Appendix B says
so outright — so `matchedKeyIndex` names the DNSKEY that actually hashed and
supplied the eligibility facts beside it. The field was called `matchedKey`,
which implied an identity a key tag cannot carry.

**`unverifiable` carries its reason.** Four distinct failures shared the token:
a DS that did not parse, an owner name the encoder refused, a runtime that
could not hash, and a candidate set whose RDATA could not be rebuilt. A detail
panel cannot remediate a result it cannot explain, and this is the same
information loss the aggregate `evidence` field was corrected for in §5.
`unverifiable-digest-type` stays a separate verdict rather than a reason: a
registered digest this build does not implement is a different statement from a
runtime failing at one it does.

**The order of the checks is normative.**

1. The DS parsed, and the owner name encodes. Otherwise `unverifiable` with a
   reason — both are statements about our input, not about the zone.
2. **Candidate selection, before digest capability.** "No key carries that tag
   and algorithm" is established without hashing anything. Deciding capability
   first reported `unverifiable-digest-type` for an orphan DS whose digest this
   build cannot compute, hiding orphan evidence behind a local limitation and
   dropping the record out of `orphanDs` — the same absent key changing verdict
   according to which hashes happen to be implemented.
3. Digest capability. A registered type this build cannot compute is
   `unverifiable-digest-type`.
4. Hash every candidate that can be rebuilt.

**A proven confirmation is never revoked.** A digest failure on a later
candidate must not discard an earlier candidate's confirmed match; before this
was fixed the verdict depended on array order. The precedence is total: any
confirmation wins, then a computation failure is `unverifiable`, and
`digest-mismatch` requires that every rebuildable candidate was hashed and none
matched.

**The match verdict and the key's eligibility are separate facts and must not
be collapsed into one token.** A DS whose digest matches a key has proved
exactly one thing: the parent and the child agree about that key. Whether the
key may then verify RRsets is a different question with a different answer, and
encoding both in `match` would force a choice between two wrong answers —
calling an ineligible key `no-matching-key`, which is false and feeds
`mismatch`, or calling it `confirmed` with no qualification, which overstates
it.

So the digest result stands on its own, and the eligibility facts sit beside it:

- **Algorithm not usable for zone signing.** IANA marks algorithms 0, 1, 2 and
  252 `Zone Signing: N` and states that only zone-signing algorithms may appear
  in DNSKEY, RRSIG and DS records. A recognized mnemonic or parseable key
  grammar does not override that registry fact. An unassigned algorithm is
  `unknown`, not silently eligible.
- **Zone flag clear.** RFC 4034 §2.1.1 is normative — the key MUST NOT verify
  RRsets. Demonstrably ineligible, from a bit this release can read.
- **`keyStructure: 'invalid'`.** A recognized algorithm carrying impossible
  material cannot be usable anchoring evidence, even if a digest matches it.
- **Digest type affirmatively prohibited.** The IANA DS registry's **"Use for
  DNSSEC Validation"** column, which is the applicable one — this tool inspects
  delegations that exist rather than creating them. The columns genuinely
  disagree, and reading the delegation column instead would mark every SHA-1
  anchor in use as prohibited: SHA-1 is `MUST NOT` for delegation and
  `RECOMMENDED` for validation, with `Implement for DNSSEC Validation: MUST`.
  Only affirmative `MUST NOT` for validation is a prohibition — types 0 and 3.
- **REVOKE flag set.** *Not* demonstrably anything. RFC 5011 §2.1 needs a
  validated self-signature this release does not compute, so the flag is
  reported and nothing is concluded from it.

The first four exclude a match from `anchorConfirmed`. The fifth does not. A DS
matching only an ineligible key falls to the residual rule 6 of §4 rather than
producing `mismatch` — raising a critical alarm on a zone that may simply be
mid-rollover is the `paypal.com` failure in a new costume.

Derived from the set:

```js
anchorConfirmed = ds.some(d => d.match === 'confirmed' &&
                              d.digestEligibility !== 'ineligible' &&
                              d.matchedKeyAlgorithmEligibility === 'eligible' &&
                              d.matchedKeyHasZoneFlag === true &&
                              d.matchedKeyStructure !== 'invalid')
orphanDs        = ds.filter(d => d.match === 'no-matching-key').map(d => d.keyTag)
```

The rule is written **once** in the implementation and read from two angles —
off a key object and off a match result. Stated twice it drifts: a mutation
disqualifying a REVOKE-flagged key was caught by only one of the two before
they were joined. The digest-eligibility clause is unreachable through the
matcher today, since the only prohibited types are also ones Web Crypto cannot
compute, so it is tested directly rather than left as a guard nothing
exercises.

**`anchorConfirmed` is existential, and this matters.** `paypal.com` publishes
two DS records: key tag 7037 confirms its KSK, and key tag 34800 matches
nothing. The zone validates, mail is delivered, and nothing is wrong with it —
one good DS beside one orphan is the ordinary appearance of a key rollover or a
stale registrar record. A rule that fires on "a DS that does not match" rather
than on "no DS that does" reports one of the internet's most security-conscious
operators as broken. An orphan DS beside a confirmed one is informational, and
nothing more.

This is not only an empirical argument. **RFC 6840 §5.11**: "if there are DS
records for multiple keys of the same algorithm, any subset of those may appear
in the DNSKEY RRset." A DS without a corresponding DNSKEY is explicitly
permitted, so a universal reading would contradict the standard as well as the
measurement.

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

**Rules 4 and 5 require the lookups they reason about to have completed**, and
this is the precondition that makes the table honest rather than merely
ordered. "No DS published" and "the DS query failed" both leave an empty `ds`
array, and rule 4 read on the arrays alone would report a domain `unanchored`
on the strength of a lookup that never returned — the unknown-as-absent defect
this release exists to eliminate, reappearing in the classifier written to
eliminate it.

- Rule 4 fires only when the DS lookup **completed** and returned nothing.
- Rule 5 fires only when the DS **and** DNSKEY lookups both completed.
- Either lookup failing sends the domain to rule 6, whose verdict is
  resolver-derived and whose missing evidence is recorded in `chain`.

Rule 5 additionally requires *positive local proof*: at least one DS whose
digest could actually be computed, and no confirmation from any of them. GOST
R 34.11-94 cannot be computed, so a GOST-only DS set can never reach
`mismatch`. Neither can a DS set matching only an ineligible key — see §3.

Rule 6 is the residual, and it covers one case worth naming: AD false with local
evidence that does not explain why. The resolver's verdict stands, the
contradiction is recorded in `chain`, and the tool declines to invent a
diagnosis it cannot support.

**The invariant.** Rules 4, 5 and 6 are reachable only when AD is false, and
`signed = (state === 'secure')`, and `secure` holds exactly when AD is true. So
`signed` is byte-identical to 0.4.0 for every domain, by construction rather
than by measurement, and `state === 'indeterminate'` marks the same set of
pillars unproven at [`js/dns.js:4327`](../../../js/dns.js). `calcScore()` at
[`js/dns.js:4335`](../../../js/dns.js), `gradeFor()` at
[`js/dns.js:3697`](../../../js/dns.js) and `unprovenPillars()` at
[`js/dns.js:4319`](../../../js/dns.js) need no change. Acceptance criterion 6 is a
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
  lookups: {
    ns:     { completed: boolean, kind: string },
    ds:     { completed: boolean, kind: string },
    dnskey: { completed: boolean, kind: string },
  },
  evidence: 'complete' | 'partial' | 'none',   // derived from `lookups`
  error,
}
```

**`lookups` records each query separately, and the classifier reads it rather
than the arrays.** An aggregate cannot say *which* lookup failed, and that is
the distinction the whole result rests on: an empty `ds` array with
`lookups.ds.completed === true` means the parent published no DS, and the same
empty array with `completed: false` means nothing was established. Those are
opposite claims. The 1.0 draft carried only the aggregate `evidence`, which
made them indistinguishable and let rule 4 report `unanchored` on a failed
lookup.

`kind` is `dohFetch()`'s own response kind — `success`, `nodata`, `nxdomain`,
`servfail`, `timeout`, `network-error` — so the detail panel can say what
happened rather than only that something did.

`evidence` survives as a **derived** summary for the interface, computed from
`lookups`, never the input to a classification. The 1.0 draft's `unknown`
boolean is still dropped: `unprovenPillars()` keys on
`state === 'indeterminate'`, and nothing would have read it.

`dsAuthenticated` is dropped too, and the reason is measurement rather than
taste. It was proposed to separate a parent that authoritatively denies a DS
from a lookup that established nothing. Cloudflare returns `AD: false` on
`amazon.com`'s DS response even though the NSEC3 authenticated denial is right
there in the Authority section, because the answer describes an insecure
delegation. The flag is therefore false in both cases and separates nothing.
The evidence that would separate them lives in the Authority section, which
`fetchDohOnce()` at [`js/dns.js:170`](../../../js/dns.js) does not return.
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

`tlsa.publishedNotQualified` is **renamed** to `tlsa.published` and rewritten.
Renamed rather than only rewritten because acceptance criterion 8 says
`qualified` must not appear anywhere in `js/app.js`, and the key name itself
did. Its old text was also scoped to "this release does not verify", which
stopped being true the moment the flag was retired rather than completed. Per host: `tlsa.authenticated` and
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
| `dnssec-deprecated-digest` | any DS on digest type 1 (SHA-1, RFC 9905) or 3 (GOST R 34.11-94, RFC 9906) | info |
| `dnssec-revoke-flag` | REVOKE bit set on a published key. Worded as the flag, never as "revoked" — RFC 5011 §2.1 needs a self-signature this release does not validate | info |
| `dnssec-key-algorithm-ineligible` | A DS confirms a key whose algorithm is affirmatively not usable for zone signing in the IANA registry | warn |
| `dnssec-key-not-zone-key` | A DS confirms a key whose zone bit is clear, so RFC 4034 §2.1.1 forbids it verifying RRsets | warn |
| `dnssec-key-malformed` | A DS confirms a key whose `keyStructure` is `invalid` | warn |
| `dnssec-bogus`, `dnssec-indeterminate` | unchanged from 0.4.0 | crit, warn |

**`dnssec-bogus` is reachable in the classifier and, for a genuinely bogus
zone, not reachable in the interface.** A validating resolver SERVFAILs *every*
query for such a zone, including the core NS lookup, and `requireUsable()`
turns that into a throw that discards the whole audit before `checkDNSSEC()` is
consulted. Measured on `dnssec-failed.org` and `servfail.nl`: the classifier
returns `bogus` correctly, and `analyzeDomain()` never completes.

This has been true since the finding shipped in 0.4.0 and is **not changed
here** — making a core lookup non-fatal is a resilience decision belonging to
[resilient-optional-checks](resilient-optional-checks.md), which
deliberately keeps the core NS/MX/TXT lookups fatal, and reversing it would
change what every failed audit in the tool reports. It is recorded because the
finding's presence in this table would otherwise imply an operator can see it.
`--dnssec-states` prints the limitation on every run rather than leaving the
two rows looking like a classifier defect.

`dnssec-unanchored` is a warning, not a critical. A zone signed with no DS gets
no protection, but that does not prove breakage — it is also the legitimate
intermediate state of a careful rollout that signs first and publishes the DS
after a soak period, and nothing in DNS distinguishes the two. Critical stays
reserved for demonstrably broken validation: `mismatch` and `bogus`
(`OQ-SEC9-01`).

### 8. Interface

The DNSSEC dot in the advanced strip at [`js/app.js:398`](../../../js/app.js) and
[`js/app.js:444`](../../../js/app.js) gains an amber state for `unanchored` and
`mismatch`, using the existing `partial` field that already drives the amber
treatment for duplicated records at [`js/app.js:402`](../../../js/app.js) and
[`js/app.js:450`](../../../js/app.js). The `done/5` count is unchanged: amber is not
configured. Everything else — keys, DS records, match verdicts, the chain array
— lives in the detail panel (`OQ-SEC9-06`).

The CSV cell at [`js/app.js:1365`](../../../js/app.js) already emits
`dnssec.state` as a token when the domain is not signed, so `unanchored` and
`mismatch` appear there without a schema change. That is a behaviour change for
anything consuming the column and it is deliberate: tokens, not prose, is the
established rule for that export.

Renderers default their collections and return nothing on an unrecognized
shape, per 0.4.0's **As implemented** item 4. A saved report from an earlier
release has no `keys` or `ds` array, and must render less rather than taking the
row down.

## As implemented

**1. `qualified` was retired, not completed — and that is the release's headline
divergence from its own inheritance.** 0.4.0's **As implemented** item 2 kept
`authenticated` and `qualified` as separate fields and said this release would
supply the second. It does not. A TLSA record lives at `_25._tcp.<host>`,
usually in a zone unrelated to the audited domain, so the audited domain's chain
evidence says nothing about it — and local DS-to-DNSKEY matching never validates
RRSIGs, so it can never exceed the per-host AD bit 0.4.0 already recorded. A
field that can only ever equal another is a claim rather than a distinction.

The knock-on work was larger than the deletion: five active documents pointed
future work at the field, and two of them expressed the same cross-zone
inference in words that did not contain the string `qualified`. Searching for
an identifier finds references to it; it does not find the idea.

**2. `dnssec-bogus` is reachable in the classifier and not in the interface.**
A validating resolver SERVFAILs *every* query for a bogus zone, including the
core NS lookup, which `requireUsable()` turns into a throw that discards the
whole audit before `checkDNSSEC()` is consulted. Measured on
`dnssec-failed.org` and `servfail.nl`: the classifier returns `bogus` correctly
and `analyzeDomain()` never completes.

True since the finding shipped in 0.4.0, and deliberately not changed here —
making a core lookup non-fatal belongs to
[resilient-optional-checks](resilient-optional-checks.md), which keeps NS, MX
and TXT fatal on purpose, and reversing it would change what every failed audit
reports. `--dnssec-states` prints the limitation on every run so the two rows do
not read as a classifier defect.

**3. The classifier tests the resolver's completion semantics exactly as 0.4.0
defined them.** `completed` means `success` or `nodata`; NXDOMAIN on the NS
probe stays `indeterminate` rather than becoming `insecure`. Both score zero,
but only `indeterminate` marks the pillar unproven in `unprovenPillars()`, and
promoting NXDOMAIN would have moved a domain out of that set — a change to what
the interface reports about a check that did not run, arriving as a side effect
of a refactor. Mutation-tested.

**4. The anchoring rule is written once and read from two angles.** It existed
twice — over a key object and inlined over the published match fields — and a
mutation disqualifying a REVOKE-flagged key was caught by only *one* of the two
tests. `anchorFactsUsable()` now holds it, with `dnskeyCanAnchor()` and
`matchConfirmsAnchor()` as adapters, plus an assertion walking the whole 18-cell
fact space to prove the two agree.

**5. The digest-eligibility clause is unreachable and kept anyway.** Every
affirmatively prohibited digest type is also one Web Crypto cannot compute, so
that half of the anchoring rule cannot be reached through the matcher — mutating
it away failed nothing. It is kept because a future registry entry can be both
computable and prohibited, and it is now tested directly through the exported
`matchConfirmsAnchor()` rather than left as protection nothing exercises.

**6. `buildSuggestions()` changed, which §7 does not mention.** The generic
"enable DNSSEC" tip fired on every unsigned domain, which on an `unanchored`
zone is wrong advice printed directly beneath a finding telling the operator to
finish what they started. It now fires only on `insecure`.

**7. Nine findings and 611 locale keys, against an estimate of 60 to 90.** The
1.1 estimate was raised from the draft's 25–35 precisely because 0.4.0 had
undershot; it undershot again. The interface strings — six state descriptions,
five match verdicts, a claim vocabulary and the attribution labels — are the
bulk, and they exist because acceptance criterion 2 requires attribution to be
visible rather than merely recorded.

**8. What review changed, and the shape it kept.** Five rounds after the spec
reached Final, and the same defect wore a different costume in four of them:
**a recognized name accepted without the value constraint its own specification
states.**

| Round | Where it landed |
| --- | --- |
| 1 | A one-octet Ed25519 key parsed as `valid` and computed a key tag |
| 2 | Four algorithms IANA marks `Zone Signing: N` could still anchor |
| 2 | RSA structure checked field presence, not RFC 3110's grammar |
| 3 | One RSA modulus floor for five algorithms; RFC 5702 §2.2 sets a second |
| 4 | A proven confirmation revoked by a later candidate failing to hash |

Round 3's arrived **inside the fix written to close the pattern**, which is the
part worth carrying forward. 0.4.0's item 9 already says a structural check that
is locally consistent is not finished. This release adds the sharper form:
**citing an RFC is not the check — the check is whether the RFC cited is the one
that defines the value being validated.** RFC 3110 defines the RSA encoding for
all five algorithms and the key-size limits for neither SHA-2 one.

Two method notes, both cheap and both would have caught a real defect:

- **Grep for the idea, not the identifier** — see item 1.
- **A tightened validator needs live-corpus evidence in the same commit.** 153
  real keys across 62 zones took one command, and it is what separates
  "stricter" from "rejects conforming records".

**9. Four assertions in this release could not fail.** Two found by me, one by
the review, one by mutation testing: a `Uint8Array` compared against an `Array`;
`matchedKey === 60485` where both candidates were forced to that tag; a
`digest-mismatch` fixture whose null fields failed the predicate anyway; and
"the state findings are mutually exclusive", which is structurally guaranteed
because `state` holds one value. **An assertion that cannot fail is
indistinguishable from one that passes**, and only mutation reveals which it is.

**10. Verification.** `npm test` passes **2,117** assertions across the five
suites, up from 1,813 at 0.4.0; `npm run locale:gate` passes 13/13 at 771/771
keys. The backtest against a `v0.4.0` worktree shows **zero grade, zero score
and zero `dnssec.signed` movement** on the 40-domain sample, with `WEIGHTS`,
`PARKED_WEIGHTS` and `GRADE_THRESHOLDS` byte-identical. That is a theorem about
the rule table rather than a property of the sample: rules 4, 5 and 6 are
reachable only when the resolver's AD flag is already false, and
`signed === (state === 'secure')`. It was also measured directly against the
released `v0.4.0` `checkDNSSEC()` across 49 live domains — zero differences.

Three domains in that comparison gained a diagnosis they did not have:
`quad9.net`, `fsf.org` and **`atlassian.com`, which is in the backtest sample**
— signed, no DS at the parent, and reported until now as having no DNSSEC.

Fan-out rises by exactly two queries per domain, measured per domain rather than
inferred from a sample total: `cloudflare.com` goes 43 → 45 with the deep checks
off and 59 → 61 with them on. The 40-domain aggregate moved by less than the
arithmetic predicts, because DKIM selector discovery varies between runs — which
is why `PRIVACY.md` now states the per-domain figure as the trustworthy one.

## Localization impact

Roughly 60 to 90 new keys: six state descriptions, five DS match verdicts,
localized labels surrounding the unmodified algorithm and digest identifiers,
`issue.<key>.msg` / `.what` / `.fix` and where useful `.fixCode` for the new
findings, the chain attribution labels, and detail panel headings.

The draft estimated 25 to 35. That estimate is raised deliberately: 0.4.0
estimated "roughly fifteen new findings" and 40 to 60 keys and shipped 23
findings and 110 keys, and the same pressure applies here — conditions that read
as one line in a design turn into their own line once an operator has to act on
them.

**Two existing keys change**, which the draft did not account for. Editing an
English string marks it `kwestic:stale` in all thirteen locales and requires
re-translation in the same change:

- `tlsa.publishedNotQualified` — renamed to `tlsa.published` and rewritten (§6).
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
[`tools/scoring.test.mjs:21`](../../../tools/scoring.test.mjs) for the DKIM key
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
| Matching SHA-1 DS | `confirmed` **and** `deprecated: true` — computed, not declined |
| SHA-384 DS | Confirmed via SHA-384, against RFC 6605 §6.2's published P-384 key and DS |
| RFC 6605 §6.1 P-256 key and DS | Key tag 55648, confirmed via SHA-256 |
| Orphan DS whose digest type is uncomputable | `no-matching-key`, and it reaches `orphanDs` |
| A candidate confirms, a later one fails to hash | `confirmed` — a proven match is never revoked |
| Nothing confirms and a computation failed | `unverifiable` with `runtime-unavailable` |
| Each `unverifiable` cause | Distinct `unverifiableReason` |
| Key tag collision | `matchedKeyIndex` names which candidate hashed |
| Digest type 0 or 3 | `digestEligibility: 'ineligible'`, distinct from a type merely unimplemented |
| Non-matching SHA-1 DS | `digest-mismatch` and `deprecated: true` |
| GOST R 34.11-94 DS | `unverifiable-digest-type`, `deprecated: true`, never `mismatch` |
| A runtime that rejects a digest algorithm | `unverifiable`, never `mismatch` |
| SHA-384 DS | Confirmed via SHA-384 |
| One confirming DS beside one orphan | `state: 'secure'`, `anchorConfirmed: true`, `dnssec-ds-orphan` at info |
| DNSKEY set with no DS, AD false | `state: 'unanchored'` |
| No DNSKEY, no DS, both lookups completed | `state: 'insecure'`, `evidence: 'complete'` |
| DS present, DNSKEY lookup fails | `state: 'insecure'`, never `mismatch` |
| **AD false, DNSKEY present, DS lookup fails** | `state: 'insecure'`, **never `unanchored`** — `lookups.ds.completed` is false, so rule 4 cannot fire |
| AD false, DNSKEY present, DS lookup returns NODATA | `state: 'unanchored'` — the lookup completed, so the absence is evidence |
| SERVFAIL then `cd=1` success | `state: 'bogus'`, taking precedence over DS and DNSKEY evidence |
| Timeout on the NS probe | `state: 'indeterminate'`, pillar unproven |
| Timeout on the DNSKEY query only, AD true | `state: 'secure'`, `evidence: 'partial'` — **not** indeterminate |
| Answer containing an RRSIG beside the record | RRSIG ignored, no spurious DS or key |
| DNSKEY base64 containing `+`, `/`, mixed case | Parsed byte-identical; digest confirms |
| REVOKE flag set on a key a DS confirms | `anchorConfirmed` stays true; `dnssec-revoke-flag` at info; no text says "revoked" |
| DS confirms a key with the zone bit clear | Excluded from `anchorConfirmed`; falls to rule 6, never `mismatch` |
| DS confirms a key with `keyStructure: 'invalid'` | Excluded from `anchorConfirmed`; `dnssec-key-malformed` |
| One-octet Ed25519 key (`257 3 15 AA==`) | `valid: true`, `keyStructure: 'invalid'` |
| Ed448 at 57 octets, ECDSA P-384 at 96 | `keyStructure: 'valid'` |
| Algorithm 17, 18 or 23 key | `keyStructure: 'unknown'`, named from the registry, not an error |
| Digest type 5 or 6 at 32 octets | Valid and named; at any other length, `bad-digest-length` |
| Algorithm 5 (RSASHA1) | `deprecatedAlgorithms: [5]` |
| Algorithm 23 (ECC-GOST12) | **Not** deprecated — RFC 9558 registers it as the replacement for 12 |
| RSAMD5 key tag | Follows RFC 6840 §5.5, not RFC 4034 Appendix B.1 as written |
| Key tag collision, two keys same tag | Both tried, match if either confirms |
| Owner name with an uppercase ASCII label | Canonical form lowercases before hashing |
| Owner name containing U+212A KELVIN SIGN | Refused — it must not fold to ASCII `k` and encode a different zone |
| Owner name at a deep subdomain | Wire-format encoding correct for 4+ labels |
| A pre-0.5.0 saved report with no `keys`/`ds` | Detail panel renders less; the row survives |

The "timeout on the DNSKEY query" row is a corrected expectation. The draft
required `state: 'indeterminate'` there, which would have zeroed the DNSSEC
pillar on a domain the resolver had just validated — a grade movement produced
by a lookup that has no bearing on the verdict.

**Live coverage** is a new `--dnssec-states` mode in
[`tools/backtest.mjs`](../../../tools/backtest.mjs), carrying the named domains
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
5. A SHA-1 DS is computed and reported on its merits with `deprecated: true`;
   it is never reported as a mismatch *because of its digest type*. A digest
   the runtime genuinely rejects is `unverifiable`, never `mismatch`.
6. `dnssec.signed` and the grade are unchanged for every backtest domain against
   `v0.4.0`, including `paypal.com`, and `WEIGHTS`, `PARKED_WEIGHTS` and
   `GRADE_THRESHOLDS` are byte-identical.
7. Local evidence never appears in the `state` classifier except through rule 5,
   which requires positive proof and is reachable only when AD is already false.
   No rule reasons about an empty `ds` or `keys` array without first checking
   that the corresponding lookup completed.
7a. No field or string asserts more than the evidence establishes. The SEP bit
   is not a KSK, the REVOKE bit is not a revocation, a parsed record is not a
   usable key, and an algorithm whose key grammar is unimplemented is `unknown`
   rather than invalid.
8. `qualified` no longer appears in `checkTlsa()`'s result, no code path in
   `js/app.js` reads it, and no string implies the tool verified DANE for an MX
   host. A comment recording *why* the flag was retired is not a violation —
   the criterion is about live claims, and a note that stops someone
   reinstating the field serves it rather than breaching it.
9. `PRIVACY.md`'s fan-out figures are **re-measured**, not adjusted by
   arithmetic. Two queries per domain are added, and the document states 39 for
   a typical domain, 59 for `cloudflare.com`, and 32 and 43 with the deep checks
   off — all four measured at `v0.4.0` and all four now stale.
10. The IANA algorithm and DS digest registries are current at implementation
   date, every registered digest type has its length checked, and the
   deprecation set cites RFC 9905/9906 rather than the obsoleted RFC 8624.
11. No active document directs future work at `qualified`. `ROADMAP.md`,
   `docs/async-development-handoff.md` and
   [findings-and-remediation](../findings-and-remediation.md) read per-host
   `authenticated` instead.
12. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

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
[implemented/fixtures/doh-shapes-0.4.0.md](fixtures/doh-shapes-0.4.0.md);
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
[findings-and-remediation](../findings-and-remediation.md), which is where severity
and confidence get a model.

**OQ-SEC9-06: How much belongs in the collapsed row versus the detail panel?**
*Amber in the dot, everything else in the panel.* Consistent with the
duplicate-record precedent, and it needs no new rendering concept: the existing
`partial` field already drives amber at [`js/app.js:402`](../../../js/app.js) and
[`js/app.js:450`](../../../js/app.js). See §8.

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

**OQ-SEC9-08: Does a DS matching only an ineligible key produce `mismatch`?**
*No. It falls to the residual rule 6.* Raised by the round-1 review of the 1.0
spec. Four eligibility facts sit beside the digest verdict rather than inside
it — the IANA Zone Signing classification, the zone flag (RFC 4034 §2.1.1),
`keyStructure` (impossible material cannot be usable evidence), and the REVOKE
flag (RFC 5011 §2.1 needs a self-signature this release does not compute, so
nothing is concluded). An affirmatively ineligible algorithm, a clear zone bit,
or an invalid structure excludes a key from `anchorConfirmed`; `unknown` does
not become a fault but also cannot become affirmative eligibility. None of the
four produces `mismatch`, because raising a critical alarm on a zone that may
be mid-rollover is the `paypal.com` failure in a different costume. See §3.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
| 1.4 | 2026-08-26 | Amended after the round-4 Codex review of the step-3 digest matcher, which returned six findings; all six reproduced before anything changed. **A proven confirmation could be revoked** — a digest failure on a later candidate returned `unverifiable` even when an earlier candidate had already confirmed, making the verdict depend on array order. The precedence is now total and normative: any confirmation wins, then a computation failure, then `digest-mismatch` only when every rebuildable candidate hashed and none matched. **Digest capability was checked before candidate selection**, so an orphan DS whose digest this build cannot compute reported `unverifiable-digest-type` and vanished from `orphanDs` — an absent key changing verdict according to which hashes are implemented. Candidate selection now comes first. **The DS digest registry repeated the algorithm-eligibility defect**: `digestEligibility` now carries the IANA determination beside the digest, read from the **"Use for DNSSEC Validation"** column, because that is the column that applies to a tool inspecting delegations rather than creating them — the columns disagree, and reading the delegation one would mark every SHA-1 anchor in use as prohibited. Reserved and private-use ranges are named so they cannot read as future assignments. **`unverifiable` lost its reason**, conflating an unparseable DS, a refused owner name, a runtime failure and an unbuildable candidate set; `unverifiableReason` separates them, and `unverifiable-digest-type` stays a verdict rather than becoming a reason. **`matchedKey` claimed an identity a key tag cannot carry** — every key in a collision set shares it, per RFC 4034 Appendix B — so it is `matchedKeyTag` beside a `matchedKeyIndex` that names the candidate, and the test asserting `matchedKey === 60485` proved nothing because both keys were forced to that tag. **The required SHA-384 matcher fixture was absent**; RFC 6605 §§6.1–6.2's published P-256 and P-384 examples are now permanent vectors. One guard the round exposed indirectly: the digest-eligibility clause in `anchorConfirmed` is unreachable through the matcher, since every prohibited digest type is also uncomputable, and mutating it away failed nothing — it is now tested directly rather than left as protection nothing exercises. |
| 1.3 | 2026-08-26 | Amended after verifying the 1.2 corrections against the RFCs and against live DNS. The 1.2 RSA structure check applied one 512-bit modulus floor to every RSA algorithm, citing RFC 3110 §3 — but **RFC 5702 §2.2 requires 1024 bits for RSA/SHA-512**, so a 512-bit algorithm-10 key was reported structurally valid against the explicit MUST of the RFC that defines it. The floor is now per-algorithm. This is the permissive direction and breaks no real zone; it is recorded because it is the same shape as every finding in this series — a recognized algorithm accepted without the value constraint its own specification states — arriving this time inside the fix written to close that pattern. The `dnssec-deprecated-digest` row also still named only digest type 1 while §2 and the implementation had already deprecated type 3 as well. **Verification:** the 1.2 tightening was re-checked against 153 live DNSKEY records across 62 zones including the root and 30 TLDs — 68 of them RSA — and rejected none, which is the evidence the round-1 response lacked when it tightened this validator against two keys. |
| 1.2 | 2026-08-26 | Amended after the Codex review of the round-1 corrections. The IANA refresh had carried four named algorithms that the same registry marks `Zone Signing: N`, but the matcher could still count them as anchors; `algorithmEligibility` now preserves that independent registry fact and `anchorConfirmed` requires an affirmative `eligible`. The RSA structure check had implemented only field presence while citing RFC 3110's full grammar; it now requires the canonical exponent-length form, rejects leading zero octets, and enforces the 4096-bit exponent and 512–4096-bit modulus protocol limits. Two stale role/localization statements were corrected, and the remaining audited-domain DANE findings were removed from the 0.6.0 draft because the already-shipped per-MX-host `authenticated` evidence is the only chain fact that applies to TLSA. |
| 1.1 | 2026-08-26 | Amended after the round-1 review of the Final spec, which returned seven findings; amended rather than deferred to **As implemented** because each one changes promised behaviour or result shape, and `docs/specs/README.md` says a Final spec discovered to be wrong is amended and re-versioned rather than allowed to diverge. **The classifier could not tell a missing DS from a failed DS lookup** — both leave an empty array, so rule 4 would have reported `unanchored` on a lookup that never returned, which is the unknown-as-absent defect reappearing inside the classifier written to remove it; per-query `lookups` status now gates rules 4 and 5, and the aggregate `evidence` survives only as a derived summary. **A recognized algorithm accepted impossible key material**: `257 3 15 AA==`, a one-octet Ed25519 key, parsed as valid and computed a key tag, so `keyStructure` now separates the record from the key with `unknown` reserved for grammars this build does not implement. **Two fields claimed more than they observed** — `isKsk` became `hasSep` (RFC 6840 §6.2: the SEP bit has no effect on how a key may be used and validation is prohibited from consulting it) and `isRevoked` became `hasRevokeFlag` (RFC 5011 §2.1 requires a self-signed RRset this release does not validate). **The registries were stale**: algorithms 17, 18 and 23 and digest types 5 and 6 were missing, so a one-octet SM3 digest parsed as a valid unnamed record; RFC 8624 is superseded by RFC 9905 and RFC 9906. **`dnsWireName()` folded case before checking ASCII**, so U+212A KELVIN SIGN became a plain `k` and encoded a different owner name than the caller asked about. **Retiring `qualified` left five active documents pointing at a deleted field**, now corrected. The review also found that §3's reason for declining SHA-1 was false — `SubtleCrypto.digest` supports it; GOST R 34.11-94 is the type that cannot be computed — so a SHA-1 DS is now computed and reported with `deprecated: true` rather than presented as an unknown where a known was available. Two corrections came from the RFCs rather than from either party: RFC 6840 §5.5 makes RFC 4034 Appendix B.1's algorithm-1 key tag erroneous, and §5.11 supplies normative support for the existential `anchorConfirmed` that 1.0 had justified only from `paypal.com`. `OQ-SEC9-08` added. Evidence: [fixtures/dnssec-live-states-0.5.0.md](fixtures/dnssec-live-states-0.5.0.md). |
| 1.0 | 2026-08-25 | Final. The state model was rebuilt: the draft defined `secure` as AD true **and** a local DS confirmation, which let local evidence demote a zone the resolver had validated. Measured against live DNS, that flips `paypal.com` — already in the backtest sample, validating, delivering mail — to `mismatch`, costing 15 points and the A tier, and so failed the draft's own acceptance criterion 6. `state` and local `dsMatch` are now separate axes, the classifier is ordered rather than a table of independent conditions (`dnssec-failed.org` satisfied three of them at once), `mismatch` requires positive proof and is reachable only when AD is already false, and the resulting invariant makes "no grade moves" a theorem rather than a hope. `OQ-SEC9-07` was raised and retires `qualified` outright: §6 would have qualified an MX host's TLSA record from the audited domain's chain state, undoing 0.4.0's **As implemented** item 2, and no arrangement of this release's evidence can make the field mean more than the per-host AD bit, because local matching never validates RRSIGs. `dsAuthenticated` and `unknown` are dropped — the first because Cloudflare returns AD false on an authenticated denial of DS, measured on `amazon.com`, so it separates nothing; the second because nothing would have read it. Three transport and parsing rules added from live capture: filter answers on the numeric type or every signed domain reports `mismatch` from its own RRSIG; never lowercase the DNSKEY base64; keep `checkDNSSEC()` unable to throw, since it is the only unwrapped entry in its `Promise.all`. Live domains were found for every state, so the draft's "if one can be found" is replaced by a named `--dnssec-states` backtest mode that leaves the longitudinal `SAMPLE` untouched. All six code references were re-pointed — all six were stale, the draft having been written against 0.2.2 — the Problem section corrected to state DNSSEC's 25-point weight on parked domains, the sandbox no longer asked to add a `crypto` global that 0.4.0 already added, the localization estimate raised from 25–35 to 60–90 keys with two existing keys marked for rewrite, and `PRIVACY.md`'s four measured fan-out figures added to the acceptance criteria. Evidence: [fixtures/dnssec-live-states-0.5.0.md](fixtures/dnssec-live-states-0.5.0.md). |
