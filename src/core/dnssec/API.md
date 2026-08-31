# `src/core/dnssec/` — API contract

Required by spec [§12](../../../docs/specs/implemented/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** DNSSEC chain evaluation and DS↔DNSKEY matching, as spec §3's
tree names them. This directory emits no finding, severity, score or locale key.

**0.5.0 is the behavioural baseline.** This is the newest code in the audit and
it was reviewed hard; Task 4.5 moved it and changed nothing.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/`, siblings in this directory | everything else — including `core/dns/`, `src/platform/`, another protocol directory, `audit/`, `ui/`, `data/` |

Both the resolver and the platform's **crypto** are passed as capabilities.
Neither `core/dns/` nor `src/platform/` is imported.

## Three modules, split on the capability boundary

| Module | Takes | Why separate |
| --- | --- | --- |
| `records.js` | nothing | The parsers and the IANA tables. Pure, so they are tested with no injection at all. |
| `matching.js` | `crypto` | **The one piece of this release that computes rather than reports.** |
| `chain.js` | resolver, `matchDsSet` | Decides `state`, and holds no crypto capability of its own. |

`chain.js` receives the matcher rather than constructing it. What that buys is
worth stating exactly, because the obvious reading is wrong:

- `chain.js` has **no crypto capability** and implements no digest arithmetic.
- It consumes the matcher's **declared verdicts**.
- Those verdicts **do** reach classification — `mismatch` is selected from them
  when resolver authentication is already false.
- What it can never do is promote a zone to `secure`, override a validated
  `bogus`, or demote a zone the resolver authenticated.

So passing the matcher makes the computation/classification boundary
**injectable and independently testable**; it does not prevent matcher output
from influencing classification, and it was never meant to.

## Two axes, and keeping them apart is the whole design

`secure` and `bogus` come **only** from the resolver. The DS-to-DNSKEY
arithmetic can establish `mismatch` when AD is already false — a real influence
on the classifier, not merely on findings — but it can never promote a zone to
`secure`, override a validated `bogus`, or demote one the resolver
authenticated.

`servfail.nl` is why: its DS confirms its KSK by SHA-256, its DNSKEY set is
published, and the zone is bogus. **Local evidence agreeing is not the same as
the chain validating.** `chain.test.js` asserts both halves — a matcher that
confirms an anchor while the resolver says nothing leaves the zone `insecure`
and cannot un-bogus one, while a matcher returning `digest-mismatch` does move
the state to `mismatch`.

## The raw resolver handle, and why it is required

`dnssecLookupStatus()` and `checkDNSSEC()` are two of spec §3's six allowed
**raw-kind readers**, moved here from `js/dns.js` by Task 4.5. The allowlist in
[`tests/contract/transport-edges.test.mjs`](../../../tests/contract/transport-edges.test.mjs)
names `core/dnssec` as their owner, and that suite now asserts the file they
are found in, so a later move cannot quietly shrink the scan's coverage.

`createDnssecCheck()` takes `dohFetch` **without** `requireUsable`, for two
reasons that must both survive any later tidying:

- **`checkDNSSEC()` must never throw.** It is the only entry in the
  `Promise.all` at the advanced-checks call site with no `optionalCheck()`
  wrapper, and that is safe only because it reads `dohFetch()`'s `.kind`
  rather than calling `requireUsable()`. Keep it that way, or add the wrapper
  — `optionalCheck()` re-throws `DnsTypeError`, so a typo in a record type
  still fails loudly either way.
- **The validated-`servfail` security path.** A SERVFAIL that resolves with
  checking disabled is the resolver saying validation FAILED, and that
  outranks every local observation. A normalized array cannot express it,
  because a SERVFAIL never becomes an array at all.

`cleanAnswerData` is passed for the same reason `core/transport/tlsa.js` takes
it: the type filters (48 for DNSKEY, 43 for DS) run here, so the cleaning runs
here too. Without the filter, a `do=1` answer's RRSIG parses as a DS record
with key tag `NaN` — no error, matching no key, and a mismatch verdict on every
signed domain audited.

## Public exports

### `records.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `parseDnskey(presentationString)` | pure | `valid` is about the RECORD. |
| `parseDs(presentationString)` | pure | Digest folded to lowercase hex. |
| `dnskeyRdata(key)`, `dnskeyKeyTag(rdata, algorithm)`, `dnsWireName(domain)` | pure | The three computed inputs to a DS digest. |
| `dnskeyStructure(algorithm, bytes)` | pure | `valid` / `invalid` / `unknown`. |
| `dnssecAlgorithmEligibility`, `dnssecDigestEligibility`, `dnssecDigestName` | pure | Read the IANA tables. |
| `DNSSEC_ALGORITHMS`, `DNSSEC_ZONE_SIGNING`, `DNSSEC_DIGESTS` | tables | IANA registries, current as of 2026-08-26. |
| `DNSKEY_ERRORS`, `DS_ERRORS` | frozen arrays | `dnssec.dnskey.errors`, `dnssec.ds.errors`. |
| `DNSSEC_ALGORITHM_ELIGIBILITY`, `DNSSEC_DIGEST_ELIGIBILITY`, `DNSKEY_STRUCTURE_STATES` | frozen arrays | `dnssec.algorithmEligibility`, `dnssec.digestEligibility`, `dnssec.keyStructure`. |
| `DEPRECATED_DNSSEC_ALGORITHMS`, `DEPRECATED_DNSSEC_DIGESTS` | arrays | **Sibling export, not public API** — `chain.js` reads them. |

### `matching.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `createDsMatcher({ crypto })` | factory | Returns `{ matchDsToDnskeys, matchDsSet }`. Holds no state. |
| `anchorFactsUsable`, `dnskeyCanAnchor`, `matchConfirmsAnchor` | pure | One anchoring rule, read three ways. |
| `DS_MATCH_STATES`, `DS_UNVERIFIABLE_REASONS` | frozen arrays | `dnssec.ds.match`, `dnssec.ds.unverifiableReason`. |
| `DNSSEC_DIGEST_WEBCRYPTO` | table | **Not an IANA registry.** This implementation's map from a numeric digest code to the Web Crypto algorithm name that computes it. It grows when a runtime gains an algorithm, not when a registry does. |

### `chain.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `createDnssecCheck({ dohFetch, cleanAnswerData, matchDsSet })` | factory | Returns the `checkDNSSEC` closure. |
| `dnssecLookupStatus(result)` | pure | `{ completed, kind }`. A named raw-kind reader. |
| `DNSSEC_STATES`, `DNSSEC_CHAIN_CLAIMS`, `DNSSEC_CHAIN_SOURCES`, `DNSSEC_EVIDENCE` | frozen arrays | `dnssec.state`, `dnssec.chain.claim`, `dnssec.chain.source`, `dnssec.evidence`. |

#### Factory product

| Product | Kind | Contract |
| --- | --- | --- |
| `checkDNSSEC(domain, queryOpts)` | async | The chain state, its evidence, the parsed records and their verdicts. **Never throws.** |

### The four numeric-keyed tables

`DNSSEC_ALGORITHMS`, `DNSSEC_ZONE_SIGNING` and `DNSSEC_DIGESTS` are IANA
registries; `DNSSEC_DIGEST_WEBCRYPTO` is a capability map of this
implementation's. None of the four is a state algebra — no result field ranges
over them, and what a result carries is one value read out of a table.

[`tests/contract/state-matrix.test.mjs`](../../../tests/contract/state-matrix.test.mjs)
excuses them from spec §12.1 rule 3's comparison under two controls: a
mechanical shape test that finds numeric-keyed candidates, and a **closed
four-entry inventory** that is the semantic allowlist. The shape test alone
proves nothing — a numeric-keyed state map has the same shape — so a fifth
table fails until someone reviews it and names it. Recorded there as a Task 4.5
contract clarification, not a spec defect: §12.1 requires exported STATE
CONSTANTS to match the registry and never said every all-string export is one.

### Not exported

`bytesToHex`, `splitRdataFields`, `dnssecDigestHex`, and the digest-length,
validation-use, flag-bit, fixed-key-length and RSA modulus tables. None was an
engine member and none is exported for a test — each is reached through the
public operation whose result it shapes.

Two registry algebras deliberately have **no** constant here:
`dnssec.digestName` is `DNSSEC_DIGESTS`' values plus `null`, and restating it
would be a second source of the same fact; `dnssec.error` is the transport
kinds plus `undefined`, and it is checked as a registry union by
`transport-edges.test.mjs`, which is where propagation paths belong.

## Three answers, not two, in four places

Every one of these was a review finding before it was a design, and collapsing
any of them reports a verdict the evidence does not support.

| Question | Answers | The collapse it prevents |
| --- | --- | --- |
| Did the lookup complete? | `completed` true / false, kind carried | NXDOMAIN on the NS probe stays `indeterminate`, not `insecure`. Both score zero, but `indeterminate` marks the pillar **unproven**. |
| Is the algorithm a zone signer? | `eligible` / `ineligible` / `unknown` | An algorithm this build has not been taught is not "cannot sign". |
| Is the key material possible? | `valid` / `invalid` / `unknown` | Rejecting `unknown` refuses zones signed to a newer specification. Only `invalid` disqualifies. |
| Did the digest match? | five `DS_MATCH_STATES` | **Every failure path lands on `unverifiable`, never `digest-mismatch`.** "Our environment could not hash this" and "your zone is broken" are different sentences. |

Capability is tested by **executing**, never asserted in advance — the 1.0 spec
declined SHA-1 on a belief about browser support that was simply false.
`matching.test.js` runs the same records through a matcher built over a crypto
with no `subtle` and over one that refuses the algorithm, and both produce
`unverifiable` / `runtime-unavailable` where the working runtime produces
`confirmed`.

### `unbuildable-key` is dead code, and stays

Candidates are selected with `key.valid === true`, and every key the parser
calls valid has decodable base64, so `dnskeyRdata()` always builds. The branch
is kept because it is a real member of a real union, and both
`matching.test.js` and `legacy-shapes.test.mjs` assert the property that makes
it unreachable rather than pretending to reach it.

## Moved, not redesigned

`js/dns.js`'s DNSSEC block, unchanged apart from the two-space dedent, the
`export` keywords, two factories naming their capabilities, and the published
state constants. `dnssecDigestHex` moved a few lines down the file so the three
functions needing the crypto are contiguous; its body, including the
now-always-true `typeof crypto` guard, is untouched.

One defect was found and fixed **in** the extraction: `chain.js` referenced
`DEPRECATED_DNSSEC_ALGORITHMS` and `DEPRECATED_DNSSEC_DIGESTS`, which were
private to `records.js`. They are now sibling exports. It was found by reading
the moved code, not by a test — a fixture producing no records ran green over
the hole.

Both five-surface equivalence subjects report zero differences.
