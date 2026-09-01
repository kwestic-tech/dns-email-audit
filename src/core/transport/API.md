# `src/core/transport/` — API contract

Required by spec [§12](../../../docs/specs/implemented/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Mail **transport** security as DNS publishes it, plus pure
inspection of an MTA-STS policy body the user supplies: MTA-STS (RFC 8461),
TLS-RPT (RFC 8460) and TLSA/DANE (RFC 6698, RFC 7671). This directory emits no
finding, severity, score or locale key.

**Nothing here connects to port 25.** Nothing fetches the MTA-STS policy file
and nothing compares a TLSA record against a certificate. The DNS-derived
`advanced.mtaSts.policyVerified` stays false; local policy analysis is a
separate user-supplied result and never upgrades that public observation.

BIMI is **not** here. Brand indicators are not mail transport security; see
[`../bimi/API.md`](../bimi/API.md).

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/`, siblings in this directory | everything else — including `core/dns/`, another protocol directory, `audit/`, `ui/`, `data/` and the platform |

## Split by record, and only one takes a resolver

The split is by protocol artifact responsibility —
not by layer, and not by whether a module happens to need injection.

| Module | Does a lookup? | Shape |
| --- | --- | --- |
| `mta-sts.js` | no | pure validator |
| `mta-sts-policy.js` | no | pure policy validator and MX comparator |
| `tls-rpt.js` | no | pure validator |
| `tlsa.js` | **yes** | factory + pure parser |
| `ext-value.js` | no | one internal constant |

Only the module that performs lookups takes injected resolver capabilities.
There is no common factory over the three and there should not be one: two of
them have nothing to inject, and wrapping them to match their neighbour would
be symmetry standing in for structure.

## Public exports

### `mta-sts.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `summarizeMtaSts(txt)` | pure | The whole MTA-STS answer for one domain from its `_mta-sts` TXT records: `present`, `advertised`, `policyVerified` (always false — this checks DNS only), `record`, `candidates`, `validation`, `multiple`, `unknown`. Moved out of the audit coordinator at Task 5.2a. |
| `validateMtaStsRecord(record)` | pure | `{ valid, id, errors }`. The `id` is reported even when it fails the grammar, so the operator can see what they published. |
| `MTA_STS_ERRORS` | frozen array | `invalid-syntax`. Registry algebra `transport.mtaSts.errors`. |

`STS_ID` — `sts-id = 1*32(ALPHA / DIGIT)` — is **private to this module**. It
is one protocol's field grammar and belongs nowhere else.

### `mta-sts-policy.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `validateMtaStsPolicy(text)` | pure | Parses an already size-bounded user-supplied RFC 8461 §3.2 policy body. LF and CRLF are valid, the version need not be first, `max_age` may be zero, later duplicate non-`mx` fields are ignored, and unknown extensions are retained for diagnostics. A BOM is reported and removed; blank, malformed and wrong-case lines retain their line numbers. Policy extension values may contain `=` and `;` under their policy-specific ABNF. Returns tokens and primitives only. |
| `compareMtaStsMx(patterns, { hosts, unknown })` | pure | Returns the closed state `compared` or `unknown`, plus unmatched delivery hosts and unused policy patterns only when comparison is possible. Matching is case-insensitive, ignores a DNS presentation dot, and a wildcard matches exactly one left-most label. **Fails closed to `unknown`** on an absent fact, a missing, non-array or EMPTY `hosts`, or any entry that is not a valid hostname after normalisation — a single bad entry fails the whole comparison. `null-mx` is not a member until its composer exists. |
| `mxComparisonApplies(policyResult)` | pure | One row of `policyFindingScope()`, kept named because the two MX mismatch findings are its most consequential consumer; it delegates rather than re-deriving. Whether comparing this policy's `mx` patterns against DNS means anything: true only when the policy is **valid** and its mode is `enforce` or `testing`. `src/audit/artifacts.js` MUST gate both MX mismatch findings on it. A valid `mode: none` policy legitimately has no `mx`, and an invalid policy still exposes the `mx` lines that parsed — comparing either produces a confident false finding. |
| `policyFindingScope(policyResult)` | pure | Which SEMANTIC findings this policy state may produce: `{ state, modeFinding, maxAgeFinding, nullMxConflict, mxComparison }`, frozen. `state` is the closed algebra `transport.mtaStsPolicy.findingScope`. `src/audit/artifacts.js` READS these flags and does not re-derive them. |

The caller measures the UTF-8 byte limit before invoking the parser. This
module imports no platform capability and performs no I/O.

`validateMtaStsPolicy().diagnostics` is a line index, not a mirror of
`errors` + `warnings`: the four `missing-*` errors are raised against the
document rather than a line and therefore appear in `errors` only.

#### Which findings a policy state may produce

| Policy state | Semantic findings allowed |
| --- | --- |
| `invalid` | Parser and profile diagnostics only. No mode, max-age, null-MX or mismatch interpretation: they would be built from the fields that happened to parse. |
| `withdrawal` (valid `mode: none`) | `mta-sts.mode-none` only. RFC 8461 §8.3's removal procedure is "publish a new policy with 'mode' equal to 'none' and a small 'max_age' (e.g., one day)", so `max-age-short` here advises working against the protocol. A withdrawn policy also advertises no mail handling, so it cannot conflict with a null MX. |
| `testing` | `mta-sts.mode-testing`, max-age-short when applicable, and either the null-MX conflict or the gated MX comparison. |
| `enforce` | Max-age-short when applicable, and either the null-MX conflict or the gated MX comparison. No mode finding — `enforce` is the intended state. |

`maxAgeFinding`, `nullMxConflict` and `mxComparison` are currently true under
exactly the same condition (valid, and mode is `enforce` or `testing`); only
`modeFinding` is independent. They are kept as separate flags because they are
separate finding classes that may diverge, and collapsing them would make any
future divergence a re-derivation rather than an edit.

#### Where the MX fact comes from, and where it must not

`compareMtaStsMx` takes `{ hosts: string[], unknown }` built by
`src/audit/artifacts.js` from the domain's **delivery candidates** — the
explicit MX exchanges, or the RFC 5321 §5.1 implicit MX (the domain itself)
when no MX is published and an address record is usable. Published MX records
alone are not enough: a domain with no MX still accepts mail at itself, and a
policy naming it is correct rather than stale. It must not be handed
`advanced.mxHealth`:

| | `advanced.mxHealth` | What this comparator needs |
| --- | --- | --- |
| `hosts` | audit objects; `audit-domain.js` writes `mxHealth.hosts.map(h => h.host)` to get names out | hostname strings |
| Availability | `null` whenever deep checks are off — the interface disables them above 50 domains — or the domain has no MX, or publishes a null MX | every audited domain |
| Meaning | whether each exchange resolves | where a conformant sender would deliver |

An empty or silently-filtered host list compares as "every pattern is unused",
so an absent fact that reads as an empty one turns a healthy policy into a
stale-policy claim. That is why the guard fails closed rather than defaulting
`hosts` to `[]` or dropping entries with `filter(Boolean)`, and why every guard
ships with a negative run proving it fails when removed.

### `tls-rpt.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `summarizeTlsRpt(txt)` | pure | The whole TLS-RPT answer for one domain from its `_smtp._tls` TXT records, the same shape as MTA-STS's without `policyVerified`. Moved out of the audit coordinator at Task 5.2a. |
| `validateTlsRptRecord(record)` | pure | `{ valid, destinations, errors }`. Every destination is reported, valid or not. |
| `TLS_RPT_ERRORS` | frozen array | `invalid-syntax`. Registry algebra `transport.tlsRpt.errors`. |

### `tlsa.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `createTlsaCheck({ dohFetch, requireUsable, optionalCheck, cleanAnswerData })` | factory | Returns the `checkTlsa` closure below. Holds no state. |
| `parseTlsaRecord(presentationString)` | pure | `{ usage, selector, matchingType, data, valid, errors }`. Always returns a record. |
| `TLSA_ERRORS` | frozen array | Seven tokens. Registry algebra `transport.tlsa.errors`. |

#### Factory product

Not an export. `checkTlsa` is the closure `createTlsaCheck()` returns.

| Product | Kind | Contract |
| --- | --- | --- |
| `checkTlsa(mxHosts, queryOpts)` | async | `{ hosts, anyPresent, allAuthenticated, unauthenticatedHosts, unknown }`. Never throws for a resolver failure: each host degrades to `unknown: true`. |

### `ext-value.js` — internal

`RECORD_EXT_VALUE` is exported for its two siblings and **must not move to
`core/shared/`**, even though it sits beside `EXT_NAME`, which did:

| Production | Shared? | Why |
| --- | --- | --- |
| `EXT_NAME` | yes | RFC 8461 §3.1's name grammar, reused verbatim by RFC 8460 §3 and by the BIMI draft. One production, three readers. |
| `RECORD_EXT_VALUE` | **no** | RFC 8461 and RFC 8460 agree; the BIMI draft omits the `=` exclusion. Three readers, two grammars. |

`mta-sts.test.js` asserts `ext=a=b` is refused here and `bimi.test.js` asserts
it is accepted there, so the split is executable rather than a claim.

## Why TLSA needs the raw response

`checkTlsa()` takes `dohFetch` and `requireUsable` rather than `dohQuery`, and
does layer 3's cleaning itself with the passed `cleanAnswerData`. Both reasons
must survive any later tidying:

- **The AD bit.** `result.ad` is the only evidence the record is carried by a
  validated chain, and a normalized array does not carry it.
- **The type-52 filter.** A TLSA query commonly returns a CNAME alongside the
  records, because pointing `_25._tcp.<host>` at a shared `_dane.<zone>` name
  is ordinary practice. Handing that CNAME string to the record parser reports
  a malformed TLSA record on a correctly configured host.

## `authenticated` is three answers

| `authenticated` | `unknown` | Meaning |
| --- | --- | --- |
| `true` | `false` | The validating resolver set AD for **this query name**. |
| `false` | `false` | It did not. The record is published unprotected. |
| `null` | `true` | The lookup did not complete. Nothing is claimed. |

`do=1` costs nothing — the query is being made anyway — and it is the
difference between "this record is not protected" and "we did not look".
Without it, `tlsa-published-unsigned` would fire on a correctly signed zone
purely because nothing had looked.

The bit is read for `_25._tcp.<host>`, **not** for the audited domain. An MX
host usually lives in someone else's zone, so the audited domain's chain
evidence says nothing about whether this record is protected.

`allAuthenticated` counts only hosts that **publish**, and an `unknown` host is
never listed in `unauthenticatedHosts`.

### The retired `qualified` flag

0.4.0 kept a second flag for the stronger claim that the chain had been walked
and verified. **0.5.0 retired it rather than completing it** (`OQ-SEC9-07`):
local DS-to-DNSKEY matching never validates RRSIGs, so it can never exceed the
per-host AD bit already recorded here, and a second field that can only ever
equal the first is a claim rather than a distinction. `authenticated` is the
ceiling, and every string the interface shows says "published", never
"enabled".

## Two rules that pull against each other in MTA-STS

Both were once wrong in opposite directions, and both suppressed
`mta-sts-invalid` — a finding whose entire purpose is to catch a control the
operator believes is working.

- **Ordered and case-sensitive.** The ABNF puts the version FIRST and writes it
  `%s"STSv1"`, so `id=abc; v=STSv1` and `v=stsv1` are both unusable.
- **A duplicate is conformant.** §3.1: parsers MUST accept the record and
  ignore all entries except the first. A blanket duplicate rejection called a
  good record invalid — and then reported the **last** `id` as effective, the
  one every sender discards.

TLS-RPT has its own version of the second rule pointing the other way: more
than one `rua` field is grammatical, so rejecting the second discarded a valid
record and threw away the first destination as evidence.

## Moved, not redesigned

Except for the new `mta-sts-policy.js`, `js/dns.js`'s TLSA, MTA-STS and TLS-RPT
blocks are unchanged apart from the
two-space dedent, the `export` keywords, `checkTlsa` becoming the body of a
factory that names its four resolver capabilities, and the three published
state constants. No parsing rule, no lookup and no result shape moved with
them; both five-surface equivalence subjects report zero differences.
