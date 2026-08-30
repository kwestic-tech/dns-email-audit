# `src/audit/` — API contract

Required by spec [§12](../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Coordination. Which checks run, in what order, what may run
concurrently, how a failure is isolated, and how the answers become one result.
This directory decides nothing about a record's meaning — every protocol rule
belongs to a `core/<protocol>/` owner.

**Task 5.1 created the directory; Task 5.2 added the coordinator.**
`context.js` is the state boundary and `audit-domain.js` is `analyzeDomain()`.
The scoring model and issue construction arrive at Tasks 5.3 and 5.4; until
then they live in `js/dns.js` and are passed in.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/<protocol>/`, `providers/`, `audit/` siblings | `core/dns/` — the resolver handle is **passed**; `core/shared/`, which §12 does not give this directory; `ui/`, `src/data/`, the platform |

`context.js` imports nothing at all. `audit-domain.js` exercises the row: it
imports the PURE functions of `core/spf/`, `core/dmarc/`, `core/bimi/`,
`core/transport/` and `core/mx/`, and its sibling `context.js`.

**The split between what is imported and what is passed is the edge rule, not a
style choice.** §12 gives this directory no edge to `core/dns/`, so every
resolver capability arrives as an argument — including `existenceFromResponse`,
which is `core/dns/`'s. Conversely a pure protocol function is imported, because
injecting one would be a capability that is not a capability. Each list is the
other's answer:

| Reached by import | Passed as a capability |
| --- | --- |
| `analyzeSpf`, `classifySpfSubnets`, `analyzeDmarc`, `emptyDmarcStatus`, `applyInheritance`, `planReportDestinations`, `validateBimiRecord`, `validateMtaStsRecord`, `validateTlsRptRecord`, `isNullMx`, `createAuditContext` | `dohFetch`, `dohQuery`, `requireUsable`, `optionalCheck`, `existenceFromResponse`, and every protocol check built over the resolver |

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `createAuditContext({ domain, options })` | factory | The state belonging to one audit of one domain. Takes no capability: no resolver, no cache, no clock. |
| `createAuditDomain(capabilities)` | factory | Returns `{ analyzeDomain }`. Takes the resolver handle, every protocol check built over it, provider detection, and — temporarily — the four audit siblings Tasks 5.3 and 5.4 have yet to move. |
| `startsWithCI(value, prefix)` | function | Case-insensitive record selection. Pure, and a legacy engine member. |

### Factory product

| Member | Contract |
| --- | --- |
| `domain` | The audited name, lowercased and trimmed. |
| `options` | The options in force, **as supplied**. |
| `queryOptions` | The options every query is issued under. Exactly `{ signal }`. |
| `disableDnssecChecking()` | Re-issues subsequent queries with `checkingDisabled: true`, returning the new object. |
| `record(fields)` | Accumulates fields into the result being built. `domain` is **not** recordable — see below. |
| `result()` | The accumulated result, `domain` first. A fresh **outer** object per call; nested values are shared by identity. |

## `audit-domain.js` — what the coordinator owns

Which checks run, in what order, which may run concurrently, how a failure is
isolated, and how the answers become one result. It reads no record: every rule
about what a record MEANS is a `core/<protocol>/` owner's, and this file reads
their answers.

**The `Promise.all` structure is byte-identical to `v0.5.0`.** Spec §35 and the
implementation plan both forbid changing concurrency and moving code in the same
phase, and this release changes it nowhere. `audit-domain.test.js` asserts it
with an instrument rather than a claim: each stub records the moment it is
CALLED and does not resolve until the whole batch has arrived, so a batch
rewritten as a sequence of awaits fails there instead of passing with an
identical result. Three batches are covered — the four core lookups, the
advanced checks and the wildcard pair.

**The one raw-kind read.** The NS `servfail` DNSSEC preflight reads
`nsResult.kind` directly, which is spec §3's audit-owned exception edge. It was
the last raw-kind reader outside an owning directory;
[`transport-edges.test.mjs`](../../tests/contract/transport-edges.test.mjs) now
locates it in this file and asserts that `js/dns.js` holds none at all.

**The three `optionalCheck()` fallback factories that copy `DnsError.kind`**
moved here with their call sites — CAA and SPF let the kind escape, the website
fallback collapses it to `@dns-error`. `dns-transport.test.mjs` counts them per
file, so the move reads as a move rather than as three deletions.

## Three pieces of state, and the boundary around them

| Owned here | Owned elsewhere |
| --- | --- |
| The options in force | — |
| The query options they produce, including cancellation's signal | The cancellation **policy** — [`core/dns/optional.js`](../core/dns/optional.js) decides what an abort means, and the transport decides what an in-flight abort returns |
| The accumulating result | Scoring (`audit/scoring.js`, Task 5.3) and issues (`audit/issues.js`, Task 5.4) |
| — | The DoH cache — [`core/dns/cache.js`](../core/dns/cache.js), at runtime/page lifetime |
| — | Every parsing rule — `core/<protocol>/` |
| — | Concurrency — the coordinator's `Promise.all`, unchanged in this release |

### `result()` is isolated at the top level, and only there

Replacing a property of a returned result cannot reach the accumulator: the
outer object is fresh on every call. That is the whole of the isolation.
`result().score` **is** the object the audit recorded, and mutating through it
changes what a later `result()` returns.

Deliberate, and it must stay that way. Deep-cloning would change legacy
identities and value types — the result carries `BigInt`s from the SPF subnet
helpers among other things — so a structural copy would be a behaviour change
rather than a stronger boundary. `context.test.js` asserts **both** halves: the
top-level isolation, and the shared nested identity. Hardening this into
serialization means deleting a passing assertion.

### The normalized name is not a recordable field

`record()` drops a `domain` key and keeps everything else in the same call. The
audited name is normalized once, at construction, and belongs to the context: a
result whose `domain` disagreed with `ctx.domain` would name a domain the audit
did not run against. Key order is unaffected — the name still leads, as it does
in both of `analyzeDomain()`'s returns. Asserted, with the contradiction an
unguarded accumulator would produce asserted beside it.

**The cache is the one worth stating twice.** Spec Design §5 declines the source
proposal's request to scope it to the active audit, and Risk R10 is why: sibling
audits reuse it, and the fan-out that reuse produces is a figure `PRIVACY.md`
publishes. A context holding the cache would make a published privacy number a
per-audit implementation detail. `context.test.js` asserts the member list
against a fabricated context carrying a cache, so the refusal is executable.

## The options are carried, not reinterpreted

No defaulting, no coercion, no narrowing. Three observed facts make that the
only safe reading at this boundary:

- `selectors` and `dkimComprehensive` are passed onward to `checkDKIM()` as
  **values**, not read as booleans;
- `retries` is accepted by callers and observably **not** forwarded into the
  query options — `analyzeDomain()` has always built `{ signal }` alone, and
  widening it would change retry behaviour and the published fan-out;
- every flag the coordinator reads (`advanced`, `wildcard`, `dkim`, `www`,
  `deepChecks`) is read in a conditional, where an absent key and an explicit
  `false` are already the same answer.

Resolving any of that would be a behaviour change wearing a boundary's clothes.
The query options are pinned to their one key by test; when Task 5.2 brings
every reader into this directory, narrowing becomes a decision that can be made
against a complete list of them rather than a guess.

## Cancellation

The `AbortSignal` enters the audit here and reaches every query as
`queryOptions.signal`. That is the whole of this directory's part in it.

The two cancellation shapes are unchanged and are not implemented here: an
already-aborted signal throws before a request, and an abort in flight returns
transport kind `cancelled`. Nothing in `context.js` inspects `signal.aborted`,
which `context.test.js` proves by constructing a context over
`AbortSignal.abort()` and finding it identical to any other.

## The one derived query option

`disableDnssecChecking()` is `analyzeDomain()`'s `cd=1` re-issue, moved
verbatim. A validating resolver answers SERVFAIL for a bogus chain; once the
DNSSEC classifier has established that verdict, the remaining diagnostic records
are retrieved with checking disabled so the operator can see the failure and its
data. The DNSSEC result still comes from the validating query.

It returns a **new** object rather than mutating the old one, exactly as the
coordinator did, so options already handed to an in-flight query cannot change
underneath it. Asserted directly.

## Moved, not redesigned

**Task 5.1:** `analyzeDomain()`'s first three lines and its two return
statements. `queryOpts` kept its name in `js/dns.js`, so not one query call site
changed.

**Task 5.2:** `analyzeDomain()` itself, its three audit-local helpers
(`startsWithCI`, `versionCandidates`, `leadingVersionMatches`) and
`resolveWebsite()`, at the same indentation and in the same order. No check, no
fallback, no ordering and no batch changed. `js/dns.js` remains the transitional
composition root and still exposes `analyzeDomain` and `startsWithCI` as engine
members.

Both five-surface equivalence subjects report zero differences at each commit.

## What Phase 5 still owes this directory

Recorded at Task 4.0 and in the Phase-5 compatibility ruling, and not payable
until Task 5.2 brings the coordinator here:

1. `spfReferencedCatalogKeys` — SPF-owned, injected into `createDkimCheck()` —
   becomes **audit-derived catalog keys** passed into DKIM.
2. `isNullMx` — MX-owned, injected into `createDetectors()` — becomes the
   **derived boolean** passed into provider detection.
3. The NS `servfail` DNSSEC preflight, the last raw-kind reader outside an
   owning directory, moves here with the coordinator — and the assertion in
   [`transport-edges.test.mjs`](../../tests/contract/transport-edges.test.mjs)
   that names it as the only one left in `js/dns.js` moves in the same commit.

The observed legacy engine-member signatures stay unchanged while that happens:
`detectEmailProvider(mx, domain, addressRecords)` and `checkDKIM(…, spfRecord,
…)` keep their shapes behind thin compatibility wrappers in the legacy assembly
if the new fact-taking APIs would otherwise change them. The wrappers are
adapters, not architecture, and Phase 6 removes them with `js/dns.js`.
