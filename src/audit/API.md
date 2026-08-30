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
| `createAuditDomain(capabilities)` | factory | Returns `{ analyzeDomain }`. Takes the resolver handle, every protocol check built over it, and — temporarily — the four audit siblings Tasks 5.3 and 5.4 have yet to move. |

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
isolated, and how the answers become one result.

### Gate 5: the coordinator holds no parsing rule

Spec §5 states it in prose — `auditDomain()` "does not parse records" — and
Gate 5 makes it a release condition. **Task 5.2 shipped a coordinator that
broke it**, and review caught what no check was asking: record SELECTION is a
parsing rule, and seven of them were in this file.

Task 5.2a moved every one to an owner:

| Rule | Owner |
| --- | --- |
| Which TXT records are SPF records, and whether there is more than one | `core/spf/`'s `selectSpfRecords` |
| The whole BIMI answer — selection, which record to show, what `present` means | `core/bimi/`'s `summarizeBimi` |
| The same for MTA-STS and TLS-RPT | `core/transport/`'s `summarizeMtaSts`, `summarizeTlsRpt` |
| Which TXT records are third-party verifications | `providers/`'s `selectVerifications` |
| `startsWithCI`, `versionCandidates`, `leadingVersionMatches` | `core/shared/record-selection.js`, once each had two protocol readers |

[`dns-transport.test.mjs`](../../tests/contract/dns-transport.test.mjs) §3b is
the standing contract: none of those names is declared here, and each is
declared by its owner. It is a lexical scan over `function NAME` declarations
and says so — it would not catch the same rule written as an arrow function or
under another name, and it is defense against the specific regression that
actually happened rather than a proof of absence.

### Concurrency

**The `Promise.all` structure is byte-identical to `v0.5.0`.** Spec §35 and the
implementation plan both forbid changing concurrency and moving code in the same
phase, and this release changes it nowhere. `audit-domain.test.js` asserts it
with an instrument rather than a claim: each stub records the moment it is
CALLED and holds until the whole batch has arrived, so a batch rewritten as a
sequence of awaits cannot complete. Because that failure mode is a HANG, every
such run is raced against a bounded deadline measured in **event-loop turns**
— the right unit for a question about the event loop, and not flaky the way a
wall-clock threshold would be — so a regression reports in milliseconds instead
of running to the CI timeout. The deadline itself is proven to fire.

Three batches are covered, and they are **this file's**: the four core lookups,
all eight advanced checks, and the wildcard pair. DKIM's selector scan is
batched at `DKIM_SCAN_BATCH_SIZE = 24` inside `core/dkim/`, which is where that
batch is owned, contracted and tested; the coordinator awaits one call and knows
nothing about it. Nothing here claims otherwise.

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

**Task 5.2:** `analyzeDomain()` and `resolveWebsite()`, at the same
indentation and in the same order. No check, no fallback, no ordering and no
batch changed. `js/dns.js` remains the transitional composition root and still
exposes `analyzeDomain` as an engine member.

**Task 5.2a:** the seven parsing rules above went on to their owners, and
`startsWithCI` — still a legacy engine member — is imported into `js/dns.js`
from `core/shared/record-selection.js` rather than from here. No behaviour
moved with any of it.

Both five-surface equivalence subjects report zero differences at each commit.

## The derived facts this directory owns

Phase 4 left two cross-protocol compositions injected into the wrong owner and
recorded both as debts rather than as design. Task 5.2 pays them here, which is
the layer whose job composition is.

| Derived here | Passed to | Retires |
| --- | --- | --- |
| The catalog keys an SPF record names, via SPF's own `spfReferencedCatalogKeys` | `checkDKIM()` and the three other selector members | `spfReferencedCatalogKeys` injected into `createDkimCheck()` at Task 4.8 |
| The RFC 7505 null-MX boolean, via `core/mx/`'s `isNullMx` | `detectEmailProvider()` | `isNullMx` injected into `createDetectors()` at Task 4.9 |

Neither owner can derive its own fact without an edge §12 forbids —
`core/dkim` → `core/spf`, `providers` → `core/mx`. Audit has both edges,
derives each fact once, and passes the fact. The null-MX boolean is derived
once and read twice: by provider detection and by the deep-check gate.

**The observed legacy engine-member signatures are unchanged.**
`detectEmailProvider(mx, domain, addressRecords)` and
`checkDKIM(…, spfRecord, …)` still exist in exactly those shapes, as thin
compatibility wrappers in `js/dns.js` that perform the old derivation and
delegate to the fact-taking APIs. `tools/scoring.test.mjs` asserts them
directly and its count did not move. The wrappers are adapters, not
architecture, and Phase 6 removes them with `js/dns.js`.

The third Phase-5 obligation, the NS `servfail` DNSSEC preflight, moved here
with the coordinator; `transport-edges.test.mjs` now locates it in
`audit-domain.js` and asserts `js/dns.js` holds no raw-kind reader at all.
