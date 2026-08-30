# `src/audit/` — API contract

Required by spec [§12](../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Coordination. Which checks run, in what order, what may run
concurrently, how a failure is isolated, and how the answers become one result.
This directory decides nothing about a record's meaning — every protocol rule
belongs to a `core/<protocol>/` owner.

**Five modules.** Phase 5 built four — `context.js` is the state boundary
(5.1), `audit-domain.js` is `analyzeDomain()` (5.2), `scoring.js` is the rubric
(5.3), `issues.js` is findings and tips (5.4) — and Task 6.1 added
`create-audit.js`, the composition boundary, when `js/` was deleted.
`createAuditDomain()` receives no temporary capability: what is passed to it is
exactly what §12 says must be passed.

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
| **Selectors and summarizers:** `selectSpfRecords`, `summarizeBimi`, `summarizeMtaSts`, `summarizeTlsRpt`, `selectVerifications`. **Pure protocol functions:** `analyzeSpf`, `classifySpfSubnets`, `spfReferencedCatalogKeys`, `analyzeDmarc`, `emptyDmarcStatus`, `applyInheritance`, `planReportDestinations`, `isNullMx`, and `providers/`'s three detectors. **Audit siblings:** `createAuditContext`, `calcScore`, `calcAdvScore`, `buildIssues`, `buildSuggestions`. | `dohFetch`, `dohQuery`, `requireUsable`, `optionalCheck`, `existenceFromResponse`, and every protocol check built over the resolver |

The three record validators — `validateBimiRecord`, `validateMtaStsRecord`,
`validateTlsRptRecord` — are **no longer** imported by the coordinator. Task
5.2a moved the selection and status shaping that called them into their owners,
so the coordinator now imports the summarizer and never sees the validator.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `createAudit(capabilities)` | factory | **The composition boundary.** Builds every protocol check over one resolver handle and returns the coordinator plus the constructed parts. |
| `createAuditContext({ domain, options })` | factory | The state belonging to one audit of one domain. Takes no capability: no resolver, no cache, no clock. |
| `createAuditDomain(capabilities)` | factory | Returns `{ analyzeDomain }`. Takes the resolver handle and every protocol check built over it — and nothing else. No temporary capability remains. |
| `calcScore`, `calcDmarcScore`, `calcSpfScore`, `gradeFor`, `calcAdvScore` | pure | The scoring model. `calcAdvScore` is internal to the audit; the other four are legacy engine members. |
| `buildIssues(facts)`, `buildSuggestions(facts)` | pure | Findings and remediation tips, as stable keys the i18n layer resolves. Both are legacy engine members. |
| `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS` | exported rubric data | The scoring rubric. Their **serialized values and ordering match `v0.5.0`** — see below. Plain objects and an array: `const` prevents rebinding, not mutation, and they are deliberately **not** frozen. |

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
of running to the CI timeout.

Three properties of that deadline are asserted rather than assumed:

- **it fires** on work that never finishes, and does not fire on work that does;
- **a rejection is not a completion.** The race resolves `completed` or
  `deadline` and lets a rejected audit reject. Mapping a rejection to
  `completed` would let a fixture that issued its whole batch and then threw
  satisfy the very assertion these runs exist to make;
- **the losing deadline is cancelled** when the audit wins, so a passing run
  does not leave a budget of scheduled turns burning behind it.

Three batches are covered, and they are **this file's**: the four core lookups,
all eight advanced checks, and the wildcard pair. DKIM's selector scan is
batched at `DKIM_SCAN_BATCH_SIZE = 24` inside `core/dkim/`, which is where that
batch is owned, contracted and tested; the coordinator awaits one call and knows
nothing about it. Nothing here claims otherwise.

**The one raw-kind read.** The NS `servfail` DNSSEC preflight reads
`nsResult.kind` directly, which is spec §3's audit-owned exception edge. It was
the last raw-kind reader outside an owning directory;
[`transport-edges.test.mjs`](../../tests/contract/transport-edges.test.mjs)
locates it in this file and — since Task 6.1 deleted `js/` — asserts that every
production reader lives under `src/`, which is the stronger form of the
question the old "`js/dns.js` holds none" assertion was asking.

**The three `optionalCheck()` fallback factories that copy `DnsError.kind`**
moved here with their call sites — CAA and SPF let the kind escape, the website
fallback collapses it to `@dns-error`. `dns-transport.test.mjs` counts them per
file, so the move reads as a move rather than as three deletions.

## `create-audit.js` — the composition boundary

Task 6.1, and the module that let `js/` be deleted. It **imports** the protocol
and provider factories and **receives** the DNS resolver capabilities, which is
§12's matrix expressed as code:

| Built by | Imports | Receives |
| --- | --- | --- |
| `src/runtime.js` | `core/dns/` — the cache, the transport, the resolver | — |
| `src/audit/create-audit.js` | every `core/<protocol>/` factory, `providers/` | the resolver handle, the two generated tables, the platform's crypto |

Neither can do the other's job without an edge the matrix forbids: this
directory has no edge to `core/dns/`, and `runtime.js` has none to
`core/<protocol>/`. That is what makes the split structural rather than a
matter of taste.

**`audit-domain.js` did not acquire these responsibilities.** It remains the
coordinator — which checks run, in what order, what may run concurrently, how a
failure is isolated — and it is handed the constructed checks exactly as it was
when `js/dns.js` constructed them. Composition and coordination are two jobs and
this directory keeps them in two files.

**It holds no compatibility wrapper.** The five observed-signature wrappers —
four string-taking DKIM members and the three-argument `detectEmailProvider` —
live with the test harness that needs them, `tools/lib/legacy-engine.mjs`. Task
6.1 shipped copies of four of them here by accident; they called a function
this module does not import and were green only because nothing ran them.
`state-matrix.test.mjs` §3b now fails on any binding under `src/` that nothing
reads.

## `scoring.js` — what scoring is allowed to read

**The serialized values and ordering match `v0.5.0`**, which is Gate 5's first
condition. Verified by an explicit diff against the tag — `JSON.stringify` of
each constant on both sides, compared byte for byte, and proven to fail on a
single changed weight before it was believed.

**They are not frozen, and must not be.** `const` prevents rebinding only;
these are plain objects and a plain array, exactly as `v0.5.0` published them.
`WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` are legacy engine members,
so freezing them would change the observable legacy surface — a compatibility
delta smuggled in under the word "constant". The guarantee here is about what
they CONTAIN, not about what a caller can do to them. `scoring.test.js` §1 pins the values the diff
confirmed. `POLICY_RANK` is included in that diff but is **not** this
directory's: it moved to `core/dmarc/record.js` at Task 4.6, and the
implementation plan lists it under Task 5.3 only because it was still in
`js/dns.js` when the plan was written.

### The input boundary

Scoring's inputs are **protocol FACTS produced by an owner**, never records.

| Reads | Produced by |
| --- | --- |
| `spfStatus.status`, `spfStatus.warnings` | `core/spf/`'s `analyzeSpf()` |
| the parsed DMARC status and `POLICY_RANK` | `core/dmarc/` |
| `advanced.caa.found`, `advanced.mtaSts.present`, `advanced.dnssec.signed`, … | each protocol owner |

**This is not a parsing rule, and the distinction is the whole point.** The
owner decides what a record MEANS; scoring decides what a meaning is WORTH.
`calcSpfScore()` reading `spfStatus.warnings` is the second of those — the
tokens are SPF's, and this module neither produces them nor looks at the record
they came from.

The line scoring may not cross is **re-deriving a fact from a record**. If a
number here ever needs something no owner reports, the owner grows the fact.
`scoring.test.js` §5 asserts that directly rather than describing it: the facts
it scores are fabricated with no parser behind them, and attaching the record
that produced them changes nothing — including a record that flatly
contradicts them, which is the assertion that would fail if this module ever
read one.

**Ruled at Task 5.3: no scoring name goes in
[`dns-transport.test.mjs`](../../tests/contract/dns-transport.test.mjs) §3b.**
That inventory protects one specific regression — parsing and selection leaking
back into the coordinator — and a weight table is not a parsing rule. Widening
it to mean "anything that reads a protocol value" would leave it protecting
nothing in particular.

## `issues.js` — findings, and the same input boundary

`buildIssues()` turns a completed audit's protocol facts into findings;
`buildSuggestions()` turns them into remediation tips. Each finding is a
`{ key, sev }` plus optional `args` for `{0}` placeholders — a stable
identifier, never English.

**The severity vocabulary is closed at three:** `crit`, `warn`, `info`.
Asserted over the source, so a fourth is a decision rather than a drift.

**The token vocabulary is a released artifact.** Every key resolves through
`locales/en.json` and thirteen translations. Gate 4 diffed it byte-identical
against `v0.5.0` — 106 tokens, 0 added, 0 removed — and Task 5.4 re-ran that
comparison after the move, plus a second one over the key literals the builders
actually emit: 98 literals, identical multiset, none left in `js/dns.js`.
Adding, renaming or removing a key is a localization change under `AGENTS.md`,
not a refactor.

**The input boundary is scoring's, restated.** Interpreting an owner-produced
fact into a finding is this module's job; re-parsing a protocol record is not.
`issues.test.js` §6 asserts it the way `scoring.test.js` §5 does — the facts
are fabricated, and a record attached to the same facts changes nothing,
including one that contradicts them. `spfRecords` is read as EVIDENCE, a count
for the multiple-record finding, and its contents are never consulted: two
records of any content raise the same finding.

No name from this file belongs in `dns-transport.test.mjs` §3b either. Same
ruling, same reason: a finding builder is not a parser.

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
batch changed. `js/dns.js` was still the transitional composition root then;
Task 6.1 took that job with `create-audit.js` and deleted the file.

**Task 5.2a:** the seven parsing rules above went on to their owners, and
`startsWithCI` — still a legacy engine member — is imported into `js/dns.js`
from `core/shared/record-selection.js` rather than from here. No behaviour
moved with any of it.

**Task 5.4:** `js/dns.js`'s issue and suggestion blocks, unchanged apart from
the two-space dedent and the `export` keywords. No key, no severity, no
threshold and no ordering moved with them, and nothing at module scope came
along — there was nothing at module scope only these two used. The last
mutation probe naming `js/dns.js` followed them, and the TEMPORARY capability
block in `createAuditDomain()` is gone.

**Task 5.3:** `js/dns.js`'s two scoring blocks, unchanged apart from the
two-space dedent and the `export` keywords. No weight, no threshold, no
rounding and no branch moved with them, and the explicit `v0.5.0` diff is what
says so. `calcScore` and `calcAdvScore` came OFF `createAuditDomain()`'s
capability list in the same commit: `scoring.js` is a sibling, so the
coordinator imports it rather than being handed it.

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
