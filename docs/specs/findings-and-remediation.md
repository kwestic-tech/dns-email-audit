# Spec: Structured findings and remediation roadmap

| Field | Value |
| --- | --- |
| Spec version | 1.1 (Final) |
| Target release | 0.7.0 |
| Status | Final — implementation may begin |
| Depends on | 0.2.3 through 0.6.0. This release consumes the stabilized protocol signals through the module boundaries shipped by the refactor. |
| Blocks | [report-comparison](report-comparison.md), whose diff operates on finding identity |
| Slug for open questions | `FIND` |
| Last updated | 2026-08-31 |

## Problem

`buildIssues()` in [`src/audit/issues.js`](../../src/audit/issues.js) returns a flat array of
`{ key, sev, args }` objects in the order the function happens to test
conditions. `buildSuggestions()` in the same module returns a
second flat array of `{ key, guide }`. Severity has three values, `crit`, `warn`
and `info`, and nothing else about a finding is modelled.

This works for the current 40-ish conditions and stops working at the scale the
previous four releases create. Three specific things it cannot express.

**Order.** A domain missing SPF, DKIM and DMARC gets three critical findings in
source order. The correct advice is to fix SPF and DKIM first, because publishing
`p=reject` before authentication is in place blocks the domain's own mail. The
tool currently presents all three as equally urgent and independently
actionable, and one of the three orderings is actively harmful.

**Dependency.** BIMI without DMARC enforcement is not a BIMI problem. TLSA
without a validated DNSSEC chain is not a TLSA problem. MTA-STS without TLS-RPT
is a monitoring gap rather than a policy gap. Each of these is a relationship
between two protocols, and the current model has no way to say "this finding is
blocked by that one".

**Confidence.** `dkimStatus.confidence` already carries `observed`, `sampled` and
`not-checked`, and `unprovenPillars()` in
[`src/audit/scoring.js`](../../src/audit/scoring.js)
already tracks which pillars scored zero because a lookup failed rather than
because the control is absent. That distinction is captured in scoring and
discarded in findings. A finding derived from a failed lookup and a finding
derived from a confirmed NXDOMAIN look identical.

Separately, findings are currently defined by their locale key. `issue.spf-missing.msg`
is both the identifier and the display string, which means a translation change
and a semantic change are the same edit, and a finding cannot carry structured
evidence because the only channel to the interface is `{0}` and `{1}`
placeholders.

## Scope

1. Define a structured `Finding` type separate from localized display strings.
2. Compose the finding set from a declarative rule layer without disturbing the
   accumulated correctness of `buildIssues()`.
3. Add severity, confidence, evidence references, and prerequisite dependencies.
4. Detect cross-protocol conditions that no single-protocol check can see.
5. Produce an ordered remediation sequence from the dependency graph.
6. Keep scoring separately versioned from finding changes.

## Non-goals

- **No scoring change.** `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS`,
  `calcDmarcScore()` and `calcSpfScore()` are untouched. A finding is not a
  score. See `RQ-FIND-06`.
- **No new DNS queries.** This release derives everything from data the previous
  releases already collect. The finding layer is pure over a completed audit
  context, so the equivalence **trace** surface (the published DNS fan-out) does
  not move.
- **No English in `src/audit/`.** The finding layer emits identifiers and
  structured evidence. `src/ui/` remains the only place tokens become words.
- **No `issue.*` → `finding.*` locale rename.** Resolved by `RQ-FIND-05`: the
  existing `issue.*` namespace is kept and a new `finding.*` namespace is added
  for the new material. The Finding's `id` is the stable identity; the locale
  key is a separate field.
- **No change to `buildIssues()` / `buildSuggestions()` behaviour.** Their output
  arrays — `result.issues` and `result.suggestions` — stay byte-identical.
  Resolved by `RQ-FIND-08`.

## Design

### 0. Architecture and implementation boundary

The 0.6.0 refactor is a binding input, not a path rename. The implementation
uses the existing allowed-edge matrix without adding or widening a row:

| Responsibility | Owner |
| --- | --- |
| Finding schema, rule layer, invariant checks and remediation ordering | `src/audit/findings.js` (new sibling of `issues.js`) |
| Legacy `issues`/`suggestions` arrays, unchanged | `src/audit/issues.js` |
| Existing score and rubric behavior | `src/audit/scoring.js`, unchanged |
| Protocol parsing and facts | Existing `src/core/<protocol>/` owners |
| Finding and plan rendering, controls, CSV and HTML presentation | `src/ui/` |
| Passing audit output to the UI | `src/runtime.js` |

`src/audit/` may import protocol owners and is where cross-protocol composition
already belongs. `src/ui/` receives completed findings through the runtime and
does not import `audit/` or `core/`. Protocol owners do not learn about finding
ids, severities or remediation.

The work is split into directory-bound commits, none combining a move with a
semantics change, a result-schema change or a UI-behaviour change:

1. **`src/audit/findings.js` + its invariant/regression suite** (semantics), with
   the English `finding.*` locale keys it asserts against.
2. **`src/audit/audit-domain.js`** wiring `findings` and `remediationPlan` into
   the result (result-schema change), and the state-matrix regeneration that
   follows from the new observable algebras.
3. **`src/ui/`** consumption — the two views and the three appended CSV columns
   (UI-behaviour change), with the equivalence binding update that the new render
   requires.
4. **Localization** — the thirteen translations of the new `finding.*` keys.

> **Amendment (1.0):** the 0.2 draft assigned "Finding schema, registry,
> invariant checks and remediation ordering" to `src/audit/` and said the work
> would "replace the imperative `buildIssues()` body with a data structure."
> Reproducing 106 findings' exact order, severities and joined arguments inside a
> flat registry, against a function whose 250 lines carry a decade of
> false-positive fixes, is precisely the risk `AGENTS.md` names first — and it is
> caught by three independent guards that pin the current shape: the equivalence
> **result** surface captures `result.issues` verbatim; `equivalence.validate.mjs`
> greps the literal `issues.push({ key: 'spf-missing', sev: 'crit' });`; and
> `tools/scoring.test.mjs` reads `buildIssues(...).map(i => i.key)` at dozens of
> sites. This revision therefore **enriches rather than replaces**: `buildIssues()`
> stays the frozen producer of `result.issues`, and `buildFindings()` composes the
> structured set from it plus the new declarative cross-protocol rules. See
> `RQ-FIND-08`.

### 1. The Finding type

```js
{
  id: string,            // stable, e.g. 'dmarc.policy-none' — matches /^[a-z0-9-]+\.[a-z0-9-]+$/
  key: string,           // the locale-key slug: 'issue.<key>' for a migrated
                         //   finding, 'finding.<key>' for a cross-protocol one
  keyspace: 'issue' | 'finding',  // which locale namespace `key` resolves under,
                         //   so a consumer need not infer it from the key shape
  protocol: string,      // 'spf' | 'dkim' | 'dmarc' | 'dnssec' | 'caa'
                         // | 'mta-sts' | 'tls-rpt' | 'bimi' | 'mx' | 'dane'
                         // | 'dns' | 'defensive' | 'reporting'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  confidence: 'confirmed' | 'probable' | 'unverified',
  evidence: [{ kind, queryName, value }],
  args: [],              // placeholder values for the localized message
  noteKey, noteArgs,     // carried through for the migrated DKIM note case
  dependsOn: string[],   // finding ids that should be fixed first
  blocks: string[],      // derived, the inverse of dependsOn
  effort: 'trivial' | 'moderate' | 'involved',
  category: 'authentication' | 'policy' | 'reporting' | 'transport'
          | 'issuance' | 'resilience' | 'hygiene',
}
```

`id` is the stable identity. It is **decoupled** from the locale key (`RQ-FIND-05`):
a migrated finding keeps its existing `issue.<key>.*` translations and carries
`key: '<key>'`; a cross-protocol finding carries `key: '<slug>'` resolving under
the new `finding.<slug>.*` namespace. The UI resolves a finding's message from
`issue.<key>.msg` or `finding.<key>.msg` according to which namespace owns it.

`severity` is a **new five-value field**, not a rewrite of the legacy three-value
`sev`. The legacy `crit`/`warn`/`info` on `result.issues` is untouched. A migrated
finding's `severity` is assigned deliberately per finding — usually `critical`←`crit`,
`medium`←`warn`, `info`←`info`, but re-levelled to `high` or `low` where the draft's
"deliberate widening" applies (for example `dmarc.policy-none` is `high`). The two
fields coexist; `audit.issue.sev` stays the closed `[crit, warn, info]` algebra and
`audit.finding.severity` is a new closed algebra.

`confidence` is derived from the same signals `unprovenPillars()` already reads
(`RQ-FIND-04` puts it on the finding, not the evidence). A finding from a
`sampled` DKIM result or an `unknown` DMARC walk is `unverified`; a finding from a
confirmed record or NXDOMAIN is `confirmed`; a finding resting on a heuristic such
as provider detection is `probable`.

`evidence` is the raw DNS material that justified the finding, so the interface
can show the record beside the claim and so the 0.9.0 report export carries
verifiable material rather than assertions. It renders through the same
node-building path (`R.value`) as any DNS-derived value, so display caps and
sentinel substitution apply.

### 2. The rule layer

`src/audit/findings.js` holds two declarative structures and the functions over
them.

**`FINDING_META`** — one entry per migrated finding, keyed by the legacy issue key.
It carries the structured metadata a `{ key, sev, args }` object lacks: `id`,
`protocol`, `severity`, `category`, `effort`, `dependsOn`, and functions for
`confidence` and `evidence` derived from the context. `buildFindings()` runs the
untouched `buildIssues(ctx)`, then maps each issue through its `FINDING_META`
entry into a Finding. An issue with no entry is skipped rather than thrown on, so
the layer is total over any legacy key (the invariant suite proves the table is
complete for the real vocabulary).

**`CROSS_PROTOCOL_RULES`** — one entry per new cross-protocol finding:

```js
{
  id: 'dmarc.enforcement-without-auth',
  key: 'dmarc-enforcement-without-auth',   // → finding.<key>.*
  protocol: 'dmarc',
  severity: 'critical',
  category: 'authentication',
  effort: 'moderate',
  dependsOn: ['spf.missing', 'dkim.none-found'],
  when: ctx => …,                          // pure predicate over the context
  evidence: ctx => […],
  confidence: ctx => 'confirmed',
}
```

`when` is a pure predicate over the audit context — the same object
`buildIssues()` receives, extended with the SPF-mechanism fact of `RQ-FIND-09`.
The predicates consume owner-produced FACTS, never record contents, the same
input boundary `issues.test.js` §6 asserts.

`buildFindings(ctx)` evaluates the migrated map and the cross-protocol rules,
concatenates the matches, resolves `dependsOn` against the matched id set —
dropping edges that point at findings which did not fire — and derives each
finding's `blocks` as the inverse (`RQ-FIND-07`).

The two structures are exported so the co-located `src/audit/findings.test.js`
suite can assert properties across the whole set at once: every `id` is unique and
matches `^[a-z0-9-]+\.[a-z0-9-]+$`; every `dependsOn` target is a known id; every
finding resolves to a real `issue.<key>` or `finding.<key>` message in
`locales/en.json`; every `severity`/`confidence`/`category`/`effort` value is in
its enumeration; and the dependency graph is acyclic. A cycle is a design error
that produces an infinite loop or an arbitrary ordering, and it is trivially
detectable when the graph is inspectable.

### 3. Cross-protocol conditions

These are the findings that motivate the release. Each is a relationship no
single protocol check can observe. Every `id` below is new (`finding.*`
namespace); none collides with a migrated `issue.*` key.

| Finding id | Condition | Severity | Depends on |
| --- | --- | --- | --- |
| `bimi.without-enforcement` | BIMI record present, DMARC `effectivePolicy` is `none` or `testMode` is true | medium | `dmarc.policy-none` |
| `bimi.without-authority` | BIMI present, no `a=` VMC (`advanced.bimi.validation.authority` empty), enforcement in place | low | none |
| `mta-sts.without-tls-rpt` | MTA-STS present, TLS-RPT absent | low | none |
| `tls-rpt.without-transport-policy` | TLS-RPT present, no MTA-STS, and no MX host reporting `authenticated: true` from `checkTlsa()` | info | none |
| `dkim.mixed-key-strength` | Selectors on one domain differ in modulus size (`dkimStatus.keyProfile.mixed`) | low | none |
| `dkim.weak-with-enforcement` | RSA key at or under 1024 bits while DMARC enforces | high | none |
| `dmarc.external-report-unauthorized` | `rua`/`ruf` destination has not published authorization (`advanced.reportAuth` state `unauthorized`) | medium | none |
| `dmarc.enforcement-without-auth` | `p=reject` while SPF `status` is `missing` (NOT `permerror`) or DKIM is unproven | critical | `spf.missing`, `dkim.none-found` |
> **Amendment (1.1):** the SPF half is `status === 'missing'` only. A `permerror`
> (multiple records, over-limit, cycle) is a *broken* SPF record, not a missing
> one; it raises its own critical finding (`spf.multiple-records` /
> `spf.over-limit` / `spf.cycle`), and `dmarc.enforcement-without-auth` does not
> depend on those, so including `permerror` here would fire an enforcement finding
> whose declared prerequisite (`spf.missing`) never fired — the resolved edge
> would be dropped and the enforcement finding would land in step 1 beside the
> broken-SPF finding, breaking the never-enforce-before-authentication guarantee.
| `mx.dangling-with-enforcement` | An MX host does not resolve on a domain that enforces DMARC | critical | none |
| `defensive.contradictory` | Null MX published alongside a permissive SPF or an MX-referencing SPF | medium | none |
| `spf.redundant-with-enforcement` | SPF authorizes a large block (`spfSubnets` HIGH tier) while DMARC enforces | medium | none |
| `reporting.blind` | No `rua` anywhere and no TLS-RPT | medium | none |

Two rows in this table are **migrations, not new findings**: `dkim.mixed-key-strength`
(the existing `issue.dkim-key-mixed`, a single-DKIM fact) and
`dmarc.external-report-unauthorized` (the existing `issue.dmarc-external-unauthorized`).
They keep their `issue.*` translations and take these ids in `FINDING_META`. The
remaining **ten** rows are genuinely new `finding.*` material. The two
enforcement-gated escalations `mx.dangling-with-enforcement` and
`spf.redundant-with-enforcement` coexist with the always-on migrated findings
they build on (`mx.dangling`, `spf.large-subnet`); the escalation is what carries
the dependency framing into the remediation plan.

The migrated finding ids these depend on are `spf.missing` (from `issue.spf-missing`),
`dkim.none-found` (from `issue.dkim-missing`/`issue.dkim-unverified` — the
"no usable DKIM" condition) and `dmarc.policy-none` (from `issue.dmarc-none`).
`FINDING_META` assigns those ids so the cross-protocol edges resolve.

There is deliberately no audited-domain DNSSEC/DANE combination in this table.
TLSA lives beneath each MX host, often in a different zone, so the audited
domain's `secure`, `insecure` or `unanchored` state says nothing about that
record. The existing `tlsa-published-unsigned` issue already uses the applicable
fact: the resolver's per-host `checkTlsa().authenticated` result. It migrates to
the Finding type with the other existing issues (`id: 'dane.published-unsigned'`);
this release does not duplicate it as `dane.without-dnssec` or escalate it from an
unrelated zone's state.

`defensive.contradictory` deserves a note. A domain with a null MX is declaring it
receives no mail, which `calcScore()` in `src/audit/scoring.js` already treats
as a separate rubric. If that same domain publishes `v=spf1 mx -all`, the SPF
record authorizes an empty set through a mechanism that costs a lookup and
communicates confusion rather than intent. It is not a vulnerability; it is a sign
that nobody owns the configuration, which is worth saying. Detecting the
"MX-referencing SPF" half needs an SPF *fact* — whether the record uses the `mx`
mechanism — which no owner currently reports; `RQ-FIND-09` adds it as a pure
`core/spf` helper composed in `audit-domain.js`, the same pattern as
`spfReferencedCatalogKeys`.

### 4. Remediation ordering

```js
function buildRemediationPlan(findings) → [{
  step: number,
  findings: string[],       // ids that can be done together at this step
  rationale: string,        // token
  unblocks: string[],       // ids that become actionable after this step
}]
```

The plan is a topological sort of the dependency graph. A finding that
participates in a dependency chain — it depends on something, or something
depends on it — is placed at its dependency depth (blockers first), and findings
at the same depth are grouped into one step, ordered within the step by severity
then effort.

> **Amendment (1.1):** the 1.0 text combined "findings at the same depth are one
> step" (which places a depth-zero finding in step 1) with "a finding with no
> unmet dependencies and no dependents lands in the last step" — contradictory for
> an isolated finding, which is depth zero. Resolved: **isolated findings — no
> prerequisites AND no dependents — carry no ordering constraint, so they are
> collected into a single FINAL step**, where hygiene items gather. Depth grouping
> governs only the connected findings. A finding that has dependencies but no
> dependents (such as `dmarc.enforcement-without-auth`) is connected, so it stays
> at its depth, never demoted to the final step. When every finding is isolated,
> that final step is also the first and only step.

The ordering rule that matters: **never recommend enforcement before
authentication.** `dmarc.policy-none` depends on `spf.missing` and
`dkim.none-found`, so a domain missing all three is told to publish SPF and DKIM
at step one and to move DMARC to enforcement at step two. That is the opposite of
the current source-order presentation and it is the single most valuable thing
this release produces.

### 5. Interface

The detail panel's issues block in
[`src/ui/events.js`](../../src/ui/events.js) is replaced
by two views over the same finding set:

- **By severity**, the default (`RQ-FIND-01`), grouped by the five severities with
  `low` and `info` collapsed behind a disclosure count (`RQ-FIND-03`).
- **By remediation step**, showing the plan from section 4, with each step's
  findings grouped and blocked findings visibly marked as waiting.

Both views render finding items as `<div class="finding">` rather than the legacy
`<div class="issue">`. `result.issues` is still rendered for nothing — it is kept
only as a stable result field and as the CSV `Issues` column source — so the
equivalence binding between `result` and the DOM moves from `result.issues` ↔
`div.issue` to `result.findings` ↔ `div.finding` (`RQ-FIND-08`; the one
instrument change the new render forces, made in the same UI commit).

Confidence is rendered where it is not `confirmed`. An `unverified` finding
carries the same visual treatment as the existing unproven-pillar grade marker
in `src/ui/events.js`, for consistency.

Evidence renders under each finding as the record that produced it, using the
node-building renderer from 0.2.3 so DNS-derived material stays a text node.

The CSV export gains `finding_ids`, `finding_severities` and
`remediation_step_1`, appended after the current final column (`TLSA Present`),
not inserted — three new positional entries in the `csv.headers` array.

### 6. Stability requirement

Findings and their ordering must be identical across all fourteen locales. The
rule layer contains no locale-dependent logic, and `buildRemediationPlan()`
sorts on severity and effort tokens rather than on translated strings. The
existing grade sort in `src/ui/events.js` is the precedent: it
sorts on `dataset.grade` rather than on rendered text precisely to stay
locale-independent.

Test this directly: run the same fixture through `buildFindings()` and
`buildRemediationPlan()` under each of the fourteen locales and assert the id
sequences are byte-identical.

## Localization impact

Far smaller than the 0.2 draft projected, because `RQ-FIND-05` keeps the `issue.*`
namespace. **No existing translated unit is touched.** The new material is:

- The ten new cross-protocol findings' `finding.<slug>.msg`, `.what`, `.fix` and,
  where useful, `.fixCode`.
- Label vocabularies the two views need: severity labels (`high`, `low` are new
  next to the existing `crit`/`warn`/`info` glyphs), confidence labels, category
  labels, effort labels, remediation step/rationale tokens, and the view-toggle
  control labels.
- Three positional `csv.headers` entries.

All of it lands under new keys, is scaffolded to `initial` by `locale:sync`, and
is translated into the thirteen non-English locales with `locale:set` before
`locale:gate` passes. Register for the new material: second person, direct,
practical, per [`AGENTS.md`](../../AGENTS.md). Remediation text in particular is
read by someone mid-incident and should say what to publish, not why it matters.

## Testing

Registry invariants, asserted over `FINDING_META` and `CROSS_PROTOCOL_RULES`:

- Every `id` is unique and matches `^[a-z0-9-]+\.[a-z0-9-]+$`.
- Every `dependsOn` entry names an id that some rule can produce.
- The dependency graph is acyclic.
- Every migrated finding resolves to an existing `issue.<key>.msg` in
  `locales/en.json`; every cross-protocol finding to a `finding.<key>.msg`.
- No cross-protocol `finding.*` key duplicates a migrated `issue.*` id.
- Every `severity`, `confidence`, `category` and `effort` value is in its
  enumeration.
- `FINDING_META` covers every legacy issue key `buildIssues()` can emit (proven
  against the `audit.issue.key` algebra), so no legacy finding silently loses its
  structured form.

> **Amendment (1.1):** the finding vocabularies are **registered as reviewed
> closed algebras** in `tests/state-algebras.json` — `audit.finding.id`,
> `.severity`, `.confidence`, `.category`, `.effort`, `.protocol`, `.keyspace`,
> and `audit.remediation.rationale` — each with its `resultPaths`, given
> reviewed-suite coverage in `tests/build/coverage.mjs`, and with the state matrix
> regenerated. `findings.test.js` asserts the registered `audit.finding.id`
> members equal the ids `FINDING_META` and `CROSS_PROTOCOL_RULES` produce, the
> same drift guard `audit.issue.key` already has. This replaces the 1.0 choice to
> bundle the enums so the `state-matrix` scanner would skip them, which satisfied
> the letter of the check by evading it rather than the intent.

Behavioral fixtures, each a synthetic audit context:

| Fixture | Expectation |
| --- | --- |
| No SPF, no DKIM, `p=reject` | `dmarc.enforcement-without-auth` critical; plan step 1 is SPF and DKIM |
| No SPF, no DKIM, no DMARC | Plan orders authentication before policy |
| BIMI with `p=none` | `bimi.without-enforcement`, marked blocked by `dmarc.policy-none` |
| BIMI with `p=reject; t=y` | Same finding; test mode is not enforcement |
| Audited domain unanchored, MX-host TLSA authenticated | no DANE/DNSSEC cross-zone finding |
| Audited domain secure, MX-host TLSA unauthenticated | migrated `dane.published-unsigned`; no dependency on audited-domain DNSSEC |
| MTA-STS without TLS-RPT | `mta-sts.without-tls-rpt` at low severity |
| Dangling MX with `p=reject` | `mx.dangling-with-enforcement` critical |
| Null MX with `v=spf1 mx -all` | `defensive.contradictory` |
| DKIM 1024-bit with `p=reject` | `dkim.weak-with-enforcement` high |
| Mixed 1024 and 2048 selectors | `dkim.mixed-key-strength` low |
| SPF `permerror` (multiple records), enforcing, DKIM present | `dmarc.enforcement-without-auth` does NOT fire; `spf.multiple-records` is the SPF finding |
| Isolated hygiene finding beside an SPF-authentication chain | the isolated finding lands in the FINAL plan step, never step 1 |
| Everything correct | Empty finding set, empty plan |
| DKIM lookup failed | Finding confidence `unverified`, not `confirmed` |
| An issue key with no `FINDING_META` entry | skipped, not thrown on — fed a fabricated unknown key, not merely a bare context |
| All fourteen locales, one fixture | Byte-identical finding-id and remediation-step sequences, asserted by rendering the fixture under each locale (`data-finding-id` on the cards) and comparing the sequences — a direct render test, not only the structural import assertion |

Regression: the existing findings must fire on the same inputs they fire on
today. Because `buildIssues()` is untouched, this is proven directly — the
regression fixture set captures `buildIssues()`/`buildSuggestions()` output over
the current contexts, and a co-located suite asserts the captured output is
reproduced byte-for-byte and that each captured `issue.<key>` maps to exactly one
`buildFindings()` id.

Every new cross-protocol rule is proven to fail against its negative case before
it is trusted (`AGENTS.md` rule 3): the fixture that does not meet the condition
must not produce the finding.

## Acceptance criteria

1. Every finding names its evidence and its prerequisites.
2. No plan ever recommends DMARC enforcement before SPF and DKIM are in place.
3. The dependency graph is acyclic, enforced by test.
4. Finding ids and remediation order are byte-identical across all fourteen
   locales.
5. Scoring output is unchanged: `node tools/backtest.mjs --json` shows zero
   grade movement against `v0.6.0`.
6. `result.issues` and `result.suggestions` are byte-identical to `v0.6.0`, and
   the equivalence **trace** surface does not move.
7. Every new `finding.*` key has a translation in all thirteen non-English
   locales.
8. `npm test`, `npm run inventory` and `npm run locale:gate` pass.

## Risks

**Reproducing 250 lines of accumulated correctness.** `buildIssues()` carries
comments explaining specific false positives that were fixed once and must not
come back. Mitigation, and the reason for the 1.0 amendment: it is **not**
reproduced. `buildIssues()` stays the producer of `result.issues`; the finding
layer enriches its output. The regression proof is therefore an identity, not a
re-derivation.

**Finding proliferation.** Ten new cross-protocol findings on top of the
existing set is a lot of text on a domain that is merely imperfect. Mitigation:
severity now has five levels and the interface defaults to grouping, so `low` and
`info` collapse behind a count (`RQ-FIND-03`).

**Touching the equivalence instrument.** The `result`↔DOM binding hard-codes
`result.issues` ↔ `div.issue`. Rendering findings forces one focused update to
`bindExecutions()` and the `equivalence.validate.mjs` §5 probes. Mitigation: the
binding's purpose (the two executions describe the same audit) is preserved; only
the field it reads changes, in the same commit as the render that requires it, and
the damaged-pair probes are updated to prove it still fails when it should.

**Plan ordering is opinionated.** Reasonable practitioners disagree about
whether, for example, CAA should come before or after MTA-STS. Mitigation: the
graph only encodes dependencies that are technically necessary. Preference
ordering within a step is severity and effort, which is defensible and visible.

## Referred here by earlier releases

Decisions other specs deliberately deferred to this one. All four are resolved
below and recorded in **Resolved questions**.

- **`psd=y` and the score** — referred by `OQ-DMARC-07` (0.3.0). Resolved: no new
  psd finding. See `RQ-FIND-10`.
- **`dmarc-multiple-records` severity source** — 0.3.0 changed where this finding
  comes from. Duplicate DMARC records at a queried name no longer terminate
  discovery: per RFC 9989 §4.10 they are discarded and the walk continues, so a
  valid record higher in the tree still applies and the status may be `missing`
  rather than `permerror`. The finding stays **critical** and is raised from
  `dmarcDiscovery.observed[]` evidence rather than from `dmarcStatus.status`. Any
  cross-protocol rule that keys on DMARC state must read the same evidence, never
  `status === 'permerror'`. `FINDING_META` migrates it faithfully.
- **Record hygiene as findings** — referred by `OQ-SEC-12` (0.2.3). Resolved: they
  stay display annotations, not findings. See `RQ-FIND-11`.
- **CSV formula injection** — referred by 0.2.3's Risks section. Resolved: it
  stays an export-time neutralization, not a finding. See `RQ-FIND-11`.

## Resolved questions

**RQ-FIND-01: Is the remediation plan the default view, or the alternate?**
*Resolved (1.0): severity is the default; the plan is a toggle.* The severity
list is the more useful artifact for the tool's primary mode — scanning many rows
for the worst offenders — and preserving today's default layout keeps the change
from disrupting a familiar workflow. The plan, more useful for someone fixing a
single domain, is one click away.

**RQ-FIND-02: Should the plan span multiple domains?**
*Resolved (1.0): out of scope for 0.7.0; deferred to its own release.* A
cross-domain plan ("publish DMARC on these 34 domains first") is a genuinely
different feature with its own interface and is the natural home for the
bulk-audit use case. 0.7.0 freezes the per-domain finding and plan model that such
a feature would build on; adding the multi-domain interface here would couple two
unfinished designs.

**RQ-FIND-03: What is the display threshold?**
*Resolved (1.0): group by severity, collapse `low` and `info` behind a count.*
Five severities plus grouping is enough to keep a mediocre domain legible without
a new toolbar filter. `critical`, `high` and `medium` show expanded; `low` and
`info` collapse behind a disclosure count. The existing status filter at
[`index.html`](../../index.html) is unchanged, keeping the scope bounded.

**RQ-FIND-04: Does `confidence` belong in the model, or is it a property of the
evidence?**
*Resolved (1.0): on the finding.* Modelling confidence per evidence entry would be
marginally cleaner in one case — a finding resting on several pieces of evidence of
mixed certainty — but it complicates every consumer, and 0.9.0's report schema
freezes whichever shape ships. The simpler finding-level field is the safer freeze;
an evidence-level `confidence` can be added later without breaking it, whereas
removing a per-consumer complication after release cannot.

**RQ-FIND-05: Can `tools/locale-sync.mjs` express a key rename without losing
translations?**
*Resolved (1.0) by measurement: technically yes, but the rename is not done.* A
controlled experiment (recorded in the review log) established both directions:

- A **coordinated move** — renaming a key across `en.json`, all thirteen locale
  bundles and `translation-status.json` in one step, values unchanged — is a
  perfect no-op. `locale:sync` reported `771 translated, 0 initial, 0 files
  changed`, fingerprints (`sourceHash`/`targetHash`) preserved, because state is
  derived from the key path and the two hashes and none of the three moved.
- A **naive `en.json`-only rename** sends every subkey to `initial`: `52 rows
  scaffolded, 52 pruned` for a single key, which is 4,680 units across the whole
  `issue.*` namespace at thirteen locales.

The coordinated move requires editing `translation-status.json`, which `AGENTS.md`
forbids doing by hand, and no tool expresses the move programmatically. Building
one — a script that rewrites the status database — is a new, high-blast-radius
surface for zero functional gain: the Finding's `id` already provides the stable
identity 0.9.0 needs, decoupled from the locale key. The rename would also be a
106-key move combined with the release's semantics change, which `AGENTS.md`
separates. So `issue.*` is kept as a historical namespace name, the model amends
§1 to decouple `id` from `key`, and only the new cross-protocol material takes the
`finding.*` namespace. This is the draft's own stated fallback ("keep `issue.*`
and note in the code that the namespace name is historical").

**RQ-FIND-06: When do findings and scoring reconnect?**
*Resolved (1.0): they stay independent, permanently.* The score measures **control
adoption** (which controls exist, weighted); findings measure **configuration
quality** (whether what exists is correct and coherent). A domain can therefore
carry a critical finding without its grade moving, which is defensible as a
permanent state rather than a transitional one: the grade answers "how much of the
standard stack is deployed" and the findings answer "is the deployed stack right."
No third number appears. This matches the project's "advisory before scoring"
constraint and keeps `OQ-FIND-06`'s freeze decision made now even though nothing
new is implemented — scoring is a non-goal.

**RQ-FIND-07: Do `blocks` edges need to be author-declared or purely derived?**
*Resolved (1.0): derived only.* `blocks` is the computed inverse of `dependsOn`,
keeping one source of truth for the graph. An author who wants "fixing this
unblocks that" edits the other rule's `dependsOn`, which is correct for a graph
and an acceptable minor awkwardness for an author.

**RQ-FIND-08: Replace `buildIssues()` or enrich it?** *(new question, raised and
resolved at 1.0.)*
*Resolved: enrich.* See the §0 amendment. Replacing the imperative body risks the
accumulated correctness `AGENTS.md` names first and is caught by three guards that
pin the current shape (the equivalence `result` surface, the
`equivalence.validate.mjs` literal probe, and `scoring.test.mjs`'s reads). The
finding layer therefore runs the untouched `buildIssues()` and enriches its
output, composing the cross-protocol rules alongside. `result.issues` and
`result.suggestions` stay byte-identical; the UI renders `findings`, and the one
equivalence binding update the new render forces is made with it.

**RQ-FIND-09: How is the "MX-referencing SPF" fact obtained without re-parsing a
record in `src/audit/`?** *(new question, raised and resolved at 1.0.)*
*Resolved: a pure `core/spf` helper composed in `audit-domain.js`.* `analyzeSpf()`
does not report whether the record uses the `mx` mechanism, and the finding-layer
input boundary forbids re-parsing the record there. `core/spf` grows a small pure
export (`spfUsesMechanism(record, 'mx')` or equivalent), `audit-domain.js` calls
it once and passes the boolean fact into the context — the exact pattern
`spfReferencedCatalogKeys` already sets. That is a `core/spf` change and lands in
its own commit with this justification.

**RQ-FIND-10: Does `psd=y` become a finding?** *(referred by `OQ-DMARC-07`.)*
*Resolved: no.* A correct `psd=y` declaration is responsible behaviour, and an
incorrect one misrepresents the domain's position in the tree — but there is no
DNS-only test that disproves a `psd=` declaration (the declaration is the
protocol's own source of truth), and the existing code already removed
`dmarc-psd-invalid` for consulting the PSL against `OQ-DMARC-04`'s invariant. The
value-vocabulary check `dmarc-bad-psd` migrates unchanged; no new psd finding is
added.

**RQ-FIND-11: Do record hygiene and CSV formula-leading become findings?**
*(referred by `OQ-SEC-12` and 0.2.3's Risks.)*
*Resolved: no, both stay as they are.* Record-hygiene sentinels are per-value
display annotations already surfaced at their exact position and named in the CSV
`record_hygiene` column; promoting them to findings would duplicate that channel
and their severity is context-dependent in a way a fixed level would misstate. CSV
formula-leading is an export artifact — a spreadsheet behaviour, not a domain
misconfiguration — already neutralized at export and flagged `formula-leading`;
the domain owner did nothing wrong in DNS, so it is not a finding about their
configuration.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.1 (Final) | 2026-08-31 | Codex review round. Fixed the `dmarc.enforcement-without-auth` SPF condition to `status === 'missing'` only (a `permerror` broke the never-enforce-before-auth guarantee); resolved the §4 standalone-finding contradiction (isolated findings collect in a final step, not step 1); documented the emitted `keyspace` field in the §1 schema; and committed to registering the finding vocabularies as reviewed algebras rather than bundling them to evade the `state-matrix` scanner. Also strengthened the testing table: a real fabricated-unknown-key negative case, and a direct fourteen-locale render comparison rather than only the structural import assertion. Implementation followed with finding-specific evidence, the remediation view marking blocked findings, and an enforcement message that no longer asserts both SPF and DKIM are absent. |
| 1.0 (Final) | 2026-08-31 | Resolved all seven open questions and the four referred decisions against the real codebase and, for `RQ-FIND-05`, a recorded locale-pipeline experiment. Amended the architecture to **enrich rather than replace** `buildIssues()` (`RQ-FIND-08`), decoupled the Finding `id` from its locale key and kept the `issue.*` namespace (`RQ-FIND-05`), added `severity` as a new five-value field beside the untouched legacy `sev`, put the new material under a `finding.*` namespace, added `RQ-FIND-09` for the SPF-mechanism fact, moved finding rendering to `div.finding` with the equivalence binding update it requires, and updated the testing and acceptance sections to the enrich model. No behavioural claim about `buildIssues`, scoring or the DNS trace changes. |
| 0.2 | 2026-08-31 | Rebased the implementation onto the shipped 0.6.0 module architecture and renumbered the target to 0.7.0. Assigned finding semantics to `src/audit/`, presentation to `src/ui/`, and composition to `src/runtime.js`; replaced deleted `js/` paths, moved invariant tests beside their owner, updated the behavioral baseline to `v0.6.0`, and updated the downstream report dependency to 0.9.0. No open question was resolved. |
| 0.1 | 2026-08-20 | Initial draft. |
