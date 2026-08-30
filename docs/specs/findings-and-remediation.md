# Spec: Structured findings and remediation roadmap

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | 0.6.0 |
| Status | Awaiting review |
| Depends on | 0.2.3 through 0.5.0. This release consumes signals; it is scheduled after they stabilize. |
| Blocks | [report-comparison](report-comparison.md), whose diff operates on finding identity |
| Slug for open questions | `FIND` |
| Last updated | 2026-08-20 |

## Problem

`buildIssues()` at `js/dns.js:1426` returns a flat array of
`{ key, sev, args }` objects in the order the function happens to test
conditions. `buildSuggestions()` at `js/dns.js:1673` returns a
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
`not-checked`, and `unprovenPillars()` at `js/dns.js:1725`
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
2. Move condition detection into a declarative rule registry.
3. Add severity, confidence, evidence references, and prerequisite dependencies.
4. Detect cross-protocol conditions that no single-protocol check can see.
5. Produce an ordered remediation sequence from the dependency graph.
6. Keep scoring separately versioned from finding changes.

## Non-goals

- **No scoring change.** `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS`,
  `calcDmarcScore()` and `calcSpfScore()` are untouched. A finding is not a
  score. See `OQ-FIND-06`.
- **No new DNS queries.** This release derives everything from data the previous
  releases already collect.
- **No English in `js/dns.js`.** The rule registry emits identifiers and
  structured evidence. `js/app.js` remains the only place tokens become words.

## Design

### 1. The Finding type

```js
{
  id: string,            // stable, e.g. 'dmarc.policy-none'
  protocol: string,      // 'spf' | 'dkim' | 'dmarc' | 'dnssec' | 'caa'
                         // | 'mta-sts' | 'tls-rpt' | 'bimi' | 'mx' | 'dane'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
  confidence: 'confirmed' | 'probable' | 'unverified',
  evidence: [{ kind, queryName, value }],
  args: [],              // placeholder values for the localized message
  dependsOn: string[],   // finding ids that should be fixed first
  blocks: string[],      // derived, the inverse of dependsOn
  effort: 'trivial' | 'moderate' | 'involved',
  category: 'authentication' | 'policy' | 'reporting' | 'transport'
          | 'issuance' | 'resilience' | 'hygiene',
}
```

`id` replaces the locale key as the identity. Locale keys become
`finding.<id>.msg`, `.what`, `.fix`, `.fixCode`, which is a mechanical rename of
the existing `issue.<key>.*` namespace and preserves all thirteen translations
through `tools/locale-sync.mjs` if the rename is done as a key move rather than a
delete and re-add. See `OQ-FIND-05`.

`severity` expands from three values to five. The current `crit`, `warn`, `info`
map to `critical`, `medium`, `info`, leaving `high` and `low` newly available.
This is a deliberate widening: the current model forces "your DMARC is p=none"
and "your DKIM key is 1024 bits" into the same bucket.

`confidence` is derived from the same signals `unprovenPillars()` already reads.
A finding from a `sampled` DKIM result is `unverified`. A finding from a
confirmed NXDOMAIN is `confirmed`. A finding from a heuristic, such as provider
detection at `js/dns.js:303`, is `probable`.

`evidence` is the raw DNS material that justified the finding, so the interface
can show the record beside the claim and so the 0.8.0 report export carries
verifiable material rather than assertions.

### 2. Rule registry

Replace the imperative `buildIssues()` body with a data structure:

```js
var RULES = [
  {
    id: 'dmarc.policy-none',
    protocol: 'dmarc',
    severity: 'high',
    category: 'policy',
    effort: 'trivial',
    dependsOn: ['spf.missing', 'dkim.none-found'],
    when: ctx => ctx.dmarcStatus.status !== 'missing'
              && ctx.dmarcStatus.effectivePolicy === 'none',
    evidence: ctx => [{ kind: 'txt',
                        queryName: '_dmarc.' + ctx.dmarcDiscovery.applied.foundAt,
                        value: ctx.dmarcRecord }],
    confidence: () => 'confirmed',
  },
  …
];
```

`when` is a pure predicate over the audit context. The context is the same object
`buildIssues()` receives today, extended with `dmarcDiscovery`, `mxHealth`,
`tlsa` and the DKIM key profile from the intervening releases.

`buildFindings(ctx)` evaluates every rule, collects the matches, resolves
`dependsOn` against the matched set, and drops dependency edges pointing at
findings that did not fire. A rule that depends on `spf.missing` on a domain
whose SPF is fine has no unmet prerequisite.

The registry is exported so `tools/scoring.test.mjs` can assert properties across
all rules at once: every `id` is unique, every `dependsOn` target exists, every
rule has a corresponding `finding.<id>.msg` key in `locales/en.json`, and the
dependency graph is acyclic.

That last assertion is the reason the registry is data rather than code. A cycle
in the graph is a design error that produces an infinite loop or an arbitrary
ordering, and it is trivially detectable at test time when the graph is
inspectable.

### 3. Cross-protocol conditions

These are the findings that motivate the release. Each is a relationship no
single protocol check can observe.

| Finding id | Condition | Severity | Depends on |
| --- | --- | --- | --- |
| `bimi.without-enforcement` | BIMI record present, DMARC `effectivePolicy` is `none` or `testMode` is true | medium | `dmarc.policy-none` |
| `bimi.without-authority` | BIMI present, no `a=` VMC, enforcement in place | low | none |
| `mta-sts.without-tls-rpt` | MTA-STS present, TLS-RPT absent | low | none |
| `tls-rpt.without-transport-policy` | TLS-RPT present, no MTA-STS, and no MX host reporting `authenticated: true` from `checkTlsa()` | info | none |
| `dkim.mixed-key-strength` | Selectors on one domain differ in modulus size | low | none |
| `dkim.weak-with-enforcement` | RSA key at or under 1024 bits while DMARC enforces | high | none |
| `dmarc.external-report-unauthorized` | `rua`/`ruf` destination has not published authorization | medium | none |
| `dmarc.enforcement-without-auth` | `p=reject` while SPF is missing or DKIM is unproven | critical | `spf.missing`, `dkim.none-found` |
| `mx.dangling-with-enforcement` | An MX host does not resolve on a domain that enforces DMARC | critical | none |
| `defensive.contradictory` | Null MX published alongside a permissive SPF or an MX-referencing SPF | medium | none |
| `spf.redundant-with-enforcement` | SPF authorizes a large block while DMARC enforces | medium | none |
| `reporting.blind` | No `rua` anywhere and no TLS-RPT | medium | none |

There is deliberately no audited-domain DNSSEC/DANE combination in this table.
TLSA lives beneath each MX host, often in a different zone, so the audited
domain's `secure`, `insecure` or `unanchored` state says nothing about that
record. The existing `tlsa-published-unsigned` issue already uses the applicable
fact: the resolver's per-host `checkTlsa().authenticated` result. It migrates to
the Finding type with the other existing issues; this release must not duplicate
it as `dane.without-dnssec` or escalate it from an unrelated zone's state.

`defensive.contradictory` deserves a note. A domain with a null MX is declaring it
receives no mail, which `calcScore()` already treats as a separate rubric at
`js/dns.js:1750`. If that same domain publishes
`v=spf1 mx -all`, the SPF record authorizes an empty set through a mechanism
that costs a lookup and communicates confusion rather than intent. It is not a
vulnerability; it is a sign that nobody owns the configuration, which is worth
saying.

### 4. Remediation ordering

```js
function buildRemediationPlan(findings) → [{
  step: number,
  findings: string[],       // ids that can be done together at this step
  rationale: string,        // token
  unblocks: string[],       // ids that become actionable after this step
}]
```

The plan is a topological sort of the dependency graph, with findings at the same
depth grouped into one step and ordered within the step by severity then effort.

The ordering rule that matters: **never recommend enforcement before
authentication.** `dmarc.policy-none` depends on `spf.missing` and
`dkim.none-found`, so a domain missing all three is told to publish SPF and DKIM
at step one and to move DMARC to enforcement at step two. That is the opposite of
the current source-order presentation and it is the single most valuable thing
this release produces.

A finding with no unmet dependencies and no dependents lands in the last step,
which is where hygiene items collect.

### 5. Interface

The detail panel's issues block at [`js/app.js:513`](../../src/main.js) is replaced
by two views over the same finding set:

- **By severity**, the default, preserving today's layout so nothing is lost for
  a user scanning a single domain.
- **By remediation step**, showing the plan from section 4, with each step's
  findings grouped and blocked findings visibly marked as waiting.

Confidence is rendered where it is not `confirmed`. An `unverified` finding
carries the same visual treatment as the existing unproven-pillar asterisk at
[`js/app.js:403`](../../src/main.js), for consistency.

Evidence renders under each finding as the record that produced it, using the
node-building renderer from 0.2.3 so DNS-derived material stays a text node.

The CSV export gains `finding_ids`, `finding_severities` and
`remediation_step_1`, appended not inserted.

### 6. Stability requirement

Findings and their ordering must be identical across all fourteen locales. The
rule registry contains no locale-dependent logic, and `buildRemediationPlan()`
sorts on severity and effort tokens rather than on translated strings. The
existing grade sort at [`js/app.js:618`](../../src/main.js) is the precedent: it
sorts on `dataset.grade` rather than on rendered text precisely to stay
locale-independent.

Test this directly: run the same fixture through `buildFindings()` and
`buildRemediationPlan()` under each of the fourteen locales and assert the id
sequences are byte-identical.

## Localization impact

The largest of any release in this roadmap. Every existing `issue.*` and
`suggestion.*` key is renamed to `finding.*`, and roughly fourteen new
cross-protocol findings need `.msg`, `.what`, `.fix` and often `.fixCode`, plus
severity labels, confidence labels, category labels, step headings and rationale
tokens.

The rename must be executed as a key move so `tools/locale-sync.mjs` carries the
existing thirteen translations forward rather than marking 400 units `initial`.
See `OQ-FIND-05`. If the tooling cannot express a move, the rename is deferred and
`issue.*` is kept as the namespace, which costs nothing functionally.

Register for the new material: second person, direct, practical, per
[`AGENTS.md`](../../AGENTS.md). Remediation text in particular is read by someone
mid-incident and should say what to publish, not why it matters.

## Testing

Registry invariants, asserted over the whole `RULES` array:

- Every `id` is unique and matches `^[a-z0-9-]+\.[a-z0-9-]+$`.
- Every `dependsOn` entry names an existing rule id.
- The dependency graph is acyclic.
- Every rule has `finding.<id>.msg` in `locales/en.json`.
- Every `finding.*` key in `locales/en.json` has a rule, so dead keys are caught.
- Every `severity`, `confidence`, `category` and `effort` value is in its
  enumeration.

Behavioral fixtures, each a synthetic audit context:

| Fixture | Expectation |
| --- | --- |
| No SPF, no DKIM, `p=reject` | `dmarc.enforcement-without-auth` critical; plan step 1 is SPF and DKIM |
| No SPF, no DKIM, no DMARC | Plan orders authentication before policy |
| BIMI with `p=none` | `bimi.without-enforcement`, marked blocked by `dmarc.policy-none` |
| BIMI with `p=reject; t=y` | Same finding; test mode is not enforcement |
| Audited domain unanchored, MX-host TLSA authenticated | no DANE/DNSSEC cross-zone finding |
| Audited domain secure, MX-host TLSA unauthenticated | migrated `tlsa-published-unsigned`; no dependency on audited-domain DNSSEC |
| MTA-STS without TLS-RPT | `mta-sts.without-tls-rpt` at low severity |
| Dangling MX with `p=reject` | `mx.dangling-with-enforcement` critical |
| Null MX with `v=spf1 mx -all` | `defensive.contradictory` |
| DKIM 1024-bit with `p=reject` | `dkim.weak-with-enforcement` high |
| Mixed 1024 and 2048 selectors | `dkim.mixed-key-strength` low |
| Everything correct | Empty finding set, empty plan |
| DKIM lookup failed | Finding confidence `unverified`, not `confirmed` |
| All fourteen locales, one fixture | Identical id sequences |

Regression: the existing findings must fire on the same inputs they fire on
today. Build a fixture set from the current `buildIssues()` test coverage and
assert each old `issue.<key>` maps to exactly one new `finding.<id>`.

## Acceptance criteria

1. Every finding names its evidence and its prerequisites.
2. No plan ever recommends DMARC enforcement before SPF and DKIM are in place.
3. The dependency graph is acyclic, enforced by test.
4. Finding ids and remediation order are byte-identical across all fourteen
   locales.
5. Scoring output is unchanged: `node tools/backtest.mjs --json` shows zero
   grade movement against 0.5.0.
6. Every rule has a translation in all thirteen non-English locales.
7. `npm test` and `npm run locale:gate` pass.

## Risks

**This is a rewrite of the most-touched function in the codebase.**
`buildIssues()` is 250 lines of accumulated correctness, much of it carrying
comments explaining a specific false positive that was fixed once and must not
come back. Mitigation: the regression fixture set is built from the existing
behavior first and must pass before the new registry is considered done. Every
comment in the current function is carried onto its corresponding rule.

**Finding proliferation.** Fourteen new cross-protocol findings on top of the
existing 40, layered onto the fifteen advisory findings from 0.4.0, is a lot of
text on a domain that is merely imperfect. Mitigation: severity now has five
levels and the interface defaults to grouping, so `low` and `info` collapse. See
`OQ-FIND-03`.

**Translation churn.** A namespace rename that the tooling handles badly would
mark hundreds of units `initial` and block the release on retranslation.
Mitigation: `OQ-FIND-05` resolves the rename mechanism before implementation
starts, and the fallback is to not rename at all.

**Plan ordering is opinionated.** Reasonable practitioners disagree about
whether, for example, CAA should come before or after MTA-STS. Mitigation: the
graph only encodes dependencies that are technically necessary. Preference
ordering within a step is severity and effort, which is defensible and visible.

## Referred here by earlier releases

Decisions other specs deliberately deferred to this one, recorded so they are
not lost between releases.

- **`psd=y` and the score** — referred by `OQ-DMARC-07` (0.3.0). A domain that
  correctly declares itself a Public Suffix Domain is doing something
  responsible that nothing currently rewards; one that incorrectly declares
  `psd=y` is misrepresenting its position in the tree. 0.3.0 deliberately made
  neither affect the score, under the advisory-before-scoring rule. This spec
  owns severity, so it decides whether either becomes a finding and at what
  level.
- **`dmarc-multiple-records` severity source** — 0.3.0 changed where this
  finding comes from. Duplicate DMARC records at a queried name no longer
  terminate discovery: per RFC 9989 §4.10 they are discarded and the walk
  continues, so a valid record higher in the tree still applies and the status
  may be `missing` rather than `permerror`. The finding stays **critical** and
  is raised from `dmarcDiscovery.observed[]` evidence rather than from
  `dmarcStatus.status`. Any rule in this release's registry that keys on
  `status === 'permerror'` for DMARC must key on the evidence instead.
- **Record hygiene as findings** — referred by `OQ-SEC-12` (0.2.3). Bidirectional
  overrides, zero-width and control characters in a published record are
  display annotations in 0.2.3, not findings. This spec decides whether they
  become findings and at what severity.
- **CSV formula injection** — referred by 0.2.3's Risks section. A cell whose
  first character makes a spreadsheet execute it is neutralized at export and
  flagged `formula-leading`; whether that also warrants a finding is this
  spec's call.

## Open questions

**OQ-FIND-01: Is the remediation plan the default view, or the alternate?**
The plan is the more useful artifact for someone fixing a single domain, and the
severity list is more useful for someone scanning 200 rows for the worst
offenders. This draft defaults to severity and offers the plan as a toggle,
preserving current behavior. The opposite default is arguable.

**OQ-FIND-02: Should the plan span multiple domains?**
An organization auditing 200 domains wants "publish DMARC on these 34 domains
first", not 200 separate plans. That is a genuinely different feature with its own
interface, and it is the natural home for the bulk-audit use case the tool
already supports. Is it in scope for 0.6.0, deferred to its own release, or out
of scope entirely?

**OQ-FIND-03: What is the display threshold?**
With five severities and roughly 70 rules, a mediocre domain could produce 20
findings. Options: show `critical` and `high` expanded with the rest collapsed
behind a count; show everything and rely on grouping; add a severity filter to
the toolbar alongside the existing status filter at
[`index.html:135`](../../index.html). This draft collapses `low` and `info`
behind a count.

**OQ-FIND-04: Does `confidence` belong in the model, or is it a property of the
evidence?**
A finding is `unverified` because its evidence is incomplete, not because the
rule is uncertain. Modelling it on the evidence rather than the finding would be
cleaner, and would let a finding with three pieces of evidence report mixed
confidence. It would also complicate every consumer. This draft puts it on the
finding. Reviewers with an opinion on the data model should weigh in now, because
0.8.0's report schema will freeze whichever shape this release picks.

**OQ-FIND-05: Can `tools/locale-sync.mjs` express a key rename without losing
translations?**
The `issue.*` to `finding.*` rename touches roughly 400 translated units across
thirteen locales. If `locale-sync.mjs` sees a delete and an add, every one of them
goes to `initial` and the release blocks on retranslating work that is already
done. If the tooling can take a rename map, or if the rename can be applied to
`translation-status.json` in the same commit as the `en.json` edit so
fingerprints still match, the cost is zero. Investigate before committing to the
rename. If the answer is no, keep `issue.*` and note in the code that the
namespace name is historical.

**OQ-FIND-06: When do findings and scoring reconnect?**
This release deliberately separates them, and the result is that a domain can
accumulate a critical finding without its grade moving. That is defensible for
one release and strange as a permanent state. The intended end state should be
decided now even if it is implemented later: does the score become a function of
findings, do they stay independent with the score measuring control adoption and
findings measuring configuration quality, or does a third number appear? This
draft holds them separate and asks for the long-term answer.

**OQ-FIND-07: Do `blocks` edges need to be author-declared or purely derived?**
`blocks` is currently the computed inverse of `dependsOn`, which keeps one source
of truth. A rule author who wants to say "fixing this unblocks that" has to edit
the other rule. That is correct for a graph and mildly awkward for an author.
Confirm derived-only is acceptable.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
