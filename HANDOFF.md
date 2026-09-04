# Development handoff

## Current state

Released through `v0.9.0`. A finished audit can be exported as a versioned JSON
report and two reports can be compared entirely in the browser tab. The
comparison overlays the existing results table, and leaving the mode or
reloading discards both reports; nothing is written to storage.

`v0.9.0` also adds a per-protocol observability fact to every audit — a total
map over the thirteen protocols, closed over observed, unproven and not-run.
That is what makes a comparison safe to trust: a protocol either report did not
observe is marked with the side that lacked it and the reason, rather than
having its findings reported as resolved. `analysisVersion` gates the score
delta only, and a difference in generator version shows the finding movement
without labelling it improved or regressed.

The `report-comparison` spec is at `1.10 (Implemented, amended)` and records
nine implementation divergences in its **As implemented** section, eight of them
found by review of the working tree rather than of the finished branch.

Three releases remain:

```text
0.9.1 MX address validity → 0.9.2 MX vanity divergence → 1.0.0 readiness
```

The two MX releases were added on 2026-09-04 from
[`docs/specs/mx-host-validity.md`](docs/specs/mx-host-validity.md) (`0.5`). **0.9.1 is
next**, and the 1.0.0 review continues independently of it. **0.9.2 is
blocked:** it adds `PTR` queries on a path
deep checks leave enabled by default, which moves published DNS fan-out, and
`AGENTS.md` makes anything implying a `PRIVACY.md` edit a stop condition. That
review has not happened, and `OQ-MXV-03` — the measured query cost — is held open
with it.

## Start here: implement 0.9.1 MX address validity

Spec: [`docs/specs/mx-host-validity.md`](docs/specs/mx-host-validity.md), **`0.5`
— the 0.9.1 portion is Final and approved for implementation.** The document
stays at `0.3` because `OQ-MXV-03` is open; approval extends to 0.9.1 and to
nothing else, per the multi-release rule in
[`docs/specs/README.md`](docs/specs/README.md). Nothing open in that document
gates 0.9.1: `OQ-MXV-03` and the §7 privacy review both concern 0.9.2, which issues `PTR`
queries. 0.9.1 issues none.

The finding it exists for is a false negative. `auditMxHosts()` computes
`resolves` from `addresses.length` alone, so an MX host answering `127.0.0.1`,
`10.0.0.4` or `::1` reports as healthy while receiving no mail from the internet.
Three adjacent defects are diagnosed as dangling hosts — an address literal in
the MX RDATA, a null MX published beside a real one, and a preference outside the
16-bit range — which is the right alarm attached to remediation the operator
cannot carry out.

Build it in four commits, in this order. **The 0.3 draft of this section said
five and put the locale strings in their own step; that is not buildable.**
`audit.issue.key` is asserted equal to the locale issue keys in two contract
suites, so strings without findings fail exactly as findings without strings do.
They are one commit.

1. `src/core/shared/ip.js` — `ipScope()` and the closed `ip.scope` algebra. Pure,
   and testable with no resolver.
2. `src/core/mx/mx.js` — the parser changes (address literal, preference range,
   `hasNullMxConflict()` beside an unchanged `isNullMx()`), the per-host
   `addressScopes` and `reachability`, and the new top-level fields.
3. `src/audit/findings.js`, `src/audit/issues.js`, `locales/en.json`, all
   thirteen translations and `npm run build:fallback` — together.
4. The registry rows each algebra needs, alongside the module that declares it,
   rather than in a trailing commit.

**Neither half of step 3 can precede the other.** `t()` returns the key itself
when a message is missing, so findings ahead of their strings ship a browser
rendering `mx-unroutable` at the reader; and the two contract suites above fail
on strings ahead of their findings. 0.9.0's steps 9 and 10 had only the first
constraint, which is why its order worked and this one does not.

Three prerequisites that are easy to miss:

- **`isNullMx()` must not change.** Its `mx.length !== 1` guard is load-bearing in
  the deep-check gate, `@null-mx` provider detection, and the MTA-STS
  `policy-on-null-mx` finding. Acceptance criterion 4 requires byte-identical
  behavior on every input; the conflict case is a separate predicate.
- **An address literal skips its lookups.** Three queries per such host are spent
  proving what the RDATA already stated. The test asserts the saved queries
  against a call-recording stub, because a saving that is only described
  regresses silently.
- **Advisory before scoring.** No score or grade moves in 0.9.1. Admitting these
  findings to the grade is a later release, backtested with
  `node tools/backtest.mjs`.

## Continuing in parallel: review `one-zero-readiness` to Final

Not the immediate delivery task, and it does not block 0.9.1 or 0.9.2.

Spec: [`docs/specs/one-zero-readiness.md`](docs/specs/one-zero-readiness.md),
**`0.1`, Draft — not approved for implementation.** Every spec is Final before
its implementation begins, and this one is not: its `OQ-ONE-*` questions are
open, starting with `OQ-ONE-01`, whether 1.0.0 remains a dedicated graduation
release at all rather than a version number placed on the state 0.9.0 leaves.

`0.9.0` is what makes that question answerable now. The public report schema is
the last compatibility surface the 1.x promise has to cover, and it exists:
`schemaVersion`, a closed rejection vocabulary, published limits, and an
explicit policy that fields are added and deprecated but never repurposed.

[`docs/specs/external-intelligence.md`](docs/specs/external-intelligence.md) is
a decision document with no implementation phase; the readiness draft requires
it to be Final before 1.0.0, subject to `OQ-ONE-05`.

## What follows

| Release | Spec | Start condition | Contract it establishes |
| --- | --- | --- | --- |
| 0.7.0 | [findings-and-remediation](docs/specs/implemented/findings-and-remediation.md) | Released as `v0.7.0` | Stable finding identity, evidence, confidence and remediation dependencies |
| 0.8.0 | [local-artifact-validation](docs/specs/implemented/local-artifact-validation.md) | Released as `v0.8.0` | User-supplied provenance and local MTA-STS/BIMI artifact results |
| 0.9.0 | [report-comparison](docs/specs/implemented/report-comparison.md) | Released as `v0.9.0` | Versioned JSON schema, import validation and stateless comparison |
| 0.9.1 | [mx-host-validity](docs/specs/mx-host-validity.md) | `v0.9.0` released; spec `0.5`, **0.9.1 implemented** | MX address-scope classification; address-literal and null-MX-conflict diagnosis |
| 0.9.2 | [mx-host-validity](docs/specs/mx-host-validity.md) | 0.9.1 released; **privacy review concluded** and `PRIVACY.md` re-measured | Forward-confirmed reverse DNS and provider address-set divergence |
| 1.0.0 | [one-zero-readiness](docs/specs/one-zero-readiness.md) | 0.7.0–0.9.0 released; spec must still be reviewed to Final | Supported 1.x compatibility, browser, accessibility and production contract |

### 0.8.0 boundary

MTA-STS policy rules belong to `src/core/transport/`; BIMI SVG rules belong to
`src/core/bimi/`; `src/audit/` composes artifact findings;
`src/runtime.js` injects the capability into `src/ui/`. There is no temporary
finding stub and no replacement `artifact.js` monolith. The hostile-SVG suite
uses the real browser parser and must prove its own detectors fail.

### 0.9.0 boundary

As shipped. Pure report schema and comparison work stays within `src/ui/`
siblings.
`ANALYSIS_VERSION` remains owned by `src/audit/scoring.js` and crosses the
existing composition boundary; the UI never imports scoring. `APP_VERSION`
lives in `src/runtime.js`, not a new unowned root module. `RQ-CMP-06` keeps one
`analysisVersion`, bumped by anything that can move a score, while 1.1
qualifies finding movement whenever generator versions differ. The closed
observability map, including unscored MX and DANE, prevents a failed or skipped
check from reading as fixed. `RQ-CMP-07` excludes artifact findings with no
reserved field, asserted against `artifactFindingCatalogIds()`.

### 1.0.0 boundary

The current draft makes 1.0.0 a dedicated graduation release, not another
protocol feature. It defines compatibility surfaces, a maintainable browser
matrix, accessibility evidence, clean-checkout reproducibility, privacy and
security reconciliation, and backlog disposition. Whether it remains a
dedicated release is `OQ-ONE-01` and must be resolved during spec review.

## Product-boundary decision alongside the feature work

[`docs/specs/external-intelligence.md`](docs/specs/external-intelligence.md) has
no implementation phase. Review it as a decision document alongside the
1.0.0 readiness spec. The 1.0 readiness draft currently requires it to be Final before
1.0.0, subject to `OQ-ONE-05`.

## Standing rules

[`AGENTS.md`](AGENTS.md) is authoritative. In particular:

- Work on a branch, never on `main`.
- A spec is Final before implementation starts. For a multi-release spec, that
  is per release: `mx-host-validity` `0.5` approves 0.9.1 only.
- A task is boundable to one owning directory; cross-directory work is split
  into separate commits with an architectural explanation.
- Resolver and generated data dependencies are passed, never imported by their
  consumers.
- Protocol and audit layers emit tokens; only `src/ui/` and `src/i18n/` turn
  them into words.
- Any English locale change includes all thirteen translations and passes the
  full locale loop.
- New checks are proven to fail before they are trusted.
- No move and semantics change share a commit. Scoring, concurrency, cache
  scope, result schema and UI behavior changes remain separate.
- `npm test` and `npm run locale:gate` pass before a PR opens. Backtest anything
  that can move a grade, score, query trace or published fan-out claim.
- Push once after the work and its review are complete. Ian decides when to
  squash and merge.

## Required verification for every phase

Use the spec's own testing and acceptance sections as the primary checklist,
then at minimum run:

```bash
npm test
npm run inventory
npm run locale:gate
git diff --check
```

Run the deterministic equivalence suite and the live backtest whenever the
phase can affect their surfaces. Quantitative documentation uses figures from
the finished branch, never memory or arithmetic over an older release.

## Keeping this handoff current

This file records only the current starting point and the dependency chain. It
is not a parallel roadmap, review log or history of completed implementation.

When a phase releases:

1. Remove its detailed “start here” instructions.
2. Make the next phase the single starting point.
3. Update the release-state sentence and dependency table.
4. Keep implementation history in the released spec's **As implemented** and
   **Revision history** sections.
5. Keep release rationale and sequencing in `ROADMAP.md`.

If this file and a spec disagree about implementation, the reviewed spec wins.
If either disagrees with `AGENTS.md` about repository process or architecture,
stop and reconcile the documents before coding.
