# Development handoff

## Current state

Released through `v0.8.0`. Private local MTA-STS policy and BIMI SVG validators
now consume 0.7.0's structured-finding boundary without changing legacy
issues, suggestions, scores or grades. Supplied artifacts remain in memory,
produce no network request, and are never rendered as active markup.

The remaining release sequence is:

```text
0.9.0 reports → 1.0.0 readiness
```

Each remaining spec must be reviewed to Final before its implementation
begins. Do not treat the sequence above as approval of the individual design
choices still recorded as `OQ-*` questions.

## Start here: review the 0.9.0 stateless report-comparison spec

Spec: [`docs/specs/report-comparison.md`](docs/specs/report-comparison.md),
currently a draft and **not approved for implementation**.

The next task is review, not code. Resolve every `OQ-CMP-*` decision, reconcile
the schema with what 0.8.0 actually exports, and promote the spec to Final
before creating an implementation branch.

The 0.8.0 release established the inputs 0.9.0 must respect:

1. Artifact findings are explicitly `user-supplied` and separate from DNS
   findings, scores and reproducible public observations.
2. CSV and static HTML present the current session's artifact findings, but the
   0.8.0 decision excludes them from 0.9.0's versioned comparison JSON.
3. Reload discards supplied material. The comparison release must preserve the
   same zero-persistence boundary for imported reports.
4. Existing CSV columns keep their positions; new report formats need an
   explicit compatibility and versioning rule before they ship.

## What follows

| Release | Spec | Start condition | Contract it establishes |
| --- | --- | --- | --- |
| 0.7.0 | [findings-and-remediation](docs/specs/implemented/findings-and-remediation.md) | Released as `v0.7.0` | Stable finding identity, evidence, confidence and remediation dependencies |
| 0.8.0 | [local-artifact-validation](docs/specs/implemented/local-artifact-validation.md) | Released as `v0.8.0` | User-supplied provenance and local MTA-STS/BIMI artifact results |
| 0.9.0 | [report-comparison](docs/specs/report-comparison.md) | 0.8.0 released; spec must be reviewed to Final | Versioned JSON schema, import validation and stateless comparison |
| 1.0.0 | [one-zero-readiness](docs/specs/one-zero-readiness.md) | 0.7.0–0.9.0 released; spec reviewed to Final | Supported 1.x compatibility, browser, accessibility and production contract |

### 0.8.0 boundary

MTA-STS policy rules belong to `src/core/transport/`; BIMI SVG rules belong to
`src/core/bimi/`; `src/audit/` composes artifact findings;
`src/runtime.js` injects the capability into `src/ui/`. There is no temporary
finding stub and no replacement `artifact.js` monolith. The hostile-SVG suite
uses the real browser parser and must prove its own detectors fail.

### 0.9.0 boundary

Pure report schema and comparison work stays within `src/ui/` siblings.
Scoring or analysis version metadata remains owned by `src/audit/` and crosses
the existing composition boundary; the UI never imports scoring. Settle
`OQ-CMP-06` before the first report is exported because the field cannot be
repurposed after release. Match `OQ-CMP-07` to what 0.8.0 actually ships.

### 1.0.0 boundary

The current draft makes 1.0.0 a dedicated graduation release, not another
protocol feature. It defines compatibility surfaces, a maintainable browser
matrix, accessibility evidence, clean-checkout reproducibility, privacy and
security reconciliation, and backlog disposition. Whether it remains a
dedicated release is `OQ-ONE-01` and must be resolved during spec review.

## Product-boundary decision alongside the feature work

[`docs/specs/external-intelligence.md`](docs/specs/external-intelligence.md) has
no implementation phase. Review it as a decision document while 0.9.0
progresses. The 1.0 readiness draft currently requires it to be Final before
1.0.0, subject to `OQ-ONE-05`.

## Standing rules

[`AGENTS.md`](AGENTS.md) is authoritative. In particular:

- Work on a branch, never on `main`.
- A spec is Final before implementation starts.
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
