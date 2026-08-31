# Development handoff

## Current state

Released through `v0.6.0`. The behavior-neutral refactor is complete: browser
code is ES modules under `src/`, the production boundary is one esbuild bundle,
the import graph is enforced, and the supported browser facade has two members.

The remaining release sequence is:

```text
0.7.0 findings → 0.8.0 artifacts → 0.9.0 reports → 1.0.0 readiness
```

The four specs are Draft and must each be reviewed to `1.0 (Final)` before its
implementation begins. Do not treat the sequence above as approval of the
individual design choices still recorded as `OQ-*` questions.

## Start here: 0.7.0 structured findings

Spec: [`docs/specs/findings-and-remediation.md`](docs/specs/findings-and-remediation.md),
version `0.2`, awaiting review.

This is the next and only implementation phase that is unblocked. It freezes the
finding identity, evidence, confidence and dependency model that both later
feature releases consume.

Before writing implementation code:

1. Review every `OQ-FIND-*` question and record each answer with reasoning.
2. Reproduce every claim against the current modules, especially
   [`src/audit/issues.js`](src/audit/issues.js),
   [`src/audit/scoring.js`](src/audit/scoring.js),
   [`src/ui/events.js`](src/ui/events.js), and the locale tooling.
3. Investigate `OQ-FIND-05` with the real locale pipeline before approving any
   `issue.*` to `finding.*` key move. Never edit
   `locales/translation-status.json` by hand.
4. Build the regression fixture set from current `buildIssues()` and
   `buildSuggestions()` behavior before replacing either implementation.
5. Amend and re-version the spec for every accepted review finding. Stop if a
   proposed solution needs an architecture-matrix change without a written
   architectural justification.

The implementation boundary is already decided by 0.6.0: finding semantics and
remediation ordering belong to `src/audit/`; protocol facts stay with their
existing `src/core/<protocol>/` owners; presentation belongs to `src/ui/`; and
`src/runtime.js` composes the two. Do not add a UI-to-audit import or move
finding severity into a protocol owner.

### Decisions that require deliberate review

- Whether remediation or severity is the default view (`OQ-FIND-01`).
- Whether plans remain per-domain (`OQ-FIND-02`).
- The display threshold for low-information findings (`OQ-FIND-03`).
- Whether confidence belongs on a finding or its evidence (`OQ-FIND-04`).
- Whether locale keys can move without destroying translation state
  (`OQ-FIND-05`).
- The long-term relationship between findings and scoring (`OQ-FIND-06`).
- Whether `blocks` is always derived from `dependsOn` (`OQ-FIND-07`).

The 0.9.0 schema will freeze the result of several of these decisions. Do not
default them silently during implementation.

## What follows

| Release | Spec | Start condition | Contract it establishes |
| --- | --- | --- | --- |
| 0.7.0 | [findings-and-remediation](docs/specs/findings-and-remediation.md) | `v0.6.0` released; spec reviewed to Final | Stable finding identity, evidence, confidence and remediation dependencies |
| 0.8.0 | [local-artifact-validation](docs/specs/local-artifact-validation.md) | 0.7.0 released; spec reviewed to Final | User-supplied provenance and local MTA-STS/BIMI artifact results |
| 0.9.0 | [report-comparison](docs/specs/report-comparison.md) | 0.8.0 released; spec reviewed to Final | Versioned JSON schema, import validation and stateless comparison |
| 1.0.0 | [one-zero-readiness](docs/specs/one-zero-readiness.md) | 0.7.0–0.9.0 released; spec reviewed to Final | Supported 1.x compatibility, browser, accessibility and production contract |

### 0.8.0 boundary

MTA-STS policy rules belong to `src/core/transport/`; BIMI SVG and optional VMC
rules belong to `src/core/bimi/`; `src/audit/` composes artifact findings;
`src/runtime.js` injects the capability into `src/ui/`. There is no temporary
finding stub and no replacement `artifact.js` monolith. `OQ-ART-08`, the
hostile-SVG testing strategy, is a real stop before implementation.

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
no implementation phase. Review it as a decision document while 0.7.0–0.9.0
progress. The 1.0 readiness draft currently requires it to be Final before
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
