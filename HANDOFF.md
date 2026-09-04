# Development handoff

## Current state

Released through `v0.8.1`. Private local MTA-STS policy and BIMI SVG validators
now consume 0.7.0's structured-finding boundary without changing legacy
issues, suggestions, scores or grades. Supplied artifacts remain in memory,
produce no network request, and are never rendered as active markup.

`v0.8.1` is a patch release with no new capability: it fixes five defects found
by an external review of `v0.8.0` — a hostile NS label that discarded a whole
run, a double click that started two audits, an unsentinelised provider badge,
prototype-chain resolution in the i18n and entity lookups, and a BIMI `url()`
screen that was wrong in both directions — plus a footer entity that rendered
as literal text, and the documentation drift the review catalogued. The
`local-artifact-validation` spec is amended to 1.11 to record the corrected
`url()` rule and the new `data-uri-reference` diagnostic.

The remaining release sequence is:

```text
0.9.0 reports → 1.0.0 readiness
```

Each remaining spec must be reviewed to Final before its implementation
begins. `report-comparison` reached that bar on 2026-09-03;
`one-zero-readiness` has not, and its `OQ-ONE-*` questions are not approved by
the sequence above.

## Start here: implement 0.9.0 stateless report comparison

Spec: [`docs/specs/report-comparison.md`](docs/specs/report-comparison.md),
**`1.9 (Final, amended)`, approved for implementation**. The review resolved all
seven `OQ-CMP-*` questions as `RQ-CMP-01`–`07`, reconciled the schema against
what `v0.8.1` actually produces, and raised and resolved one more —
`RQ-CMP-08`, per-protocol comparability. The 1.1 amendment corrects the
implementable contract without reopening those product decisions.

Build it in the ten owner-bound commits the spec's §0 lists, in that order.
Each leaves the browser working, and the order is load-bearing in two places:

1. `src/audit/` — `ANALYSIS_VERSION` and the observability projection.
2. `src/runtime.js` — `APP_VERSION` and injected version metadata.
3. `src/ui/report-data.js` — pure schema, validation and comparison.
4. `src/platform/browser.js` — `nowIso()`, the report's UTC instant.
5. `src/runtime.js` — the resolver URL as a capability.
6. `src/ui/events.js` — the run context the export reads, and the composed
   selector predicate replacing an inlined copy of the grammar.
7. `src/ui/report.js` — `exportJSON()`.
8. `src/ui/report-data.js` — the coded importer error shape.
9. `locales/en.json` and all thirteen translations.
10. `src/ui/`, `index.html`, `css/style.css` — import controls, comparison
    mode, rendering and filters — plus `src/audit/findings.js`,
    `src/audit/create-audit.js` and `src/runtime.js` for the finding-id
    catalog. The one step that is not owner-bound: markup, listener and
    presentation are not shippable apart, and the unknown-id note cannot be
    answered from inside `src/ui/`.

**The locale commit precedes the UI wiring, and that is not a preference.**
Step 7 calls `t('toast.jsonExported')`, and `t()` returns the key itself when it
is missing, so a control wired before step 9 would ship a browser whose export
toast reads `toast.jsonExported`. Nothing invokes that call until a control
exists, which is what makes step 7 sound on its own. Step 8 has to precede the
locales for the same kind of reason: the messages written there are messages for
its codes.

The review findings are implementation prerequisites rather than design notes,
and these are the easiest to miss:

- **`generator.version` has no runtime source.** The package version reaches
  only the bundle's comment banner in `tools/build-bundle.mjs`. Commit 2 adds
  `APP_VERSION` to the existing `src/runtime.js` composition owner and pins it
  to `package.json`; `src/version.js` is not permitted by the import matrix.
- **`generatedAt` is the moment the audit run completed**, captured once in
  `src/ui/events.js` run state and reused by every export of that run. As
  export time, acceptance criterion 4 is untestable.
- **The schema is a projection, not a dump.** The exclusion table in §1 is the
  specification; its normalized record paths are asserted in both directions,
  because a test that only checks the wanted fields would pass on a dump or a
  dead whitelist member.
- **`deepChecks` is part of report provenance.** Its mismatch makes MX and DANE
  incomparable without blanking unrelated protocols.
- **Observability is an audit fact.** Do not infer it from finding confidence:
  that loses unscored MX/DANE failures and overstates partial DMARC failures.
- **Cross-generator finding movement is qualified.** Keep the raw id diff, but
  use `changed` and baseline/current-only labels rather than claiming domain
  improvement or regression.

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
| 0.9.0 | [report-comparison](docs/specs/report-comparison.md) | 0.8.0 released; spec Final, amended at `1.9` | Versioned JSON schema, import validation and stateless comparison |
| 1.0.0 | [one-zero-readiness](docs/specs/one-zero-readiness.md) | 0.7.0–0.9.0 released; spec reviewed to Final | Supported 1.x compatibility, browser, accessibility and production contract |

### 0.8.0 boundary

MTA-STS policy rules belong to `src/core/transport/`; BIMI SVG rules belong to
`src/core/bimi/`; `src/audit/` composes artifact findings;
`src/runtime.js` injects the capability into `src/ui/`. There is no temporary
finding stub and no replacement `artifact.js` monolith. The hostile-SVG suite
uses the real browser parser and must prove its own detectors fail.

### 0.9.0 boundary

Pure report schema and comparison work stays within `src/ui/` siblings.
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
