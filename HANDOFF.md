# Development handoff

## Current state

Released through `v0.9.1`. An MX host is now read for what it resolves to, not
only for whether it resolves: every resolved address is classified against the
IANA special-purpose registries, so a host answering only loopback, private,
link-local, carrier-shared, documentation or reserved space is reported as
unreachable instead of healthy. A host mixing routable and unreachable addresses
gets its own finding, because delivery succeeds intermittently and correlates
with nothing the sender can see.

Two adjacent defects are now named for what they are rather than diagnosed as
dangling hosts: an address written where the record requires a hostname, which
also stops spending three lookups proving what the RDATA already stated; and a
null MX published beside a real MX record, which RFC 7505 §3 forbids and which
was previously reported nowhere at all, because the parser rejects `0 .` before
any lookup.

`v0.9.1` issues no new DNS query and moves no score or grade. Deterministic
replay across the 32-case corpus shows byte-identical query traces, and the
cross-release guard in `tests/build/release-compat.test.mjs` bounds every
surface of the authorized delta with 67 assertions.

Two releases remain:

```text
0.9.2 MX vanity divergence → 1.0.0 readiness
```

## Start here: conclude the 0.9.2 privacy review

Spec: [`docs/specs/mx-host-validity.md`](docs/specs/mx-host-validity.md) §7,
`0.13`. **0.9.2 does not begin until this concludes**, and nothing else in the
document gates it.

0.9.2 adds `PTR` lookups to identify the provider behind a vanity MX host by
forward-confirmed reverse DNS, and reports the addresses a customer's copy has
fallen behind on. That moves published DNS fan-out, and `AGENTS.md` makes
anything implying a `PRIVACY.md` edit a stop condition rather than a note.

The review has to answer one question the spec deliberately does not presume:
whether inferring and resolving a provider name the user never supplied is
within the consent an audit run already carries, or whether it needs its own
control. §4 records that a dedicated flag is the mechanism if the answer is the
latter, and what its provenance and comparability cost would be.

`OQ-MXV-03` — the measured query cost — is held open with it, because the same
traces answer both what it costs and what it discloses. Two entries must be
added to `PRIVACY.md`'s disclosure list, and its published per-domain figures
re-measured rather than estimated.

The 1.0.0 readiness review continues independently of both.

## What follows

| Release | Spec | Start condition | Contract it establishes |
| --- | --- | --- | --- |
| 0.7.0 | [findings-and-remediation](docs/specs/implemented/findings-and-remediation.md) | Released as `v0.7.0` | Stable finding identity, evidence, confidence and remediation dependencies |
| 0.8.0 | [local-artifact-validation](docs/specs/implemented/local-artifact-validation.md) | Released as `v0.8.0` | User-supplied provenance and local MTA-STS/BIMI artifact results |
| 0.9.0 | [report-comparison](docs/specs/implemented/report-comparison.md) | Released as `v0.9.0` | Versioned JSON schema, import validation and stateless comparison |
| 0.9.1 | [mx-host-validity](docs/specs/mx-host-validity.md) | Released as `v0.9.1` | MX address-scope classification; address-literal and null-MX-conflict diagnosis |
| 0.9.2 | [mx-host-validity](docs/specs/mx-host-validity.md) | 0.9.1 released; **privacy review concluded** and `PRIVACY.md` re-measured | Forward-confirmed reverse DNS and provider address-set divergence |
| 1.0.0 | [one-zero-readiness](docs/specs/one-zero-readiness.md) | 0.7.0–0.9.1 released; spec must still be reviewed to Final | Supported 1.x compatibility, browser, accessibility and production contract |

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
  is per release: `mx-host-validity` `0.13` covers 0.9.1, which shipped, and
  0.9.2, which is not approved.
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
