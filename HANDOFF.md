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
surface of the authorized delta with 60 assertions.

Two releases remain:

```text
0.9.2 MX vanity divergence → 1.0.0 readiness
```

## Start here: 0.9.2 awaits approval, not investigation

Spec: [`docs/specs/mx-host-validity.md`](docs/specs/mx-host-validity.md) `0.16`,
§7. **The privacy review is done and its fan-out is executed, not projected. 0.9.2
is not started and must not begin until `OQ-MXV-03` is accepted and the document
is promoted to `1.0 (Final)`.**

What the review established, before any 0.9.2 code was written:

- **The fan-out is small, and it was executed — including what leaves the
  browser.** A measurement-only spike runs §4 through the **production cache and
  transport** with a recording `fetch` beneath: **16 calls above the cache, 14
  requests actually sent, 0.175 per audited domain**, with three controls. Two
  earlier drafts got this wrong in the same way at different layers — the first
  counted stored addresses and called it measured; the second measured the 16
  calls and *calculated* the 14. `PRIVACY.md` speaks in outbound requests, so 14
  is the figure, and it is now observed at the transport seam. Evidence:
  [`fixtures/ptr-fan-out-0.9.2.md`](docs/specs/fixtures/ptr-fan-out-0.9.2.md).
  A domain whose MX hosts are named by its provider — the common case for hosted
  mail — costs **nothing**, because the gate requires an in-domain MX host.
- **The worst case was unbounded, and is not any more.** §4 capped addresses per
  host and candidates per domain but never the number of hosts, so ten in-domain
  MX hosts would have cost forty `PTR` queries. It now examines the two
  lowest-preference qualifying hosts, bounding a domain at 12 additional queries
  and the whole default path at 600.
- **Two name classes reach the resolver that no earlier release sent it:** the
  reverse zone of each checked address, and — where the reverse name is
  forward-confirmed — a provider name the user never typed and the audited zone
  never published.
- **No separate opt-in — but the reasoning changed.** The new disclosure is
  query *intent and linkability*, not data: the resolver learns that this client
  is investigating this address and links it to the provider name and the rest of
  the run. §7.4 weighs that and still declines a separate control, because the
  correlation is already inferable from the MX, `A`, `CNAME` and `TLSA` queries
  the same page issues for the same host, and 0.9.2 adds no application-level
  identifier, persistence, or new recipient. It does **not** claim a run is
  unlinkable to another — Cloudflare can correlate runs from ordinary connection
  metadata, and `PRIVACY.md` promises nothing to the contrary. §7.4 names what
  would reverse the decision.
- **`OQ-MXV-03` is open, on purpose.** The evidence exists; accepting it is the
  reviewer's call, and it is the last thing between this document and
  `1.0 (Final)`.

`PRIVACY.md` is deliberately unchanged. It describes what the shipped
application does, and 0.9.2 does not ship yet; §7.5 carries the exact amendment
to apply in the release that ships the behavior, and requires the per-domain
figures to be re-measured rather than adjusted.

The 1.0.0 readiness review continues independently.

## What follows

| Release | Spec | Start condition | Contract it establishes |
| --- | --- | --- | --- |
| 0.7.0 | [findings-and-remediation](docs/specs/implemented/findings-and-remediation.md) | Released as `v0.7.0` | Stable finding identity, evidence, confidence and remediation dependencies |
| 0.8.0 | [local-artifact-validation](docs/specs/implemented/local-artifact-validation.md) | Released as `v0.8.0` | User-supplied provenance and local MTA-STS/BIMI artifact results |
| 0.9.0 | [report-comparison](docs/specs/implemented/report-comparison.md) | Released as `v0.9.0` | Versioned JSON schema, import validation and stateless comparison |
| 0.9.1 | [mx-host-validity](docs/specs/mx-host-validity.md) | Released as `v0.9.1` | MX address-scope classification; address-literal and null-MX-conflict diagnosis |
| 0.9.2 | [mx-host-validity](docs/specs/mx-host-validity.md) | 0.9.1 released; privacy review conducted and **approved**; `PRIVACY.md` amended and re-measured on the shipping release | Forward-confirmed reverse DNS and provider address-set divergence |
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
  is per release: `mx-host-validity` `0.16` covers 0.9.1, which shipped, and
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
