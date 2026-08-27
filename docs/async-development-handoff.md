# Async agentic build handoff: dns-email-audit roadmap

**Audience:** Claude Code (or any coding agent) executing this roadmap.
**Purpose:** Turn the eight planned specs under `docs/specs/` into a concrete,
dependency-safe execution order for an automated/async build pipeline,
superseding release-number order for scheduling purposes only.
**Source of the ranking and dependency map:** `claude/spec-evaluation-results.md`
in the Kwestic project (an analysis pass over every spec, `ROADMAP.md`,
`docs/specs/README.md`, `AGENTS.md`, and `PRIVACY.md`). This document turns
that analysis into an execution plan. Read the evaluation doc first if you
want the full reasoning; this document assumes it and gets operational.
**Written:** 2026-08-24.

---

## 0. Ground rules that apply to every phase below

These are not new — they're the existing project rules, restated here because
an agent working phase-by-phase needs them at hand without re-deriving them
from four separate files each time.

1. **A spec is reviewed to `1.0 (Final)` before implementation starts.**
   Per `docs/specs/README.md`'s review process: produce (a) a verdict on
   every numbered open question with reasoning, (b) any correctness objection
   cited to the RFC or the file/function it contradicts, (c) anything that
   would break the privacy boundary in `PRIVACY.md`, the CSP, or the
   localization contract in `AGENTS.md`, (d) anything the spec claims about
   the current codebase that isn't true. Record the resolution in the spec's
   **Resolved questions** table with the version that resolved it, and add a
   **Revision history** row. Do not accept a review wholesale — the project's
   own history (0.2.3, rounds 1–2) shows a reviewer contradicting itself and
   proposing a mechanism that didn't work; check every point against the code
   before folding it in.
2. **Never renumber open question IDs, never rename spec files for the
   release number.** Specs are named for capability. `OQ-DMARC-01` stays
   `OQ-DMARC-01` even after the document is edited ten times.
3. **`js/dns.js` returns tokens, not English.** Only `js/app.js` turns them
   into words. This is binding on every phase that touches `js/dns.js`.
4. **A change to `locales/en.json` translates all thirteen other locales in
   the same change** — not a follow-up. Run `npm run build:fallback` after
   the edit, then the translation loop in `AGENTS.md` (`locale:sync`,
   `locale:todo`, `locale:set`, `locale:gate`). `npm run locale:gate` must
   report 13/13 before a pull request opens. This is the single most
   frequently-cited acceptance criterion across all eight specs — do not treat
   it as optional because a phase feels DNS-focused rather than UI-focused.
5. **Advisory before scoring.** A new check reports its finding for at least
   one release before it affects the grade. A scoring change is backtested
   with `node tools/backtest.mjs` before it merges. `WEIGHTS`,
   `PARKED_WEIGHTS`, and `GRADE_THRESHOLDS` stay byte-identical across every
   phase below except where a spec explicitly says otherwise (none of the
   eight do).
6. **No new network destinations.** `connect-src` stays
   `'self' https://cloudflare-dns.com`. Nothing in this plan changes that.
7. **`npm test` and `npm run locale:gate` pass before any pull request
   opens.** Every phase below ends there.
8. **When a spec's own acceptance criteria and testing section exist, they
   are the authority.** This document sequences work; it does not restate
   every fixture. Open the spec before starting its phase.
9. **Human checkpoints are real stops, not suggestions.** Several open
   questions below are marked "STOP — needs Ian" because the spec itself says
   the answer requires something an agent shouldn't guess (RFC text open in
   front of a human, a product trade-off, a decision that locks a schema).
   Do not resolve these unilaterally and proceed; surface them and wait.

---

## 0a. Reconciling this document with the installed `.claude/skills` pack

As of 2026-08-24 this machine has the `obra/superpowers` skill pack installed
locally (`using-git-worktrees`, `systematic-debugging`,
`finishing-a-development-branch`, `requesting-code-review`,
`receiving-code-review`, `verification-before-completion`,
`subagent-driven-development` — see `skills-lock.json`). It's local-only
(excluded via `.git/info/exclude`, not the shared `.gitignore`), so this
section applies to work done on this machine and doesn't need to travel with
the repo. Reviewed and judged net-positive, with two things that need
explicit reconciliation rather than being left to default behavior:

- **`subagent-driven-development`'s "rulings, not stalls" default does NOT
  override rule 9 above or any "STOP — needs Ian" marker in this document.**
  That skill's own stop conditions (destructive ops, security-sensitive
  actions, external side effects, an unworkable plan) are real, but they are
  a floor, not a ceiling, on when to stop for this repo. `OQ-DMARC-01` (RFC
  9989 numbers must come from the actual text, never memory) and `OQ-ART-08`
  (which SVG-validation strategy to take) are exactly the kind of decision
  that skill would otherwise rule on and continue past. Don't let it. Treat
  every "STOP — needs Ian" in this document as a fifth stop condition,
  standing alongside that skill's own four, for any work under this roadmap.
- **`subagent-driven-development` expects a decomposed task plan, not a
  spec.** None of the eight `docs/specs/*.md` documents are broken into the
  numbered-task format that skill's tooling (`sdd-workspace`, `task-brief`,
  `review-package`) assumes. If you use that skill for a phase below, write
  the task breakdown first (a plan file with a Global Constraints section
  copying the relevant hard rules from section 0 above and the spec's own
  Acceptance Criteria) — don't feed it a spec directly and expect the
  tooling to work.
- **`requesting-code-review`'s reviewer template is generic** and doesn't
  know this repo's hard rules on its own. Every time it's dispatched, put
  this repo's non-negotiables — zero runtime dependencies, no markup sinks
  (`innerHTML`/`outerHTML` assignment anywhere in `js/`), `js/dns.js` returns
  tokens not English, `connect-src` stays exactly `'self'
  https://cloudflare-dns.com`, no persistence beyond the one `localStorage`
  language key, 13/13 locale completeness — into the `PLAN_OR_REQUIREMENTS`
  placeholder alongside the spec's own Acceptance Criteria. Don't rely on the
  reviewer to know these from context; it doesn't.
- `using-git-worktrees`, `verification-before-completion`,
  `systematic-debugging`, and `finishing-a-development-branch` need no
  reconciliation — use them as designed. `verification-before-completion` in
  particular is a good match for rule 7 above; treat them as the same rule
  stated twice.

---

## 1. Priority order (why this order, not release order)

> **Amended 2026-08-27.** `modular-architecture-and-production-build` was added
> at 0.6.0 and the three feature specs each moved up one release number —
> `findings-and-remediation` 0.6.0 → 0.7.0, `local-artifact-validation`
> 0.7.0 → 0.8.0, `report-comparison` 0.8.0 → 0.9.0. Only the numbers changed:
> spec filenames, `OQ-*` identifiers, dependency structure and the usefulness
> ranking below are all untouched, per the naming rule in
> [`docs/specs/README.md`](specs/README.md). The refactor is inserted as
> **Phase 3½**, described in §4½ below.

| Order | Spec | Usefulness | Group | Why here |
| --- | --- | --- | --- | --- |
| 1 | `rendering-and-robustness` (0.2.3) | 4/10 | A | Hard prerequisite gate for 0.3.0 and 0.8.0. Must go first regardless of its own score. |
| 2 | `dmarcbis-tree-walk` (0.3.0) | 7/10 | B (link 1/3) | First link in the protocol-correctness chain; also decides the fixture-resolver mechanism (`OQ-DMARC-03`) that 0.4.0 and 0.5.0 testing reuses. |
| 3 | `dns-protocol-depth` (0.4.0) | 9/10 | B (link 2/3) | Second link; adds `DS`/`DNSKEY`/`TLSA` transport 0.5.0 needs, and the per-host `authenticated` evidence 0.5.0 keeps as the honest ceiling for DANE. |
| 3′ | `local-artifact-validation` (0.8.0) | 5/10 | D (parallel) | Can start as soon as 0.2.3 lands, run alongside the whole B chain. Only sync point is 0.7.0's `Finding` shape (stub it, reconcile later). |
| 4 | `dnssec-evidence` (0.5.0) | 6/10 | B (link 3/3) | Closes the B chain; needs 0.4.0's transport and TLSA shape. |
| 4′ | `modular-architecture-and-production-build` (0.6.0) | n/a | G | **Spec 1.0 Final.** No audit/UI behavior change by design; undocumented legacy globals are replaced by a two-member supported facade. Sits between B and C because every spec below it reads or extends output shapes inside `js/dns.js`. |
| 5 | `findings-and-remediation` (0.7.0) | 10/10 | C | Highest end-user value in the roadmap, but structurally the most downstream — it reads the output shapes of 0.3.0, 0.4.0, and 0.5.0. Cannot start for real until B is done. |
| 6 | `report-comparison` (0.9.0) | 4/10 | E | Hard-bound to 0.7.0's finding-id namespace. Last in the signal chain. |
| — | `external-intelligence` | 1/10 | F | No code. Finalize as a **decision document** (mark `1.0 (Final)` as a deliberate refusal per its own `OQ-EXT-04`) whenever convenient — no dependency either direction. |
| — | `excluded-requires-companion-app` | n/a | n/a | No code, ever, in this repo. Documentation only, already recorded. Nothing to schedule. |

**Net effect on wall-clock:** the long pole is 0.2.3 → 0.3.0 → 0.4.0 → 0.5.0 →
0.6.0 → 0.7.0 → 0.9.0, a seven-link sequential chain. The only real parallelism
available is 0.8.0 running alongside links 2–5 of that chain. `external-intelligence`
and the exclusion spec can be closed out by a single agent at any point with no
scheduling coordination.

```
Phase 1        Phase 2                        Phase 3½   Phase 4    Phase 5
0.2.3    ──┬──  0.3.0 → 0.4.0 → 0.5.0   ────►  0.6.0  ──► 0.7.0  ──► 0.9.0
           │                                  refactor
           └──  0.8.0  (starts after 0.2.3, syncs once at 0.7.0's Finding type)

anytime, no coordination:  external-intelligence → Final ; excluded-requires-companion-app already recorded
```

> **The refactor is a serialization point, and that is the cost of scheduling
> it here.** It moves every file the parallel 0.8.0 track will touch. Either
> 0.8.0 finishes and merges before Phase 3½ starts, or it rebases onto `src/`
> afterwards. Landing them concurrently means resolving a rename of the entire
> source tree by hand, which is the one merge this plan should never ask anyone
> to do.

---

## 2. Phase 1 — `rendering-and-robustness` (0.2.3) — **RELEASED**

> **Status, 2026-08-24: released as `v0.2.3`.** Merged via
> [PR #18](https://github.com/kwestic-tech/dns-email-audit/pull/18) (squashed to
> `6bf8bda`). Spec finalized at `1.0`, then amended to `1.3` — defects in the
> spec's own text found during implementation, in internal review, and in
> external review by Codex; each recorded in its Revision history. `npm test`
> 972 assertions / 0 failures, `npm run locale:gate` 13/13,
> `node tools/backtest.mjs --sample --json` diffed against the v0.2.2 baseline
> shows zero grade or score movement across 40 domains. The spec has moved to
> [`docs/specs/implemented/`](specs/implemented/rendering-and-robustness.md)
> with its **As implemented** section.
>
> **Phase 2 (0.3.0) and Phase 3 (0.8.0) are now unblocked** and may run in
> parallel.

**Why first:** everything else in this plan either directly depends on it
(0.3.0, 0.8.0) or transitively does (everything downstream of those two).
This is also the designated pilot for the whole async pipeline — the spec
farthest along, with the least ambiguity and no RFC-transcription risk — so
it's the phase used to validate the process itself before trusting it on the
higher-stakes chain in Phase 2.

**Spec status at handoff:** version `0.3 (Draft, revised after round 2)` — the
furthest along of the eight. Two open questions remained as of 2026-08-24;
**both are now resolved and approved by Ian** (2026-08-24, in conversation
with Claude/Cowork — not yet written into the spec document itself). Apply
these directly rather than re-deriving or re-asking:

- **`OQ-SEC-11` (do sentinels appear in the CSV export, or only the
  interface/HTML report) → resolved as: raw characters stay in the CSV data
  column; add a separate `record_hygiene` column naming what was found (e.g.
  `bidi-override`).** Reasoning: the CSV is the machine-readable export people
  pipe into other tools — silently rewriting a cell's bytes to a sentinel
  string breaks anyone parsing it programmatically, while the new column still
  warns a human reader who opens it in a spreadsheet. Consistent with the
  spec's own "display caps never reach the data" principle: the interface is
  annotated/capped, the export stays faithful. Append `record_hygiene`, never
  insert, per the positional-header backfill rule at `js/app.js:744`.
- **`OQ-SEC-12` (do record-hygiene observations become findings, or stay
  display annotations) → resolved as: stay annotations in 0.2.3, explicitly
  deferred to `findings-and-remediation` (0.7.0).** Reasoning: this release's
  own non-goals rule out a scoring change and any edit to `js/dns.js` for
  grading purposes; turning a hygiene observation into a finding mid-release
  would smuggle a scope change into a release whose entire point is rendering
  correctness. 0.7.0 is where severity gets modeled properly.

**Action:** write these into the spec's **Resolved questions** table (with
"0.2 workflow, approved 2026-08-24" or similar as the resolving context) and
**Revision history**, bump the header to `1.0 (Final)`, then proceed to
implementation. Do not stop to re-confirm these two — they're settled. Stop as
normal for anything this document or the spec doesn't already answer.

**Scope reminder:** DOM-node-building renderer (`js/render.js`), single-pass
`interpolate()`, `sanitizeFragment()` replacing the string round-trip, the
full malformed-record-display table (oversized values, bidirectional
overrides, zero-width characters, control characters, large RRsets), the
dependency-free DOM shim with a setter trap, CSP touch-ups (`img-src`, hash
instead of nonce), and the `README.md` assertion-count correction.

**Non-negotiable acceptance bar (from the spec's own criteria):** no fixture
places a DNS-derived value anywhere but a text node or an allowlisted
attribute; the markup-sink allowlist is empty, enforced by both the shim's
throwing setters and a static scan; grades are byte-identical to `v0.2.2` via
`node tools/backtest.mjs --json` diff; 489+ assertions; 13/13 locales.

**On completion:** move the spec to `docs/specs/implemented/`, add its **As
implemented** section, update the status table in `docs/specs/README.md`, and
tag/reference the release per `CONTRIBUTING.md`'s checklist.

---

## 3. Phase 2 — the protocol-correctness chain (0.3.0 → 0.4.0 → 0.5.0)

This phase is **sequential by construction**, not by convention — see the
evaluation doc's Group B analysis for the three confirmed couplings (shared
fixture-resolver mechanism, transport-type dependency, and a DANE data
dependency that the 0.5.0 spec review resolved by retiring `qualified` rather
than by satisfying it — see 3c). Do not attempt to run these three in parallel; the second
and third literally cannot be implemented against a frozen interface until
the first two exist.

### 3a. `dmarcbis-tree-walk` (0.3.0)

> **Status, 2026-08-25: released as `v0.3.0`.** Merged via [PR #20](https://github.com/kwestic-tech/dns-email-audit/pull/20) (squashed to `8c3a36f`). Spec finalized at `1.1`, then amended to
> `1.2` across four review rounds — one internal, three by Codex. Every
> amendment came from transcribing RFC 9989 and RFC 9990 against the code, and
> all are recorded in the spec's Revision history and **As implemented**
> section. `npm test` 1,189 assertions / 0 failures, `npm run locale:gate` 13/13
> (606/606 keys). Backtested against `v0.2.3`: no DMARC-pillar movement across
> 40 apex domains, one move across 40 subdomains (`www.gov.uk`, F → D, a genuine
> PSL-versus-Tree-Walk divergence). Fan-out measured at 30.4 → 32.0 queries per
> domain and written into `PRIVACY.md`. The spec has moved to
> [`docs/specs/implemented/`](specs/implemented/dmarcbis-tree-walk.md).
>
> **The lesson worth carrying to 3b.** All four rounds found the same failure
> mode: a confident verdict the evidence did not support — a failed lookup
> reported as a missing record, a critical finding raised while a policy
> governed, a destination reported authorized when receivers would send nothing,
> and a remediation example naming an owner no receiver queries. 0.4.0 parses
> `DS`, `DNSKEY` and `TLSA`, where the same mistake reads as "your DNSSEC is
> broken" on a healthy zone. Budget review rounds accordingly.
>
> `OQ-DMARC-03` resolved to a programmable sandbox `fetch`, and the shared
> helper is `tools/lib/doh-fixture.mjs` — **3b and 3c reuse it rather than
> inventing a second mechanism.**
>
> **Phase 2b (0.4.0) is now unblocked.**

**STOP — needs Ian before implementation, not before spec finalization:**
`OQ-DMARC-01` is explicit that the Tree Walk's label arithmetic, query budget,
and long-name handling **must be transcribed from the RFC 9989 text directly**,
not reconstructed from memory or another implementation. If you (the
implementing agent) cannot fetch and read the actual RFC 9989 text, say so
plainly rather than filling in numbers from recall. This is the spec's own
explicit instruction, not an inferred caution.

Six more open questions to resolve during review (`OQ-DMARC-02` through
`-07`) — none block spec finalization the way `OQ-DMARC-01` does, but resolve
all seven before marking `1.0 (Final)`, per the process in section 0.

**Decide `OQ-DMARC-03` (fixture-resolver injection) with the downstream
consumers in mind.** `dns-protocol-depth` and, transitively,
`dnssec-evidence` both reuse whatever mechanism this resolves to. The draft
prefers a programmable `fetch` in the test sandbox with no production code
change — confirm or override, but whichever way it goes, document it clearly
enough that Phase 2b and 2c don't have to re-derive it.

**Key correctness surface:** the Tree Walk replacing the PSL fallback, the
`foundAt`/`labelsUp`/`terminated`/`observed[]` discovery object, the
diagnostic pass distinguishing a misplaced `v=DMARC1` from a genuinely
missing record, `np=` gated on actual domain existence rather than applied
unconditionally, and the three tightenings to `checkExternalReportAuth()`.

**Cross-cutting field to protect:** `foundAt`, `labelsUp`, and `terminated`
are read directly by `findings-and-remediation` (0.7.0, Phase 4) and exported
as schema fields by `report-comparison` (0.9.0, Phase 5). If you rename any of
these during implementation, update both downstream specs in the same pass —
do not leave it for Phase 4/5 to discover.

**On completion:** update `PRIVACY.md`'s stated query-fan-out number with the
measured value from the backtest (the spec's own risk section calls this out
— don't skip it because it feels like documentation rather than code). Move
to `docs/specs/implemented/`.

### 3b. `dns-protocol-depth` (0.4.0)

> **Status, 2026-08-25: released as `v0.4.0`.** Merged via [PR #22](https://github.com/kwestic-tech/dns-email-audit/pull/22) (squashed to `9bda3ad`).
> Spec finalized at `1.0`, then amended to `1.1` — see its **As implemented**
> section. `npm test` 1,813 assertions / 0 failures, `npm run locale:gate` 13/13
> (724/724 keys).
> Backtested against `v0.3.0`: **zero grade movement and zero score movement**
> across the 40-domain sample with the deep checks both off and on, which is the
> expected result here and unlike 0.3.0, where movement was expected and
> explained. Fan-out measured at about 32 queries per domain with the deep
> checks off — unchanged from 0.3.0, `cloudflare.com` issues exactly 43 on both
> — and about 39 with them on, where the same domain issues 59; all of it is
> written into `PRIVACY.md`. The spec has moved to
> [`docs/specs/implemented/`](specs/implemented/dns-protocol-depth.md) with its
> fixtures.
>
> **Budget for far more review than 3a needed.** 0.3.0 took four rounds; this
> took **eight**, and every one found something real. Six were in the DER key
> walk alone, each underneath a boundary the previous round had drawn: accept
> both envelopes → exact bit length → strict structure → strict values → exact
> `e < n` → canonical lengths → odd modulus. The lesson for 3c, which parses
> `DS` and `DNSKEY` records of its own: **a structural check that is locally
> consistent is not finished.** Validate the encoding, then the values, then the
> relationships between them, and expect the next layer to exist.
>
> **The other three rounds found the opposite failure**, and it is the one to
> watch when tightening: validators that rejected *conforming* records. A
> blanket duplicate-field rule contradicted RFC 8461 §3.1 and RFC 8460 §3, which
> require the first entry to win and permit repeated `rua` respectively; an
> FQDN-only URI check refused `https://[2001:db8::1]/r`. Both were caught by
> reading the RFC text rather than reasoning from familiarity — one of them
> after I had drafted a reply declining the finding.
>
> **The 3a lesson held, and cost two corrections.** Both were the same shape it
> warned about — a confident verdict the evidence did not support. The
> `tlsa-published-unsigned` finding, gated on `qualified` as the spec's text
> implies, would have announced "DANE offers no protection here" on **every**
> domain publishing TLSA, a correctly signed zone included, purely because this
> release does not walk the chain; it is now gated on the resolver's AD bit for
> the MX host's own name, which costs no extra query. And the DER walk was
> written SPKI-only, which would have reported a conformant bare PKCS#1 key as
> unparseable because `crypto.subtle.importKey` does not accept that encoding —
> an implementation's input formats standing in for the protocol's rules.
>
> **What 3c inherits.** `dnsTypeNum()` now throws on an unknown type and knows
> `PTR`/`DS`/`DNSKEY`/`TLSA`; `optionalCheck()` re-throws that error rather than
> degrading it to an unknown. `checkTlsa()` records `authenticated` (the AD bit)
> separately from `qualified` (still hardcoded `false`) — 0.5.0 makes the latter
> mean something without having to redefine the former. `tools/lib/doh-fixture.mjs`
> gained the four new types.

**STOP — needs Ian, likely early in implementation:** `OQ-DEPTH-01` requires
someone to capture real DoH JSON responses for `DS`, `DNSKEY`, and `TLSA`
against a signed domain and a DANE-enabled mail host, and attach them to the
spec, before the parsers are written. Do this before writing `parseDs()`,
`parseDnskey()`-adjacent TLSA parsing, or trusting any assumption about
presentation-format vs. escaped/hex encoding. Guessing the shape and fixing it
later is more expensive than capturing it first.

**Also decide before implementation, not silently default:**
- `OQ-DEPTH-02` (Web Crypto vs. DER walk for RSA key size) — the spec leans
  Web Crypto; confirm, given the `crypto.subtle` secure-context caveat for
  `file://` usage that `README.md` currently advertises as supported.
- `OQ-DEPTH-03` (MX health / TLSA on by default vs. behind a toggle) — the
  draft prefers a single combined toggle, on by default, auto-disabled above
  50 domains. This is a product decision with query-volume consequences for
  `PRIVACY.md`; confirm with Ian if the auto-disable threshold feels
  arbitrary.
- `OQ-DEPTH-06` (long-term scoring intent) — the spec explicitly asks for the
  end-state answer now even though it isn't implemented until later. Get the
  answer recorded so `findings-and-remediation` (Phase 4) and any future
  scoring release aren't guessing.

**Key correctness surface:** `dnsTypeNum()` failing loudly instead of
silently returning the TXT type number for unknown types (this is also the
transport dependency 0.5.0 needs), DKIM key decoding via Web Crypto with
explicit RSA/Ed25519/revoked/unparseable states, structured CAA with the
`issue`-vs-`issuewild` semantics called out explicitly in the spec, MX health
(`dangling`, `cname target`, `same-prefix`), and TLSA syntax validation with
`qualified` hardcoded `false` — the field 0.5.0 **retires** rather than completes, see 3c.

**On completion:** confirm zero grade movement via
`node tools/backtest.mjs --json` per the spec's own acceptance criterion 5.
Move to `docs/specs/implemented/`.

### 3c. `dnssec-evidence` (0.5.0)

> **Status, 2026-08-26: release metadata finalized for `v0.5.0` via
> [PR #25](https://github.com/kwestic-tech/dns-email-audit/pull/25).** The tag
> identifies the squashed release commit; the implemented spec records the tag
> rather than a branch-history SHA.

**The spec is `1.5 (Implemented)` as of 2026-08-26 and all open questions are
resolved.** Read it, not this summary, and read
[`docs/specs/fixtures/dnssec-live-states-0.5.0.md`](specs/implemented/fixtures/dnssec-live-states-0.5.0.md)
beside it — the review overturned several things this section used to
prescribe, and the corrections came from measurement rather than argument.

The implementation dependency on 3b's `dnsTypeNum()` change and TLSA shape is
closed: 0.4.0 released first, and 0.5.0 was built against that stable contract.

**Highest-stakes correctness requirement in the whole roadmap:** the RFC 4034
Appendix B key-tag algorithm must match the RFC's own reference values
exactly. An off-by-one produces a false "your DNSSEC is broken" verdict on a
healthy zone, which the spec calls "the most damaging defect this project could
ship." Do not treat the key-tag fixture table as optional coverage — it's the
load-bearing test in this phase. The algorithm was implemented during the spec
review and verified against seven live zones, so the arithmetic is known
tractable; the risk that survives is in the parsers feeding it.

**Three ways to ship that defect, all found during review, all cheap to
avoid:**

1. **Parse an RRSIG as a DS record.** A `do=1` answer returns the RRSIG beside
   the record it signs. Filter on `a.type === 43` and `a.type === 48`. Skip
   this and every signed domain reports `mismatch`.
2. **Lowercase the DNSKEY base64.** `parseTlsaRecord()`'s normalization is
   right for a hex digest and destroys a key. `parseDs()` may reuse it;
   `parseDnskey()` may not.
3. **Let local evidence into the state classifier.** See below.

**Key correctness surface:** the state model is **two axes, not one enum**.
`state` derives from the resolver's AD flag and from what is published;
per-DS digest matching is a separate axis that never reaches `signed`. The
draft ANDed them, and measured against live DNS that flips `paypal.com` — in
the backtest sample, validating, delivering mail, publishing one good DS beside
one orphan — to `mismatch`, costing it 15 points and the A tier. The classifier
is **ordered**, and the order is normative: `dnssec-failed.org` satisfies three
conditions at once. `mismatch` requires positive local proof and is reachable
only when AD is already false, which is what makes "no grade moves" provable
rather than hoped for.

Also in scope: explicit `resolver`-vs-`local` attribution on every claim (the
interface must never assemble a `secure` claim from local evidence alone —
`servfail.nl` is the live proof that it could), and **retiring** `qualified`
from `checkTlsa()`. This section previously prescribed
`qualified = dnssec.state === 'secure' && dnssec.resolverValidated`; that is
**wrong and must not be implemented**. It applies the audited domain's chain
state to a TLSA record in an MX host's unrelated zone, undoing 0.4.0's **As
implemented** item 2, and no arrangement of this release's evidence can make
the field mean more than the per-host AD bit, because local matching never
validates RRSIGs. Each host reports `authenticated: true | false | null`.

**Decided, not open** — `OQ-SEC9-01` warning, `OQ-SEC9-04` resolver stays
fixed, `OQ-SEC9-06` amber via the existing `partial` field, `OQ-SEC9-07`
`qualified` retired. Reasoning is in the spec's Resolved questions; don't
re-litigate.

**Two release artifacts that go stale silently here:** `PRIVACY.md` carries
four *measured* fan-out figures and this release adds two queries per domain —
re-measure, don't do arithmetic. And two existing `locales/en.json` keys change
(`tlsa.publishedNotQualified`, `adv.tip.dnssecOff`), which marks them stale in
all thirteen locales.

**On completion:** assert `dnssec.signed` is unchanged for every backtest
domain against 0.4.0 (spec's own acceptance criterion 6 — zero grade
movement). Move to `docs/specs/implemented/`. **This closes the Group B
chain.**

---

## 4. Phase 3 (parallel with Phase 2, links 2–3) — `local-artifact-validation` (0.8.0)

**Start condition:** as soon as Phase 1 (0.2.3) is merged. Does not need to
wait for any part of Phase 2 — it has no data dependency on DMARC discovery,
DKIM key analysis, or DNSSEC state. Run this as a parallel workstream against
the 0.4.0/0.5.0 links of Phase 2.

**One soft sync point:** section 6 of the spec references "the Finding shape
from 0.7.0" for `artifactFindings`. Since 0.7.0 hasn't been built yet when
this phase starts, define a local stub matching the `Finding` type as
described in `findings-and-remediation.md` section 1, and reconcile the
actual shape once Phase 4 lands. Flag this reconciliation explicitly in the
PR description so it doesn't get missed.

**STOP — this spec's `OQ-ART-08` decides whether it's buildable as
specified.** The zero-dependency testing rule cannot be satisfied for a
hostile-SVG parser the way it was for the DOM renderer in 0.2.3 — there's no
`DOMParser` in Node without a dependency, and a shim can't reproduce entity
expansion or malformed-XML recovery. The spec itself ranks four ways out and
prefers option 3 (a conservative fail-closed tokenizer instead of a real
parser, testable with no dependency). **Get Ian's sign-off on which of the
four options to take before writing the SVG validator** — this changes what
gets built, not just how it's tested.

**Other decisions to make explicit during review, not silently default:**
- `OQ-ART-03` (is the supplied logo ever displayed) — draft says never;
  this is flagged as the single most likely post-release feature request, so
  get it decided deliberately rather than left ambiguous.
- `OQ-ART-05` (does a verified MTA-STS policy earn the withheld scoring
  points) — draft says no, report the finding without changing the score.
  Consistent with the advisory-before-scoring rule in section 0.
- `OQ-ART-07` (do artifact findings appear in the 0.9.0 report export) —
  draft excludes them; this needs to match whatever `report-comparison`
  (Phase 5) actually implements, so confirm the two specs agree before Phase 5
  starts.

**Key correctness surface:** the MTA-STS policy validator (pure string
parsing, the MX-pattern cross-check is the headline feature), the SVG
validator's hard rule that no parsed node is ever inserted into the live DOM
under any code path, and every artifact-derived finding carrying
`source: 'user-supplied'` through the interface and both exports.

**On completion:** verify via the spec's own acceptance criterion 3 — grep
`js/artifact.js` for `fetch`, `XMLHttpRequest`, `Image`, `import(`, `<img`,
and confirm none appear. Move to `docs/specs/implemented/`.

---

## 4½. Phase 3½ — `modular-architecture-and-production-build` (0.6.0)

**Added 2026-08-27; spec 1.0 Final.** Not part of the original eight-workstream
evaluation, and it scores no usefulness points — by design it ships no audit or
UI behavior change. It does intentionally replace undocumented legacy globals
with the supported `DnsAudit.{analyzeDomain,checkConnectivity}` facade.

**Start condition:** Phase 2 fully merged and released (0.3.0, 0.4.0, 0.5.0),
which it is. The spec makes released 0.5.0 the behavioral baseline explicitly,
because a refactor needs a fixed reference and a released tag is the only
honest one.

**Finish condition, and this is the scheduling constraint that matters:**
finish it before Phase 4 starts, and before the parallel Phase 3 track merges.
It renames every source file in the repository. Two branches that both touch
`js/dns.js` cannot both be right afterwards.

**Detailed plan:**
[`Modular Architecture, Production Build Refactor Implementation.md`](../Modular%20Architecture,%20Production%20Build%20Refactor%20Implementation.md)
— six phases, per-phase gates, and the standing verification commands. Read it
rather than re-deriving the sequence; the ordering constraints in it are not
arbitrary.

**Blocking open questions:** none. All nine `OQ-ARCH-*` decisions are resolved
in spec 1.0. Linux `npm ci` and the postinstall policy remain Gate 1 evidence;
they are measurements, not open architecture.

**What this phase must not do**, and the temptation is real because the
architecture makes each of them easy: no concurrency change, no request
deduplication beyond today's cache, no change to existing audit cancellation,
no Web Worker, no
finding-schema redesign, no bundle splitting. Spec §46: a capability is not
implemented merely because the refactor made it possible.

**One correction worth carrying forward from the spec review.** The source
proposal asked for stable machine-readable finding identifiers as though they
did not exist. They do — the token vocabulary is the binding rule in
`js/dns.js`'s header and in section 0.3 of this document. Renaming
`'spf-missing'` to `SPF_LOOKUP_LIMIT`-style constants was **declined**: it would
touch every locale file and every `issue.*` key for no behavioral gain. Any
agent picking up this phase should expect the token vocabulary to come out
byte-identical, and treat a diff in it as a defect rather than progress.

**Key correctness surface:** the three-way equivalence replay — `v0.5.0` `js/`
versus refactored `src/` versus the built `dist/app.min.js` — against a
deterministic fixture corpus. It must be fixtures, not `tools/backtest.mjs`:
that tool queries live DNS, so two of its runs differ because someone else's
records changed. The bundle arm is the one the source proposal left out
entirely, and it is the arm that catches a minifier or tree-shaking fault
before production does.

**On completion:** `js/` is deleted, `AGENTS.md` documents module ownership,
`npm test` is no lower than 2,121 assertions, `npm run locale:gate` is 13/13,
and `PRIVACY.md` needed no edit. Move the spec to `docs/specs/implemented/`.
**This unblocks Phase 4.**

---

## 5. Phase 4 — `findings-and-remediation` (0.7.0)

**Start condition:** Phase 2 fully merged (0.3.0, 0.4.0, 0.5.0). This is the
highest end-user-value spec in the roadmap and also the one with the most
upstream dependencies — do not start the rule registry against
still-changing context fields.

**This is the largest rewrite in the roadmap** by the spec's own admission —
`buildIssues()` is 250 lines of accumulated correctness. The spec's own
mitigation is the right one: build the regression fixture set from the
*existing* `buildIssues()` behavior first, get it passing, and only then
consider the new rule registry done. Carry forward every comment in the
current function onto its corresponding rule — those comments encode
false-positive fixes that must not silently regress.

**Decide before finalizing (these lock in structure other specs will build
against):**
- `OQ-FIND-04` (does `confidence` belong on the finding or the evidence) —
  the spec is explicit that whichever shape this picks, `report-comparison`'s
  schema (Phase 5) freezes around it. Decide this one carefully; it's not a
  low-stakes open question despite reading like one.
- `OQ-FIND-05` (can the `issue.*` → `finding.*` locale-key rename preserve
  translations) — **investigate before committing to the rename.** If
  `tools/locale-sync.mjs` can't express a rename map, ~400 translated units
  across thirteen locales go to `initial` and block the release on
  retranslating work that already exists. The spec's own fallback — keep
  `issue.*` as a historical namespace name — is acceptable if the answer is
  no. Don't attempt the rename speculatively.
- `OQ-FIND-06` (long-term relationship between findings and scoring) — the
  spec asks for the intended end state now even though it isn't implemented
  here. Get this answered so it doesn't drift.

**Key correctness surface:** the declarative `RULES` registry replacing
imperative condition detection, the dependency graph that must be acyclic
(enforced by test — this is exactly why the registry is data, not code), the
`buildRemediationPlan()` topological sort, and the ordering rule that
matters most for the target user: **never recommend DMARC enforcement before
SPF and DKIM authentication is in place.**

**On completion:** confirm scoring is unaffected
(`node tools/backtest.mjs --json` shows zero grade movement against 0.5.0,
per acceptance criterion 5), confirm finding-id sequences are byte-identical
across all fourteen locales (acceptance criterion 4 — this is the property
`report-comparison` depends on for correct cross-language diffing). Move to
`docs/specs/implemented/`. **This unblocks Phase 5.**

---

## 6. Phase 5 — `report-comparison` (0.9.0)

**Start condition:** Phase 4 fully merged. Finding identity (the `id`
namespace from 0.7.0) is a hard prerequisite — the spec is explicit that
comparing on locale keys or message text "would report every finding as new
the moment a translation changed."

**Decide before finalizing:**
- `OQ-CMP-06` (what happens to comparisons across a discovery-only change like
  0.3.0, where scores move with no rubric change) — the draft leans toward a
  single `analysisVersion` replacing `rubricVersion`. **This field cannot be
  repurposed later once reports are in the wild**, so lock it in deliberately
  rather than defaulting.
- `OQ-CMP-07` (do 0.8.0's artifact findings appear in the export) — resolve
  in agreement with whatever Phase 3 actually shipped for `OQ-ART-07`. If the
  two specs disagree, that's a real inconsistency to fix before either merges
  further, not a documentation nit.

**Key correctness surface:** the versioned JSON schema (no display text, only
ids and tokens — this is what makes cross-language comparison possible),
strict import validation (byte limits, array-length limits, nesting-depth
limits, a `JSON.parse` reviver that rejects `__proto__`/`constructor`/
`prototype` keys), and the `incomparable` classification for mismatched
rubric versions or options — the spec is explicit that silently presenting a
phantom regression because DKIM was off in one run is the failure mode this
field exists to prevent.

**On completion:** verify the persistence assertion from the spec's own
testing section — after an import and a comparison, `localStorage` contains
exactly one key (`dns-email-audit-lang`) and `indexedDB.databases()` is
empty. Move to `docs/specs/implemented/`. **This closes the main signal
chain.**

---

## 7. Anytime, no scheduling coordination

**`external-intelligence`:** no code to write. Its own `OQ-EXT-04` asks
whether the document is ever marked Final. The draft position is yes — Final
as a deliberate refusal, so a future proposal argues against a recorded
decision rather than pitching a fresh idea. Resolve its four open questions
(mostly about whether informational links to CT search/etc. are worth
including, and whether the deferral is restated in the interface) and bump to
`1.0 (Final)` whenever convenient. No dependency on anything in Phases 1–5.

**`excluded-requires-companion-app`:** already recorded at `0.1 (Draft)` as of
this handoff. No implementation task exists or will exist against this
document inside this repository. Its only open question (`OQ-APP-01`, whether
a companion app is in scope for the project at all) is explicitly "decide
when there's a reason to decide" — not a blocking item for anything above.

---

## 8. What changed in the repo to produce this handoff

For traceability, since an agent picking this up cold should be able to see
exactly what was touched:

- `docs/specs/excluded-requires-companion-app.md` — new. Records scheduled
  drift monitoring as the first (and currently only) entry in the
  "requires a companion app" exclusion category, structured to hold future
  entries in one place.
- `docs/specs/README.md` — added a note above the Planned table pointing to
  this document for build order, and a new "Excluded — requires a companion
  app" section listing the new spec.
- `ROADMAP.md` — added an addendum section explaining that the release
  sequence is preserved for versioning purposes, while build order for the
  automated pipeline now follows this document.
- `docs/async-development-handoff.md` — this file.

No file under `js/`, `tools/`, `locales/`, or `index.html` was touched. No
spec's Design, Scope, or Non-goals section was edited — only status/ordering
metadata and the two files above.

## 9. Reporting back

Update `docs/specs/README.md`'s status table as each phase's spec moves
Draft → Final → Implemented, per the existing convention. Update this
document's phase markers (or add a short status note at the top) as phases
complete, so a session picking this up later — human or agent — can see
progress at a glance without re-reading every spec's revision history.
