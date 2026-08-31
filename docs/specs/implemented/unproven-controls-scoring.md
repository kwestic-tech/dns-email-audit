# Spec: Unproven controls score zero

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Implemented) |
| Target release | 0.2.0 |
| Status | Implemented and released |
| Released in | `v0.2.0`, 2026-08-20 |
| Pull request | [#10](https://github.com/kwestic-tech/dns-email-audit/pull/10) |
| Implementation commit | `4bb7149` |
| Merge commit | `67a2339` |
| Depends on | Nothing |
| Blocks | Nothing |
| Slug for open questions | `RANGE` |
| Last updated | 2026-08-20 |

> **Retrospective spec.** This document was written after the work shipped, from
> the original working specification and the merged diff. It is recorded so the
> reasoning behind a decision that is still binding survives, and so the
> implemented set matches the format of [`docs/specs/`](../README.md). The
> **As implemented** section states where the shipped code differs from what the
> original spec asked for, because in this release the difference is substantial
> and the shipped behavior is the one later specs inherit.

## Problem

When DKIM confidence was `sampled` — no key found among the tested selectors,
but absence not proven — or DNSSEC state was `indeterminate`, `calcScore()`
scored that pillar as `null` and flagged it `unknown: true`. The result was a
floor–ceiling range grade: the floor assumed zero points for the unproven
pillar, the ceiling assumed full points, and the interface displayed both, as
`D–C` or in the worst observed case `B–A+`.

Across a 40-domain live sample, 9 domains — 22.5% — displayed a range. A
two-letter grade reads as an error rather than a result, and it tells the reader
nothing about what to do next. It was also inconsistent with the project's own
parked-domain rubric, which had always scored an unproven pillar as zero.

## Scope

1. Unproven and indeterminate pillars score zero. No ranges anywhere.
2. Remove `gradeMin`, `gradeMax`, `maxPossible` and `uncertain` from the score
   object and from every reader of it.
3. Because uncertainty now costs real points, every unproven control states what
   it cost and how to recover it.

## Non-goals

- **No change to `checkDNSSEC()`.** The `secure` / `insecure` / `bogus` /
  `indeterminate` state machine and the retry-with-checking-disabled step are
  correct as they stand.
- **No change to `checkDKIM()`,** the selector catalogs, or the
  comprehensive-scan cap.
- **No change to `gradeFor()`.** It already took a single `pts` and returned a
  single grade. Only its caller was building a range around it.

## Design

`calcScore()`'s active-domain branch drops the `dkimUnknown` and `dnssecUnknown`
locals and the `null` pillar values with them. `dnssecSigned` already evaluates
false for the indeterminate state, so indeterminate falls through to zero with
no special-casing.

Three call sites in `js/app.js` stop reading the removed fields: the grade tile
subtitle, the sort-and-filter dataset attribute, and the grade cell tooltip.

Two issue messages are rewritten to be actionable rather than reassuring:
`dkim-unverified` names the **Additional DKIM selectors** field and asks for a
re-run; `dnssec-indeterminate` asks for a re-run first, then names the evidence
a GitHub issue would need. Both are raised from `info` to `warn`, consistent
with every other point-costing gap.

A new `dkim-not-checked` note covers the domain audited with DKIM checking
switched off. `buildIssues()` already excluded that case from
`dkim-unverified`/`dkim-missing`, correctly — but under the new scoring it would
otherwise have dropped 15 points in silence, which is worse than the range
behavior being replaced. It is `info`, not `warn`, because it reflects the
user's own choice in this run rather than a misconfiguration.

## As implemented

The shipped change is materially larger than the specification asked for. Three
additions were made during implementation and are now load-bearing.

**1. The `unproven` array and the asterisk marker.** The original spec removed
the range and stopped there, which would have made an unverifiable check
invisible. The shipped code adds `unprovenPillars()`
(`js/dns.js:1725`) and a `score.unproven` array
(`js/dns.js:1807`) naming the pillars a grade is resting
on. `js/app.js:401`–`408` draws that grade with a dashed border in its own tier
colour and appends an asterisk — `B*` rather than `B` — so a recoverable check
is visible while scanning a 200-domain table without expanding a row.

The marker is deliberately display-only. `pts`, `grade` and `cls` are untouched,
and it keeps the tier colour rather than turning amber, because the grade is the
real grade. This is the precedent later specs mean when they say *unknown is not
absent*.

**2. Coverage beyond DKIM and DNSSEC.** The spec addressed two pillars. The
shipped `unprovenPillars()` also covers a failed CAA, MTA-STS, BIMI or TLS-RPT
lookup. This became necessary because
[resilient-optional-checks](resilient-optional-checks.md) had just stopped a
failed optional lookup from discarding the whole audit, which made unverified
optional checks common rather than theoretical.

That release had already added the `checks-unverified` finding
(`js/dns.js:1666`) naming which checks could not be
completed. This release raises it from `info` to `warn`, for the same reason the
other two were raised: the gap now costs points, and a re-run is what recovers
them.

**3. The parked branch changed after all.** The spec stated that the
parked-domain branch was already correct and needed no change. It needed one:
parked domains also carry an `unproven` array
(`js/dns.js:1775`), filtered to the four parked pillars,
because DKIM is not a parked pillar and an unproven DKIM check must not mark a
parked grade.

**4. Localization scope was understated.** The spec named `locales/en.json` and
`locales/es.json`. Nine locales were shipping by then — `de`, `en`, `es`, `fr`,
`it`, `ja`, `ko`, `zh-CN`, `zh-TW` — and the merged commit touched all nine. The
spec was stale on this point, not the implementation. The rule now stated in
[`AGENTS.md`](../../../AGENTS.md) exists so this cannot recur.

## Localization impact

Removed: `score.range`. Rewritten: `issue.dkim-unverified.msg`,
`issue.dnssec-indeterminate.msg`. Added: `issue.dkim-not-checked.*`,
`score.unproven`, `score.pillar.*`. `issue.checks-unverified.*` already existed,
added by [resilient-optional-checks](resilient-optional-checks.md); only its
severity changes here. All nine locales shipping at the time.

## Testing

Section 20 of `tools/scoring.test.mjs` asserted the old behavior and was
rewritten rather than extended. The assertions that a sampled DKIM produced a
range and stored `null` were replaced with assertions that it scores zero,
produces a single-letter grade, and carries no `gradeMin` field. New coverage
was added for indeterminate DNSSEC at the `calcScore()` level, where none had
existed, and for the `not-checked` path.

A repo-wide search for `.uncertain`, `.gradeMin`, `.gradeMax` and
`.maxPossible` was required to return nothing before merge.

## Acceptance criteria

All met at merge.

1. No code path produces a two-letter grade. ✅
2. Unproven DKIM or indeterminate DNSSEC shows a single grade with those
   pillars at zero. ✅
3. `dkim-unverified` names the **Additional DKIM selectors** field. ✅
4. `dnssec-indeterminate` asks for a re-run, then names the three pieces of
   evidence a GitHub issue needs. ✅
5. A domain audited with DKIM checking off raises `dkim-not-checked` and does
   not also raise `dkim-unverified` or `dkim-missing`. ✅
6. Severities: `warn`, `warn`, `info` respectively. ✅
7. `npm test` and `npm run check` pass. ✅
8. `tools/backtest.mjs --sample` confirmed the distribution shift was downward
   only — no domain jumped a tier from this change. ✅

## Risks

**Domains lose points for something the tool could not verify.** Accepted
deliberately, and mitigated by requiring that every unproven control carry an
issue saying what it cost and how to recover it. The asterisk marker was added
during implementation for the same reason.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| `OQ-RANGE-01` | Does an unproven pillar score zero, or stay unscored? | Zero, matching the parked rubric. A range reads as an error and is not actionable. | 1.0 |
| `OQ-RANGE-02` | Is a deliberately skipped DKIM check the same as a failed one? | No. Both score zero, but `not-checked` is `info` and gets its own message, because it reflects the user's choice rather than a misconfiguration. Found during review of the original draft, not in it. | 1.0 |
| `OQ-RANGE-03` | Is scoring an unverifiable control as zero dishonest to the reader? | It would be without a marker. Resolved by adding `score.unproven` and the dashed-circle asterisk during implementation, so the grade is stated as real and its unproven basis is stated too. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-08-20 | Retrospective record of the shipped 0.2.0 change, reconciled against `4bb7149`. |
