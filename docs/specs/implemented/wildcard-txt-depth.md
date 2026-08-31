# Spec: Judge a wildcard TXT record at the depth that predicts the harm

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Implemented) |
| Target release | 0.2.0 |
| Status | Implemented and released |
| Released in | `v0.2.0`, 2026-08-20 |
| Pull request | [#9](https://github.com/kwestic-tech/dns-email-audit/pull/9) |
| Implementation commit | `8632875` |
| Merge commit | `b41b50d` |
| Depends on | `optionalCheck()`, added by [#8](https://github.com/kwestic-tech/dns-email-audit/pull/8) |
| Blocks | [unproven-controls-scoring](unproven-controls-scoring.md), which changed how the confidence machinery this release routes into is scored |
| Slug for open questions | `WILDCARD` |
| Last updated | 2026-08-20 |

> **Retrospective spec.** Written after the work shipped, reconciled against
> `8632875` and the working handoff that drove it. It is recorded because the
> reasoning — an RFC 4592 argument and a 15-domain survey — existed nowhere in
> the repository except as a changelog paragraph, and the conclusion it reached
> is the reason two well-known domains stopped scoring F.

## Problem

`apple.com` and `ibm.com` scored **F (0/100)** on the strength of the wildcard
TXT check. Both verdicts were wrong.

The probe queried `_wildcardtest99xyz.<domain>` — **one label** deep. The harm it
inferred was to DKIM discovery, which happens at
`<selector>._domainkey.<domain>` — **two labels** deep. Under RFC 4592 a wildcard
does not synthesize below an existing node, so wherever `_domainkey.<domain>`
exists — true of any domain publishing real selectors — an apex wildcard never
reaches DKIM at all.

The check measured at a depth that does not predict the harm, and then applied
the harshest penalty in the rubric to the result.

`*.apple.com IN TXT "v=spf1 redirect=_spf.apple.com"` is real, served by Apple's
own nameservers, and is a deliberate anti-spoofing measure: mail from an invented
subdomain meets a real SPF policy instead of finding none. Apple's authentication
is otherwise strong — `p=quarantine; sp=reject`, aggregate reporting, SPF with
includes. The tool was scoring a domain zero for a hardening measure.

Measured over 15 major domains:

| Domain | Apex wildcard | `_domainkey` wildcard | Verdict before |
| --- | --- | --- | --- |
| `apple.com` | yes | **no** | F — false positive |
| `ibm.com` | yes | **no** | F — false positive |
| `netflix.com` | yes | **yes** | F — the DKIM harm is real |
| 12 others | no | no | unaffected |

**Two of the three F verdicts in the survey were wrong.**

DKIM is also the only check a wildcard can poison. Every other record type
filters on a version prefix — `v=DMARC1`, `v=STSv1`, `v=BIMI1`, `v=spf1` — so a
stray synthesized string is already discarded. Selector names are unpredictable
and carry no prefix to filter on before the lookup happens.

## Scope

1. Probe both depths and report the one that was actually measured.
2. An apex-only wildcard is informational and costs nothing.
3. A `_domainkey` wildcard routes into the existing DKIM confidence machinery.
4. Retire the blanket instant-F.

## Non-goals

- **No new DKIM machinery.** `confidence: 'sampled'` and `noteWildcard` already
  exist and are already the honest representation of *absence cannot be proven
  here*. This release routes into them; it does not build a parallel path.
- **No change to any other record type's handling.** The version-prefix filters
  are already correct.

## Design

### Two probes, two findings

`_wildcardtest99xyz.<domain>` and `_wildcardtest99xyz._domainkey.<domain>`, run
concurrently. RFC 4592 says a wildcard should not synthesize below an existing
`_domainkey` node, but not every nameserver honours that, **so only the probe is
authoritative** — the rule is the reason to check the second depth, not a
substitute for checking it.

`wildcard-txt-dkim` is a warning; `wildcard-txt-apex` is informational and
affects no score. The blanket `wildcard-txt` critical issue is removed.

### Retiring the instant-F

This is the part that needed sign-off, because it is a scoring-philosophy change
rather than a bug fix. Even for `netflix.com`, where the `_domainkey` wildcard is
real, F=0 was the wrong answer. A poisoned `_domainkey` makes DKIM **absence**
unverifiable. It leaves SPF, DMARC, DNSSEC and CAA perfectly measurable, and
selectors that are genuinely published still resolve and still verify.

Scoring DKIM as unproven and letting the remaining pillars stand is how this
project handles every other uncertainty. A domain does not become unmeasurable
because one pillar became unmeasurable.

### A synthesized value is not a key

A wildcard whose value happens to parse as a DKIM key would otherwise report
DKIM present at every selector tried, which is worse than reporting none. The
records returned by the `_domainkey` probe are carried into `checkDKIM()` and
discarded **by content** wherever they reappear at a selector.

### Failure is not absence

Each depth stays `false` until its own probe returns. A failed probe must never
read as *no wildcard*; `optionalCheck()` handles the conversion to a declared
unknown.

## As implemented

The implementation follows the design. Three details are worth recording.

**1. The synthesized-value filter is carried as a set, not a flag.** `checkDKIM()`
takes `{ dkim, records }` and builds `synthesized` from the probe's actual
records (`js/dns.js:495`), passing it into
`inspectDkimSelector()`. Comparing by content is what makes it safe: a real key
at a real selector is kept even on a domain that has a `_domainkey` wildcard.

**2. `wildcardBug` is gone entirely.** The old flag no longer appears anywhere in
`js/` or `tools/`. It is replaced by `wildcardApex` and `wildcardDkim`, which
travel separately through `buildIssues()` and into the result object.

**3. The interaction with the release that followed.** The handoff proposed
routing a `_domainkey` wildcard into the confidence machinery so it would produce
an *unknown pillar and a grade range*. That was accurate when written. One
release later, [unproven-controls-scoring](unproven-controls-scoring.md) removed
ranges entirely and scored unproven pillars as zero, so the same wildcard now
produces a single grade with DKIM at zero, an asterisk marker, and a
`dkim-unverified` warning naming the selector field. The routing decision made
here survived; only what the machinery does downstream changed.

## Localization impact

`issue.wildcard-txt` retired. Added: `issue.wildcard-txt-apex.*` and
`issue.wildcard-txt-dkim.*` (each with `msg`, `what`, `fix`, `fixCode`),
`labels.wildcardApexTitle`/`Text`, `labels.wildcardDkimTitle`/`Text`, and
`stat.wildcardDkim`. `badge.wildcardBug` removed. Nine locales in the same
change, plus `js/locales-en.js` via `npm run build:fallback`.

## Testing

Section 25 of `tools/scoring.test.mjs`, *Wildcard TXT: apex synthesis vs
synthesis over `_domainkey`*. The pre-existing `wildcard TXT → instant F`
assertion had to be deleted rather than adjusted — it asserted precisely the
behavior being retired.

Fixtures cover: apex-only synthesis producing `wildcard-txt-apex` at `info` with
no score effect; synthesis over `_domainkey` producing `wildcard-txt-dkim` at
`warn` with DKIM routed to `sampled`/`noteWildcard`; a synthesized value that
parses as a DKIM key being discarded by content rather than reported as found;
a real key surviving on a domain that also has a `_domainkey` wildcard; and a
failed probe at either depth staying `false` rather than reading as *no
wildcard*.

`node tools/backtest.mjs --sample` was required before merge, with `apple.com`,
`ibm.com` and `netflix.com` the only domains expected to move. Anything else
moving would have been a regression.

## Acceptance criteria

All met at merge.

1. Both depths probed; the finding reflects the depth actually measured. ✅
2. An apex-only wildcard costs no points. ✅ — `apple.com` and `ibm.com` leave F.
3. A `_domainkey` wildcard routes into `sampled` confidence rather than an
   instant F, leaving SPF, DMARC, DNSSEC and CAA standing. ✅
4. A value synthesized by the wildcard is never accepted as a DKIM key. ✅
5. A failed probe is never read as *no wildcard*. ✅
6. Only the three surveyed domains move in the backtest. ✅

## Risks

**Under-reporting a wildcard that does reach DKIM.** The apex finding is
deliberately toothless, so the whole verdict now rests on the second probe
answering correctly. Mitigated by treating the probe rather than RFC 4592 as
authoritative — nameservers that synthesize below an existing node are exactly
the case the rule would have caused the tool to miss.

**Reduced severity reading as reduced importance.** A `_domainkey` wildcard is
still a real problem for DKIM discoverability. It is now a warning attached to an
unproven DKIM pillar rather than an F, which is a more accurate statement of the
harm, not a smaller one.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| `OQ-WILDCARD-01` | Is RFC 4592 enough, or must the second depth be probed? | Probe it. The RFC says a wildcard should not synthesize below an existing node, but nameserver behavior varies, and the non-conforming case is the one that matters. Only the probe is authoritative. | 1.0 |
| `OQ-WILDCARD-02` | Does a real `_domainkey` wildcard still score F? | No. It makes DKIM absence unverifiable and leaves every other pillar measurable. Scoring DKIM unproven and letting the rest stand matches how every other uncertainty in the project is handled. Flagged at the time as a scoring-philosophy change requiring sign-off, not a bug fix. | 1.0 |
| `OQ-WILDCARD-03` | Should an apex-only wildcard be reported at all? | Yes, informationally. It is often deliberate — Apple's is an anti-spoofing measure — so it is worth surfacing and not worth penalising. | 1.0 |
| `OQ-WILDCARD-04` | Can a wildcard-synthesized value be treated as a DKIM key? | Never. Accepting it would report DKIM present at every selector tried, which is worse than reporting none. Discarded by content, so genuine keys on the same domain survive. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-08-20 | Retrospective record of the shipped 0.2.0 change, reconciled against `8632875` and the working handoff that drove it. |
