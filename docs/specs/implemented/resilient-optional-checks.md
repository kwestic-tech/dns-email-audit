# Spec: A failed optional lookup must not discard the audit

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Implemented) |
| Target release | 0.2.0 |
| Status | Implemented and released |
| Released in | `v0.2.0`, 2026-08-20 |
| Pull request | [#8](https://github.com/kwestic-tech/dns-email-audit/pull/8) |
| Implementation commit | `4070a5b` |
| Merge commit | `e74b47b` |
| Depends on | Nothing |
| Blocks | [wildcard-txt-depth](wildcard-txt-depth.md) and [unproven-controls-scoring](unproven-controls-scoring.md), both of which build on `optionalCheck()` and the unknown-versus-absent distinction established here |
| Slug for open questions | `RESIL` |
| Last updated | 2026-08-20 |

> **Retrospective spec, reconstructed.** Unlike the other documents in this
> directory, this release had no working specification and no handoff file. It is
> reconstructed from the merged diff `4070a5b` and the `0.2.0` changelog. The
> design is therefore stated as the code states it; the **Resolved questions**
> record decisions that are legible in the implementation, not a recovered
> transcript of how they were reached.

## Problem

Every check behind the `www`, `wildcard` and advanced option groups threw on
SERVFAIL. Nothing caught the throw, so the exception unwound the whole
per-domain audit and the entire result was discarded — SPF, DKIM, DMARC, MX and
all — for a domain whose core records had resolved perfectly.

A transient resolver failure on **website-hosting detection** was enough to
delete a complete email-security audit. Across a 200-domain run, hitting that at
least once is close to certain.

Three smaller defects sat behind the same boundary.

**A failed lookup was indistinguishable from a clean negative.** Nothing recorded
whether a check had actually answered, so a CAA lookup that timed out and a
domain with genuinely no CAA record produced the same output.

**The advanced-checks counter counted failures as outstanding work.** A check
whose lookup never completed was neither done nor missing, but the denominator
treated it as missing.

**The DKIM note strings rendered raw placeholders.** `dkim-unverified` and
`dkim-missing` take completed and failed selector counts as `{0}` and `{1}`. The
counts were never passed, so users saw the literal placeholder text — a defect
that was about to become far more visible, since fixing the crash is precisely
what makes failed selector lookups survive to be reported.

## Scope

1. Optional checks degrade to a declared unknown instead of throwing.
2. Unknown is recorded, named to the user, and kept distinct from absent.
3. No advice is given about a check that never ran.
4. Carry the DKIM selector counts through to the renderer.

## Non-goals

- **Core lookups stay fail-closed.** With no usable NS response there is nothing
  to audit, and reporting a failure is better than inventing a result. This
  release deliberately does not extend the wrapper to the core path.
- **No scoring model change.** At this release an unknown check is unscored
  rather than zero. That is revisited one release later — see **As implemented**.

## Design

### `optionalCheck()`, the single wrapper

Every optional check routes through one function
(`js/dns.js:180`):

```js
async function optionalCheck(run, fallback) {
  try {
    return await run();
  } catch (error) {
    if (error && error.name === 'AbortError') throw error;
    return typeof fallback === 'function' ? fallback(error) : fallback;
  }
}
```

Two properties make it safe.

**The fallback declares itself unknown.** A resolver hiccup must degrade one
check, never delete the result — but it must equally never become a quiet
passing or failing verdict. Every fallback marks `unknown: true` so the scorer
can treat it as unscored rather than as a clean zero.

**Cancellation is re-thrown.** `AbortError` propagates instead of being converted
to a fallback, because an aborted audit is not an unknown result. Swallowing it
would make a cancelled run look like a completed run full of failed checks.

### Unknown is named, not omitted

A `checks-unverified` finding lists exactly which checks could not be completed —
CAA, MTA-STS, TLS-RPT, BIMI, SPF lookup depth, and the website check via the new
`@dns-error` hosting state. An audit that quietly omits a control looks identical
to one where the control is fine, so the gap has to be stated rather than left
for the reader to notice.

`@dns-error` ("Lookup failed") is a distinct hosting state from `@no-web`, which
means the domain genuinely has no web presence.

### No advice about a check that never ran

Every recommendation is guarded on the corresponding `unknown` flag: MTA-STS,
TLS-RPT, CAA and DNSSEC are suppressed when their lookup did not complete, and
BIMI is skipped outright. Telling someone to publish a record the tool never
managed to look for is worse than saying nothing.

The advanced-checks counter takes unknowns out of the **denominator** rather than
counting them against the domain:

```js
return { done: checks.filter(Boolean).length, total: 5 - unknown, unknown };
```

### DKIM note arguments

`buildIssues()` carries `noteArgs: [testedCount - failedCount, failedCount]` on
the issue, and `issueMessage()` in `js/app.js` applies them when resolving the
note key, replacing a call that passed no arguments at all.

### A failed probe is not a negative

Each wildcard depth stays `false` until its own probe returns, so a failed probe
is never read as *no wildcard*. This is the same rule as everything above, at the
one place where the fallback value and the negative value would otherwise be
identical.

## As implemented

**1. `unknown` means unscored here, and zero one release later.** This release
established that an unverifiable check must be visible and must not be scored as
a clean negative, and implemented that as *unscored* — which fed the
floor–ceiling range grade. [unproven-controls-scoring](unproven-controls-scoring.md)
then removed ranges and scored unproven controls as zero. The distinction this
release drew survived intact; only its consequence for the number changed.

**2. `checks-unverified` shipped at `info` and was raised to `warn` in #10,**
for exactly that reason: once the gap costs points, naming it is a warning rather
than a note.

**3. `requireUsable()` is the counterpart to the wrapper.** It converts a
non-answering DNS result into a thrown `dnsError` at eight call sites, which is
what `optionalCheck()` then catches on the optional path and what stays uncaught
— deliberately — on the core path. The two functions together are the whole
fail-open/fail-closed boundary.

## Localization impact

Added: `issue.checks-unverified.*` (`msg`, `what`, `fix`, `fixCode`),
`provider.dnsError`, `provider.porkbunForwarding`, `dkim.noteNotFound` and
`dkim.noteNotFoundWithErrors`. Nine locales, plus `js/locales-en.js`.

## Testing

Section 24 of `tools/scoring.test.mjs`, *Resilience: a failed optional lookup
must not discard the audit*. 32 new assertions.

The central fixture is a **simulated resolver in which only the core records
answer and every optional lookup returns SERVFAIL**. The audit must complete,
return a grade, and name every failed check — the exact scenario that previously
returned nothing at all.

Further coverage: each optional check individually failing while the rest
succeed; `AbortError` propagating rather than being converted to a fallback;
`@dns-error` distinguished from `@no-web`; recommendations suppressed for
unknown checks; the advanced counter's denominator shrinking rather than its
numerator; and the DKIM note rendering real counts instead of `{0}`/`{1}`.

## Acceptance criteria

All met at merge.

1. A domain whose core records resolve produces a result no matter how many
   optional lookups fail. ✅
2. Every failed optional check is named to the user rather than omitted. ✅
3. An unknown check is never rendered or scored as a clean negative. ✅
4. Cancelling an audit is never reported as a set of unknown results. ✅
5. No recommendation is issued for a check that did not run. ✅
6. DKIM notes render counts, not placeholders. ✅
7. Core lookups still fail closed. ✅

## Risks

**Fail-open hiding a systematic resolver problem.** If the DoH endpoint degrades,
every domain in a run now returns a result with many checks unverified rather
than returning nothing. That is the right behavior — partial evidence beats no
evidence — but only because the unverified checks are named. The mitigation is
the naming, not the fallback.

**A fallback drifting into a verdict.** The whole design rests on every fallback
carrying `unknown: true`. A future check whose fallback returns a plausible-
looking negative would silently reintroduce the bug this release fixed, with no
test failure. Any new optional check must route through `optionalCheck()` and
declare its unknown.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| `OQ-RESIL-01` | Do core lookups get the same treatment? | No. With no usable NS response there is nothing to audit; reporting a failure beats inventing a result. The boundary is deliberate and is the reason `requireUsable()` throws on both paths while only one catches. | 1.0 |
| `OQ-RESIL-02` | Is a cancelled audit an unknown result? | No. `AbortError` is re-thrown rather than converted, so cancelling never resembles a completed run full of failures. | 1.0 |
| `OQ-RESIL-03` | Does an unverified check count against the domain? | Not in this release — it leaves the denominator entirely. Revisited by [unproven-controls-scoring](unproven-controls-scoring.md), which scores it zero and marks the grade instead. | 1.0 |
| `OQ-RESIL-04` | Should the tool advise on a check that failed to run? | Never. Every recommendation is guarded on the `unknown` flag. Advice about a record the tool never looked for is worse than silence. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-08-20 | Retrospective reconstruction of the shipped 0.2.0 change from `4070a5b` and the changelog. No original spec or handoff existed. |
