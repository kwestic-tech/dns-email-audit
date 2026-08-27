# Modular build framework — temporary contract for 0.6.0

**Status:** Temporary. Governs the modular architecture refactor only.
**Supersedes:** nothing. Where it is silent, [`AGENTS.md`](AGENTS.md) applies unchanged.
**Where it conflicts with `AGENTS.md`:** this document wins, **for this branch only**, and every conflict is listed in §7 so none of it happens silently.
**Ends:** at the 0.6.0 release commit, when the parts that proved useful are folded into `AGENTS.md` and this file is deleted.
**Authority:** the spec, [`docs/specs/modular-architecture-and-production-build.md`](docs/specs/modular-architecture-and-production-build.md) `1.0 (Final)`, is binding. This document says *how to work*, not *what to build*. Where they disagree, the spec wins — and the disagreement is a defect to fix, not a preference to exercise.

---

## 1. The three rules everything else serves

**1. The browser works at every commit.** Not every phase — every commit. A
commit that leaves the application broken pending the next one has the wrong
boundary. From Phase 1 onward there is exactly one delivery boundary,
`dist/app.min.js`, and every commit either leaves it working or is not a commit.

**2. Nothing is asserted that has not been executed.** Four mechanism claims in
this project's spec reviews were wrong and all four were cheap to check:
`globalName`'s semantics, the resolver's result algebra, `legalComments`
behavior, and "esbuild has zero transitive dependencies". Before any statement
about how a tool, runtime or API behaves enters code, a commit message, the task
summary or a review document, it is run.

**3. Every check is proven to fail before it is trusted.** A green check nobody
has watched fail is not evidence. This is not theoretical here: the
fixture-identity probe written specifically to catch silent data substitution
would itself have passed silently under substitution, because its four PSL rules
were real PSL rules. [`tools/csp.test.mjs`](tools/csp.test.mjs) already sets the
precedent — its `SINK_CASES` array proves the markup-sink scan catches
`el.innerHTML += x` before the scan is trusted over the source tree. Every new
check ships with the negative case that proves it works.

---

## 2. Work in small pieces

**Decompose until a piece is independently testable.** A piece is the right size
when it can be extracted, tested, and shown equivalent on its own — not when it
is a tidy-looking directory.

- One responsibility per commit. Not one file, not one directory.
- **Never in one commit:** a move *and* a semantics change, a result-schema
  change, a scoring change, a concurrency change, a cache-scope change, or a UI
  behavior change.
- Test each piece as it lands. Do not accumulate untested pieces and integrate
  at the end.
- Pull pieces together for a larger test **only** when the pieces themselves are
  green, or when a piece genuinely cannot be proven alone and says so.

**Two commits get isolated hardest**, because they are where the release breaks
if it breaks:

| Commit | Why | Shape |
| --- | --- | --- |
| Phase 1, `index.html` seven tags → one | The delivery boundary moves; everything after depends on it | That change and nothing else. No config tweak riding along. |
| Phase 2, `js/dns.js` wrapper → ESM | 5,704 lines touched | **Wrapper only, zero code movement.** The diff must read as: remove the IIFE opener, convert the closing export object to named exports, add imports. A moved function in that diff means it was done wrong. |

---

## 3. Verification rhythm

Locale handling differs from `AGENTS.md` for this branch — see §7.

| When | What runs |
| --- | --- |
| **Every commit** | `npm test`; equivalence on the fast surfaces (result projection + DNS query trace) |
| **Every phase gate** | All five surfaces, three-way, through the bundle; `npm run build`; artifact and parity tests |
| **Phase gate, locally** | `node tools/backtest.mjs --sample` — distribution sanity only, live DNS, **never a gate** |
| **Once, before push** | `npm run locale:gate` — must report 13/13 |

**Measure the equivalence runner's cost on day one.** If a full five-surface run
is seconds, it moves to every commit and the fast/full distinction disappears.
Decide that by measuring, not by assuming.

**`check-locales.mjs` stays in `npm test`.** It is the only thing that catches
`js/locales-en.js` drifting from `locales/en.json`, and Phase 2 changes that
file's format. Dropping it would let an i18n break degrade silently to English
and surface phases later.

---

## 4. Validate the oracle before trusting it

The equivalence runner is the instrument everything else is measured with. It is
built and proven **before** any source moves.

1. Run it twice against the same root → byte-identical. Catches nondeterminism
   in the runner itself: map ordering, timestamps, ICU differences.
2. Run it against a **deliberately mutated** copy of `js/` — flip one `WEIGHTS`
   value, reorder one array, change one issue token, drop one DNS query — and
   confirm each mutation is caught, **on the surface that should catch it**.
3. A mutation that passes is a hole in the runner. Fix it before capturing the
   baseline, not after.

Step 2 is what would have caught the `a.b.ck` probe. It is mandatory.

---

## 5. Document as you go

`modular-build-task-summary.md` — untracked, repository root, in
`.git/info/exclude`.

Written **as work happens**, not reconstructed afterwards. Summary style: what
was done, what it proved, what it cost. One entry per commit or per meaningful
step.

```markdown
## <phase> — <task> — <date>
**Commit:** <sha> — <subject>
**Did:** one or two sentences.
**Proved:** which gates ran and what they returned. Real numbers.
**Surprised by:** anything that did not match expectation. Blank is fine; wrong is not.
**Next:** the immediate next step.
```

This file is working material, not a release artifact. It is deleted at push and
PR. `CHANGELOG.md`, `README.md` and the PR description are written **once, at the
end, from the finished state** — never incrementally from this log.

---

## 6. When to stop and ask for a Codex review

**Stop, write the review document, and tell Ian. Do not push through.**

Triggers:

1. **An equivalence diff that cannot be explained within one sitting.** Not
   "investigate and continue" — stop.
2. **A canonicalization tolerance whose admitted difference class cannot be
   bounded.** Spec Risk R11. Widening the rule quietly is the failure mode.
3. **A state in the inventory the fixture corpus cannot reach.** Inventing a
   response shape is worse than saying it cannot be reached.
4. **Anything implying a `PRIVACY.md` edit.** That means DNS fan-out moved,
   which is a published figure.
5. **A spec defect.** `docs/specs/README.md`: a Final spec found wrong is
   amended and re-versioned, never quietly diverged from.
6. **A cross-module change with no architectural explanation** — spec §33's
   leakage signal.
7. **Any proposal to weaken a security control**: the markup-sink allowlist, a
   CSP directive, the namespace contract, the deployment allowlist.

Review documents follow the existing pattern: `CODEX Review <topic>.md` for the
request, `CODEX follow-up review for <topic>.md` for the response, both in
`.git/info/exclude`. State what was verified and how, not just what is claimed.

**Reviewer findings are claims, not facts.** Reproduce every one against the
real code before folding it in — including findings that contradict this
project's own earlier conclusions. Every finding, accepted or declined, is
recorded with its reasoning.

---

## 7. Where this differs from `AGENTS.md`

Listed so no divergence is silent. Everything not listed here is unchanged.

| Topic | `AGENTS.md` | This branch | Why |
| --- | --- | --- | --- |
| `locale:gate` | Passes before the PR opens; implied throughout | **Once, before push.** Not per commit or per build. | Ian's direction. This release adds, changes and removes **no** `locales/en.json` key, so the strict completeness gate has nothing to say until the end. |
| `check-locales.mjs` | Part of `npm test` | Unchanged — stays in `npm test` | It catches `locales-en.js` drift, and Phase 2 changes that file's format |
| Translation work | Part of the same change as an `en.json` edit | **None expected.** If any key changes, the rule reapplies in full and the change is suspect | A refactor that edits `en.json` has exceeded its scope |
| Release artifacts | Written once at the end | Unchanged, and reinforced by §5 | The task summary is not a changelog draft |

**One rule from `AGENTS.md` is load-bearing here and is restated rather than
changed:** the release commit touches its own file set — version bump,
`CHANGELOG.md`, `README.md`, spec status, `ROADMAP.md`, the handoff phase marker
— and **never** a file under `src/`. If a commit touches both, it is two commits.
Six phases give six chances to get this wrong.

---

## 8. Commit, push, review

Unchanged from `AGENTS.md`, restated because a six-phase branch makes them easy
to drift from:

- **Commit locally, freely.** Push is not free and the branch is squashed.
- **Push once**, when the work is tested and reviewed. Open the PR then, not
  before.
- **The merge is Ian's call**, every time. Push, open the PR, say it is ready,
  stop.
- **Tag after the merge**, annotated, on the squashed commit.

---

## 9. Two carried obligations

Neither is in the routine loop, so both are recorded where they will be seen.

**Linux `npm ci` — Gate 1.** The `OQ-ARCH-01` spike measured darwin-arm64 only:
two packages, one `postinstall`, 25 unmet optional platform packages. That is
not cross-platform evidence and must not be presented as such.

**The legacy-globals compatibility delta — Phase 2 and the release.** Removing
the 14 `js/app.js` globals is a **decision**, not a discovery: the search proved
*no repository consumer*, not *no consumer*. A static site can be driven from a
console, an extension, or an embedding page absent from this checkout. It is an
authorized compatibility delta and must appear in the equivalence manifest, the
changelog and the PR body. This is the item most likely to be quietly forgotten
between spec and release.

---

## 10. At the end

The parts of this document that earned their place are folded into `AGENTS.md`,
optimized for the modular production-build architecture — module ownership and
agent modification boundaries (spec §32), the build and artifact contract, the
test layout, and the verification rhythm. Then this file is deleted.

What that revision should capture, on current evidence: the three rules in §1,
the check-must-fail discipline in §4, and the small-pieces decomposition in §2.
What should not survive: the locale exception in §7, which is specific to a
release that touches no keys.
