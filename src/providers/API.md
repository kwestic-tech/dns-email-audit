# `src/providers/` — API contract

Required by spec [§12](../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Names, from records. Which DNS operator serves a zone,
which mail provider an MX set points at, which host answers for the website.
Every answer is a stable token (`@custom`, `@null-mx`, `@no-web`) or a proper
noun passed through untranslated by design.

This directory emits no finding, severity, score or locale key, and decides
nothing about a domain's security posture. A provider name is an input to the
audit's reasoning, never a verdict.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/` | everything else — including any `core/<protocol>/`, `core/dns/`, `audit/`, `ui/`, `src/data/` and the platform |

It imports nothing at all, and takes no capability either.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `selectVerifications(txt)` | pure | The third-party verification records a domain publishes at its apex. Names, from records — the same job as the detectors, which is why it is here and not in `src/audit/`. Moved at Task 5.2a. |
| `detectDNSProvider(ns, domain)` | pure | A vendor name, or `@unknown` / `@custom`. |
| `detectEmailProvider(mx, domain, addressRecords, nullMx)` | pure | A vendor name, or `@null-mx` / `@implicit-mx` / `@none` / `@custom-unknown`. `nullMx` is a derived FACT — see below. |
| `detectHosting(aRecs, wwwCname, domain)` | pure | A host name, or `@no-web` / `@custom`. |

**There is no factory.** Task 4.9 had one for the single injected capability;
Task 5.2 retired that capability, and a factory that injects nothing is a false
statement about what a module needs. Three pure functions, which is what §12's
table said this directory was.

`cap()` is private. One reader, and never an engine member.

## Three ways to have no mail

Reached in that order, and collapsing any two would tell an operator something
they did not publish:

| Answer | Meaning |
| --- | --- |
| `@null-mx` | RFC 7505 `0 .` — an explicit refusal of mail. |
| `@implicit-mx` | No MX, but an address record: RFC 5321 §5.1's implicit MX. |
| `@none` | No MX and no address. |

The null-MX test comes **first**, so a `0 .` domain that also publishes
addresses is not read as implicit MX.

## The null-MX fact, and why it is an argument

`detectEmailProvider()` needs to know whether an MX set is `0 .`, and that
predicate is MX semantics owned by [`core/mx/`](../core/mx/API.md). §12 gives
this directory an edge to `core/shared/` only.

**Ruled at Task 4.0, finding 4; completed at Task 5.2.** Task 4.9 injected
`isNullMx` — the PREDICATE — because the ruling's end state needed an
`src/audit/` that did not exist yet. It exists now, so this directory receives
the derived **fact**: [`src/audit/`](../audit/API.md) computes the boolean once
with `core/mx/`'s own predicate and reads it twice, here and at its deep-check
gate.

`detectors.test.js` proves the edge rather than describing it, and the control
is stronger than the injected predicate's was: the verdict follows the
ARGUMENT rather than the records. `['0 .']` with the fact `false` answers
`@custom-unknown`; `['10 mail.example.test']` with the fact `true` answers
`@null-mx`. Neither would be possible if this module decided for itself.

An omitted fourth argument is `undefined`, which is falsy, so an old
three-argument call never invents a null MX — it simply gets the wrong answer,
which is why the legacy shape is wrapped rather than left to degrade.

### The legacy signature, preserved

`detectEmailProvider(mx, domain, addressRecords)` is a legacy engine member
whose three-argument form is asserted directly by `tools/scoring.test.mjs`. It
survives as a thin compatibility wrapper in
[`tools/lib/legacy-engine.mjs`](../../tools/lib/legacy-engine.mjs), which
derives the boolean and delegates here. It moved there with Task 6.1, when
`js/` was deleted — the harness is where the assertions written against the old
shape live, and it is a test harness rather than application code.
`scoring.test.mjs`'s count did not move.

## Moved, not redesigned

The provider-detection block from the pre-refactor engine, unchanged apart
from the dedent and the `export` keywords. Every pattern, every token and every fallback order is
byte-identical — including the order that matters most, in which the null-MX
test comes FIRST so a `0 .` domain that also publishes addresses is not read as
implicit MX. Both five-surface equivalence subjects report zero differences.
