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

It currently imports nothing at all.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `createDetectors({ isNullMx })` | factory | Returns `{ detectDNSProvider, detectEmailProvider, detectHosting }`. |

### Factory product

| Product | Contract |
| --- | --- |
| `detectDNSProvider(ns, domain)` | A vendor name, or `@unknown` / `@custom`. |
| `detectEmailProvider(mx, domain, addressRecords)` | A vendor name, or `@null-mx` / `@implicit-mx` / `@none` / `@custom-unknown`. |
| `detectHosting(aRecs, wwwCname, domain)` | A host name, or `@no-web` / `@custom`. |

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

## The null-MX collaborator

`detectEmailProvider()` needs to know whether an MX set is `0 .`, and that
predicate is MX semantics owned by [`core/mx/`](../core/mx/API.md). §12 gives
this directory an edge to `core/shared/` only.

**Ruled at Task 4.0, finding 4:** `providers/` receives the null-MX
determination rather than importing `core/mx/`. `isNullMx` therefore arrives as
an injected capability, supplied by the composition root — the same arrangement
`core/dkim/` has for SPF's `spfReferencedCatalogKeys`.

`detectors.test.js` proves the edge rather than describing it: a detector built
over a predicate that never fires cannot produce `@null-mx`, and one built over
a predicate that always fires produces it for any MX set. Neither would be
possible if this module reached for the real one.

### What is still owed

The ruling's end state is audit passing the derived **fact** — a boolean — not
the predicate. That cannot be built here:

- `detectEmailProvider(mx, domain, addressRecords)` is a legacy engine member
  whose three-argument form is asserted directly by `tools/scoring.test.mjs`;
- there is no `src/audit/` to derive the fact in until Phase 5.

Injecting the predicate removes the forbidden **edge** today and leaves every
signature untouched. **Phase 5** extracts audit, derives the boolean there, and
retires this parameter with the same move that retires the SPF collaborator.

## Moved, not redesigned

`js/dns.js`'s provider-detection block, unchanged apart from the two-space
dedent, the `export` keyword, and becoming the body of a factory. Every
pattern, every token and every fallback order is byte-identical; both
five-surface equivalence subjects report zero differences.
