# `src/core/bimi/` — API contract

Required by spec [§12](../../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Deciding whether a string is a conformant BIMI record and
reporting what it says. This directory emits no finding, severity, score or
locale key, performs no lookup, and does not decide whether a domain "has"
BIMI.

## Its own directory

Brand indicators are **not mail transport security**. BIMI says which logo a
receiver may display beside authenticated mail; MTA-STS and TLS-RPT say how
mail is carried. The earlier plan filed BIMI under `core/transport/` and the
spec's tree omitted it entirely — both corrected in round 1, and the separation
is the substance of this task rather than an accident of it.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/` | everything else — including `core/dns/`, another protocol directory, `audit/`, `ui/`, `data/` and the platform |

`parseOrderedFields` and `EXT_NAME` from `core/shared/record-fields.js`,
`isHttpUri` from `core/shared/uri.js`.

## No resolver, and therefore no factory

`core/caa/` and `core/mx/` take a resolver because they do lookups of their
own. This one does not. The `default._bimi` TXT lookup, the
candidate-versus-effective record selection, and the
`present` / `declined` / `advertised` / `multiple` shaping all live in the
audit layer, which is where they were and where Phase 5 will find them.

Inventing a factory so this owner matches its neighbours would be symmetry
standing in for structure.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `validateBimiRecord(record)` | pure | `{ valid, logo, authority, declined, errors }`. Always returns a result; never throws. |
| `BIMI_ERRORS` | frozen array | `invalid-syntax`, `duplicate-tags`. Registry algebra `bimi.errors`. |

`duplicate-tags` is the more specific complaint and **suppresses**
`invalid-syntax` on a record that is both.

## Pinned to a draft, deliberately

BIMI is still an Internet-Draft. This validates
draft-brand-indicators-for-message-identification §4.3 **as of 2026-08**. A
later revision must be a deliberate change here *and* in the fixtures — not
something that drifts in because a reader reached for the newest text.

## Three distinctions the previous validator could not express

| Case | Reading | Why it matters |
| --- | --- | --- |
| `l=` present and **empty** | `valid: true`, `declined: true` | An explicit "we publish no indicator" is conformant. `parsed.tags.l \|\| ''` collapsed it into "missing" and reported a good record invalid. `l=` may be empty; it may not be **absent**. |
| `v=BIMI1` | case-**sensitive**, and **first** | `v=bimi1` and `l=…; v=BIMI1` are both unusable and both validated before. |
| `l=https://example.test/logo.svg` | https + FQDN + SVG suffix | `https://` is a scheme and two slashes. A logo URL needs a real host, and a `.png` is not an indicator. |

## What BIMI adds, and what it does not inherit

`core/shared/uri.js` defaults `httpsOnly` and `requireFqdn` **off**; BIMI is
the protocol that turns both on, for `l=` and `a=` alike. The SVG suffix rule
belongs to `l=` only — a Verified Mark Certificate at `a=` is not an image.

In the other direction, BIMI's pinned grammar does **not** carry MTA-STS's
exclusion of `=` from the extension value class. That is exactly why
`EXT_NAME` moved to `core/shared/record-fields.js` while `RECORD_EXT_VALUE`
stays with `core/transport/`: the extension NAME production is one grammar all
three validators share, the extension VALUE class is not. `bimi.test.js`
asserts `ext=a=b` is legal here, so the difference is executable rather than a
comment.

## Moved, not redesigned

`js/dns.js`'s `validateBimiRecord`, `BIMI_EXT_VALUE` and `BIMI_LOGO_SUFFIX`,
unchanged apart from the two-space dedent and the `export` keyword. `EXT_NAME`
moved to `core/shared/` in the same commit. No validation rule and no result
shape changed; both five-surface equivalence subjects report zero differences.
