# `src/core/dkim/` — API contract

Required by spec [§12](../../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** DKIM as RFC 6376 defines it: which selectors to try, what a
published key record says, and whether the key material is structurally sound.
This directory emits no finding, severity, score or locale key.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/` | everything else — including `core/dns/`, `core/spf/`, `src/data/`, another protocol directory, `audit/`, `ui/` and the platform |

## Injected capabilities

| Capability | Why it is passed |
| --- | --- |
| `dohFetch`, `requireUsable`, `cleanAnswerData` | §12 gives no edge to `core/dns/`. The RAW handle is required: `inspectDkimSelector()` walks CNAMEs and reads the answer chain, which a normalized array does not carry. |
| `crypto` | The platform's, not the platform. Validation is optional — see below. |
| `dkimSelectorCatalog` | Generated data; §12 gives no edge to `src/data/`. The fixture-identity probes work by substituting it. |
| `spfReferencedCatalogKeys` | **Transitional.** See below. |

## The transitional SPF collaborator

`catalogSelectors()` widens the selector scan using the vendors a domain's own
SPF record names — a `include:` is the domain stating that this vendor sends
mail for it, which is as good a reason to probe that vendor's selectors as MX
is for the inbound provider. Deriving that needs SPF's term grammar.

**Ruled at Task 4.0 and in force here.** DKIM does **not**:

- import `core/spf/` — §12 gives a protocol directory no such edge;
- copy `parseSpfTerms()`;
- grow a second SPF grammar.

So until Task 4.8 creates the SPF owner, `spfReferencedCatalogKeys()` stays
beside the existing SPF parser in `js/dns.js` and arrives here as an argument.

**This is a transitional capability, not the target shape.** Cross-protocol
composition belongs to the audit layer: once `core/spf/` can expose its parsed
references, audit derives the catalog keys and passes the derived input, and
this parameter goes away. Task 4.8 and Phase 5 own that move. Nothing here
should be built to depend on the arrangement lasting.

`checkDKIM()`'s signature is **unchanged** — it still takes the SPF record as a
string — because changing it is the composition decision this task is
explicitly not making.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `createDkimCheck({ … })` | factory | Returns the ten members below. |
| `analyzeDkimKey(txtValue)` | pure | The full key analysis, DER walked without the browser's help. |
| `parseDkimKeyTagList(record)` | pure | `{ tags, duplicates, order, errors }`. Tag names are **not** lowercased — RFC 6376 §3.2 makes them case-sensitive, unlike DMARC's, which is why this is not `core/dmarc/record.js`'s `parseTagList()`. |
| `validDkimSelector(selector)` | pure | The selector name grammar. |
| `DKIM_SELECTORS` | array | The base list tried on every domain. A **reference vocabulary**, not a state algebra — see below. |
| `DKIM_SCAN_BATCH_SIZE` | number | **24, unchanged.** How many selectors are queried at once — see below. |

### Factory product

`checkDKIM`, `catalogSelectors`, `spfSelectorSources`, `buildDkimSelectorList`,
`isRecognizedDkimSelector`, `inspectDkimSelector`, `summarizeDkimKeys`,
`validateDkimKeyStructure`, `dkimKeyRecords`, `dkimRecordSet`.

`dkimKeyRecords` and `dkimRecordSet` **look pure and are not**: both take raw
answers and clean them through the passed `cleanAnswerData`, so they belong to
the factory. Found by running them, not by reading them — a `ReferenceError`
from inside a `.map()`.

## Why `DKIM_SCAN_BATCH_SIZE` is preserved

It bounds **batching, and therefore maximum concurrency**. It does **not**
change how many selector queries an audit makes: `checkDKIM()` slices the same
selector list either way, so the query total is identical at any batch size.
`PRIVACY.md`'s "roughly 41 queries" and 61-for-`cloudflare.com` figures do not
depend on it.

It is preserved for two other reasons, and they are the real ones:

- Phase 4 forbids concurrency changes outright;
- the equivalence trace observes concurrency and batch size directly, so
  changing it moves a surface this refactor is measured against.

## `cryptoValidated` is three answers

| Value | Meaning |
| --- | --- |
| `null` | We did not check. No `crypto.subtle`, or the runtime declined the algorithm, or the key is a bare PKCS#1 that `importKey` has no format for. |
| `true` | Web Crypto accepted it. |
| `false` | Web Crypto rejected an SPKI key it should have been able to read. |

`null` must never collapse into `false`. Silence about our own environment and
a verdict about the operator's key are different sentences.

The `false` case is a **real claim of structural invalidity**, and it carries
consequences the other two do not:

| | `cryptoValidated` | `valid` | `errors` | `keyBits` |
| --- | --- | --- | --- | --- |
| No implementation, or a format `importKey` has no name for | `null` | unchanged | unchanged | unchanged |
| Accepted | `true` | unchanged | unchanged | unchanged |
| **SPKI rejected** | `false` | **`false`** | gains `key-structure-invalid` | **unchanged** |

The DER-derived size survives all three. It was read without the browser's help
and does not become less true because the browser declined to confirm it.

## Revoked is not absent

An empty `p=` is a revocation: the record is **valid**, `revoked` is true, and
`appliesToEmail` is false. Collapsing revocation into a parse failure would
turn a deliberate act into "no DKIM at all" — a worse answer, and the loss of
an existing finding.

The same reasoning covers `s=` scoped to another service and an unrecognized
`k=`: a perfectly good record that is simply not for this purpose.

## Attribution

`spfSelectorSources()` returns a Map from selector to the catalog key that
explains it, and a selector the baseline would have supplied **anyway** is
deliberately absent — it needed no explaining. Set iteration follows SPF term
order, so a selector two referenced vendors share is credited to the one named
first, deterministically.

## `DKIM_SELECTORS` is a reference vocabulary

**Input** vocabulary, not a result algebra. It defines the selector names the
audit TRIES; the selectors a result reports as observed are unbounded, so no
field ranges over it. Its export is also required to reconstruct the
transitional legacy engine surface.

Accepted at Task 4.7 into the closed named inventory in
[`tests/contract/state-matrix.test.mjs`](../../../tests/contract/state-matrix.test.mjs)
— the third instance of the Task 4.5 clarification and the first outside
`core/dmarc/`. No spec amendment required.

## Moved, not redesigned

`js/dns.js`'s DKIM constants, tag parsers, DER reader, key analysis and
discovery, unchanged apart from the two-space dedent, the `export` keywords,
and the capability-using half becoming the body of a factory.
`DKIM_SCAN_BATCH_SIZE` is 24, the CNAME-walk depth is unchanged, and selector
ordering and attribution are byte-identical; both five-surface equivalence
subjects report zero differences.
