# `src/core/shared/` — API contract

Required by spec [§12](../../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Pure value helpers that **two or more protocol owners**
read. Nothing else. This directory emits no finding, severity, score, locale
key or protocol verdict, performs no I/O, and retains no state.

## Allowed edges

| May import | May not |
| --- | --- |
| **nothing** | everything, including a sibling in this directory |

Spec §12's matrix gives `src/core/shared/` no outgoing edges at all. The
sibling case is the one worth stating out loud, because it is the one that
looks harmless: `uri.js` keeps its own IP-literal predicates rather than
importing `ip.js`, and that is not duplication — the two answer different
questions (*is this text a legal URI host* versus *what number is this
address*) and were already two implementations before the move.
[`tests/contract/dns-transport.test.mjs`](../../../tests/contract/dns-transport.test.mjs)
asserts the floor directly, the way it does for `src/platform/` and `src/data/`.

## The admission test (Task 4.0)

A helper belongs here only if all four hold:

1. **Two or more protocol owners call it.** Not two call sites — two owning
   directories. Audit and `providers/` do not count: §12 gives `src/audit/` no
   edge to this directory at all.
2. **Pure.** No resolver, no platform, no generated data, no closure state.
3. **Value-only.** In and out are plain values; it decides no verdict.
4. **The same grammar, not the same policy.** Where callers need different
   constraints, the constraint is an argument the caller passes, and the
   caller keeps ownership of it.

If a helper fails the test it stays with its one owner, even when a sibling
here looks related. Duplication is preferable to a false shared owner.

## Public exports

### `uri.js` — RFC 3986 and RFC 6068 productions

| Export | Kind | Contract |
| --- | --- | --- |
| `isHttpUri(value, opts)` | pure | An `http`/`https` URI. `opts.httpsOnly` and `opts.requireFqdn` both default OFF. |
| `isMailtoUri(value, opts)` | pure | An RFC 6068 `mailtoURI`, including a percent-encoded quoted local part or domain literal. `opts.requireFqdn` defaults OFF. |

Read by `core/caa/` (`iodef`), `core/transport/` (TLS-RPT `rua`) and
`core/bimi/` (`l=`, `a=`) — three owners. The eleven helpers these are built
from are module-private and are covered through them.

**The defaults are load-bearing.** Requiring HTTPS or an FQDN everywhere
rejected conforming TLS-RPT and CAA records. BIMI adds both; nobody else may
inherit them.

### `record-fields.js` — ordered `name=value` records

| Export | Kind | Contract |
| --- | --- | --- |
| `parseOrderedFields(record, opts)` | pure | `[{ name, value }]` in record order, or `null` if any field is not `name=value`. One trailing delimiter is permitted. `opts.strictFieldSyntax` keeps whitespace around `=` inside the field. |
| `EXT_NAME` | regex | `sts-ext-name = (ALPHA / DIGIT) *31(ALPHA / DIGIT / "_" / "-" / ".")`. No `g` flag, so `.test()` retains nothing. |

Read by `core/transport/` (MTA-STS, TLS-RPT) and `core/bimi/` — two owners.

**`EXT_NAME` arrived at Task 4.3, and should have arrived at 4.0.** The Task
4.0 sweep analysed FUNCTION callers mechanically and read the constant list by
eye; a constant used directly by three validators rather than through a moved
helper fell between the two methods. It meets the admission test unchanged —
one production, three call sites, two owners, pure and value-only — so it
moved when BIMI needed it rather than being duplicated.

`RECORD_EXT_VALUE` deliberately did **not** come with it. The extension NAME
production is one grammar all three share; the extension VALUE class is not —
BIMI's pinned draft does not carry MTA-STS's exclusion of `=` — so each owner
keeps its own, and `bimi.test.js` asserts the difference rather than
describing it.

**Order is the contract**, because RFC 8461 §3.1 and RFC 8460 §3 both put the
version field first, and a bare token is a malformed record rather than a
field to drop. `core/dmarc/`'s `parseTagList()` is a *different* reader — it
lowercases names, trims unconditionally, ignores fields without `=`, and
reports duplicates — and stays where it is.

### `ip.js` — address and CIDR arithmetic

| Export | Kind | Contract |
| --- | --- | --- |
| `ipv4ToBigInt(text)` | pure | 32-bit `BigInt`, or `null`. |
| `ipv6ToBigInt(text)` | pure | 128-bit `BigInt`, or `null`. Expands `::` to exactly eight hextets and folds an embedded IPv4 (RFC 4291 §2.2.3). |
| `parseIpCidr(text, family)` | pure | `{ address, prefix, bits }`, or `null`. An absent prefix is a single host; `family` is the caller's declaration, never guessed from the text. |

Read by `core/mx/` (`auditMxHosts()` block concentration) and `core/spf/`
(`classifySpfSubnets()`, `findSpfRedundancy()`) — two owners.

`BigInt` end to end: 128 bits does not fit in a Number, and an IPv6 address
that rounds is wrong in a way no test output makes obvious.

`bigIntToIp()` (MX only) and `cidrContains()` (SPF only) are **not** here.

### `base64.js` — RFC 4648 decoding

| Export | Kind | Contract |
| --- | --- | --- |
| `base64ToBytes(value)` | pure | `Uint8Array`, or `null` for input that is not canonical base64. Never throws. |

Read by `core/dkim/` (`analyzeDkimKey()`, `validateDkimKeyStructure()`) and
`core/dnssec/` (`dnskeyRdata()`, `parseDnskey()`) — two owners.

Hand-written rather than `atob`: `atob` throws where it is absent, and the
caller reads a throw as "this key does not decode", so every DKIM key on every
domain would be reported unparseable in such an environment. Unused pad bits
must be zero (RFC 4648), and only the folding whitespace RFC 6376 §3.2 allows
is removed — a bare LF makes the record malformed and must not disappear.

`bytesToHex()` is not here; `core/dnssec/` is its only reader.

## Considered and rejected

Recorded so a later phase does not reopen a settled question, and so the
directory cannot quietly become a dumping ground.

| Helper | Callers | Why not shared |
| --- | --- | --- |
| `parseTagList` | `core/dmarc/` only | The line in `dkimRecordSet()` that names it is a comment explaining why DKIM does **not** use it. |
| `versionCandidates`, `leadingVersionMatches` | `audit` only | One owner, and audit has no edge here. |
| `startsWithCI` | `core/spf/` + `audit` | One protocol owner. Audit has no edge here, so each keeps its own three lines — applied at Task 4.8, not reopened. |
| `isNullMx` | `providers/` + `audit` | No protocol-owner caller. MX semantics; belongs to `core/mx/`. See finding 4. |
| `cap` | `providers/` only | One owner. |
| `bytesToHex`, `splitRdataFields`, `dnsWireName` | `core/dnssec/` only | One owner. |
| `bigIntToIp` | `core/mx/` only | One owner, even though `ip.js` is next to it. |
| `cidrContains`, `classifySpfSubnet`, `stripSpfQualifier` | `core/spf/` only | One owner. |
| `domainLabels`, `oneLabelBelow` | `core/dmarc/` only | One owner. |
| the `derReadTlv` family | `core/dkim/` only | One owner. |
| `parseSpfTerms` | `core/dkim/` + `core/spf/` | Two owners, but it is **one protocol's grammar**, not shared vocabulary. See finding 1. |

### Findings, and the rulings on them

Task 4.0 moves code; it does not redesign it. Each finding below was reviewed
and ruled on at the Task 4.0 boundary — the ruling binds the later task, so a
future phase inherits a decision rather than an open question.

1. **`core/dkim/` cannot import `core/spf/`.** `spfReferencedCatalogKeys()`
   calls `parseSpfTerms()` to widen the selector list from the SPF record, and
   §12 gives a protocol directory an edge to `core/shared/` only. Putting SPF
   term parsing here would make this directory a place for one protocol's
   grammar, which is the failure mode the admission test exists to prevent.

   **Ruled.** DKIM neither imports `core/spf/` nor grows a second SPF parser.
   Cross-protocol composition is audit's job.

   **Where it stands after Task 4.8.** `spfReferencedCatalogKeys()` is
   SPF-owned, living beside the grammar it reads, and the COMPOSITION ROOT
   imports it and injects it into `createDkimCheck()`. There is no
   `core/dkim → core/spf` edge and no second parser. `checkDKIM()` still
   receives the SPF record as a string.

   That injection is transitional. **Phase 5** replaces the string-taking
   collaborator with audit-derived input — audit parses the references once and
   passes the derived catalog keys — after which the helper stops being reached
   across the composition root.

2. **`core/dmarc/`'s `parseDmarcUriList()` parses `mailto:` by hand** rather
   than through `isMailtoUri()`, with a looser rule — `/^[^\s@]+\.[^\s@.]+$/`
   on the domain. The two disagree about which report destinations are valid.

   **Ruled.** Task 4.6 **preserves DMARC's current, looser behaviour exactly.**
   Reconciliation is outside 0.6.0 unless separately authorized. The
   equivalence instrument DETECTS a behaviour change here; it does not
   authorize one, and a green run is not permission to have made the change.

3. **`{ address, prefix, bits }` is an open value.** Both owners read its
   fields directly — `auditMxHosts()` computes its own network address from
   `.bits` and `.prefix`. Moving the accessors here would not have closed it,
   so it was not a reason to move them.

4. **`isNullMx` belongs to `core/mx/`,** and `providers/` must not import it
   from there.

   **Ruled.** Same shape as finding 1: audit derives the null-MX fact and
   passes it to `providers/`. Task 4.2 gives the predicate its owner; Task 4.9
   takes the derived fact as input.

5. **`src/audit/` has no edge to `core/shared/`.**

   **Ruled.** Do not add one for convenience. A helper doing protocol
   interpretation moves to its protocol owner; a genuinely audit-local helper
   stays local, duplicated if need be. §12's matrix is amended only if a real
   architectural need survives Phase 5 — and that is an amendment, argued on
   its own, not a side effect of an extraction.
