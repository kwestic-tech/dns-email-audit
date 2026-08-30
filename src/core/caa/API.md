# `src/core/caa/` — API contract

Required by spec [§12](../../../docs/specs/implemented/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** CAA policy (RFC 8659, RFC 9495): reading a CAA record set
and reporting what it authorizes. This directory emits no finding, severity,
score or locale key — `caa-blocks-all-issuance` and its siblings are built by
the audit layer from the facts below.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/` | everything else — including `core/dns/`, another protocol directory, `audit/`, `ui/`, `data/` and the platform |

The resolver is **passed**, not imported. `createCaaCheck()` names the two
capabilities it needs and can reach no others, which is what lets
`caa.test.js` drive the tree walk over a fake transport with no network and no
`core/dns/` in the graph at all.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `createCaaCheck({ dohFetch, requireUsable })` | factory | Returns the `checkCAA` closure below. Holds no state; two checks over two transports share nothing. |
| `parseCaaRecord(presentationString)` | pure | One record from `<flags> <tag> "<value>"`. Always returns a record; `valid` and `errors` say whether it parsed. |
| `summarizeCaa(records)` | pure | The derived policy: issuers, wildcard issuers, the two blocked flags, `iodef`, `unknownCritical`, `malformed`. |
| `parseCaaIssueValue(value)` | pure | The issuer-domain-name, `''` for a value naming nobody, `null` for one that does not parse. The three are distinct and the distinction is load-bearing. |
| `isCaaIodefUrl(value)` | pure | RFC 8659 §4.4: a `mailto`, `http` or `https` **URL**, via `core/shared/uri.js`. |
| `CAA_KNOWN_TAGS` | frozen array | The six properties. Registry algebra `caa.knownTags`. |
| `CAA_ERRORS` | frozen array | The six error tokens `parseCaaRecord()` can emit. Registry algebra `caa.errors`. |

### Factory product

Not an export. `checkCAA` is the closure `createCaaCheck()` returns, and it is
reachable only through the factory — which is the point: it cannot be called
without someone having named the transport it runs on.

| Product | Kind | Contract |
| --- | --- | --- |
| `checkCAA(domain, queryOpts)` | async | `{ found, records, atDomain }` merged with a `summarizeCaa()` summary. Climbs to the parent (CAA is inherited) and stops before the bare TLD. **Throws** on a resolver failure — see below. |

## The three states of an issuer value

`''`, `null` and a name are three different answers and collapsing any two of
them reports the policy backwards:

| Value | `parseCaaIssueValue` | Meaning |
| --- | --- | --- |
| `letsencrypt.org` | `'letsencrypt.org'` | This CA is authorized. |
| `;` or empty | `''` | **Nobody** is authorized. Issuance is blocked. |
| `%%%%%` | `null` | Does not parse. RFC 8659 §4.2 uses this exact example and requires a CA to treat it as an ABSENT issuer-domain-name — so it blocks too, and reporting it as "authorized: %%%%%" says a domain is open when the RFC says it is shut. |

The same directional care applies to `issuewild`: RFC 8659 §4.3 says wildcard
issuance is governed by the `issue` set when no `issuewild` is present, so an
absent `issuewild` is **not** an open wildcard policy.

## Errors and the transport

`checkCAA()` goes through the passed `requireUsable()`, so three transport
kinds pass and the other seven **throw**. This module states no unknown of its
own. The caller wraps it in `optionalCheck()` with a fallback that copies
`DnsError.kind` onto `advanced.caa.error` — one of the eleven typed
propagation paths in spec §3 — and that copy is made at the call site, by the
caller that owns the shape of its unknown.

This module reads no raw `.kind` and appears on no reader allowlist.

## Why one module

`core/dns/` is four files because it is four layers. CAA is one protocol with
one grammar and one lookup; splitting a fourteen-line tree walk into its own
file would be file count standing in for structure. The owners that genuinely
hold several records split by record, as spec §3's tree already says of
`core/transport/`.

## Deliberately not validated

`contactemail` and `contactphone` are **known tags whose values are not
checked**. Neither affects the derived issuance posture, both are defined by
CA/Browser Forum documents rather than by an RFC this repository otherwise
tracks, and a partial mailbox or telephone parser is far easier to reject
wrongly than to check usefully. A false `caa-malformed` on a real record is
worse than an unvalidated one.

An unquoted value is named (`unquoted-value`) but not fatal: it is still
readable, and every resolver observed quotes it.

## Moved, not redesigned

`js/dns.js`'s CAA block, unchanged apart from the two-space dedent, the
`export` keywords, `checkCAA` becoming the body of a factory that names its
two resolver capabilities, and `Object.freeze` on the two published state
constants. No parsing rule, no walk order and no result shape moved with it;
both five-surface equivalence subjects report zero differences.
