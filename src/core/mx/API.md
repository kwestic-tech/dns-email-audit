# `src/core/mx/` — API contract

Required by spec [§12](../../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** What DNS alone can say about a domain's MX set: whether
each exchange resolves, whether it sits behind a CNAME, how the preferences
are published, and how concentrated the addresses are. This directory emits no
finding, severity, score or locale key — `mx-dangling-host`,
`mx-single-host` and their siblings are built by the audit layer from the facts
below.

**No SMTP, ever.** Nothing here connects to port 25. Everything is inferred
from DNS, so what is reported is what is published and never what a delivery
attempt would do.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/` | everything else — including `core/dns/`, another protocol directory, `audit/`, `ui/`, `data/` and the platform |

`core/shared/ip.js` supplies `parseIpCidr()` for the block-concentration
grouping; `core/spf/` will read the same function for a different question.
The resolver is **passed**.

`bigIntToIp()` is **private**: it renders a network address back to text for
the prefix label and has one internal caller. Its observable contract is
`sharedPrefixes[].prefix`, which is where the tests read it — exporting it so a
unit test could call it directly would widen the API for the test's
convenience.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `createMxAudit({ dohQuery, optionalCheck })` | factory | Returns the `auditMxHosts` closure below. Holds no state; two audits over two resolvers share nothing. |
| `isNullMx(mx)` | pure | RFC 7505: exactly one record, exactly `0 .`. Not an absent MX and not a broken one. |
| `parseMxRecord(record)` | pure | `10 mail.example.com.` → `{ preference, host }`, host lowercased with the trailing dot dropped; `null` if it is not a record. |
| `MX_HOST_RESOLVES` | frozen array | `yes`, `no`, `unknown`. Registry algebra `mx.host.resolves`. |
| `MX_IPV6_COVERAGE` | frozen array | `none`, `some`, `all`. Registry algebra `mx.ipv6Coverage`. |

### Factory product

Not an export. `auditMxHosts` is the closure `createMxAudit()` returns, and it
is reachable only through the factory — which is the point: it cannot be called
without someone having named the resolver it runs on.

| Product | Kind | Contract |
| --- | --- | --- |
| `auditMxHosts(mx, domain, queryOpts)` | async | `{ hosts, danglingHosts, cnameHosts, duplicatePreferences, singleHost, ipv6Coverage, sharedPrefixes, unknown }`. Never throws for a resolver failure: each host degrades to `resolves: 'unknown'`. |

## Three values, not two

`resolves` is `yes` / `no` / `unknown` because **`no` is a total inbound mail
outage**, and it is claimed only when both address lookups actually returned.
One failed lookup beside one empty answer is not evidence of absence.

The consequences are asserted, not assumed:

- an `unknown` host is **never** counted in `danglingHosts`;
- an `unknown` host is left **out** of the block-concentration grouping rather
  than counted as sharing or not sharing a block;
- `cnameUnknown` exists for the same reason on the CNAME lookup.

`optionalCheck` is applied **per host and per record type**, not to the audit
as a whole. A resolver hiccup on one target must not turn the other targets'
answers into an outage report. That is layer 4's policy at a finer grain than
the audit uses it, and it is why this module needs the policy passed rather
than a plain resolver.

## Records versus targets

Two MX records naming the same exchange at different preferences are **one
host**: one point of failure and one set of lookups. Mapping records straight
to audits queried it twice, counted it twice in the CSV, and suppressed
`mx-single-host` on a domain that has exactly one.

Both readings are kept, because they answer different questions:

| Field | About |
| --- | --- |
| `hosts[]`, `singleHost`, `sharedPrefixes` | the delivery **targets** |
| `duplicatePreferences` | the **records** — the preference analysis is about what was published |
| `hosts[].preferences` | every preference one host is published at, kept as evidence |

`hosts[].preference` is the **lowest** of them, because that is the one a
sender reaches first and so the one that describes the target.

## `isNullMx` and the providers ruling

`isNullMx()` is MX semantics, so this directory owns it, and §12 lets
`providers/` import `core/shared/` only.

**Ruled at Task 4.0, and complete since Task 5.2:** `providers/` receives the
DERIVED null-MX fact and does not import `core/mx/`. Task 4.9 injected the
PREDICATE into `createDetectors()` as an interim step — the ruling's end state
needed an `src/audit/` that did not exist yet — and Task 5.2 replaced it with
the fact.

[`src/audit/`](../../audit/API.md) is the only caller now. It derives the
boolean once and reads it twice: `detectEmailProvider()` and its own
deep-check gate. `js/dns.js` importing `isNullMx` is that file's wiring for the
three-argument compatibility wrapper, not the target graph.

## Moved, not redesigned

`js/dns.js`'s MX health block and `isNullMx`, unchanged apart from the
two-space dedent, the `export` keywords, `auditMxHosts` becoming the body of a
factory that names its two resolver capabilities, and the two published state
constants. No lookup, no grouping rule and no result shape moved with it; both
five-surface equivalence subjects report zero differences.
