# `src/core/mx/` — API contract

Required by spec [§12](../../../docs/specs/implemented/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** What DNS alone can say about a domain's MX set: whether
each exchange resolves, whether it sits behind a CNAME, how the preferences
are published, how concentrated the addresses are, whether the addresses are
reachable at all, and — since 0.9.2 — what the forward-confirmed reverse DNS of
those addresses evidences about a relationship between the host and a provider
name. It evidences a relationship; it does not establish who owns or operates
the address, which §Non-goals of the spec says explicitly. This directory emits no finding, severity,
score or locale key — `mx-dangling-host`, `mx-single-host` and their siblings
are built by the audit layer from the facts below.

**No SMTP, ever.** Nothing here connects to port 25. Everything is inferred
from DNS, so what is reported is what is published and never what a delivery
attempt would do.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/` | everything else — including `core/dns/`, another protocol directory, `audit/`, `ui/`, `data/` and the platform |

`core/shared/ip.js` supplies `parseIpCidr()` for the block-concentration
grouping and `ipScope()` for address reachability (0.9.1); `core/spf/` reads the
same file for a different question. The resolver is **passed**.

`addressKey()` — the value identity two spellings of one address share — is
**private to this directory**, built from the shared parsers. `core/shared/` is
for value helpers two or more protocol owners read, and MX is the only owner
asking this question; a second owner is what would move it, not the possibility
of one.

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
| `hasNullMxConflict(mx)` | pure | `true` when `0 .` is published **beside a different record**. Two copies of `0 .` are a duplicate, not a conflict, and an MX set that is only `0 .` is a valid null MX. |
| `parseMxRecord(record)` | pure | `10 mail.example.com.` → `{ preference, host, isAddressLiteral }`, host lowercased with the trailing dot dropped; `null` if it is not a record — including `0 .`, whose target is empty once the dot is stripped. |
| `reverseName(address, family)` | pure | The name a `PTR` is asked under: `100.2.0.20` → `20.0.2.100.in-addr.arpa`, and an IPv6 address expanded to all 32 nibbles under `ip6.arpa`. `null` for text that is not an address, validated with the shared parsers rather than a shape test — this is what reaches the resolver, so a malformed name must never be built from it. |
| `MX_HOST_RESOLVES` | frozen array | `yes`, `no`, `unknown`. Registry algebra `mx.host.resolves`. |
| `MX_IPV6_COVERAGE` | frozen array | `none`, `some`, `all`. Registry algebra `mx.ipv6Coverage`. |
| `MX_HOST_REACHABILITY` | frozen array | `global`, `partial`, `none`, `unknown`. Registry algebra `mx.host.reachability` (0.9.1). |

### Factory product

Not an export. `auditMxHosts` is the closure `createMxAudit()` returns, and it
is reachable only through the factory — which is the point: it cannot be called
without someone having named the resolver it runs on.

| Product | Kind | Contract |
| --- | --- | --- |
| `auditMxHosts(mx, domain, queryOpts)` | async | The result below. Never throws for a resolver failure: each host degrades to `resolves: 'unknown'`. |

#### Result — top level

| Field | Since | Meaning |
| --- | --- | --- |
| `hosts[]` | — | One entry per delivery **target**, shape below. |
| `danglingHosts[]` | — | `resolves === 'no'` and not an address literal. A total inbound outage for that target. |
| `cnameHosts[]` | — | The exchange is a CNAME (RFC 2181 §10.3, RFC 5321 §5.1). |
| `duplicatePreferences[]` | — | Preferences published more than once, about the **records** rather than the targets. |
| `singleHost` | — | Exactly one target. |
| `ipv6Coverage` | — | `none` / `some` / `all` over the hosts that resolved. |
| `sharedPrefixes[]` | — | `{ prefix, hosts }` for a /24 or /48 holding more than one target. Hosts that did not resolve are excluded, never counted as not sharing. |
| `unknown` | — | Some host could not be read. |
| `addressLiteralHosts[]` | 0.9.1 | The MX RDATA is an address, not a domain name (RFC 1035 §3.3.9). |
| `unroutableHosts[]` | 0.9.1 | `reachability === 'none'`. |
| `partiallyRoutableHosts[]` | 0.9.1 | `reachability === 'partial'`. |
| `nullMxConflict` | 0.9.1 | `hasNullMxConflict()` over the record set. Computed outside the resolved-host path, so it survives a set where nothing parses into a host. |
| `divergentHosts[]` | 0.9.2 | `{ host, provider, missing[] }` — a forward-confirmed provider publishing addresses this host lacks. |
| `hostsWithoutReverse[]` | 0.9.2 | Hosts where **every** checked address answered and none published a `PTR`. |

#### Result — per host

| Field | Since | Meaning |
| --- | --- | --- |
| `host`, `preference`, `preferences[]` | — | The target, the lowest preference it is published at, and every preference as evidence. |
| `addresses[]`, `v4Count`, `v6Count` | — | The addresses **as published**, not canonicalized: this is the answer, and evidence should read as the zone wrote it. |
| `resolves` | — | `yes` / `no` / `unknown` — see below. |
| `isCname`, `cnameUnknown` | — | The CNAME reading, with its own unknown. |
| `inAudited` | — | The exchange is named inside the audited domain. Gates every 0.9.2 lookup. |
| `isAddressLiteral` | 0.9.1 | Set from the record, never from a failed lookup. |
| `addressScopes[]` | 0.9.1 | `{ address, scope }` per address, `scope` from `ipScope()` and `null` for text that did not parse. |
| `reachability` | 0.9.1 | `global` / `partial` / `none` / `unknown`, over the addresses that **did** parse. An address that could not be classified is excluded rather than assumed reachable. |
| `reverseNames` | 0.9.2 | Three states, below. |
| `providerName`, `providerAddresses[]` | 0.9.2 | Populated **only** after forward confirmation, never before. |
| `missingAddresses[]` | 0.9.2 | `P \ H`, and non-empty only when `H ⊂ P` strictly. |

#### `reverseNames` is three states, not two

| Value | Means |
| --- | --- |
| a non-empty array | those names returned, whatever else failed |
| `[]` | every checked address answered, and none published a `PTR` — the only state that supports the absence advisory |
| `null` | no name returned **and** at least one lookup did not answer |

`null` is not reserved for "every lookup failed": one failure beside one empty
answer is `null` too, because nothing distinguishes that host from one whose
`PTR` never reached the resolver. Unknown is not absent — the same rule that
gives `resolves` three values.

#### An address set is a set of values

De-duplication, forward confirmation and the `H ⊂ P` subset test compare
`addressKey()` identities, not text. `2a01:100::20` and its expanded form are
one address; comparing the strings made them two, which failed confirmation and
reported nothing. First-seen text is preserved for evidence, and the two
families are kept apart: an `AAAA` publishing `::ffff:203.0.113.1` is a
different delivery path from an `A` publishing `203.0.113.1`.

#### And it is a set of **reachable** values

`H` and `P` are taken over globally routable addresses only. The finding is
about missing reachable redundancy, so a provider's private, shared, mapped,
documentation or unparseable value is not something the operator is missing,
and naming it in the remediation would tell them to publish an address
`mx.unroutable` reports as broken. Both sides are restricted, not just the
provider's: an extra private address on the host would otherwise read as
divergence in the other direction and suppress a real missing global one. A host
with no reachable address of its own supports no claim at all, and produces
none.

#### What 0.9.2 costs, and what bounds it

Three caps, set by the privacy review and load-bearing in code: at most two
qualifying hosts per domain, at most four addresses reversed per host, at most
two candidate provider names per domain — twelve additional queries per domain
at the ceiling. Lookups happen only for a host named **inside** the audited
domain that resolved to something reachable, and only through the `optionalCheck`
the caller passed. Whether they happen at all is the audit layer's deep-check
gate; this directory issues what it is asked for and caps it.

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

That paragraph describes the move at 0.6.0 and is kept as the record of it.
The result shape has since grown twice, in `v0.9.1` and in 0.9.2, and this
document is written against the current surface — eight exports and the fields
tabled above — rather than against what was moved.
