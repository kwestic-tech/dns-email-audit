# `src/core/spf/` — API contract

Required by spec [§12](../../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** SPF as RFC 7208 defines it: record status, term parsing,
the ten-lookup accounting, subnet classification and redundancy. This directory
emits no finding, severity, score or locale key.

The last protocol owner extracted.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/` | everything else — including `core/dns/`, another protocol directory, `audit/`, `ui/`, `src/data/` and the platform |

`core/shared/ip.js` supplies `parseIpCidr`, `ipv4ToBigInt` and `ipv6ToBigInt`;
`core/mx/` reads the same functions for a different question.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `createSpfChecks({ dohQuery, dohFetch, requireUsable, cleanAnswerData })` | factory | Returns `{ countSpfLookups, findSpfRedundancy, auditSpfSubnets }`. |
| `analyzeSpf(spf, emailProvider, multiple)` | pure | `{ status, cls, warnings }`. |
| `parseSpfTerms(spf)` | pure | **The only SPF term parser in this repository.** |
| `classifySpfSubnets(spf)` | pure | `{ subnets, blocks }`, blocks separated by family. |
| `classifySpfSubnet(prefix, family)` | pure | `HIGH` / `MEDIUM` / `LOW`, from one of **two** tables. |
| `cidrContains(block, address)` | pure | Prefix-bit comparison. |
| `stripSpfQualifier(raw)` | pure | Removes a leading `+`, `-`, `~` or `?`. |
| `spfReferencedCatalogKeys(spf)` | pure | The DKIM catalog keys a record's own `include:`/`redirect=` names. See below. |

## `permerror` outranks the contents

RFC 7208 §4.5: more than one `v=spf1` record is a permanent error, and SPF then
fails for **all** mail regardless of what either record says. `analyzeSpf()`
reports `permerror` even for a record that would otherwise have been `ok`, and
the test asserts both halves of that.

## Two subnet tables, never one

IPv4 is judged on **host count**: a /24 is 256 addresses and it is unusual for
a sender to control that much space directly.

IPv6 must **not** reuse that table. RFC 4291 §2.5.4 makes /64 the standard
single-subnet allocation, frequently one mail server, while the 2^n reasoning
behind the IPv4 tiers would rate that same /64 as eighteen quintillion hosts
and scream about it. nih.gov publishes four of them and they are entirely
unremarkable — which is the whole argument for a separate table.

`spf.test.js` asserts the consequence directly: **prefix 32 is `HIGH` in IPv6
and `LOW` in IPv4.**

Blocks are kept per family so an IPv4 address is never tested for containment
against an `ip6:` mechanism.

## The raw handle, and where the unknown is shaped

`countSpfLookups()` walks with the raw `dohFetch` and applies `requireUsable`
itself, because it filters by type and keeps only TXT records beginning
`v=spf1`. A **void lookup** — a name that answers with no SPF record — is
counted differently from one that failed, and layer 3 hands back the same empty
array for both.

**This directory states no unknown of its own.** `countSpfLookups()` THROWS on
a resolver failure; the caller's `optionalCheck()` fallback factory is what
copies `DnsError.kind` onto `advanced.spfLookups.queryError`, one of the eleven
typed propagation paths in spec §3. The fallback owns the shape of the unknown.
Asserted as a throw, because the alternative reading would put that shape in
the wrong module.

Counts: `warning` is the 8–10 band, `error` is past 10 **or** more than two
void lookups. They are mutually exclusive at the top of the range, and the test
pins both.

## `spfReferencedCatalogKeys()` — SPF-owned, injected across the root

`core/dkim/` widens its selector scan using the vendors a domain's SPF record
names. That needs SPF's term grammar, and §12 gives a protocol directory no
edge to a sibling protocol.

**Ruled at Task 4.0, and this is where it lands.** The helper lives here, with
the grammar it reads. The composition root imports it and injects it into
`createDkimCheck()`. `checkDKIM()`'s signature is unchanged — still an SPF
record string.

What must **not** happen:

- a `core/dkim → core/spf` import;
- a second SPF grammar anywhere;
- a copy of `parseSpfTerms()`.

**The injection is transitional.** Cross-protocol composition belongs to the
audit layer: Phase 5 derives the catalog keys there and passes the derived
input, after which this export stops being reached across the composition root.
Nothing should be built to depend on the arrangement lasting.

Only the domain's **own** `include:`/`redirect=` hostnames count. Following an
include into its own includes would attribute the vendor's upstream to the
audited domain — freshdesk.com's SPF includes sendgrid.net, which says nothing
about who signs the domain's mail — and would cost DNS lookups this function
deliberately does not make. A macro cannot be reduced to a literal hostname, so
it matches nothing, the same treatment `countSpfLookups()` gives it.

## Its own `startsWithCI`

Three lines, duplicated deliberately. The other reader is `analyzeDomain()` in
the audit layer, and §12 gives `src/audit/` no edge to `core/shared/` — Task
4.0's finding 5, ruled: a genuinely audit-local helper stays local, duplicated
if need be, and the matrix is amended only for a real architectural need. One
protocol owner and one audit reader is not that.

## Moved, not redesigned

`js/dns.js`'s SPF blocks, unchanged apart from the two-space dedent, the
`export` keywords, and the resolver-using half becoming the body of a factory.
No lookup count, no classification threshold and no redundancy rule moved with
it; both five-surface equivalence subjects report zero differences.
