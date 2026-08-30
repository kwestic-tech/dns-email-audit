# `src/core/spf/` — API contract

Required by spec [§12](../../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** SPF as RFC 7208 defines it: record status, term parsing,
the ten-lookup accounting, subnet classification and redundancy. The last
protocol owner extracted.

### What it emits, stated accurately

This directory emits no **score** and no **locale key**, and it decides no
user-facing issue. It does emit protocol findings, which spec §12 assigns to
the owning directory:

| Emitted | Shape | Who turns it into user-facing output |
| --- | --- | --- |
| `analyzeSpf().warnings[]` | issue-key tokens such as `spf-softfail`, `spf-multiple-records` | forwarded **verbatim** into `audit/issues.js`'s finding list |
| `classifySpfSubnets().subnets[]` | objects carrying `SPF_LARGE_SUBNET` | `audit/issues.js` and `audit/scoring.js` map them into findings and points |
| `findSpfRedundancy()` | entries carrying `SPF_REDUNDANCY` | as above |
| `classifySpfSubnet()` | `LOW` / `MEDIUM` / `HIGH` | a protocol severity, which audit weights |

These are **protocol facts about the record**, not presentation. Nothing here
looks up prose, computes a grade, or decides what the interface shows — the
tokens are stable identifiers the i18n layer resolves and the audit layer
ranks.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/` | everything else — including `core/dns/`, another protocol directory, `audit/`, `ui/`, `src/data/` and the platform |

`core/shared/ip.js` supplies `parseIpCidr`, `ipv4ToBigInt` and `ipv6ToBigInt`;
`core/mx/` reads the same functions for a different question.

## Public exports

| Export | Kind | Contract |
| --- | --- | --- |
| `selectSpfRecords(txt)` | pure | `{ records, record, multiple }` — which of a domain's TXT records are SPF records, all of them kept as evidence, and whether RFC 7208 §4.5's multiple-record case applies. Moved out of the audit coordinator at Task 5.2a. |
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

## `spfReferencedCatalogKeys()` — SPF-owned, called by audit

`core/dkim/` widens its selector scan using the vendors a domain's SPF record
names. That needs SPF's term grammar, and §12 gives a protocol directory no
edge to a sibling protocol.

**Ruled at Task 4.0, and this is where it lands.** The helper lives here, with
the grammar it reads. [`src/audit/`](../../audit/API.md) — the layer whose job
composition is — calls it and passes the derived catalog KEYS into DKIM.

What must **not** happen:

- a `core/dkim → core/spf` import;
- a second SPF grammar anywhere;
- a copy of `parseSpfTerms()`.

### The injection is retired

Task 4.8 could not put the call in audit, because there was no `src/audit/`
yet. It injected this function into `createDkimCheck()` through the composition
root instead and recorded the arrangement as a **debt, not a design**.

**Task 5.2 paid it.** `core/dkim/` no longer receives this function and no
longer sees an SPF record: its four selector members take `spfCatalogKeys`. The
legacy engine surface still offers the string-taking form through thin
compatibility wrappers in `js/dns.js`, which perform this derivation and
delegate; Phase 6 removes them with that file.

Only the domain's **own** `include:`/`redirect=` hostnames count. Following an
include into its own includes would attribute the vendor's upstream to the
audited domain — freshdesk.com's SPF includes sendgrid.net, which says nothing
about who signs the domain's mail — and would cost DNS lookups this function
deliberately does not make. A macro cannot be reduced to a literal hostname, so
it matches nothing, the same treatment `countSpfLookups()` gives it.

## `startsWithCI` — the duplicate, and why it is gone

This file kept its own three-line copy from Task 4.8. The ruling was Task 4.0's
finding 5: the other reader was `analyzeDomain()`, §12 gives `src/audit/` no
edge to `core/shared/`, and a genuinely audit-local helper stays local —
duplicated if need be — rather than the matrix being amended for one caller.

That was correct while it held. **Task 5.2a removed the premise:** the
coordinator holds no parsing rule, so the record selection moved to the owners,
`audit` stopped being a reader, and the second reader is `providers/`'s
`selectVerifications()`. Two protocol owners is the `core/shared/` admission
test met on its own terms, so the helper now lives in
[`core/shared/record-selection.js`](../shared/record-selection.js) and this
file imports it. The matrix was **not** amended.

## Moved, not redesigned

`js/dns.js`'s SPF blocks, unchanged apart from the two-space dedent, the
`export` keywords, and the resolver-using half becoming the body of a factory.
No lookup count, no classification threshold and no redundancy rule moved with
it; both five-surface equivalence subjects report zero differences.
