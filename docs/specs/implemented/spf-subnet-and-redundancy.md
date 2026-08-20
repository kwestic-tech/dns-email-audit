# Spec: SPF authorized-range size and a/mx redundancy

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Implemented) |
| Target release | 0.2.0 |
| Status | Implemented and released |
| Released in | `v0.2.0`, 2026-08-20 |
| Pull request | [#11](https://github.com/kwestic-tech/dns-email-audit/pull/11) |
| Implementation commit | `eb3e102` |
| Merge commit | `ef26ca5` |
| Depends on | The SPF lookup counter, already present |
| Blocks | Nothing |
| Slug for open questions | `SUBNET` |
| Last updated | 2026-08-20 |

> **Retrospective spec.** Written after the work shipped, from the original
> working specification and the merged diff. The **As implemented** section is
> the part worth reading: two of the original design decisions were reversed
> during implementation on the evidence of live domains.

## Problem

An SPF record states which hosts may send as a domain. Two things about that
statement went unexamined.

The first is how much address space it authorizes. `ip4:198.51.100.0/24` is 256
addresses that can all send as you, and on shared hosting that is 255 strangers.
Nothing in the audit read the prefix length.

The second is whether a mechanism is buying anything. An `a` or `mx` mechanism
spends one of the ten DNS lookups RFC 7208 §4.6.4 permits. When every address it
resolves to already sits inside an `ip4:`/`ip6:` block written into the same
record, that lookup buys no authorization at all and can be reclaimed. Domains
run out of lookups and hit `permerror`, which fails every message; a redundant
mechanism is one of the more common ways to get back under the ceiling.

## Scope

1. Classify every `ip4:`/`ip6:` mechanism by prefix length, with separate
   threshold tables per protocol.
2. Detect `a` and `mx` mechanisms whose resolved addresses are already covered
   by an `ip4:`/`ip6:` block in the same record.
3. Surface both as advisory findings.

## Non-goals

- **No ownership attribution.** No ASN, WHOIS, Team Cymru or shared-hosting
  detection. Size and redundancy are evaluated independently of who owns the
  block. This is a network destination the tool does not have and will not add.
- **No `include:` traversal.** Only mechanisms present directly in the audited
  record are evaluated. `ptr:` is excluded outright; RFC 7208 §5.5 discourages
  its use.
- **No scoring change.** See `OQ-SUBNET-01`.

## Design

### Size classification

IPv4 is judged on host count, because a subnet of this size is genuinely
allocated to one organization or smaller:

| Prefix | Hosts | Severity |
| --- | --- | --- |
| `/29`–`/32` | 1–8 | Low |
| `/25`–`/28` | 9–128 | Medium |
| `/0`–`/24` | 256+ | High |

IPv6 **must not** reuse that table. RFC 4291 §2.5.4 makes `/64` the standard
single-subnet allocation, frequently one mail server. Host-count reasoning would
rate that same `/64` at eighteen quintillion hosts and flag it hardest of all;
`nih.gov` publishes four of them and they are unremarkable. IPv6 is judged on
allocation tier:

| Prefix | Tier | Severity |
| --- | --- | --- |
| `/128` | Single host | Low |
| `/65`–`/127` | Sub-subnet | Low |
| `/64` | Standard single subnet | Low |
| `/48`–`/63` | Multi-subnet site block | Medium |
| `/0`–`/47` | ISP or RIR scale | High |

A bare `ip4:` is `/32`; a bare `ip6:` is `/128`. A malformed prefix — `/33`,
`/-1`, non-numeric — drops that one mechanism out of the audit rather than
aborting the record.

### Redundancy

Resolve the addresses behind each `a`, `a:host`, `mx` and `mx:host` mechanism,
then test containment against every same-family block in the record. IPv4 is a
32-bit mask comparison. IPv6 is the same logic over 128 bits using `BigInt`,
after expanding `::` into the correct number of zero hextets — naive splitting
on `:` misaligns the address, and `Number` silently loses precision above 53
bits.

**The dual-stack rule governs every verdict.** A mechanism is redundant only if
*both* families are fully covered. A hostname with an `AAAA` record, in a record
carrying no `ip6:` mechanism, is never flagged: the IPv4 side looks fully
covered, and acting on that would silently drop IPv6 authorization. Partial
coverage is reported as an informational note, never as a removal
recommendation — the mechanism is still doing real work.

## As implemented

**1. Findings emit tokens, not English.** The original spec's schema carried
`message` and `action_item` as human-readable strings. That violates the rule
that `js/dns.js` returns identifiers and `js/app.js` turns them into words, and
it would have been unlocalizable. The shipped code emits issue keys with
arguments: `spf-large-subnet`, `spf-medium-subnet`, `spf-redundant-mechanism`,
`spf-redundant-mechanism-nocount` and `spf-partial-coverage`
([`js/dns.js:1628`](../../../js/dns.js)). This is the divergence with the
longest reach, and later specs restate the rule as inherited.

**2. The Low tier is classified but never surfaced.** The spec listed
`/29`–`/32` as an informational finding. Implemented against live domains, that
was wrong: `stanford.edu` publishes 15 `ip4:` mechanisms, 13 of them `/32`, and
a line each saying *this is one host* buries everything worth reading. The Low
tier is still classified and still present in the result object; only its issue
emission is suppressed ([`js/dns.js:1636`](../../../js/dns.js)).

**3. The lookup count is folded into the advice.** The spec asked only that the
two features be sequenced together. The shipped finding names the current count
and the count after removal — 8 lookups to 7 — because the advice is worth much
more next to the number than alone. A separate `-nocount` variant covers the
case where the lookup count itself is unknown, rather than printing a wrong
number.

**4. Redundancy resolution is skipped entirely when no block is present.** Not
in the spec. With no `ip4:`/`ip6:` mechanism, nothing can be contained in one,
so the whole resolution phase is skipped ([`js/dns.js:1197`](../../../js/dns.js))
and records built purely from `include:` — `google.com`, `apple.com`, most of
the sample — cost no DNS at all.

**5. Size classification never touches the network,** and is deliberately
computed before redundancy resolution so a DNS failure during resolution cannot
take the size findings down with it.

## Localization impact

Five new issue keys with their explainers, plus severity labels. All nine
locales shipping at the time.

## Testing

Fixtures cover: bare `ip4:` as `/32`; `/24` as High regardless of other
mechanisms; bare `ip6:` as `/128`; `/64` as Low, explicitly *not* flagged the way
an equivalent-looking IPv4 range would be; `/48` Medium and `/32` High; a bare
`a` inside a block; `a:host` outside every block; three MX records with two
covered and one not, yielding partial coverage and no removal advice; a record
with both families present, confirming no cross-family checking; a record with
no blocks at all; a hostname with `AAAA` and no `ip6:` mechanism, confirming the
dual-stack rule prevents the flag; compressed `2001:db8::/64` verified against
its uncompressed equivalent; and `/33` and `/-1` confirming the parser ignores
the mechanism rather than throwing.

`python.org` is the live redundancy case: its `mx` resolves to exactly the two
addresses its own `ip4:`/`ip6:` mechanisms list.

## Acceptance criteria

All met at merge.

1. IPv4 and IPv6 classified on separate tables, `/64` never flagged as large. ✅
2. Removal recommended only under full dual-stack coverage. ✅
3. Partial coverage reported without a removal recommendation. ✅
4. Malformed prefixes drop the mechanism, not the audit. ✅
5. Advisory only — a before/after backtest across the 40-domain sample showed no
   grade or score movement. ✅
6. No DNS cost on records carrying no `ip4:`/`ip6:` block. ✅

## Risks

**Recommending removal of a mechanism that is still authorizing something.**
The worst outcome this feature could produce is silently dropping IPv6
authorization for a domain that took the advice. Mitigated by the dual-stack
rule, which is the single most important sentence in this document, and by
downgrading anything short of full coverage to an informational note.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| `OQ-SUBNET-01` | Do these checks affect the score? | No. Advisory in v1, backtested to confirm zero movement. Neither threshold had been validated against a real-domain distribution, and a size rule that looks right on paper moves grades in ways nobody predicted. This became the general rule now stated in [`docs/specs/README.md`](../README.md): a new check reports for at least one release before it scores. | 1.0 |
| `OQ-SUBNET-02` | Is a `/32` worth reporting? | No. Classified, never surfaced. Reversed during implementation on the `stanford.edu` evidence. | 1.0 |
| `OQ-SUBNET-03` | Should the finding schema carry English text? | No. Tokens and arguments only. The original schema was unlocalizable. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-08-20 | Retrospective record of the shipped 0.2.0 change, reconciled against `eb3e102`. |
