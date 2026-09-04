# Spec: MX host address validity and vanity divergence

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | 0.9.1, then 0.9.2 |
| Status | Draft, awaiting review |
| Depends on | 0.9.0 [report-comparison](report-comparison.md) for the observability projection and the `deepChecks` provenance field; [findings-and-remediation](implemented/findings-and-remediation.md) for finding identity |
| Blocks | Nothing |
| Slug for open questions | `MXV` |
| Last updated | 2026-09-04 |

> **Two releases, one document.** The capability is one question — what DNS can
> say about an MX host beyond whether the name resolves — but it splits on a
> hard boundary: 0.9.1 issues no query the audit does not already make, and
> 0.9.2 introduces a new query class. They are specified together because both
> extend the same `auditMxHosts()` result object, and splitting the document
> would duplicate that shape. They are released apart because their risk
> profiles are not comparable. See §0.

## Problem

[`src/core/mx/mx.js`](../../src/core/mx/mx.js) resolves every MX target and reports
eleven findings about the result. Its own docblock states the finding it exists
for: an MX host that does not resolve is a total inbound mail outage that,
before it was checked, read in the interface exactly like a healthy mail domain.

That sentence is still true of four other configurations, because `resolves` is
computed at [`mx.js:180`](../../src/core/mx/mx.js:180) as `addresses.length ? 'yes' : …`
and nothing downstream asks what those addresses are.

**An MX host resolving only to unroutable space reports as healthy.** A host
answering `127.0.0.1`, `10.0.0.4` or `::1` produces `resolves: 'yes'`, no
finding, and a domain that reads as correctly configured. No sending server on
the internet can reach it. A grep of `src/` finds no address-range predicate of
any kind: `parseIpCidr()` in [`src/core/shared/ip.js`](../../src/core/shared/ip.js) does
the arithmetic for `mx.same-prefix` and for SPF prefix sizing, and neither
caller asks about scope. This is the only case in this spec where the tool
states a false negative rather than a true finding with the wrong explanation,
and it is the reason 0.9.1 exists.

**An address literal in the MX RDATA is diagnosed as a missing address record.**
`parseMxRecord()` at [`mx.js:97`](../../src/core/mx/mx.js:97) requires only a numeric
preference and a non-empty remainder, so `10 203.0.113.5` parses to host
`203.0.113.5`. Two lookups are then spent on a name that cannot exist, and the
host surfaces as `mx.dangling`. The severity is right and the remediation is
not: the `mx-dangling` locale entry tells the operator to check the hostname for
a typo and confirm the zone still publishes an address record for it, when the
actual defect is that an MX names a host and never an address. RFC 1035 §3.3.9
defines the RDATA as a `<domain-name>`; RFC 5321 §5.1 requires that name to
have an address record of its own.

**A null MX published beside a real one is diagnosed the same way.**
`isNullMx()` at [`mx.js:64`](../../src/core/mx/mx.js:64) returns `false` whenever
`mx.length !== 1`, which is correct for its own contract and wrong as a whole
account of the record set. A domain publishing both `0 .` and
`10 mail.example.com` is therefore treated as an ordinary mail domain, the `.`
target is looked up, and the contradiction is reported as a dangling host. RFC
7505 §3 requires that a null MX be the only MX record in the set. The operator
is told a host is broken when what is broken is the intent.

**A vanity MX silently loses the redundancy its provider publishes.** Where a
domain points its MX at a name in its own zone whose address record is a
hand-copied snapshot of a hosted provider's, that copy is a fork. It does not
follow the provider's renumbering, and it does not have to contain all of the
provider's addresses. Observed on 2026-09-04, `allremote.com.tw`:

```text
mailfilter.hibox.hinet.net.    316 IN A  210.71.187.212     ; provider, two hosts
mailfilter.hibox.hinet.net.    316 IN A  61.219.36.11
mailfilter.allremote.com.tw.  3158 IN A  210.71.187.212     ; customer, one
```

The customer reaches one of the two mail servers their provider advertises. The
audit reports `mx.single-host` at `info` — technically true, and it names the
wrong cause, because the operator reads it as "my provider gave me one host"
when the provider gave them two. `inAudited` is already computed per host at
[`mx.js:183`](../../src/core/mx/mx.js:183) and is consumed by no finding, so the
discriminator this needs is present and unused.

## Scope

**0.9.1 — address validity.** No new DNS query.

1. Classify every resolved MX address by special-purpose scope, and report a
   host whose addresses are wholly or partly unreachable from the internet.
2. Report an MX RDATA that is an address literal as the distinct defect it is,
   and stop spending two lookups proving that it does not resolve.
3. Report a null MX published alongside other MX records.
4. Reject an MX preference outside the 16-bit range the wire format defines.

**0.9.2 — vanity divergence.** Adds reverse lookups under the existing
deep-check gate.

5. Identify the canonical provider name behind an in-domain MX host by
   forward-confirmed reverse DNS.
6. Report an in-domain MX host whose address set is a strict subset of that
   provider's, naming the addresses that were not copied.
7. Report the absence of reverse DNS for an MX host as an advisory note.

## Non-goals

- **No SMTP, ever.** The rule the module opens with is unchanged. Nothing here
  connects to port 25, and no finding claims what a delivery attempt would do.
- **No vanity-MX finding as such.** A branded MX name that resolves to the
  provider's full, current address set is correct, and is what every Google
  Workspace and Microsoft 365 customer using a CNAME-free branded host looks
  like. Reporting the pattern would fire on a correct configuration and train
  the reader to ignore the check. Only divergence is a finding. See `OQ-MXV-02`.
- **No ownership attribution.** The PTR gives a name, not an operator. No ASN,
  no WHOIS, no registry of hosted mail providers. This follows the precedent
  set by [spf-subnet-and-redundancy](implemented/spf-subnet-and-redundancy.md), whose
  Non-goals excluded the same network destinations for the same reason.
- **No reverse-DNS finding on the sending path.** Reverse DNS matters most for
  the IP that connects outbound, and this tool audits a domain's published
  records, not its egress. The MX-side note in scope item 7 is advisory and
  says so; see the severity argument in §2.3.
- **No TTL findings.** The `allremote` failure mode is a stale copy held at a
  long TTL, and it is not observable here: `dohQuery` normalizes answers to
  string arrays and carries no TTL to any caller. Making TTL visible is a layer
  3 change to the transport contract and is out of scope for both releases. It
  is recorded as a known limitation rather than an oversight.
- **No scoring change in either release.** Both inherit the advisory-before-
  scoring constraint from [the specs README](README.md): a new check reports for at
  least one release before it affects the grade.

## Design

### 0. Why the release boundary falls where it does

0.9.1 reads addresses the audit has already fetched. It adds a pure predicate to
`src/core/shared/ip.js`, four findings, and no query. Its blast radius is the
finding catalog and the state matrix, and it can be reviewed by reading one
function.

0.9.2 adds PTR lookups and a heuristic. The heuristic is the load-bearing part:
it infers "this is my provider's canonical name" from a reverse pointer, which
is a convention and not a guarantee. It roughly doubles the query count for the
MX section on domains that qualify. It deserves its own review and its own
release, and it must not delay four unambiguous correctness findings.

`PTR` is already a supported transport type — [`errors.js:48`](../../src/core/dns/errors.js:48)
lists it in `DNS_TYPES` — so 0.9.2 needs no transport change and no new
architectural edge. `createMxAudit()` already receives `dohQuery` and
`optionalCheck` as arguments, per §12's rule that a protocol directory has no
edge to `core/dns/`. Both releases use what is already injected.

### 1. `ipScope()` — 0.9.1

New export in [`src/core/shared/ip.js`](../../src/core/shared/ip.js), beside
`parseIpCidr()` which it uses for the range arithmetic. Placement follows the
existing import matrix: `core/mx/` already imports from `core/shared/`, and
`core/spf/` will be able to use the same predicate without a new edge.

```js
export function ipScope(address, family)  // → one of IP_SCOPE
```

Registry algebra `ip.scope`, owner `core/shared`, closed:

| Member | IPv4 | IPv6 | Reachable |
| --- | --- | --- | --- |
| `global` | everything not below | everything not below | yes |
| `unspecified` | `0.0.0.0/8` | `::/128` | no |
| `loopback` | `127.0.0.0/8` | `::1/128` | no |
| `private` | `10/8`, `172.16/12`, `192.168/16` | `fc00::/7` | no |
| `link-local` | `169.254.0.0/16` | `fe80::/10` | no |
| `shared` | `100.64.0.0/10` | — | no (`OQ-MXV-04`) |
| `documentation` | `192.0.2/24`, `198.51.100/24`, `203.0.113/24` | `2001:db8::/32` | no |
| `benchmarking` | `198.18.0.0/15` | `2001:2::/48` | no |
| `multicast` | `224.0.0.0/4` | `ff00::/8` | no |
| `reserved` | `240.0.0.0/4`, `255.255.255.255/32` | — | no |
| `v4-mapped` | — | `::ffff:0:0/96` | no |

The registry is RFC 6890 and the IANA special-purpose address registries it
establishes. `v4-mapped` is separated from `reserved` because an AAAA record
holding `::ffff:203.0.113.5` is a specific and recognisable authoring mistake,
and telling the operator that is more useful than telling them the address is
reserved.

`global` is the default rather than an enumeration, so an address in a range
added to the registry after this ships is reported as reachable rather than as
a finding. That direction of error is the safe one: this check must never
invent an outage.

### 2. MX result-shape changes

Both releases extend the object `auditMxHosts()` returns. Every field added is
optional in the sense that a host the resolver could not read carries the
module's existing third value rather than a claim — the discipline `resolves`
already follows and the reason it has three members and not two.

#### 2.1 Per host — 0.9.1

```js
{
  …existing fields,
  isAddressLiteral: boolean,      // RDATA was an address, not a name
  addressScopes: [                // one entry per address in `addresses`
    { address: string, scope: string }   // scope ∈ IP_SCOPE
  ],
  reachability: 'global' | 'partial' | 'none' | 'unknown',
}
```

`reachability` is registry algebra `mx.host.reachability`, closed, and is
derived rather than looked up:

- `unknown` when `resolves !== 'yes'`. An address set we could not read supports
  no claim about scope, and this keeps the new field from contradicting the old
  one.
- `none` when every address is non-`global`. The host is unreachable.
- `partial` when at least one address is `global` and at least one is not.
- `global` when every address is `global`.

`partial` is a real and distinct state, not a rounding of `none`. A host with
one routable and one private address accepts mail most of the time and stalls
whichever senders select the unroutable one, which is the harder fault to
diagnose from the outside and the reason it is not folded into either
neighbour. Its severity is `OQ-MXV-01`.

#### 2.2 Per host — 0.9.2

```js
{
  …0.9.1 fields,
  reverseNames: string[] | null,  // null when the PTR lookup did not return
  providerName: string | null,    // forward-confirmed canonical name, if any
  providerAddresses: string[] | null,
  missingAddresses: string[],     // provider set minus this host's set
}
```

#### 2.3 Top level

```js
{
  …existing fields,
  // 0.9.1
  addressLiteralHosts: string[],
  unroutableHosts: string[],       // reachability === 'none'
  partiallyRoutableHosts: string[],
  nullMxConflict: boolean,
  invalidPreferences: number[],
  // 0.9.2
  divergentHosts: [ { host, provider, missing: string[] } ],
  hostsWithoutReverse: string[],
}
```

### 3. Parser changes — 0.9.1

`parseMxRecord()` gains two rejections and one classification. Its return shape
gains `isAddressLiteral`; existing callers reading `preference` and `host` are
unaffected.

**Address literal.** A target is an address literal when it parses as an IPv4
dotted quad or contains a colon. Both tests are safe: the DNS root delegates no
all-numeric top-level domain, so a name that parses as a dotted quad cannot be
a hostname, and a colon cannot appear in one. A host so classified skips its A,
AAAA and CNAME lookups entirely — they are three queries per host spent proving
something the RDATA already stated — and reports `resolves: 'no'` with
`isAddressLiteral: true`.

Whether the host then also raises `mx.dangling` is `OQ-MXV-05`. The draft
position is that it must not: two findings for one defect, one of which
prescribes the wrong fix, is worse than the single finding this release adds.

**Preference range.** RFC 1035 §3.3.9 defines the preference as a 16-bit
unsigned integer. The current guard is `/^\d+$/`, which accepts `99999`. Values
above 65535 are collected into `invalidPreferences` and the record is otherwise
processed normally — the host is still resolved and still audited, because a
bad preference is a hygiene defect and not a reason to stop looking at the
host.

**Null MX conflict.** A new predicate, beside `isNullMx()` and not inside it:

```js
export function hasNullMxConflict(mx)   // any record is `0 .` AND mx.length > 1
```

`isNullMx()` is **not** changed. Its `mx.length !== 1` guard is load-bearing in
three places — the `src/audit/` deep-check gate, provider detection via
`@null-mx`, and the MTA-STS `policy-on-null-mx` finding at
[`artifacts.js:341`](../../src/audit/artifacts.js:341) — and every one of them wants the
current meaning, which is "this domain has declared it receives no mail". A
domain with a contradictory set has declared nothing coherent, so it correctly
fails that predicate and correctly raises this one. When `hasNullMxConflict()`
holds, the `.` pseudo-target is excluded from `targets` and never looked up.

### 4. Divergence detection — 0.9.2

Runs only where all four hold: `inAudited === true`, `resolves === 'yes'`,
`reachability !== 'none'`, and the deep-check gate is on. It produces at most
one finding per host.

Per qualifying host:

1. **Reverse.** `PTR` on each of the host's addresses, capped at the first four,
   each through `optionalCheck` per address. A lookup that does not return
   leaves `reverseNames: null` and ends the procedure for that host — never a
   claim of absence.
2. **Candidate.** Take the first returned name that is neither the MX host
   itself nor a name under the audited domain. A PTR pointing back into the
   audited zone means there is no separate provider name to compare against,
   which is the self-hosted case and is not a finding. Cap at two distinct
   candidates per domain.
3. **Forward-confirm.** Resolve the candidate's A and AAAA. If the address the
   PTR came from is absent from that set, the pointer is not forward-confirmed
   and the procedure stops. **This gate is the whole basis for trusting the
   name**: a PTR is authored by whoever holds the reverse zone, which for hosted
   mail is the provider, but nothing forces it to name a service. FCrDNS is the
   standard test — the one large receivers apply to sending IPs — and without
   it this check would report divergence against an arbitrary string.
4. **Compare.** With `H` the host's address set and `P` the confirmed
   provider's: report when `H ⊂ P` strictly. `missingAddresses` is `P \ H`.
   `H = P` is the correct vanity configuration and produces nothing. `H ⊄ P`
   means the two names have diverged in both directions, which is not this
   finding and is left alone; see `OQ-MXV-06`.

**Query budget.** Per qualifying host: up to 4 PTR, plus 2 per candidate name,
so a bounded worst case of 8 additional queries per host and 4 candidate
resolutions per domain. On the common shape — one in-domain MX host with one
address — it is 3. The gate keeps this off the default path entirely.

**Why the deep-check gate and not a new one.** MX already sits behind it, DANE
already extends it at [`audit-domain.js:347`](../../src/audit/audit-domain.js:347),
and 0.9.0 makes `deepChecks` part of report provenance precisely so that a
report run without it is not compared as though the protocol were observed.
Putting 0.9.2 behind the same flag means the comparison release handles it
correctly with no further work. A separate flag would need its own provenance
field and its own comparability rule.

### 5. Findings

Registered in [`src/audit/findings.js`](../../src/audit/findings.js) and raised from
[`src/audit/issues.js`](../../src/audit/issues.js) beside the existing `mx-*` block at
lines 532–546.

| Release | Key | Id | Severity | Category | Effort |
| --- | --- | --- | --- | --- | --- |
| 0.9.1 | `mx-unroutable` | `mx.unroutable` | critical | transport | moderate |
| 0.9.1 | `mx-partially-routable` | `mx.partially-routable` | medium (`OQ-MXV-01`) | transport | moderate |
| 0.9.1 | `mx-address-literal` | `mx.address-literal` | critical | transport | trivial |
| 0.9.1 | `mx-null-conflict` | `mx.null-conflict` | medium | hygiene | trivial |
| 0.9.1 | `mx-invalid-preference` | `mx.invalid-preference` | info | hygiene | trivial |
| 0.9.2 | `mx-vanity-divergent` | `mx.vanity-divergent` | medium | resilience | moderate |
| 0.9.2 | `mx-no-reverse-dns` | `mx.no-reverse-dns` | info | resilience | moderate |

`mx.unroutable` is critical for the same reason `mx.dangling` is: where it is
the only host, the domain receives no mail. `mx.address-literal` is critical
because it is the same outage; it is `trivial` effort because the fix is one
record.

`mx.no-reverse-dns` is `info` and must stay `info`. RFC 5321 §4.1.4 states that
a failed reverse lookup **SHOULD NOT** on its own be grounds for refusing mail,
and the receiving path is not where reverse DNS is enforced in practice. Raising
it higher would misrepresent a hygiene note as a delivery risk, on the protocol
side where it matters least.

### 6. Evidence

All seven findings emit `host` evidence, already an `EVIDENCE_KINDS` member at
[`findings.js:72`](../../src/audit/findings.js:72), except `mx-null-conflict` and
`mx-invalid-preference`, which emit `mx` evidence because the defect is in the
record rather than in the host. `mx.unroutable` and `mx.partially-routable`
carry the offending address and its scope in their arguments, so the report
states which address is unreachable and why, not merely that one is.

## Localization impact

Seven new entries in `locales/en.json` under the existing findings block, each
with `msg`, `what` and `fix`; `fixCode` on `mx-address-literal`,
`mx-null-conflict` and `mx-vanity-divergent`, where a zone fragment is clearer
than a sentence. Five ship in 0.9.1 and two in 0.9.2, each with its own release.

Per the inherited constraint, each release translates all thirteen other locales
in the same change, runs `npm run build:fallback`, and passes
`npm run locale:gate`. `src/data/locales-en.js` is regenerated in the same
commit.

Two drafting notes for the `what` text:

- `mx-vanity-divergent` must not assert that the named provider *is* the
  operator. The evidence is a forward-confirmed reverse pointer, and the wording
  says that: the addresses reached from this host's reverse name include ones
  this host does not publish.
- `mx-no-reverse-dns` must state the RFC 5321 §4.1.4 position rather than imply
  that inbound mail is at risk, and should distinguish the receiving path from
  the sending path, which is where the reader has probably heard the rule.

## Testing

Unit, in `src/core/shared/ip.test.js`:

1. `ipScope()` against a table of at least two addresses per algebra member,
   both families, including the boundary address at each end of every range.
2. Addresses immediately outside each range classify as `global`.

Unit, in `src/core/mx/mx.test.js`:

3. `reachability` for each of its four members, including `partial` from a
   mixed set and `unknown` from a host that did not resolve.
4. An address-literal target in both families: classified, not looked up, and
   raising exactly one finding. The "not looked up" half is asserted against a
   stub resolver that records its calls — a spec that says three queries are
   saved and does not assert it will regress silently.
5. `hasNullMxConflict()` true for `0 .` beside a real host, false for a lone
   `0 .`, false for a normal set; and `isNullMx()` unchanged on all three.
6. Preferences at 0, 65535 and 65536.
7. 0.9.2: divergence reported for a strict subset; not reported for an equal
   set; not reported when forward confirmation fails; not reported when the PTR
   points back into the audited domain; `unknown` rather than a claim when the
   PTR lookup fails.

Integration:

8. The `allremote.com.tw` shape as a committed fixture — one in-domain MX host,
   one address, provider name resolving to two — asserting `mx.vanity-divergent`
   with exactly one missing address. Captured under `docs/specs/fixtures/`
   per the captured-evidence rule, dated, naming the resolver.
9. Regenerated `tests/state-algebras.json` carrying `ip.scope` and
   `mx.host.reachability` with their `resultPaths`, and `tests/state-matrix.json`
   and `tests/inventory.json` regenerated to match.
10. `npm test` and `npm run locale:gate` pass before either pull request opens.

No scoring test, because neither release changes scoring. When these findings
are later admitted to the grade, that change is backtested with
`node tools/backtest.mjs` as its own release.

## Acceptance criteria

**0.9.1**

1. An MX host resolving only to loopback, private, link-local, unspecified,
   documentation, benchmarking, multicast, reserved or v4-mapped space raises
   `mx.unroutable` at critical and no longer reports as a healthy host.
2. A host with a mixed address set raises `mx.partially-routable` and names the
   unreachable address.
3. An MX record whose RDATA is an address literal raises `mx.address-literal`,
   raises no `mx.dangling`, and issues no A, AAAA or CNAME query for it.
4. A null MX beside any other MX record raises `mx.null-conflict`, and the `.`
   target is not resolved. `isNullMx()` behavior is byte-identical to `v0.9.0`
   on every input.
5. A preference above 65535 raises `mx.invalid-preference` and does not prevent
   the host from being audited.
6. No score or grade differs from `v0.9.0` on the deterministic corpus.

**0.9.2**

7. An in-domain MX host whose forward-confirmed provider name resolves to a
   strict superset of its addresses raises `mx.vanity-divergent` naming the
   missing addresses.
8. An equal address set raises nothing.
9. A reverse name that does not forward-confirm raises nothing, and a PTR
   lookup that does not return raises nothing.
10. With deep checks off, no PTR query is issued and neither 0.9.2 finding
    appears.
11. No score or grade differs from `v0.9.1` on the deterministic corpus.

## Risks

**The PTR heuristic names the wrong thing.** A reverse pointer is authored by
the holder of the reverse zone and need not name a mail service; some providers
point every address at a generic per-IP name, as `210.71.187.193` does with
`210-71-187-193.hinet-ip.hinet.net`. *Mitigation:* forward confirmation, the
in-domain exclusion, and `medium` severity with the evidence stated rather than
summarized. A generic per-IP name will almost never resolve to a superset, so
it fails the comparison rather than producing a false finding.

**Scope classification is too aggressive.** An address range added to the IANA
registry after this ships, or a deployment using shared address space
deliberately behind a NAT that does receive mail, would be reported as an
outage. *Mitigation:* `global` is the default, so unknown ranges are reported as
reachable; `100.64.0.0/10` is `OQ-MXV-04` precisely because it is the range with
a plausible legitimate use.

**Query volume on large estates.** A 200-domain audit with deep checks on could
add several hundred queries. *Mitigation:* the caps in §4 — four addresses per
host, two candidates per domain — and the deep-check gate. The 0.9.2 pull
request states the measured additional query count on the deterministic corpus.

**Two findings for one defect.** `mx.unroutable` and `mx.dangling` are adjacent,
as are `mx.address-literal` and `mx.dangling`, and `mx.vanity-divergent` and
`mx.single-host`. A reader given two findings for one cause loses confidence in
both. *Mitigation:* `OQ-MXV-05` settles the suppression rule; the draft position
is that the more specific finding suppresses the more general one, and the
acceptance criteria assert the suppression rather than leaving it to review.

## Open questions

**`OQ-MXV-01` — Is `mx.partially-routable` medium or critical?** A host with one
routable and one unroutable address delivers most mail and stalls some senders
intermittently. The argument for critical is that intermittent inbound loss is
worse to diagnose than total loss. The argument for medium is that the domain is
receiving mail and critical should mean it is not. Draft position: medium.

**`OQ-MXV-02` — Should divergence run on out-of-domain MX hosts?** The check is
gated on `inAudited` because a vanity name is by definition in the audited zone.
A domain pointing directly at a provider name could in principle also lag, but
that name is the provider's own and there is nothing for the operator to fix.
Draft position: in-domain only, as scoped.

**`OQ-MXV-03` — Is the query cost acceptable at the stated caps?** §4 bounds it
at 8 per qualifying host. Settling this may want a measurement against the
deterministic corpus, captured under `docs/specs/fixtures/` per the
captured-evidence rule.

**`OQ-MXV-04` — Is `100.64.0.0/10` unroutable for this purpose?** RFC 6598
shared address space is not globally routable, but it is used inside carrier and
cloud networks where a mail host might genuinely sit behind a translator. Draft
position: classify as `shared`, and include it in `none`/`partial` — but this is
the most likely false positive in the table.

**`OQ-MXV-05` — Does a specific finding suppress `mx.dangling`?** Draft position
in §3: yes, and asserted in acceptance criterion 3. The alternative is that both
appear and the reader reconciles them.

**`OQ-MXV-06` — What is reported when the sets diverge in both directions?**
`H ⊄ P` and `P ⊄ H` means the vanity name holds an address the provider no
longer publishes — the stale-copy case, and arguably the more serious one, since
mail is being routed somewhere the provider has disowned. §4 currently ignores
it. Draft position: defer to a later release rather than widen 0.9.2, but it is
the strongest candidate for inclusion.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-09-04 | First complete statement. Six open questions. |
