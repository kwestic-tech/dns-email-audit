# Spec: DMARCbis Tree Walk and complete RFC 9989 discovery

| Field | Value |
| --- | --- |
| Spec version | 1.2 (Implemented) |
| Target release | 0.3.0 |
| Status | Implemented |
| Pull request | [#20](https://github.com/kwestic-tech/dns-email-audit/pull/20) |
| Depends on | [rendering-and-robustness](rendering-and-robustness.md) (0.2.3), because this release adds new rendered evidence |
| Blocks | [findings-and-remediation](../findings-and-remediation.md), which consumes discovery provenance |
| Slug for open questions | `DMARC` |
| Last updated | 2026-08-24 |

## Problem

The application already advertises RFC 9989 conformance. `js/dns.js` implements
the full DMARCbis tag vocabulary at [`js/dns.js:558`](../../../js/dns.js), handles
`t=` test mode, `psd=`, `sp`/`np` inheritance, case-insensitive anchored tag
parsing, DMARC URI list parsing with size-limit suffixes, and external report
authorization. The scoring rubric was already migrated off `pct=`. That is most
of the specification.

What is missing is discovery. RFC 9989 replaced the Public Suffix List with a
DNS Tree Walk for locating the Organizational Domain, and this application still
uses the PSL. `analyzeDomain()` at [`js/dns.js:1844`](../../../js/dns.js) queries
`_dmarc.<domain>`, and on a miss makes exactly one more query at
`_dmarc.<organizational-domain>` where the organizational domain comes from
`getOrganizationalDomain()` at [`js/dns.js:246`](../../../js/dns.js), which reads
the vendored PSL snapshot in `js/public-suffixes.js`.

That approximation is wrong in three ways that matter. It reaches the wrong name
for any domain whose real DMARC boundary differs from its PSL boundary. It cannot
observe a policy published at an intermediate level, so `a.b.c.example.com`
inheriting from `b.c.example.com` is invisible. And it cannot honor `psd=`,
which exists precisely so the walk knows where to stop without consulting a
list maintained outside DNS.

Two smaller defects sit alongside it. Record selection at
[`js/dns.js:1846`](../../../js/dns.js) filters TXT strings with
`startsWithCI(v, 'v=DMARC1')`, so a record written as `p=reject; v=DMARC1` is
never selected and is reported as if no record exists. `validateDmarcVersion()`
at [`js/dns.js:601`](../../../js/dns.js) already knows how to say `not-first`, but
nothing ever reaches it in that case. Separately, `np=` is scored through
`effectiveNp` without ever testing whether the audited name is in fact a
non-existent subdomain, so the non-existent-subdomain branch of the policy is
applied to names that plainly exist.

## Scope

1. Implement the RFC 9989 DNS Tree Walk for Organizational Domain and policy
   discovery, replacing the single PSL-derived fallback query.
2. Record and surface discovery provenance: which name the applied record was
   found at, how many steps the walk took, and whether the policy is inherited.
3. Honor `psd=` as a walk terminator.
4. Implement the domain-existence test so `np=` applies only where it should.
5. Distinguish missing, malformed, duplicate, and inherited records in both the
   result object and the interface.
6. Diagnose a misplaced `v=DMARC1` as misplaced rather than absent.
7. Tighten external report authorization: version-tag position and duplicate
   record handling.
8. Keep parsing, discovery, evidence and scoring as four separate layers.

## Non-goals

- No scoring change in this release. The rubric in `calcDmarcScore()` at
  [`js/dns.js:1334`](../../../js/dns.js) is untouched. Discovery correctness will
  move some domains between grades because a different record is found, and that
  is a discovery change, not a rubric change. Any deliberate rubric change is a
  separate release and is backtested first.
- No removal of the vendored PSL *file*. Both DMARC call sites move to the Tree
  Walk per `OQ-DMARC-04` — discovery and `findExternalReportDestinations()`
  alike — so no DMARC decision consults the PSL after this release. The vendored
  list stays only because the hosting and provider heuristics still use it; it is
  no longer part of any DMARC answer.
- No aggregate or failure report parsing. RFC 9990 and RFC 9991 report ingestion
  is out of scope for the browser tool.

## Design

### 1. Layer separation

Discovery becomes its own function with no parsing and no scoring inside it.

```js
async function discoverDmarc(domain, queryOpts) → {
  applied: {            // the record receivers will actually use, or null
    record: string,
    foundAt: string,    // the DNS name whose _dmarc held the APPLIED record
    labelsUp: number,   // 0 when published at the audited name itself
    inherited: boolean, // foundAt !== domain
  } | null,
  policyDomain: string | null,          // alias of applied.foundAt, read-only
  organizationalDomain: string,         // §4.10.2 selection; never null —
                                        // falls back to the audited name
  psdBoundary: string | null,           // name that declared psd=y, if any
  steps: [{ queryName, kind, txtCount, dmarcCount, selected }],
  terminated: 'psd-y' | 'psd-n' | 'root' | 'error',
  queries: number,
  observed: [{ queryName, record, why }],  // diagnosis-only, see section 3
  error: string | null,
}
```

**`applied.foundAt` and `applied.labelsUp` are defined as the location of the
policy record actually applied**, and are not renamed. Both are read directly by
[findings-and-remediation](../findings-and-remediation.md) and exported as schema
fields by [report-comparison](../report-comparison.md), so their names are frozen.
`policyDomain` is an alias of `applied.foundAt` provided for readability at call
sites that care about the policy rather than the discovery evidence.
`organizationalDomain` is a **separate** value and is often not the same name:
the applied policy is the Author Domain's record when it has one, whereas the
Organizational Domain comes from the §4.10.2 selection described in section 2 and
may be a name that carries no record. Conflating the two is the defect that
produced version 0.1 of this section.

`analyzeDmarc()` keeps its current signature and stays pure. `calcDmarcScore()`
keeps its current signature. The orchestration in `analyzeDomain()` calls
`discoverDmarc()`, passes `applied.record` to `analyzeDmarc()`, and attaches the
discovery object to the result as `dmarcDiscovery`.

The existing post-hoc mutation of `dmarcStatus` at
[`js/dns.js:1856`](../../../js/dns.js), which overwrites `policy` with
`effectiveSp` and rewrites `status` and `cls`, is replaced by an explicit
`applyInheritance(dmarcStatus, discovery)` function returning a new object. That
mutation is currently the only place a `dmarcStatus` is edited after
construction, and it is easy to miss when reasoning about the record.

### 2. The Tree Walk itself

The parameters below are **transcribed from RFC 9989 §4.10**, not reconstructed.
Per `OQ-DMARC-01` the normative text is quoted here and again in a code comment
beside the implementation, so a reviewer can check the code against the RFC
without leaving the diff.

> To guard against such abuse of the DNS, a shortcut is built into the process
> so that Author Domains with more than eight labels do not result in more than
> eight DNS queries.
>
> 3. Break the subject DNS domain name into a set of ordered labels. Assign the
>    count of labels to "x", and number the labels from right to left […]
> 4. If x < 8, remove the left-most (highest-numbered) label from the subject
>    domain. If x >= 8, remove the left-most (highest-numbered) labels from the
>    subject domain until 7 labels remain. The resulting DNS domain name is the
>    new target for the next lookup.
> 7. Determine the target for the next query by removing the left-most label
>    from the target of the previous query. Repeat steps 5, 6, and 7 until the
>    process stops or there are no more labels remaining.

So: **query budget 8**, and a name of eight or more labels is shortened to seven
labels after the initial query rather than walked one label at a time. The walk
reaches the TLD — RFC 9989's own worked example ends at `_dmarc.com`.

**The walk does not stop at the first record it finds.** Steps 2 and 6 stop
early *only* when a single surviving record carries `psd=n` or `psd=y`. A plain
valid record is collected and the walk continues. Selection happens afterwards,
over the whole set:

- The **applied policy** is the Author Domain's record if it has one; otherwise
  it is the record at the **highest** name in the tree that has one. RFC 9989
  §B.4.2: *"the policy domain is the highest element in the DNS tree with a
  DMARC Policy Record"*.
- The **Organizational Domain** is selected by RFC 9989 §4.10.2's three rules,
  applied over the records retrieved, **longest name to shortest**:

  1. a record with `psd=n` — that name is the Organizational Domain, stop;
  2. a record with `psd=y` at any name *other than where the walk started* — the
     Organizational Domain is the name **one label below** it, which may itself
     carry no record at all;
  3. otherwise, the record at the name with the **fewest labels**.

  And, normatively: *"If this process does not determine the Organizational
  Domain, then the initial target domain is the Organizational Domain."* So a
  walk that retrieves no records at all yields the audited name itself, not
  `null`.

  Only rule 3 is "the highest name carrying a record", which is what §B.4.1's
  example illustrates. Treating rule 3 as the whole rule — as an earlier draft of
  this section did — gets the `psd=y` case wrong in the direction that matters,
  since under a PSD the Organizational Domain is a name that may have no DMARC
  record of its own.

Version 0.1 of this spec said the walk stops "at the first name that yields
exactly one valid record". That is wrong, and wrong in the direction that
produces a false verdict on a correctly configured domain: for
`signing.example.com` with records at both `signing.example.com` and
`example.com`, first-match reports the wrong policy domain for exactly the
delegated-subdomain case DMARCbis exists to serve. It also said the threshold
was five labels, which was the number in an early DMARCbis draft rather than in
the published RFC.

Implementation constraints that are settled:

- Each step records `queryName`, the response `kind` from `dohFetch()`, how many
  TXT strings came back, how many were DMARC records, and whether that step's
  record was selected. This array is the evidence trail and is what the interface
  shows.
- A step returning `servfail`, `timeout`, `network-error` or `http-error`
  terminates the walk with `terminated: 'error'` and `applied: null`. A failed
  lookup is not a missing record. The result is `unknown`, and per the pattern
  established by `optionalCheck()` at [`js/dns.js:180`](../../../js/dns.js) an
  unknown control must never be presented as an absent one. This holds even when
  a record was already collected at a lower step: a transient error means the
  higher names could not be examined, so the *highest* record is not knowable.

  > **Amended at 1.2 — see [As implemented](#as-implemented) item 2.** The last
  > sentence is too strong. It holds for an inherited policy and for the
  > Organizational Domain, and it does **not** hold for a record found at the
  > Author Domain itself, which RFC 9989 §4.10.1 settles on the first query
  > before any walk begins. That record survives the error; `terminated` stays
  > `error` and `organizationalDomain` still falls back to the audited name.
  > As originally written, a slow `_dmarc.com` would have reported a healthy
  > domain's own `p=reject` as unknown.
- A step at which more than one valid record exists **discards them and
  continues**. RFC 9989 step 2: *"If multiple DMARC Policy Records are returned
  for a single target, they are all discarded."* The duplicate is recorded in
  `observed[]` as diagnostic evidence, and a policy found higher in the tree
  still applies. If no record is found anywhere, the result is *missing*, not
  `permerror` — but see section 3 for why the finding stays critical.
- `terminated` describes how the completed walk ended, not what was found in it.
  Finding a record is not a termination reason and neither is a duplicate. The
  vocabulary is `psd-y`, `psd-n`, `root` (labels exhausted), and `error`.
  There is deliberately no `query-limit` outcome: the eight-query bound is
  achieved by the shortening rule, not by aborting. A thirteen-label name is
  shortened to seven labels after the first query and then walks one label at a
  time, so it reaches the TLD on query eight — labels always run out exactly at
  the budget. A walk that stopped early because it ran out of queries would be a
  bug, not a state to report.
- Every step goes through `dohFetch()` and therefore through the existing cache,
  concurrency limiter and retry logic. A 200-domain audit of subdomains of the
  same parent will hit the cache for the shared upper steps.
- `psd=y` at a step means that name is a Public Suffix Domain. The walk stops
  there and the record is not inherited downward as an ordinary organizational
  policy. `psd=u` is the default and means continue normally. `psd=n` means the
  name is explicitly not a PSD and also stops the walk.

### 3. Record selection and misplaced version tags

Selection runs in two passes at each step.

The **strict pass** is what determines policy. Keep TXT strings that begin with
`v=DMARC1` after leading-whitespace trimming, case-sensitive on the value
`DMARC1` per [`js/dns.js:601`](../../../js/dns.js) and case-insensitive on the tag
name `v`. If exactly one survives, it is that step's record. If more than one
survives, **all are discarded and the walk continues**, and the step is recorded
in `observed[]` with `why: 'multiple-at-step'`.

The finding does not soften. `dmarc-multiple-records` stays **critical** and is
now raised from the `observed[]` evidence rather than from
`dmarcStatus.status === 'permerror'`. Publishing two records at a name is a real
misconfiguration that makes every receiver ignore both, and an auditor that
reported only "no DMARC record" would be describing the symptom instead of the
cause. What changes is the *policy verdict*, which becomes RFC-correct: a record
higher in the tree still applies, and if none exists the status is `missing`.
Scoring is unaffected either way — `missing`, `present` and `permerror` all
score zero at [`js/dns.js:1371`](../../../js/dns.js).

**The message must not lie about the policy.** When a duplicate is found at one
name but a valid record applies from higher in the tree, the finding says the
duplicate is ignored by receivers *and* names the policy that actually governs.
It must never read as "no DMARC policy applies" in that case — the whole point of
the corrected walk is that one does. Two locale keys therefore exist: one for a
duplicate with a policy still in force, one for a duplicate with nothing above
it.

The **diagnostic pass** exists only to explain a miss. When the strict pass
yields nothing, scan the same TXT strings for `/(?:^|;)\s*v\s*=\s*DMARC1\s*(?:;|$)/i`
appearing anywhere other than first, and for a case-mismatched value such as
`v=dmarc1`. Each hit is recorded in `observed[]` with a `why` token:

| `why` token | Condition |
| --- | --- |
| `version-not-first` | `v=DMARC1` present but not the first tag |
| `version-bad-case` | `v=dmarc1` or similar, wrong case on the value |
| `version-absent` | Looks like a DMARC record (has `p=`) with no `v=` at all |
| `at-apex-not-underscore` | A `v=DMARC1` string found on the domain's own TXT set rather than under `_dmarc` |

`at-apex-not-underscore` requires no extra query: `analyzeDomain()` already has
the apex TXT set in `txt`. This is a common misconfiguration and currently
produces a bare "no DMARC record" verdict.

`observed[]` never affects `applied`, never affects the score, and never turns a
missing record into a present one. Its only job is to change the message from
"you have no DMARC record" to "you have a DMARC record that no receiver will
read, and here is why".

### 4. Domain existence and `np=`

`np=` applies to non-existent subdomains of the Organizational Domain. RFC 9989
defines existence in terms of DNS, so the test is a DNS test, and it must be run
before `effectiveNp` is treated as the applicable policy for the audited name.

```js
async function domainExists(name, queryOpts) → 'yes' | 'no' | 'unknown'
```

Implementation: an NXDOMAIN response for any type at that name means `no`;
NOERROR with or without data means `yes`; any transport failure means `unknown`.
`analyzeDomain()` already issues NS, MX, TXT, A and AAAA queries for the audited
name at [`js/dns.js:1819`](../../../js/dns.js), and `nsResult.status === 3` is
already the unregistered-domain test. The existence verdict should be derived
from those existing responses rather than adding a query. See `OQ-DMARC-02` for
which record type is authoritative for this purpose.

The consequence for scoring is deliberately conservative: when the audited name
exists, `effectiveSp` governs and `effectiveNp` is reported but not applied. When
existence is `unknown`, the weaker of the two continues to govern, matching the
existing weakest-link rule at [`js/dns.js:1349`](../../../js/dns.js).

### 5. Stricter tag validation

`analyzeDmarc()` gains no new tags, but the following move from parsed-and-
reported to explicitly diagnosed. Each produces a token on the status object, not
an English string.

| Tag | Additional validation |
| --- | --- |
| `p` | An unrecognized value already forces `malformed`. Add the raw value to the status so the message can name it. |
| `sp`, `np` | Same treatment: an unrecognized value is currently silently normalized to `null` by `normalizePolicy()` and then inherits. Distinguish "absent, inherits" from "present but unrecognized". |
| `adkim`, `aspf` | Currently any value other than `s` becomes `r` at [`js/dns.js:715`](../../../js/dns.js). Distinguish `absent`, `r`, `s`, and `invalid`. |
| `t` | `tValid` exists. Surface it as a finding rather than only as a field. |
| `psd` | `psdValid` exists. A `psd=y` on a name that is plainly not a public suffix is worth naming. |
| `fo` | `foValid` exists. Add the existing "fo without ruf is a no-op" observation as a first-class finding. |
| `rua`, `ruf` | `parseDmarcUriList()` already distinguishes malformed syntax from an unsupported scheme. Surface both distinctly. |
| unknown tags | `unknownTags` exists and is unused by the interface. Report them as informational; RFC 9989 requires receivers to ignore unknown tags, so this is not an error. |

### 6. External report authorization

`checkExternalReportAuth()` at [`js/dns.js:828`](../../../js/dns.js) is close to
correct and needs three tightenings.

First, the authorization record must have `v=DMARC1` as its **first** tag, which
is what RFC 9990 §4 requires and what the comment at
[`js/dns.js:815`](../../../js/dns.js) already states. The check uses
`startsWithCI(r, 'v=DMARC1')`, which is correct for position but accepts
`v=DMARC1x`. Route it through `validateDmarcVersion()` so one function owns the
rule.

Second, multiple authorization records at the same name are currently resolved by
taking `match[0]`. The rule is normative and permissive: RFC 9990 §4 step 6
discards each record that fails to parse, and step 8 states *"If at least one TXT
resource record remains in the set after parsing, then the external reporting
arrangement was authorized by the Report Consumer."* So every returned record is
parsed, and the destination is **authorized when at least one survives**. There
is no `multiple` state here.

This is deliberately the opposite of the DMARC *policy* duplicate rule in section
2, where duplicates are discarded and the walk continues. The two questions are
asked at different names for different purposes, and RFC 9989 and RFC 9990 answer
them differently; the asymmetry is intentional and is called out in a code
comment so a future reader does not "fix" one to match the other. See
`OQ-DMARC-05`.

Third, the wildcard query is only issued when the exact query returns nothing,
which is correct, but a `nodata` response and an `nxdomain` response are
currently indistinguishable in the result. Record which one occurred, because
NXDOMAIN at `<policy>._report._dmarc.<dest>` with a record at the wildcard is
normal vendor practice, while NOERROR with unrelated TXT data usually means
someone put the record at the wrong name.

The `policyDomain` passed in is `dmarcAtDomain` at
[`js/dns.js:1938`](../../../js/dns.js). Once the Tree Walk lands, the correct value
is the name the applied record was found at, which is `discovery.applied.foundAt`.
This must be updated in the same change or authorization will be checked against
the wrong source domain.

### 7. Result and interface surface

New fields on the per-domain result:

```js
dmarcDiscovery: { …as in section 1… },
dmarcExistence: 'yes' | 'no' | 'unknown',
```

`dmarcAtDomain` is retained as an alias of `dmarcDiscovery.applied.foundAt` for
one release so the CSV export and the report do not break, then removed.

The detail panel gains a discovery line under the existing DMARC row at
[`js/app.js:494`](../../../js/app.js), showing the found-at name, the number of
steps, and the termination reason. The existing `dmarc.inheritedFrom` message is
kept and extended.

The CSV export at [`js/app.js:737`](../../../js/app.js) gains columns for
`dmarc_found_at`, `dmarc_labels_up` and `dmarc_discovery_terminated`. Note the
positional-header backfill logic at [`js/app.js:744`](../../../js/app.js): new
columns must be appended, never inserted, and `locales/en.json` `csv.headers`
defines the column count.

## Localization impact

New keys are required for the diagnostic tokens in section 3, the tag-validation
findings in section 5, the discovery evidence line, and the three CSV headers.
Estimated 20 to 30 new keys under `issue.*`, `dmarc.*` and `csv.headers`.

All thirteen locales are translated in the same change per
[`AGENTS.md`](../../../AGENTS.md). `npm run build:fallback` runs after the
`locales/en.json` edit. `npm run locale:gate` must report 13/13 before the pull
request opens. Protocol tokens (`v=DMARC1`, `p=`, `sp=`, `np=`, `psd=`, `t=y`,
`_dmarc`, `_report._dmarc`) are never translated.

## Testing

Discovery is tested against a fixture resolver rather than the network, with
**no production code change**. Per `OQ-DMARC-03` the mechanism is a programmable
`fetch` in the test sandbox: the sandbox already stubs `fetch` to return
`{ok: false}` at [`tools/scoring.test.mjs:15`](../../../tools/scoring.test.mjs), and
this replaces that stub with one that pattern-matches the DoH query string and
returns a canned DoH JSON body.

The helper lives in `tools/lib/doh-fixture.mjs` rather than inline, because
[dns-protocol-depth](../dns-protocol-depth.md) and [dnssec-evidence](../dnssec-evidence.md)
reuse it. It takes a map of query name and type to response, and defaults any
unmatched query to `nxdomain` so a fixture cannot accidentally depend on a real
lookup. No `__setResolver` hook and no transport seam is added to `js/dns.js`:
a production seam that exists only for tests is exactly what this repo has
consistently refused.

Fixture matrix, each asserting `applied.foundAt`, `labelsUp`, `terminated`,
`queries`, and the resulting `policy` and `effectivePolicy`:

| Fixture | Expectation |
| --- | --- |
| Policy at the audited name | `labelsUp: 0`, not inherited, `p` governs |
| Policy one level up | inherited, `sp` governs the audited name |
| Policy several levels up | walk reaches it, step count recorded |
| Records at BOTH the audited name and higher | applied is the audited name's; `organizationalDomain` is the **highest**, not the nearest |
| Records at two ancestors, none at the audited name | applied is the **highest**, per RFC 9989 §B.4.2 |
| Deep name, 13 labels | exactly 8 queries; second query shortens to 7 labels; last query is the TLD |
| Name with exactly 8 labels | shortcut engages at x >= 8 |
| Name with 7 labels | one label removed per step, no shortcut |
| `psd=y` encountered mid-walk | `terminated: 'psd-y'`, no inheritance below it |
| `psd=n` mid-walk | `terminated: 'psd-n'`, walk stops |
| Two valid records at one step | discarded, walk continues, `observed[].why === 'multiple-at-step'` |
| Two records at one step, valid record higher | higher record applies; duplicate still a critical finding |
| Two records and nothing higher | status `missing`, `dmarc-multiple-records` still critical |
| SERVFAIL mid-walk | `terminated: 'error'`, `applied: null`, unknown not absent |
| SERVFAIL after a record was already collected | still `error` and `applied: null` — the highest is unknowable |
| No record anywhere | `terminated: 'root'`, status `missing` |
| `p=reject; v=DMARC1` | `observed[].why === 'version-not-first'`, still `missing` for policy |
| `v=dmarc1; p=reject` | `version-bad-case`, still `missing` |
| `v=DMARC1; p=reject` at the apex TXT set | `at-apex-not-underscore` |
| Existing subdomain with `np=none` | `sp` applies, `np` reported not applied |
| NXDOMAIN subdomain with `np=none` | `np` applies |
| Cached upper steps | second subdomain of the same parent issues fewer queries |
| External report auth, wildcard only | `via: 'wildcard'`, `authorized` |
| External report auth, two records, one parses | authorized — RFC 9990 §4 step 8 |
| External report auth, two records, neither parses | not authorized |
| External report auth, `v=DMARC1x` | `unauthorized`, `malformed: true` |

Add a PSL-versus-Tree-Walk divergence table: a fixture list of names where the
two disagree, asserting the Tree Walk answer, so a future PSL refresh cannot
silently change DMARC behavior.

Run `node tools/backtest.mjs domains.txt --json` at `v0.2.3` and at the release
candidate and diff. Any domain whose grade moves must be explainable by a
discovery difference and listed in `CHANGELOG.md`.

## Acceptance criteria

1. Every fixture above passes deterministically with no network access.
2. `discovery.terminated` never reports a value outside `psd-y` / `psd-n` /
   `root` / `error`. Finding a record and encountering a duplicate are not
   termination reasons, and neither is exhausting the query budget — that cannot
   happen.

   > **Amended at 1.2 — see [As implemented](#as-implemented) item 2.** This
   > criterion originally also required that `terminated` is never `error` with
   > a non-null `applied`. That requirement encoded the defect described above
   > and is withdrawn. The narrower guarantee that replaces it: after an error,
   > `applied` is non-null **only** for a record found at the audited name
   > itself, with `labelsUp: 0` and `inherited: false`. A record collected at an
   > ancestor never survives an error.
3. A misplaced or miscased `v=DMARC1` produces a specific diagnosis, not
   "missing".
4. `np=` is applied only when the audited name does not exist.
5. External report authorization is evaluated against the name the applied
   record was found at.
6. The grade distribution diff against 0.2.3 is explained domain by domain.
7. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

## Risks

**Query amplification.** The current implementation issues at most two DMARC
queries per domain. A Tree Walk issues more, and a 200-domain audit multiplies
that. `PRIVACY.md` states a typical domain fans out to roughly 30 queries, and
that number will rise. Mitigation: the `dohFetch()` cache at
[`js/dns.js:65`](../../../js/dns.js) is keyed on name and type and already
deduplicates shared upper steps across domains in the same run. Measure the
actual fan-out change with the backtest and update `PRIVACY.md` with the real
number.

**Grade movement without a rubric change.** Users will see grades move and read
it as a scoring change. Mitigation: name it explicitly in `CHANGELOG.md` as a
discovery correction, and keep the rubric byte-identical so the claim is
verifiable.

**RFC transcription error.** The Tree Walk's label arithmetic is fiddly and easy
to get subtly wrong. Mitigation: `OQ-DMARC-01` requires the numbers be lifted
from the RFC text with a section citation in the code comment, and the fixture
table exercises the boundary cases.

## Open questions

None. All seven were resolved on 2026-08-24 — see **Resolved questions** below.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| OQ-DMARC-01 | Who transcribes the normative Tree Walk parameters, and against what text? | RFC 9989 was fetched as published text (`rfc-editor.org`, May 2026, obsoletes 7489/9091) and §4.10 transcribed directly; no parameter comes from memory or another implementation. **Yes** to the procedural question: the normative subsection is quoted verbatim in section 2 above and again in a code comment beside the implementation, so a reviewer can check the code against the RFC without leaving the diff. Transcription immediately caught two defects in this spec's own 0.1 text — a five-label threshold that is eight in the published RFC, and a first-match stop condition that is highest-match. | 1.0 |
| OQ-DMARC-02 | Which query answers the domain-existence question? | NXDOMAIN on the existing NS query is sufficient; no additional query is needed. RFC 9989 §3.2.13 and Appendix A.4 are explicit that existence is a property of the *name*, not of any record type: *"if any RR exists for a domain, then the domain exists"*, NXDOMAIN means the name does not exist, and NODATA (NOERROR with no records of the queried type) means the name exists but that type does not. The spec's own worry — a name with only a TXT record — is therefore handled correctly, because such a name returns NOERROR/NODATA rather than NXDOMAIN on the NS query. `analyzeDomain()` already holds NS, MX, TXT, A and AAAA responses, so existence is `no` on NXDOMAIN, `yes` on any NOERROR, and **`unknown` on any transient error** — a timeout or SERVFAIL must never be read as non-existence. | 1.0 |
| OQ-DMARC-03 | How is a fixture resolver injected into `js/dns.js`? | A programmable `fetch` in the test sandbox that pattern-matches the DoH query string. No production code change, and the test stays honest about the wire format. Approved by Ian 2026-08-24, with the downstream consumers in mind: [dns-protocol-depth](../dns-protocol-depth.md) and [dnssec-evidence](../dnssec-evidence.md) reuse this mechanism, so the fixture helper is written to be shared rather than inlined in this release's test file. A `__setTransport()` hook was rejected as a production seam existing only for tests; extracting the transport was rejected as a refactor this release's non-goals exclude. | 1.0 |
| OQ-DMARC-04 | Does the PSL stay after the Tree Walk lands? | **No — both call sites switch to the Tree Walk.** Approved by Ian 2026-08-24. RFC 9990 defines the externality test in terms of the Organizational Domain, which after this release means the Tree Walk result, and carrying two definitions of "organizational domain" in one codebase is the kind of ambiguity that produces a wrong answer years later. The cost is accepted and must be measured, not estimated: the externality test now walks the *destination's* tree, so the query fan-out rises beyond what this spec originally anticipated. `PRIVACY.md`'s stated fan-out is updated from a measured backtest before merge. | 1.0 |
| OQ-DMARC-05 | What is the verdict when a report destination publishes multiple authorization records? | Not ambiguous, contrary to the 0.1 text. RFC 9990 §4 step 6 discards records that fail parsing, and step 8 states: *"If at least one TXT resource record remains in the set after parsing, then the external reporting arrangement was authorized by the Report Consumer."* Multiple authorization records are therefore **authorized** so long as one parses. This is the opposite of the conservative reading the draft leaned toward, and it is not a judgement call — the permissive reading is the normative one. Note this differs deliberately from the DMARC *policy* rule, where duplicates are discarded; the two questions are asked at different names for different purposes. | 1.0 |
| OQ-DMARC-06 | Should discovery evidence be shown by default or on demand? | The middle option, confirmed. The found-at line always shows; the full step list appears only when `labelsUp > 0` or `terminated` is not `root`, and is behind a disclosure control otherwise. The step list is what makes a surprising result explicable and is noise the rest of the time. | 1.0 |
| OQ-DMARC-07 | Does `psd=y` change the score? | No, in this release. `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` stay byte-identical, per the advisory-before-scoring rule: a new signal reports for at least one release before it affects a grade. Whether a correct `psd=y` earns credit, or an incorrect one costs it, is referred to [findings-and-remediation](../findings-and-remediation.md) (0.6.0), which owns severity. Recorded there rather than left as a verbal note. | 1.0 |

**Scores will move in this release, and that is expected.** 0.3.0 is a
discovery-only change: no rubric, weight or threshold is touched, but a domain
whose policy is found at a different name than the PSL previously chose will
score differently, and a domain with duplicate records at one name may now
inherit a valid policy from higher in the tree where it previously scored zero.
The backtest is run and the movement reported in the pull request rather than
suppressed — this is the case [report-comparison](../report-comparison.md)'s
`OQ-CMP-06` exists to describe.

## As implemented

**1. The applied record is chosen by §4.10.1's preference list, not by height
alone.** The 1.1 text said the applied policy is the Author Domain's record if
it has one and otherwise "the record at the **highest** name in the tree that
has one", citing §B.4.2. Transcribing §4.10.1 during implementation showed that
is right in every case except one, and wrong in the case `psd=` exists for. The
RFC's preference list is *Author Domain, then Organizational Domain, then PSD*,
and §4.10.1 closes with a note that settles it outright:

> Note: PSD policy is not used for Organizational Domains that have published a
> DMARC Policy Record.

So for `x.giant.bank.example` with a plain record at `giant.bank.example` and
`psd=y` at `bank.example`, the Organizational Domain is `giant.bank.example`
(§4.10.2 rule 2) and *its* record applies — even though the PSD's record sits
higher in the tree. Height-alone would apply the PSD's policy, which the note
forbids. Where no `psd=` tag is involved, §4.10.2 rule 3 makes the
Organizational Domain the fewest-labels record and the two readings agree, which
is why §B.4.1 and §B.4.2 read as they do. `selectAppliedRecord()` implements the
preference list; the divergent case is a fixture in section 28 of
[`tools/scoring.test.mjs`](../../../tools/scoring.test.mjs).

**2. A record at the Author Domain survives a transient error higher up.** The
1.1 text said a `servfail`/`timeout`/`network-error` step terminates the walk
with `applied: null` and that this "holds even when a record was already
collected at a lower step", reasoning that the *highest* record is not knowable.
That reasoning is correct for the Organizational Domain and for an inherited
policy, and it does not hold for the Author Domain's own record, because
§4.10.1 settles that one before any walk happens:

> Policy discovery first starts with a query for a valid DMARC Policy Record at
> the name created by prepending the label "_dmarc" to the Author Domain of the
> message being evaluated. If a valid DMARC Policy Record is found there, then
> this is the DMARC Policy Record to be applied to the message

and performs the Tree Walk only "If no valid DMARC Policy Record is found by the
first query". Nothing discovered higher can displace it. As specified, a
SERVFAIL at `_dmarc.com` would have turned a domain's own `p=reject` into an
unknown — a false "no policy" verdict on a healthy domain, which is the failure
mode this project treats as the most damaging kind. `terminated` is still
`error` and `organizationalDomain` still falls back to the audited name; only
`applied` survives, and only when it was found at the audited name itself. Both
branches are fixtures.

**3. Duplicate records get two locale keys, and the walk supplies the
evidence.** As specified. `dmarc-multiple-records` now names the queried name
and is raised only when nothing governs; `dmarc-multiple-records-inherited`
names the duplicate, the governing name and the governing policy. Both are
critical. The finding is keyed on `observed[]` rather than on
`status === 'permerror'`, which the Tree Walk never produces — so the old
`permerror` branch in `buildIssues()` is now unreachable through
`analyzeDomain()` and is retained only for a directly-constructed status.

**4. The version diagnostics moved from `status === 'present'` to
`observed[]`.** A consequence of the strict pass being `validateDmarcVersion()`
itself: a record with a bad `v=` is never *selected*, so it can no longer arrive
as a `present` status. `dmarc-version-not-first`, `dmarc-version-bad-value` and
`dmarc-version-missing` are now raised from the walk's diagnostic pass. The
`present` branch still exists for what remains reachable — a record receivers
will read and cannot act on (bad `p=`, duplicate tags).

**5. `dmarcExistence` is derived, and is `yes` on every path that reaches the
DMARC code.** `OQ-DMARC-02` resolved that NXDOMAIN on the existing NS query is
sufficient and no extra query is needed. In `analyzeDomain()` that is stronger
than it looks: an NXDOMAIN on NS returns `unregistered` before any DMARC work
happens, and a transient NS failure throws, so anything reaching discovery
resolved without NXDOMAIN. The `np=` gate is therefore correct and conservative
rather than frequently exercised, and `dmarc-np-not-applied` exists to explain
the reported policy when a record publishes an `np=` that does not govern.
`domainExists()` is exported and tested independently for the destinations and
fixtures that have no NS response to hand.

**6. `findExternalReportDestinations()` takes a map of walked Organizational
Domains.** `OQ-DMARC-04` moved both DMARC call sites to the Tree Walk, which
makes the externality test asynchronous — but `buildIssues()` is synchronous and
calls it. Rather than make `buildIssues()` async, `analyzeDomain()` resolves
every candidate destination's Organizational Domain with
`resolveDestinationOrgDomains()` and passes both the map and the finished list
down. A destination already equal to the policy domain's Organizational Domain
is settled by string comparison and never walked. A destination whose own walk
fails falls back to its bare name, which can only make it look external — a
"verify this" notice rather than a silent pass.

**7. A step list marks which record was applied.** Found in interface
verification, not specified. A walk that stops at a `psd=y` boundary collects a
record at two names, and both rendered as the word "record" — leaving the reader
unable to tell which one governs. `dmarc.stepApplied` distinguishes them.

**8. `tools/backtest.mjs` measures the query fan-out.** `PRIVACY.md` has to
state the number and `OQ-DMARC-04` requires it be measured rather than
estimated, so the backtest counts the requests that actually reach the network
and reports per-domain fan-out on every run. It also carries the walk's
provenance into `--json`, so a grade diff between two runs can be explained by
naming the record that moved.

**9. A failed walk is `unknown`, and every surface says so.** Found in internal
review, and the most consequential defect in the release. `discoverDmarc()`
reported `terminated: 'error'` correctly and nothing downstream consumed it, so
`analyzeDomain()` fell through to `analyzeDmarc('')` and produced `missing` — the
badge, the finding, the CSV, the summary tile and the filter all asserting
absence on the strength of our own failed lookup. That is what section 2 of this
spec forbids and what `optionalCheck()` exists to prevent, and it was a
regression: at 0.2.3 the same failure threw and the domain showed as an error
rather than as unprotected. The exposure had also grown, because the walk issues
up to eight queries where the old code issued one or two. `analyzeDmarc()` gains
an `unknown` status carrying `cls: 'warn'`, `unprovenPillars()` gains the DMARC
pillar, and `dmarc-unverified` names the failure kind. The score stays zero, per
the advisory-before-scoring rule for controls this audit cannot prove.

**10. The apex diagnosis gets the duplicate finding's two-variant treatment.**
Also internal review. `dmarc-at-apex` was raised as critical whenever a
`v=DMARC1` string appeared in the apex TXT set, including when `_dmarc` held a
perfectly good record — and its text asserts that "the domain is treated as
having no DMARC policy at all", which in that state is false. `zoom.us` is a
live example: it publishes both, and the release's headline new finding was
firing as a false critical on it. `dmarc-at-apex-ignored` (info) names the
governing policy; `dmarc-at-apex` (critical) is kept for when the apex copy is
the only one. This is section 3's "must not lie" rule, which the spec stated for
duplicates and should have stated generally.

**11. Report-destination walks are capped at ten.** `parseDmarcUriList()` caps
nothing, so the number of walks — and therefore the query count for one audit —
was set by the audited domain's own record content. Twenty distinct destinations
would have been 160 queries. Destinations past the cap fall back to their bare
name, which per `findExternalReportDestinations()` can only make one look
*external*, producing a "verify this" notice rather than a silent pass.

**12. Nine user-facing RFC citations were wrong.** The `v=` rules are §4.7
(DMARC Policy Record Format); §5.4 is Policy Enforcement Considerations. RFC
9990's procedure is §4, which has no subsections. Five of the nine predate this
release. `OQ-DMARC-01` makes the citation part of the deliverable, so they are
corrected in the locale strings, in nineteen code comments, and in this document.

**13. External authorization issues one query, and never the literal wildcard
owner.** Found in external review (Codex). RFC 9990 §4 constructs and queries
exactly one name; the wildcard form a Report Consumer publishes is an ordinary
DNS wildcard owner, and the resolver synthesizes its RRset while answering that
one query. Querying `*._report._dmarc.<host>` directly is not the algorithm —
RFC 4592 §2.3 is explicit that *"when a wildcard domain name appears in a
message's query section, no special processing occurs"*, so it retrieves the
literal node instead of exercising synthesis.

This changed verdicts, which is why it was not merely a wasted query. Synthesis
is suppressed when the queried owner already exists, so a destination whose
exact owner holds unrelated or malformed TXT data is **not** authorized under
RFC 9990 — while the literal wildcard lookup found `v=DMARC1` beside it and
authorized the arrangement anyway. Confirmed empirically both ways: three live
reporting vendors (`vali.email`, `rua.agari.com`, `dmarc.microsoft`) return the
synthesized record for the constructed query, and PayPal's four real vendors
still authorize with one query each instead of two. `via: 'wildcard'` is gone,
because a DoH JSON answer carries no evidence of whether it was synthesized and
the second query was never that evidence. The fixture resolver in
`tools/lib/doh-fixture.mjs` now models synthesis *and* its suppression, so the
test proves the production code is right for the right reason.

**14. Authorization records are parsed in full, not just at the version tag.**
Also external review. RFC 9990 §4 step 6 requires each record be parsed *"as a
series of 'tag=value' pairs"* and *then* that `v=DMARC1` be present and first —
the version test is necessary and not sufficient. `v=DMARC1;
this-is-not-a-tag-value-pair` was being accepted as an authorization.
`parseReportAuthRecord()` now requires every non-trailing segment to be a
well-formed `tag=value` pair, with the optional trailing `;` allowed. Step 8
stays permissive, as resolved: one *complete* record among several still
authorizes. The step 9 `rua` override is captured with its same-destination-host
constraint checked — it changes no verdict here because this tool never sends
reports, but an "authorized" result that silently discarded it would be
incomplete evidence about where conformant receivers actually deliver.

**15. One cap now bounds the whole destination-driven workflow.** As implemented
#11 claimed a bound it did not deliver: `MAX_WALKED_REPORT_DESTINATIONS` capped
only the Organizational Domain walks, leaving authorization uncapped, so a
record naming twenty destinations still produced forty authorization queries.
Measured before the fix: 62 network queries for one domain. `MAX_REPORT_DESTINATIONS`
now applies once, in RFC 9990 §3.5's stated order (*"MUST evaluate the provided
reporting URIs [...] in the order given"*), across walks, externality
classification and authorization alike — the same section sanctions the limit
itself (*"up to the Receiver's limits on supported URIs"*). The truncation is
reported rather than implied away: `dmarc-report-destinations-truncated` names
how many of how many were checked and which were not, because ten verdicts for
a twenty-destination record would otherwise read as a complete list.

**16. `dmarc-psd-invalid` is removed.** This was the open question flagged for
Ian in the first review round — the last PSL consult in a DMARC code path,
against `OQ-DMARC-04`'s rule. External review supplied the argument that settles
it as a defect rather than a preference: the check asked about the **audited
name** rather than the name carrying the applied record. A domain inheriting the
genuine `_dmarc.gov` PSD policy is its own PSL organizational domain, so the
check fired and called the correct CISA-operated `psd=y` declaration invalid — a
false positive on the exact inherited-PSD case this release adds, reproduced
against a fixture. There is no DNS-only test that disproves a `psd=`
declaration; the declaration is the protocol's own source of truth, and a
vendored list snapshot is not evidence for "this domain is not a public suffix".
`dmarc-bad-psd` remains, checking the protocol-defined value vocabulary. With
this gone, no DMARC code path calls `getOrganizationalDomain()` — the invariant
`OQ-DMARC-04` asked for is now actually true. Reconsidered in 0.6.0, such a
check would have to be explicitly heuristic, informational, and evaluated at
`dmarcDiscovery.applied.foundAt`.

**17. A cross-host `rua` override makes the destination unusable, and the
result says so.** External review, follow-up round — my first pass at step 9 was
incomplete. It recorded `overrideValid: false` and still returned
`state: 'authorized'`, and since `buildIssues()` branches only on `state`, the
interface presented the destination as working. RFC 9990 §4 is explicit that
this is not a cosmetic problem:

> Further, if the confirming record includes a URI whose host is again different
> than the domain publishing that override, the Mail Receiver generating the
> report MUST NOT generate a report to either the original or the override URI.

So neither address receives anything, and reporting `authorized` told the
operator their reports were flowing when nothing was being sent at all. That is
the same class of error as #9 and #10 — a confident verdict the evidence does
not support — arriving by a third route.

The result now carries a distinct `override-mismatch` state, consumed by
`buildIssues()` as unusable and raised as its own finding. It is deliberately
not folded into `unauthorized`: the destination *did* authorize, and the fix
belongs to the reporting vendor rather than to the domain owner, so collapsing
the two would misdirect whoever reads it.

A merely malformed override is treated differently, and that distinction is also
from the RFC: §3.5 says of reporting URIs that *"if any of the URIs are
malformed, they SHOULD be ignored"* — ignored, not escalated — so the
authorization stands and only the override is dropped. `overrideReason`
separates `cross-host` from `malformed`.

The fix example that shipped with this finding was itself wrong, caught in the
same review round: its comment named
`yourdomain.com._report._dmarc.vendor.example` while all three record owners
read `_report._dmarc`, which in the vendor's zone resolves to
`_report._dmarc.vendor.example` — the policy-domain prefix missing, so a record
published exactly as shown could never answer the query RFC 9990 §4 constructs
(*"Prepend the domain name from which the policy was retrieved"*; the RFC's own
worked example is `blue.example.com._report._dmarc.red.example.net`). Remediation
text is part of the deliverable, not decoration around it: an operator following
it literally would have published a dead record and concluded the tool was
wrong. All three owners now carry the full name, in English and in all thirteen
translations.

## Verification

- `npm test` — 1,130 assertions, 0 failures (972 at `v0.2.3`).
- `npm run locale:gate` — 13/13 locales, 593/593 keys.
- `node tools/backtest.mjs --sample --json`, diffed against `v0.2.3`:
  **no DMARC-pillar movement across 40 apex domains.**
- A second 40-name run over subdomains, where the PSL and the Tree Walk can
  disagree, moved the DMARC pillar on exactly one: **`www.gov.uk`, 0 → 14
  points, F → D.** `gov.uk` is a PSL public suffix, so the old code treated
  `www.gov.uk` as its own organizational domain and never issued a second query;
  the Tree Walk queries `_dmarc.gov.uk` and finds a real
  `p=reject; sp=none; np=reject` record. `sp=none` governs because the audited
  name exists, which is why the pillar is 14 rather than 27. Two other domains
  moved on the DNSSEC pillar in that run; both were confirmed as resolver
  flakiness by reproducing the same flip at `v0.2.3`.
- Fan-out, measured: **30.4 → 32.1 queries per domain** on the 40-domain sample
  (+5.6%), and 42 → 46 for `cloudflare.com` with the interface's default
  options. `PRIVACY.md` is updated from these numbers.
- Two real-world findings the release surfaces that 0.2.3 could not: `zoom.us`
  publishes a complete DMARC record on its apex TXT set where no receiver reads
  it (`dmarc-at-apex`), and `_dmarc.gov` publishes `psd=y`, which terminates the
  walk for every `.gov` domain (`terminated: 'psd-y'`).

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
| 1.0 | 2026-08-24 | Final. Resolved all seven open questions. Two corrections came out of transcribing RFC 9989 §4.10 rather than trusting the draft: the label threshold is **eight**, not five (five was an early DMARCbis draft), and the walk selects the **highest** name carrying a record, not the first one found going up — first-match would report the wrong policy domain for exactly the delegated-subdomain case DMARCbis exists to serve. Consequent changes: `applied.foundAt`/`applied.labelsUp` keep their names and are defined as the location of the applied record, `policyDomain` is added as an alias, `organizationalDomain` stays separate and is the highest name with a record; duplicate records at a step are discarded and the walk continues rather than terminating as `multiple`, with the duplicate kept as diagnostic evidence and the critical finding raised from that evidence; and the `terminated` vocabulary now describes how the walk ended (`psd-y`, `psd-n`, `root`, `query-limit`, `error`) rather than what was found in it. `OQ-DMARC-05` was resolved against RFC 9990 §4 step 8, which is explicit where the draft called it ambiguous. Corrections contributed by external review (Codex). |
| 1.2 | 2026-08-25 | Implemented. Two corrections came out of transcribing RFC 9989 against the code, both in the same direction as 1.0's: the spec's summary of the RFC was tidier than the RFC. The applied record is selected by §4.10.1's preference list (Author Domain, then Organizational Domain, then PSD) rather than by height alone — §4.10.1's closing note, *"PSD policy is not used for Organizational Domains that have published a DMARC Policy Record"*, decides the one case where the two readings differ. And a record found at the Author Domain survives a transient error higher in the walk, because §4.10.1 settles that record on the first query and performs the walk only "If no valid DMARC Policy Record is found by the first query"; as written, 1.1 would have reported a false "no policy" on a healthy domain whenever `_dmarc.com` was slow. See **As implemented** 1 and 2. Internal review then found four more defects, recorded as **As implemented** 9–12; the first of them — a failed walk reported as a missing record — was a regression against 0.2.3 and against this spec's own section 2. External review (Codex) found four more, recorded as 13–16: the external-authorization check queried the literal wildcard owner rather than relying on resolver synthesis (RFC 4592 §2.3), which changed verdicts where synthesis is suppressed; authorization records were accepted on the version tag alone rather than parsed in full (RFC 9990 §4 step 6); the destination cap bounded only the walks and not the authorization queries; and `dmarc-psd-invalid` was both PSL-dependent and evaluated at the wrong name, producing a false positive on domains inheriting the real `_dmarc.gov` PSD policy. A second Codex round found the step 9 fix incomplete — a cross-host `rua` override was recorded as invalid while the destination was still reported `authorized`, and nothing downstream read the flag — recorded as **As implemented** 17. |
| 1.1 | 2026-08-24 | Consistency pass over the 1.0 text before implementation, after external review (Codex) found six places where 1.0 still contradicted its own resolutions. Removed the non-goal claiming the PSL stays for `findExternalReportDestinations()`, which `OQ-DMARC-04` had already moved to the Tree Walk. Rewrote section 6's duplicate-authorization rule, which still proposed a `multiple` state after `OQ-DMARC-05` resolved to "authorized when at least one record parses", and corrected the matching fixture. Replaced the testing section's `__setResolver`/transport-injection proposal with the resolved programmable sandbox `fetch` helper. Removed `query-limit` from `terminated`: the eight-query bound is achieved by the shortening rule and labels always run out exactly at the budget, so it is not a reachable outcome. Corrected `organizationalDomain` to RFC 9989 §4.10.2's three-rule selection — `psd=n` wins outright, `psd=y` puts the Organizational Domain one label below (a name that may carry no record), and only otherwise is it the fewest-labels record — with the initial target as the normative fallback, so the field is never null. Added the requirement that a duplicate finding never claims no policy applies when one does. |
