# Spec: DMARCbis Tree Walk and complete RFC 9989 discovery

| Field | Value |
| --- | --- |
| Spec version | 1.1 (Final) |
| Target release | 0.3.0 |
| Status | Final — approved for implementation |
| Depends on | [rendering-and-robustness](implemented/rendering-and-robustness.md) (0.2.3), because this release adds new rendered evidence |
| Blocks | [findings-and-remediation](findings-and-remediation.md), which consumes discovery provenance |
| Slug for open questions | `DMARC` |
| Last updated | 2026-08-24 |

## Problem

The application already advertises RFC 9989 conformance. `js/dns.js` implements
the full DMARCbis tag vocabulary at [`js/dns.js:558`](../../js/dns.js), handles
`t=` test mode, `psd=`, `sp`/`np` inheritance, case-insensitive anchored tag
parsing, DMARC URI list parsing with size-limit suffixes, and external report
authorization. The scoring rubric was already migrated off `pct=`. That is most
of the specification.

What is missing is discovery. RFC 9989 replaced the Public Suffix List with a
DNS Tree Walk for locating the Organizational Domain, and this application still
uses the PSL. `analyzeDomain()` at [`js/dns.js:1844`](../../js/dns.js) queries
`_dmarc.<domain>`, and on a miss makes exactly one more query at
`_dmarc.<organizational-domain>` where the organizational domain comes from
`getOrganizationalDomain()` at [`js/dns.js:246`](../../js/dns.js), which reads
the vendored PSL snapshot in `js/public-suffixes.js`.

That approximation is wrong in three ways that matter. It reaches the wrong name
for any domain whose real DMARC boundary differs from its PSL boundary. It cannot
observe a policy published at an intermediate level, so `a.b.c.example.com`
inheriting from `b.c.example.com` is invisible. And it cannot honor `psd=`,
which exists precisely so the walk knows where to stop without consulting a
list maintained outside DNS.

Two smaller defects sit alongside it. Record selection at
[`js/dns.js:1846`](../../js/dns.js) filters TXT strings with
`startsWithCI(v, 'v=DMARC1')`, so a record written as `p=reject; v=DMARC1` is
never selected and is reported as if no record exists. `validateDmarcVersion()`
at [`js/dns.js:601`](../../js/dns.js) already knows how to say `not-first`, but
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
  [`js/dns.js:1334`](../../js/dns.js) is untouched. Discovery correctness will
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
[findings-and-remediation](findings-and-remediation.md) and exported as schema
fields by [report-comparison](report-comparison.md), so their names are frozen.
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
[`js/dns.js:1856`](../../js/dns.js), which overwrites `policy` with
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
  established by `optionalCheck()` at [`js/dns.js:180`](../../js/dns.js) an
  unknown control must never be presented as an absent one. This holds even when
  a record was already collected at a lower step: a transient error means the
  higher names could not be examined, so the *highest* record is not knowable.
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
`DMARC1` per [`js/dns.js:601`](../../js/dns.js) and case-insensitive on the tag
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
score zero at [`js/dns.js:1371`](../../js/dns.js).

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
name at [`js/dns.js:1819`](../../js/dns.js), and `nsResult.status === 3` is
already the unregistered-domain test. The existence verdict should be derived
from those existing responses rather than adding a query. See `OQ-DMARC-02` for
which record type is authoritative for this purpose.

The consequence for scoring is deliberately conservative: when the audited name
exists, `effectiveSp` governs and `effectiveNp` is reported but not applied. When
existence is `unknown`, the weaker of the two continues to govern, matching the
existing weakest-link rule at [`js/dns.js:1349`](../../js/dns.js).

### 5. Stricter tag validation

`analyzeDmarc()` gains no new tags, but the following move from parsed-and-
reported to explicitly diagnosed. Each produces a token on the status object, not
an English string.

| Tag | Additional validation |
| --- | --- |
| `p` | An unrecognized value already forces `malformed`. Add the raw value to the status so the message can name it. |
| `sp`, `np` | Same treatment: an unrecognized value is currently silently normalized to `null` by `normalizePolicy()` and then inherits. Distinguish "absent, inherits" from "present but unrecognized". |
| `adkim`, `aspf` | Currently any value other than `s` becomes `r` at [`js/dns.js:715`](../../js/dns.js). Distinguish `absent`, `r`, `s`, and `invalid`. |
| `t` | `tValid` exists. Surface it as a finding rather than only as a field. |
| `psd` | `psdValid` exists. A `psd=y` on a name that is plainly not a public suffix is worth naming. |
| `fo` | `foValid` exists. Add the existing "fo without ruf is a no-op" observation as a first-class finding. |
| `rua`, `ruf` | `parseDmarcUriList()` already distinguishes malformed syntax from an unsupported scheme. Surface both distinctly. |
| unknown tags | `unknownTags` exists and is unused by the interface. Report them as informational; RFC 9989 requires receivers to ignore unknown tags, so this is not an error. |

### 6. External report authorization

`checkExternalReportAuth()` at [`js/dns.js:828`](../../js/dns.js) is close to
correct and needs three tightenings.

First, the authorization record must have `v=DMARC1` as its **first** tag, which
is what RFC 9990 §4.3 requires and what the comment at
[`js/dns.js:815`](../../js/dns.js) already states. The check uses
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
[`js/dns.js:1938`](../../js/dns.js). Once the Tree Walk lands, the correct value
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
[`js/app.js:494`](../../js/app.js), showing the found-at name, the number of
steps, and the termination reason. The existing `dmarc.inheritedFrom` message is
kept and extended.

The CSV export at [`js/app.js:737`](../../js/app.js) gains columns for
`dmarc_found_at`, `dmarc_labels_up` and `dmarc_discovery_terminated`. Note the
positional-header backfill logic at [`js/app.js:744`](../../js/app.js): new
columns must be appended, never inserted, and `locales/en.json` `csv.headers`
defines the column count.

## Localization impact

New keys are required for the diagnostic tokens in section 3, the tag-validation
findings in section 5, the discovery evidence line, and the three CSV headers.
Estimated 20 to 30 new keys under `issue.*`, `dmarc.*` and `csv.headers`.

All thirteen locales are translated in the same change per
[`AGENTS.md`](../../AGENTS.md). `npm run build:fallback` runs after the
`locales/en.json` edit. `npm run locale:gate` must report 13/13 before the pull
request opens. Protocol tokens (`v=DMARC1`, `p=`, `sp=`, `np=`, `psd=`, `t=y`,
`_dmarc`, `_report._dmarc`) are never translated.

## Testing

Discovery is tested against a fixture resolver rather than the network, with
**no production code change**. Per `OQ-DMARC-03` the mechanism is a programmable
`fetch` in the test sandbox: the sandbox already stubs `fetch` to return
`{ok: false}` at [`tools/scoring.test.mjs:15`](../../tools/scoring.test.mjs), and
this replaces that stub with one that pattern-matches the DoH query string and
returns a canned DoH JSON body.

The helper lives in `tools/lib/doh-fixture.mjs` rather than inline, because
[dns-protocol-depth](dns-protocol-depth.md) and [dnssec-evidence](dnssec-evidence.md)
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
2. `discovery.terminated` is never `error` with a non-null `applied`, and never
   reports a value outside `psd-y` / `psd-n` / `root` / `error`. Finding a record
   and encountering a duplicate are not termination reasons, and neither is
   exhausting the query budget — that cannot happen.
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
[`js/dns.js:65`](../../js/dns.js) is keyed on name and type and already
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
| OQ-DMARC-03 | How is a fixture resolver injected into `js/dns.js`? | A programmable `fetch` in the test sandbox that pattern-matches the DoH query string. No production code change, and the test stays honest about the wire format. Approved by Ian 2026-08-24, with the downstream consumers in mind: [dns-protocol-depth](dns-protocol-depth.md) and [dnssec-evidence](dnssec-evidence.md) reuse this mechanism, so the fixture helper is written to be shared rather than inlined in this release's test file. A `__setTransport()` hook was rejected as a production seam existing only for tests; extracting the transport was rejected as a refactor this release's non-goals exclude. | 1.0 |
| OQ-DMARC-04 | Does the PSL stay after the Tree Walk lands? | **No — both call sites switch to the Tree Walk.** Approved by Ian 2026-08-24. RFC 9990 defines the externality test in terms of the Organizational Domain, which after this release means the Tree Walk result, and carrying two definitions of "organizational domain" in one codebase is the kind of ambiguity that produces a wrong answer years later. The cost is accepted and must be measured, not estimated: the externality test now walks the *destination's* tree, so the query fan-out rises beyond what this spec originally anticipated. `PRIVACY.md`'s stated fan-out is updated from a measured backtest before merge. | 1.0 |
| OQ-DMARC-05 | What is the verdict when a report destination publishes multiple authorization records? | Not ambiguous, contrary to the 0.1 text. RFC 9990 §4 step 6 discards records that fail parsing, and step 8 states: *"If at least one TXT resource record remains in the set after parsing, then the external reporting arrangement was authorized by the Report Consumer."* Multiple authorization records are therefore **authorized** so long as one parses. This is the opposite of the conservative reading the draft leaned toward, and it is not a judgement call — the permissive reading is the normative one. Note this differs deliberately from the DMARC *policy* rule, where duplicates are discarded; the two questions are asked at different names for different purposes. | 1.0 |
| OQ-DMARC-06 | Should discovery evidence be shown by default or on demand? | The middle option, confirmed. The found-at line always shows; the full step list appears only when `labelsUp > 0` or `terminated` is not `root`, and is behind a disclosure control otherwise. The step list is what makes a surprising result explicable and is noise the rest of the time. | 1.0 |
| OQ-DMARC-07 | Does `psd=y` change the score? | No, in this release. `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` stay byte-identical, per the advisory-before-scoring rule: a new signal reports for at least one release before it affects a grade. Whether a correct `psd=y` earns credit, or an incorrect one costs it, is referred to [findings-and-remediation](findings-and-remediation.md) (0.6.0), which owns severity. Recorded there rather than left as a verbal note. | 1.0 |

**Scores will move in this release, and that is expected.** 0.3.0 is a
discovery-only change: no rubric, weight or threshold is touched, but a domain
whose policy is found at a different name than the PSL previously chose will
score differently, and a domain with duplicate records at one name may now
inherit a valid policy from higher in the tree where it previously scored zero.
The backtest is run and the movement reported in the pull request rather than
suppressed — this is the case [report-comparison](report-comparison.md)'s
`OQ-CMP-06` exists to describe.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
| 1.0 | 2026-08-24 | Final. Resolved all seven open questions. Two corrections came out of transcribing RFC 9989 §4.10 rather than trusting the draft: the label threshold is **eight**, not five (five was an early DMARCbis draft), and the walk selects the **highest** name carrying a record, not the first one found going up — first-match would report the wrong policy domain for exactly the delegated-subdomain case DMARCbis exists to serve. Consequent changes: `applied.foundAt`/`applied.labelsUp` keep their names and are defined as the location of the applied record, `policyDomain` is added as an alias, `organizationalDomain` stays separate and is the highest name with a record; duplicate records at a step are discarded and the walk continues rather than terminating as `multiple`, with the duplicate kept as diagnostic evidence and the critical finding raised from that evidence; and the `terminated` vocabulary now describes how the walk ended (`psd-y`, `psd-n`, `root`, `query-limit`, `error`) rather than what was found in it. `OQ-DMARC-05` was resolved against RFC 9990 §4 step 8, which is explicit where the draft called it ambiguous. Corrections contributed by external review (Codex). |
| 1.1 | 2026-08-24 | Consistency pass over the 1.0 text before implementation, after external review (Codex) found six places where 1.0 still contradicted its own resolutions. Removed the non-goal claiming the PSL stays for `findExternalReportDestinations()`, which `OQ-DMARC-04` had already moved to the Tree Walk. Rewrote section 6's duplicate-authorization rule, which still proposed a `multiple` state after `OQ-DMARC-05` resolved to "authorized when at least one record parses", and corrected the matching fixture. Replaced the testing section's `__setResolver`/transport-injection proposal with the resolved programmable sandbox `fetch` helper. Removed `query-limit` from `terminated`: the eight-query bound is achieved by the shortening rule and labels always run out exactly at the budget, so it is not a reachable outcome. Corrected `organizationalDomain` to RFC 9989 §4.10.2's three-rule selection — `psd=n` wins outright, `psd=y` puts the Organizational Domain one label below (a name that may carry no record), and only otherwise is it the fewest-labels record — with the initial target as the normative fallback, so the field is never null. Added the requirement that a duplicate finding never claims no policy applies when one does. |
