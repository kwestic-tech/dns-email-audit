# Spec: DMARCbis Tree Walk and complete RFC 9989 discovery

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | 0.3.0 |
| Status | Awaiting review |
| Depends on | [rendering-and-robustness](implemented/rendering-and-robustness.md) (0.2.3), because this release adds new rendered evidence |
| Blocks | [findings-and-remediation](findings-and-remediation.md), which consumes discovery provenance |
| Slug for open questions | `DMARC` |
| Last updated | 2026-08-20 |

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
- No removal of the vendored PSL. It stays for
  `findExternalReportDestinations()` and for hosting and provider heuristics. See
  `OQ-DMARC-04`.
- No aggregate or failure report parsing. RFC 9990 and RFC 9991 report ingestion
  is out of scope for the browser tool.

## Design

### 1. Layer separation

Discovery becomes its own function with no parsing and no scoring inside it.

```js
async function discoverDmarc(domain, queryOpts) → {
  applied: {            // the record receivers will actually use, or null
    record: string,
    foundAt: string,    // the DNS name whose _dmarc held it
    labelsUp: number,   // 0 when published at the audited name itself
    inherited: boolean, // foundAt !== domain
  } | null,
  organizationalDomain: string | null,  // per the Tree Walk, not the PSL
  psdBoundary: string | null,           // name that declared psd=y, if any
  steps: [{ queryName, kind, txtCount, dmarcCount, selected }],
  terminated: 'found' | 'psd' | 'root' | 'query-limit' | 'multiple' | 'error',
  queries: number,
  observed: [{ queryName, record, why }],  // diagnosis-only, see section 3
  error: string | null,
}
```

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

The walk queries `_dmarc.<name>` at the audited name and then at successively
shorter suffixes, stopping at the first name that yields exactly one valid
record, at a name that declares `psd=y`, at the configured query limit, or when
no shorter name remains.

The exact label arithmetic, the query budget, and the treatment of names with
more than five labels are normative in RFC 9989 and **must be transcribed from
the RFC text rather than reconstructed from memory or from another
implementation**. See `OQ-DMARC-01`. This spec fixes the interface and the
evidence; it does not restate the numbers.

Implementation constraints that are settled:

- Each step records `queryName`, the response `kind` from `dohFetch()`, how many
  TXT strings came back, how many were DMARC records, and whether that step's
  record was selected. This array is the evidence trail and is what the interface
  shows.
- A step returning `servfail`, `timeout`, `network-error` or `http-error`
  terminates the walk with `terminated: 'error'` and `applied: null`. A failed
  lookup is not a missing record. The result is `unknown`, and per the pattern
  established by `optionalCheck()` at [`js/dns.js:180`](../../js/dns.js) an
  unknown control must never be presented as an absent one.
- A step at which more than one valid record exists terminates the walk with
  `terminated: 'multiple'`. RFC 9989 §4.7 stops policy discovery entirely in that
  case, which is already why `analyzeDmarc()` returns `permerror` for the
  multiple case at [`js/dns.js:660`](../../js/dns.js).
- Every step goes through `dohFetch()` and therefore through the existing cache,
  concurrency limiter and retry logic. A 200-domain audit of subdomains of the
  same parent will hit the cache for the shared upper steps.
- `psd=y` at a step means that name is a Public Suffix Domain. The walk stops
  there and the record is not inherited downward as an ordinary organizational
  policy. `psd=u` is the default and means continue normally. `psd=n` means the
  name is explicitly not a PSD.

### 3. Record selection and misplaced version tags

Selection runs in two passes at each step.

The **strict pass** is what determines policy. Keep TXT strings that begin with
`v=DMARC1` after leading-whitespace trimming, case-sensitive on the value
`DMARC1` per [`js/dns.js:601`](../../js/dns.js) and case-insensitive on the tag
name `v`. If exactly one survives, it is the record. If more than one survives,
terminate with `multiple`. This is unchanged behavior and is what conformant
receivers do.

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
taking `match[0]`. Decide and document the rule: this draft treats more than one
as a `multiple` state, reported distinctly from `unauthorized`, on the same
reasoning that makes duplicate policy records a `permerror`. See `OQ-DMARC-05`.

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

Discovery is tested against a fixture resolver rather than the network. Add a
`__setResolver` hook or an injectable transport to `js/dns.js` so
`tools/scoring.test.mjs` can register a name-to-response map. The current test
sandbox already stubs `fetch` to return `{ok: false}` at
[`tools/scoring.test.mjs:15`](../../tools/scoring.test.mjs); this replaces that
stub with a programmable one. See `OQ-DMARC-03`.

Fixture matrix, each asserting `applied.foundAt`, `labelsUp`, `terminated`,
`queries`, and the resulting `policy` and `effectivePolicy`:

| Fixture | Expectation |
| --- | --- |
| Policy at the audited name | `labelsUp: 0`, not inherited, `p` governs |
| Policy one level up | inherited, `sp` governs the audited name |
| Policy several levels up | walk reaches it, step count recorded |
| Deep name beyond the label threshold | matches the RFC's shortcut behavior exactly |
| `psd=y` encountered mid-walk | `terminated: 'psd'`, no inheritance below it |
| `psd=n` mid-walk | walk continues |
| Two valid records at one step | `terminated: 'multiple'`, status `permerror` |
| SERVFAIL mid-walk | `terminated: 'error'`, `applied: null`, unknown not absent |
| No record anywhere | `terminated: 'root'`, status `missing` |
| `p=reject; v=DMARC1` | `observed[].why === 'version-not-first'`, still `missing` for policy |
| `v=dmarc1; p=reject` | `version-bad-case`, still `missing` |
| `v=DMARC1; p=reject` at the apex TXT set | `at-apex-not-underscore` |
| Existing subdomain with `np=none` | `sp` applies, `np` reported not applied |
| NXDOMAIN subdomain with `np=none` | `np` applies |
| Cached upper steps | second subdomain of the same parent issues fewer queries |
| External report auth, wildcard only | `via: 'wildcard'`, `authorized` |
| External report auth, two records | new `multiple` state |
| External report auth, `v=DMARC1x` | `unauthorized`, `malformed: true` |

Add a PSL-versus-Tree-Walk divergence table: a fixture list of names where the
two disagree, asserting the Tree Walk answer, so a future PSL refresh cannot
silently change DMARC behavior.

Run `node tools/backtest.mjs domains.txt --json` at `v0.2.3` and at the release
candidate and diff. Any domain whose grade moves must be explainable by a
discovery difference and listed in `CHANGELOG.md`.

## Acceptance criteria

1. Every fixture above passes deterministically with no network access.
2. `discovery.terminated` is never `found` with `applied: null`, and never
   `error` with a non-null `applied`.
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

**OQ-DMARC-01: Who transcribes the normative Tree Walk parameters, and against
what text?**
This spec deliberately does not restate the label counts, the query budget, or
the handling of names longer than the threshold, because getting them from
memory or from a third-party implementation is how subtle protocol bugs are
born. The implementer needs the RFC 9989 text open. The question for review is
procedural: should the pull request include a verbatim quotation of the relevant
subsection in a code comment so a reviewer can check the implementation against
the text without leaving the diff? This draft says yes.

**OQ-DMARC-02: Which query answers the domain-existence question?**
RFC 9989 defines subdomain existence for the `np=` branch. `analyzeDomain()`
already holds NS, MX, TXT, A and AAAA responses for the audited name, and
`nsResult.status === 3` already gates the unregistered case at
[`js/dns.js:1822`](../../js/dns.js). Is NXDOMAIN on the NS query sufficient
evidence of non-existence for this purpose, or does the existence test need its
own query of a different type? Note that a name with only a TXT record exists for
DNS purposes but has no NS record of its own.

**OQ-DMARC-03: How is a fixture resolver injected into `js/dns.js`?**
The file is a plain IIFE attached to `window` with `DOH` and `dohFetch` exported
for testing. Options: export a `__setTransport(fn)` hook used only by tests;
have the test sandbox provide a programmable `fetch` that pattern-matches on the
DoH query string; or extract the transport into its own file that the test loads
separately. The second option requires no production code change at all and
keeps the test honest about the wire format, at the cost of the test knowing the
DoH JSON shape. This draft prefers the programmable `fetch`. Which?

**OQ-DMARC-04: Does the PSL stay after the Tree Walk lands?**
`getOrganizationalDomain()` is used by DMARC discovery today, and also by
`findExternalReportDestinations()` at [`js/dns.js:795`](../../js/dns.js) to
decide whether a report destination is external. RFC 9990 defines that test in
terms of the Organizational Domain, which after this release means the Tree Walk
result. Do we switch that call site too, accepting extra queries against the
destination's own tree, or keep the PSL for the externality test only? Keeping
both means the codebase carries two definitions of "organizational domain",
which needs to be named clearly in comments if we do it.

**OQ-DMARC-05: What is the verdict when a report destination publishes multiple
authorization records?**
The DMARC policy rule is unambiguous: multiple records mean discovery
terminates. RFC 9990 authorization records are a different query at a different
name and the spec is less explicit. Treating duplicates as `multiple` and
therefore not authorized is the conservative reading and matches how the tool
handles every other duplicate. Treating them as authorized if any one of them is
valid is the permissive reading. Which do we implement, and do we say which
reading it is in the message?

**OQ-DMARC-06: Should discovery evidence be shown by default or on demand?**
The step list is genuinely useful when a policy is not where someone expects it
and is noise the other 95 percent of the time. Options: always show the found-at
line and put the full step list behind a disclosure; show the step list only when
`labelsUp > 0` or `terminated !== 'found'`; or always show everything. This draft
takes the middle option. Confirm.

**OQ-DMARC-07: Does `psd=y` change the score?**
A domain that correctly declares itself a public suffix domain is doing
something responsible that nothing currently rewards, and a domain that
incorrectly declares `psd=y` is misrepresenting its position in the tree. Neither
affects the score in this draft, on the principle that scoring changes are
separately versioned. Should either become a finding in 0.6.0, and if so at what
severity?

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
