# Spec: Stateless report export and comparison

| Field | Value |
| --- | --- |
| Spec version | 1.2 (Final, amended) |
| Target release | 0.9.0 |
| Status | Approved for implementation |
| Depends on | [findings-and-remediation](implemented/findings-and-remediation.md), which defines finding identity, plus the 0.8.0 decision on user-supplied artifact findings |
| Blocks | Nothing |
| Slug for open questions | `CMP` |
| Last updated | 2026-09-03 |

## Problem

The tool answers "what is the state of these domains right now" and cannot answer
"what changed". Both existing exports are terminal. `exportCSV()` in
[`src/ui/report.js`](../../src/ui/report.js) writes localized, human-readable strings into
positional columns and flattens findings into a single pipe-joined cell.
`exportHTML()` in the same module writes a static document with
the stylesheet inlined. Neither can be read back, and neither should be: parsing
localized display text back into structured data would break the moment someone
exported in a different language.

The consequence is that the tool cannot support its most obvious repeat use.
Someone who audits their estate monthly, fixes things, and audits again has no
way to see that eleven domains improved, two regressed, and one newly appeared.
They compare two spreadsheets by eye.

The constraint that shapes the solution is that nothing may be stored by the
application. The tool's privacy claim rests on results never being transmitted
and never being written to application-managed storage. Server-side history is
out of the question, and browser-side history would contradict `PRIVACY.md`,
which currently states that `localStorage` holds at most one key, the language
preference. A user-initiated download is distinct: the user holds the files,
supplies two, and gets a diff that exists only until the page reloads.

## Scope

1. A versioned JSON report schema carrying normalized evidence, not display text.
2. Export of that schema alongside the existing CSV and HTML exports.
3. Strictly validated import with size and structure limits.
4. In-memory comparison of two reports.
5. New, resolved, regressed, improved, changed and unchanged classification, with
   per-protocol comparability so an unobserved protocol is never reported as
   fixed, and cross-version qualification so analyzer evolution is never
   reported as domain drift.
6. No persistence of any report or comparison.

## Non-goals

- **No HTML import.** Only the JSON schema is accepted. The exported HTML report
  is a human artifact and is never parsed back.
- **No persistence.** No `localStorage`, no `IndexedDB`, no cache, no service
  worker. Reloading the page discards everything.
- **No network.** Reports come from the user's file picker. No upload, no
  download from a URL, no sharing feature.
- **No trend analysis across three or more reports.** Two at a time
  (`RQ-CMP-05`).
- **No integrity field.** The report is neither checksummed nor signed
  (`RQ-CMP-03`).
- **No scoring change.**

## Design

### 0. Architecture and implementation boundary

The report feature uses the shipped module graph rather than adding an import
from UI back into the audit engine:

| Responsibility | Owner |
| --- | --- |
| Pure schema validation, upgrade functions and report comparison | new `src/ui/report-data.js` |
| JSON construction/download and the existing CSV/HTML exports | `src/ui/report.js` |
| Import controls, comparison mode and rendering | `src/ui/events.js` |
| `ANALYSIS_VERSION` | `src/audit/scoring.js`, carried in audit output or injected capabilities |
| `APP_VERSION` | `src/runtime.js`, injected into the UI with the other runtime capabilities |

Both new UI modules remain within the existing `ui/` sibling edge. The UI must
not import `src/audit/scoring.js`; the composition boundary passes version
metadata with completed audit facts.

Implementation is split into directory-bound commits, in this order, because
each is a different owner and two of them can move a published surface:

1. `src/audit/` — `ANALYSIS_VERSION` and the closed per-protocol observability
   facts carried in audit output. No UI change and no scoring change.
2. `src/runtime.js` — `APP_VERSION`, pinned to `package.json`, and injection of
   both version values into the UI. No UI behavior change.
3. `src/ui/report-data.js` — pure schema, validation and comparison. No DOM.
4. `src/ui/report.js` — `exportJSON()` beside the existing two exports.
5. `src/ui/events.js` — import controls, comparison mode, rendering, filters.
6. `locales/en.json` and all thirteen translations.

### 1. The report schema

The schema is a **named projection of the result object, not a dump of it.**
That distinction is the whole of section 1: a dump would export display state,
locale routing, unrelated TXT records and the query trace, and would exceed this
release's own import limit (`RQ-CMP-01`, `RQ-CMP-02`).

```json
{
  "schema": "dns-email-audit/report",
  "schemaVersion": 1,
  "generatedAt": "2026-08-20T04:12:00.000Z",
  "generator": { "version": "0.9.0", "analysisVersion": 1 },
  "resolver": "https://cloudflare-dns.com/dns-query",
  "options": { "dkim": true, "dkimComprehensive": false, "www": true,
               "wildcard": false, "advanced": true, "deepChecks": true,
               "selectors": [] },
  "domains": [
    {
      "domain": "example.com",
      "organizationalDomain": "example.com",
      "state": "audited",
      "observability": { "spf": "observed", "dkim": "unproven",
                         "dmarc": "observed", "dnssec": "observed",
                         "caa": "observed", "mta-sts": "observed",
                         "tls-rpt": "observed", "bimi": "observed",
                         "mx": "observed", "dane": "observed",
                         "dns": "observed", "defensive": "observed",
                         "reporting": "observed" },
      "score": { "pts": 72, "max": 100, "grade": "A", "parked": false,
                 "unproven": ["dkim"],
                 "pillars": [{ "key": "dmarc", "pts": 25, "max": 30 }] },
      "dmarcDiscovery": { "foundAt": "example.com", "labelsUp": 0,
                          "terminated": "root", "organizationalDomain": "example.com",
                          "policyDomain": "example.com", "psdBoundary": "" },
      "records": {
        "ns": [], "mx": [], "spf": [], "dmarc": [], "dkim": [],
        "bimi": [], "caa": [], "mtaSts": [], "tlsRpt": [], "tlsa": [],
        "dnskey": [], "ds": []
      },
      "findings": [
        { "id": "dmarc.policy-none", "protocol": "dmarc", "severity": "high",
          "confidence": "confirmed", "category": "policy", "effort": "moderate",
          "args": [], "dependsOn": [],
          "evidence": [{ "kind": "txt", "queryName": "_dmarc.example.com",
                         "value": "v=DMARC1; p=none" }] }
      ],
      "remediationPlan": [
        { "step": 1, "rationale": "foundation", "findings": [], "unblocks": [] }
      ]
    }
  ]
}
```

`state` is one of `audited`, `unregistered` or `error`, projected from the
result's `unregistered` and `error` flags. An `unregistered` or `error` domain
carries no `observability`, `score`, `dmarcDiscovery`, `records`, `findings` or
`remediationPlan`.

The example above is structural, but its path set is normative. `records`
contains only the named keys shown. Every member is an array of normalized record
entries `{ queryName: string, value: string }`; `tlsa` entries additionally carry
`authenticated: boolean`, and DKIM entries additionally carry `selector: string`,
`keyType: string | null` and `keyBits: integer | null`. Every added field is
required on that record kind. Absence is an empty array, never an omitted key.
Entries are deduplicated by their complete value tuple and sorted
lexicographically by that tuple before export and comparison, so resolver answer
order cannot create a record change. No internal `advanced`, `dkimStatus`,
parser, detector or display object crosses this boundary.

The rest of the scalar contract is closed too:

| Path | Type or allowed values |
| --- | --- |
| `schema` | Literal `dns-email-audit/report` |
| `schemaVersion`, `generator.analysisVersion` | Positive integers |
| `generatedAt` | UTC RFC 3339 timestamp in canonical `YYYY-MM-DDTHH:mm:ss.sssZ` form |
| `generator.version` | Canonical `major.minor.patch` release string |
| `resolver` | HTTPS URL string |
| `options.dkim`, `dkimComprehensive`, `www`, `wildcard`, `advanced`, `deepChecks` | Booleans |
| `options.selectors` | Array of syntactically valid selector strings, sorted and deduplicated |
| `domain`, `organizationalDomain` | Normalized ASCII domain strings |
| `state` | `audited`, `unregistered`, `error` |
| `observability.*` | `observed`, `unproven`, `not-run` |
| `score.pts`, `score.max`, `score.pillars[].pts`, `score.pillars[].max` | Finite non-negative numbers |
| `score.grade` | `A++`, `A+`, `A`, `B`, `C`, `D`, `F` |
| `score.parked` | Boolean |
| `score.unproven`, `score.pillars[].key` | Arrays/members of `spf`, `dmarc`, `dkim`, `dnssec`, `caa`, `mtaSts`, `bimi`, `tlsRpt` |
| `dmarcDiscovery.foundAt`, `policyDomain`, `psdBoundary` | Normalized ASCII domain string or `null` |
| `dmarcDiscovery.labelsUp` | Non-negative integer or `null` |
| `dmarcDiscovery.organizationalDomain` | Normalized ASCII domain string |
| `dmarcDiscovery.terminated` | `root`, `error`, `psd-y`, `psd-n` |
| `findings[].id`, `dependsOn[]`, `remediationPlan[].findings[]`, `unblocks[]` | Finding-id strings |
| `findings[].protocol` | One of the thirteen `PROTOCOLS` tokens listed in `observability` |
| `findings[].severity` | `critical`, `high`, `medium`, `low`, `info` |
| `findings[].confidence` | `confirmed`, `probable`, `unverified` |
| `findings[].category` | `authentication`, `policy`, `reporting`, `transport`, `issuance`, `resilience`, `hygiene` |
| `findings[].effort` | `trivial`, `moderate`, `involved` |
| `findings[].args` | Array of strings, numbers or booleans |
| `findings[].evidence[]` | `{ kind, queryName: string, value: string }`, where `kind` is `txt`, `absent`, `selector`, `host`, `mx`, `address`, `cname`, `caa`, `dnssec`, `tlsa`, `mechanism` or `info` |
| `remediationPlan[].step` | Positive integer, unique and contiguous from 1 |
| `remediationPlan[].rationale` | `foundation`, `afterPrereq`, `cleanup` |

All arrays not otherwise qualified are required and may be empty. All object
members shown in the example or table are required for an audited domain; no
additional members are allowed. A bidirectional schema test asserts both that
every emitted path is in this list and that every listed path is reached by a
fixture; the compatibility surface cannot be widened accidentally by object
spread.

`observability` is a total map over `PROTOCOLS`. Each value is exactly
`observed`, `unproven` or `not-run`. It is produced by `src/audit/` from the
finished facts and options, not reconstructed by the UI from finding text or
confidence. Cross-protocol tokens are conservative: `defensive` is observed only
when MX and SPF are observed, and `reporting` only when DMARC and TLS-RPT are
observed.

#### What is excluded, and why

Every exclusion below is a decision. An implementation that adds one of these
fields back has changed the schema, not fixed an omission.

| Excluded | Reason |
| --- | --- |
| `score.cls`, `dmarcStatus.cls` | CSS class names. Display state, not a fact about the domain. |
| `finding.key`, `finding.keyspace` | Locale-lookup routing. `id` is the identity 0.7.0 froze; `key` resolves a translation and is explicitly decoupled from `id`. Exporting it would invite a future importer to compare on it. |
| `finding.noteKey`, `finding.noteArgs` | Display note routing, same reason. |
| `finding.blocks` | Derived — the inverse of the resolved `dependsOn` within one run. Recomputed on import, never carried. |
| `txt`, `verifications` | **Privacy.** These carry every TXT record at the apex, including `google-site-verification=`, `atlassian-domain-verification=` and every other vendor token. A report is made to be handed to a colleague, an auditor or a vendor; handing over the domain's third-party SaaS inventory is not what the recipient asked for and has nothing to do with email posture. `spf` and `spfRecords` carry the TXT material the audit actually reasons about. |
| `dmarcDiscovery.queries`, `dmarcDiscovery.steps` | The Tree Walk query trace. Large, and provenance for one run rather than a comparable fact. `foundAt`, `labelsUp` and `terminated` are the tokens the CSV already publishes. |
| `aRec`, `aaaaRec`, `hosting`, `dnsProvider`, `emailProvider` | Website and provider heuristics. `dnsProvider`/`emailProvider` are DNS-derived labels resolved through a detector table; they are display attribution, and 0.8.1 had to sentinelise them for exactly that reason. |
| `issues`, `suggestions`, `advScore` | Legacy surfaces superseded by `findings` and `remediationPlan`. Kept in the result as a stable field and a CSV column source; comparing them would compare localized keys. |
| Artifact findings | `RQ-CMP-07`. No field, and no reserved field. |

#### Three properties that matter

**No display text.** Every finding is an id. Every state is a token. Two reports
of the same audit exported in Japanese and in German are byte-identical, which is
what makes cross-language comparison possible and what stops the schema from
drifting with the locale files.

That property depends on `generatedAt` being the **moment the audit run
completed**, captured once and reused by every export of that run — not the
moment the file was written. As export time it would differ between two exports
of one audit and acceptance criterion 4 would be untestable. No such timestamp
exists in the result today; it is UI run state, owned by `src/ui/events.js`, and
is added there rather than in audit output.

**`analysisVersion` is explicit.** See section 2.

**`options` is recorded.** A report generated without the DKIM check and a report
generated with it are not comparable on DKIM. The comparison detects mismatched
options and applies the closed protocol mapping in section 5 rather than
reporting a phantom regression.

`schemaVersion` is an integer. An importer accepts its own version and any
earlier version it has an explicit upgrade path for, and rejects anything newer
with a clear message rather than attempting a partial parse.

### 2. `analysisVersion`

A single integer, owned by `src/audit/scoring.js`, that gates **the score delta
and nothing else** (`RQ-CMP-06`).

It is bumped in the same commit as any change that can move a score. That is
broader than the rubric:

- `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS`, `calcDmarcScore()`,
  `calcSpfScore()`, `calcAdvScore()`, `calcScore()`; **and**
- any discovery or detection change that moves a score without touching those.
  0.3.0 is the confirmed instance: replacing the Public Suffix List with the
  RFC 9989 Tree Walk moved scores with `WEIGHTS`, `PARKED_WEIGHTS` and
  `GRADE_THRESHOLDS` untouched.

Two guards, and the second matters more than the first:

1. A test hashes the source text of the scoring constants and functions and
   compares against a committed value. A mismatch fails with a message saying to
   bump `analysisVersion`. **This catches only the rubric half.** A hash of
   `scoring.js` cannot see a Tree Walk landing in `src/core/dmarc/`.
2. `AGENTS.md` already requires a backtest of anything that can move a grade or
   score. This spec adds the consequence: **a backtest that shows grade or score
   movement requires an `analysisVersion` bump in the same release**, and the
   release notes say which of the two causes it was.

What `analysisVersion` deliberately does **not** gate is the raw finding-id diff.
A version that hid that diff would make the feature useless in its commonest
case — audit in March, audit again in September, two releases later. Stable ids
establish identity, not identical detector semantics, so section 5 qualifies
finding movement whenever generator versions differ. An unknown id is displayed
by id, and a renamed id ships with an alias map (see Risks).

`APP_VERSION` in `src/runtime.js` is separate. It supplies human context and the
conservative `findingSemanticsMatch` comparison. The package version currently
reaches only the bundle's comment banner in
[`tools/build-bundle.mjs`](../../tools/build-bundle.mjs), so the runtime gains a
hand-maintained exported constant bumped by the release commit and asserted
equal to `package.json`. This uses the existing composition owner and import
edges; it does not invent a root module absent from the architecture matrix.

### 3. Export

`exportJSON()` sits beside the existing two export buttons in
[`index.html`](../../index.html). It builds the structure from the in-memory
`results` array and downloads it through the existing download capability
already passed into `src/ui/report.js`.

The exported filename includes a UTC date so two exports do not collide in a
downloads folder: `dns-email-audit-2026-08-20.json`.

Conservative size bound, from
[`fixtures/report-size-measurement-0.9.0.md`](fixtures/report-size-measurement-0.9.0.md):
the broader 1.0 candidate projection, which still carried the internal
`advanced` and `dkimStatus` objects, measured 6,103 bytes per domain and **1.16
MiB at the 200-domain maximum**, against an 8 MiB import limit. The normalized
1.1 record projection is a subset, so this is an upper bound for the same corpus,
not a claim about the implementation's exact output. The implementation reruns
the measurement against what it emits.

### 4. Import and validation

Import is the entire attack surface of this release, since the file is
attacker-supplied by construction: a hostile report could be handed to someone as
"last month's audit".

```js
function parseReport(text) → { ok: true, report } | { ok: false, errors: [] }
```

Enforced in order, each failing closed:

| Limit | Value | Derivation |
| --- | --- | --- |
| Byte length before parse | 8 MiB | ~7x the measured 200-domain export |
| `domains` array length | **200** | `MAX_DOMAINS` in `src/ui/events.js` |
| `findings` per domain | 200 | |
| `evidence` per finding | 20 | |
| Object nesting depth | 8 | |
| `schema` value | Exactly `dns-email-audit/report` | |
| `schemaVersion` | Integer, at most the current version | |

The domain limit is 200 rather than a round 1000 because **this tool cannot
produce a report with more than 200 domains in it**. An importer that accepts
more accepts a file this application could not have written. The limit is
imported from the same constant the run enforces, not restated, so the two
cannot drift.

The byte check runs against `File.size` before `FileReader` does any work,
which is the pattern 0.8.0 already established for supplied artifacts in
`src/ui/events.js`.

Validation is a hand-written structural walk, not a schema library, keeping the
runtime dependency-free. Every field is checked for type and range. Unknown
fields are dropped rather than carried, so a future field cannot smuggle content
through an older importer.

There is deliberately no arbitrary limit on every string. Domain names,
versions, tokens and other semantic strings keep their grammar-specific bounds;
record and finding-evidence values are bounded by the 8 MiB file limit and their
collection limits. The producer has no 4096-character DNS-record ceiling, so an
importer with one could reject a report the same build exported.

Two rules that are easy to get wrong and are not optional:

- **`JSON.parse` with a reviver that rejects `__proto__`, `constructor` and
  `prototype` as keys**, and every map built from imported material created with
  `Object.create(null)`. This is not a new discipline: 0.8.1 fixed exactly this
  class of defect for DNS-derived and locale keys, and `src/ui/events.js`,
  `src/core/transport/mta-sts.js` and `src/core/mx/mx.js` already carry the
  pattern. Follow the existing precedent rather than inventing a second one.
- **Every string from an imported report is rendered as a text node.** The 0.2.3
  renderer makes this the default rather than a discipline. Imported values are
  treated exactly like DNS values: untrusted input from a stranger.

A finding id in an imported report that the current build does not recognize is
displayed by id with a note that this build has no description for it, rather
than being dropped. That preserves the diff's completeness when comparing across
tool versions.

### 5. Comparison

```js
function compareReports(baseline, current) → {
  meta: {
    schemaVersionsMatch, analysisVersionsMatch, findingSemanticsMatch,
    optionsMatch,
    optionDifferences: string[],
    baselineGeneratedAt, currentGeneratedAt,
    baselineAppVersion, currentAppVersion,
  },
  domains: [{
    domain,
    status: 'added' | 'removed' | 'improved' | 'regressed' | 'changed' | 'unchanged' | 'incomparable',
    scoreDelta: number | null,
    scoreComparable: boolean,
    gradeChange: { from, to } | null,
    incomparableReasons: string[],
    incomparableProtocols: [{ protocol, reason, side }],
    findings: {
      new: [id], resolved: [id], unchanged: [id], unknown: [id],
      severityChanged: [{ id, from, to }],
    },
    recordChanges: [{ path, from, to }],
  }],
  summary: { added, removed, improved, regressed, changed, unchanged, incomparable },
}
```

Domain identity is the domain name. Finding identity is the finding `id`, which
is why 0.7.0's stable id namespace is a hard prerequisite: comparing on locale
keys or on message text would report every finding as new the moment a
translation changed.

Status is deterministic, in this order:

1. A domain present on only one side is `added` or `removed`.
2. A state mismatch, no comparable protocol, or only incomparable movement is
   `incomparable`, with every cause in `incomparableReasons`.
3. Different generator versions with any finding or record movement are
   `changed`; the raw diff remains visible but makes no causal claim.
4. With matching generator versions, compare the highest-severity changed
   finding. At that severity, more resolved than new is `improved`, more new than
   resolved is `regressed`; a tie proceeds to the next severity. A severity
   increase is new at the higher severity and resolved at the lower severity;
   a decrease is the reverse.
5. If finding movement ties, a comparable positive score delta is `improved` and
   a negative delta is `regressed`.
6. Remaining comparable movement is `changed`; no movement is `unchanged`.

Thus a domain whose score is unchanged but which resolves a critical finding and
gains a low one is `improved`. Counts and ordering cannot change that answer.

#### Per-protocol comparability

A finding missing from the current report has two possible causes, and calling
both of them `resolved` tells someone a problem is fixed when it is not. This is
the same error `incomparable` exists to prevent, one level down.

The application produces the second cause routinely. 0.2.0's resilient optional
checks mean a failed lookup degrades one check rather than discarding the audit,
so a domain can be `audited` with one protocol unobserved. The finished audit
facts and options are projected by `src/audit/` into the closed `observability`
map in section 1. Finding confidence is not used as a proxy:
`dns.checks-unverified` names MX and TLSA in its evidence while its own protocol
is `dns`, and `dmarc.external-unverifiable` does not erase a successfully
observed DMARC policy.

Comparison then applies, per protocol and per side:

- a protocol other than `observed` on **either** side is `incomparable` for that protocol;
- its findings are reported as `unknown`, never as `new` or `resolved`;
- `incomparableProtocols` records the protocol, the reason and which side;
- the domain's own status is still decided from the protocols that **are**
  comparable, so one failed DKIM lookup does not blank the DMARC diff.

`scoreComparable` is false when `analysisVersion` differs, and `scoreDelta` is
then `null`. The score is a single number over all pillars, so an unproven scored
protocol also makes it unsafe. An unscored MX or DANE failure does not erase a
score comparison.

Options remain recorded as provenance, but mismatch is applied through a closed
mapping rather than blanking the domain: `dkim`, `dkimComprehensive` and
`selectors` affect `dkim`; `deepChecks` affects `mx` and `dane`; `wildcard`
affects `dns` and `dkim`; `www` affects `dns`; and `advanced` affects the five
dedicated advanced protocols — `dnssec`, `caa`, `mta-sts`, `tls-rpt` and
`bimi` — **and also `spf`, `dmarc` and `reporting`**. Selector arrays are sorted
and deduplicated before export and compare as sets.

That last clause is the 1.2 correction, and it is not a tidy-up. `advanced`
gates sub-audits on two protocols whose records are core queries:
`audit-domain.js` defaults `spfLookups`, `spfSubnets` and `reportAuth` to `null`
and populates them only inside `if (ctx.options.advanced)`. Nine finding ids
depend on those three facts — eight on `protocol: 'spf'` (`spf.over-limit`,
`spf.near-limit`, `spf.cycle`, `spf.large-subnet`, `spf.medium-subnet`,
`spf.redundant-mechanism`, `spf.partial-coverage`, `spf.indeterminate`) and
`dmarc.external-unverifiable`. Treating `spf` as observed with `advanced` off
would let a comparison across an `advanced` mismatch report all eight SPF
findings as `resolved`, which is the precise harm `RQ-CMP-08` exists to prevent,
in the protocol that carries the most findings.

`spf` and `dmarc` are still never `not-run`: their records are always retrieved.
With `advanced` off they are `unproven` — partially observed, which is exactly
what they are. And the distinction stays about whether a check RAN: an external
authorization result that ran and came back uncertain leaves `dmarc` `observed`,
because `dmarc.external-unverifiable` reporting uncertainty is not the same as
the check not happening.

A domain is `incomparable` outright when its state differs, no protocol remains
comparable, or every observed change belongs to an incomparable protocol. Global
analysis and option differences are also exposed in `meta`; per-domain causes
are carried in `incomparableReasons` rather than implied by `status` alone.

`findingSemanticsMatch` is true only when `generator.version` matches. When it is
false the id diff still runs, but its UI labels are “baseline only” and “current
only”, and domain status cannot be `improved` or `regressed`. This is deliberately
conservative: a release can add or correct advisory findings without moving a
score, so `analysisVersion` cannot establish finding equivalence.

`recordChanges` reports the raw record deltas: an SPF record that changed, a
DMARC policy that moved, a DKIM selector that appeared. This is often more
useful than the finding diff, because it shows what someone actually did. A
record path belonging to an incomparable protocol is omitted rather than shown as
a change.

### 6. Interface

Comparison mode is entered by importing a baseline report while results are on
screen, or by importing two reports with no audit running.

Comparison is an **overlay on the existing results table**, not a separate view
(`RQ-CMP-04`). The table gains a delta column and per-row change indicators, and
reuses the existing filter mechanism in `src/ui/events.js` with new filter values
for `improved`, `regressed`, `changed`, `added` and `removed`. Paired baseline
and current values go in the existing per-row detail row — the `.detail-row` element the
static report already expands — rather than doubling every cell in the main grid.

A comparison summary replaces the existing stats grid while in comparison mode.

An incomparable protocol is marked in the row, with its reason, using the same
visual treatment as the existing unproven-pillar grade marker. It is never
rendered as a zero delta.

Leaving comparison mode discards the imported report from memory. So does
reloading, which is the point.

## Localization impact

Roughly 40 to 50 new keys: export button, import controls, the seven comparison
statuses, the incomparable reasons, the per-protocol unknown state, delta labels,
the summary tiles, the filter options, and the import error messages.

Never translated: `JSON`, `schemaVersion`, `analysisVersion`, finding ids,
protocol tokens, and any schema field name. Always translated: every status,
reason and instruction.

The import error messages deserve care. "This file is not a report from this
tool" and "This report was made by a newer version" are different problems with
different actions, and both will be read by someone who has just been handed a
file by a colleague.

## Testing

Round-trip: export a fixture audit, import it, assert the parsed structure equals
the exported structure field for field.

Projection: assert the exported body contains **none** of the excluded fields in
section 1 — `cls` at any depth, `key`, `keyspace`, `noteKey`, `noteArgs`,
`blocks`, `txt`, `verifications`, `dmarcDiscovery.queries`,
`dmarcDiscovery.steps`, `issues`, `suggestions`, `dnsProvider`, `emailProvider`,
`advanced` and `dkimStatus`. A bidirectional path test also proves every emitted
path is registered and every registered path has a fixture. A test that checks
only the wanted fields would pass on a dump or on a dead whitelist member.

Artifact exclusion: export from a session with supplied MTA-STS and BIMI
material and assert no id from `artifactFindingCatalogIds()` and no
`source: 'user-supplied'` string appears anywhere in the file.

Size: re-run the measurement in
[`fixtures/report-size-measurement-0.9.0.md`](fixtures/report-size-measurement-0.9.0.md)
against the projection the implementation actually emits, and assert the
200-domain projection stays under the 8 MiB import limit.

Comparison fixtures:

| Fixture | Expectation |
| --- | --- |
| Identical reports | Every domain `unchanged`, summary all zero but unchanged |
| DMARC moved `none` to `reject` | `improved`, `dmarc.policy-none` resolved |
| DMARC moved `reject` to `none` | `regressed` |
| A domain only in the baseline | `removed` |
| A domain only in the current | `added` |
| Same score, one critical resolved and one low added | `improved` |
| DKIM off in one report | `incomparable`, reason `options` |
| Different `analysisVersion` | `scoreDelta` null, finding diff still produced |
| Different `generator.version`, same DNS | raw id diff shown as baseline/current-only; status `changed`, never improved/regressed |
| `deepChecks` differs | MX and DANE incomparable; other protocol diffs intact |
| `advanced` differs | SPF, DMARC and the five advanced protocols incomparable; the eight advanced-gated SPF ids report `unknown`, never `resolved` |
| `advanced` on, external authorization uncertain | DMARC still `observed`; the policy diff runs |
| DKIM unproven in the current report | DKIM findings `unknown`, DMARC diff intact, domain not blanked |
| DKIM unproven in the baseline | Same, `side: 'baseline'` |
| Every protocol unproven on one side | Domain `incomparable` |
| MX-health lookup failed on one side | MX incomparable even though `score.unproven` omits it |
| TLSA lookup failed on one side | DANE incomparable even though the emitted warning's protocol is `dns` |
| `dmarc.external-unverifiable` beside an observed policy | External-auth uncertainty does not erase the policy diff |
| Baseline in Japanese, current in German | Identical result to two English reports |
| Unknown finding id in the baseline | Displayed by id, counted in the diff |
| `unregistered` in one report, `audited` in the other | `incomparable`, reason `state` |

Hostile import fixtures, each asserting rejection or safe rendering:

| Fixture | Expectation |
| --- | --- |
| `{"__proto__": {"polluted": true}}` | Rejected; `({}).polluted` is undefined |
| `constructor`/`prototype` as object keys | Rejected |
| A finding id of `__proto__` | Looked up on a null-prototype map, no resolution |
| 20 MiB file | Rejected before `JSON.parse` |
| 100,000 domains | Rejected on array length |
| 201 domains | Rejected on array length |
| 50-level nesting | Rejected on depth |
| `<img src=x onerror=alert(1)>` as a domain name | Rendered as text, no execution |
| A bidirectional override in a record value | Rendered under the 0.2.3 hygiene rules |
| `"schema": "something-else"` | Rejected with a specific message |
| `"schemaVersion": 99` | Rejected as too new |
| Valid JSON, wrong shape | Rejected, no partial state |
| Truncated JSON | Rejected, no partial state |
| HTML file renamed `.json` | Rejected |

Persistence assertion: after an import and a comparison, `localStorage` contains
no key other than `dns-email-audit-lang`, and `indexedDB.databases()` is empty.

`analysisVersion` assertion: hash the source text of the scoring constants and
functions and compare against a committed value; a mismatch fails the test with a
message saying to bump `analysisVersion`. The test's own comment states what it
cannot catch — a discovery change outside `scoring.js` — and points at the
backtest rule in section 2.

`APP_VERSION` assertion: the export from `src/runtime.js` equals `package.json`'s
`version`.

## Acceptance criteria

1. Reloading the page removes every imported report and comparison.
2. Malicious strings in imported JSON render as text and never execute.
3. Prototype pollution through an imported report is impossible, asserted by
   test.
4. Two exports of the same audit run, taken in different languages, are
   byte-identical.
5. An analysis-version mismatch reports `scoreDelta: null`; an option mismatch
   makes only its mapped protocols incomparable. Both still produce the finding
   diff wherever that diff is meaningful.
6. A comparison across different generator versions exposes the raw finding-id
   diff but never labels it improved, regressed, new or resolved.
7. A protocol that was unproven or not run on either side reports its findings
   as `unknown`, never as `resolved`, and does not blank the other protocols'
   diff.
8. MX and DANE failure states are represented directly even though they do not
   appear in `score.unproven`.
9. No artifact finding, and no `user-supplied` provenance, appears in an exported
   report.
10. No excluded field from section 1 appears in an exported report.
11. `localStorage` holds no key other than `dns-email-audit-lang` after a full
   comparison session.
12. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

## Risks

**The schema is a compatibility commitment.** Once users have exported reports,
the importer has to keep reading them. Mitigation: `schemaVersion` from day one,
an explicit upgrade path per version, and a policy that fields are added and
deprecated, never repurposed. 1.0.0 records that policy as a supported surface.

**Comparison invites persistence requests.** "Just remember last month's report
for me" is the obvious next ask and would end the privacy claim. Mitigation: the
stateless design is stated in `PRIVACY.md` and in the interface, and the
acceptance criteria make it testable.

**Finding id churn breaks old reports.** If a later release renames a finding,
every baseline report from 0.9.0 shows the old id only in the baseline and its
replacement only in the current report.
Mitigation: finding ids are treated as public API from 0.7.0 onward, and a rename
ships with an alias map that the comparison consults.

**The exported file is a disclosure.** It carries a domain's full published
mail-security posture, its MX hosts, its DKIM selectors and its DMARC report
addresses. All of it is public DNS, so this is a convenience risk rather than a
confidentiality one. The interface says plainly what the user-initiated download
contains. It does not change what the application stores or transmits and
therefore does not change the boundary documented in `PRIVACY.md`. The excluded
`txt` and `verifications` fields are the part that would have been a genuine
disclosure.

**The analysis-version bump is a human step.** The hash test covers the rubric;
nothing mechanically detects a discovery change in `src/core/`. Mitigation is the
backtest rule in section 2, which is a process guard and is stated as one rather
than dressed up as a test.

## Resolved questions

**RQ-CMP-01: How much evidence goes in the export?**
*Resolved (1.0): full evidence.* The question assumed evidence was the size
driver. It is not: dropping every `evidence[]` entry saves 735 bytes per domain,
12% of the body, while records account for 49%. The severity-threshold middle
option optimizes the wrong half of the file, and buying 12% by making a report
unverifiable by its recipient is a bad trade. Measured in
[`fixtures/report-size-measurement-0.9.0.md`](fixtures/report-size-measurement-0.9.0.md).

**RQ-CMP-02: Does the report include the raw records, the findings, or both?**
*Resolved (1.0): both, as a named projection, with the import cap set to 200
domains.* The 0.3 draft exported the whole result object at a 1000-domain import
cap; measured, that is 8.62 MiB against its own 8 MiB pre-parse limit, so the tool
could emit files it would then reject. Two things fix it and neither is a
compromise on content. The projection in section 1 drops display state, locale
routing, the query trace and the unrelated TXT records. The broader 1.0 candidate
measured 6,103 bytes per domain; 1.1's normalized record projection is smaller by
construction. The domain cap becomes `MAX_DOMAINS` — 200 — because the
application cannot produce more, putting even that conservative candidate at
1.16 MiB with roughly sevenfold headroom.

**RQ-CMP-03: Should the exported report be signed or checksummed?**
*Resolved (1.0): neither.* An embedded SHA-256 is recomputed by anyone who edits
the file, so it detects accident, not tampering — and `JSON.parse` already
detects the accidents that matter. Real integrity needs a signature over a key
this application does not have and could not manage in a browser with no
identity. No appeal to another report format changes that product constraint:
formats with identity support can sign, while this application has no signing
identity to offer. If this is ever revisited, RFC 8785 JSON Canonicalization is the
serialization to use, and the honest form is a detached signature. The interface
must therefore never present an imported report as having verified provenance.

**RQ-CMP-04: Is comparison a separate mode or an overlay on the results table?**
*Resolved (1.0): an overlay.* One mental model, and it reuses the filter and sort
apparatus that already exists. The counterargument — a table built for one audit
does not naturally show two — is answered by putting paired values in the
per-row detail row that the table already has and the static HTML report already
expands, rather than doubling roughly fifty columns.

**RQ-CMP-05: Two reports, or more?**
*Resolved (1.0): two, and a trend view is outside the 1.x contract.* Three or
more multiplies the interface and the incomparability cases, and a trend is the
feature that most directly invites "just store them for me", which is the one
thing this design cannot concede. Someone with four files can compare them
pairwise. Revisiting this needs a design that produces a trend without
persistence, not a scope increase.

**RQ-CMP-06: What is the version field when the rubric has not changed but
discovery has?**
*Resolved (1.0), amended (1.1): one `analysisVersion`, gating the score delta
only; generator-version mismatch qualifies finding movement.* Section 2
carries the design. Two things were decided. It covers discovery as well as the
rubric, because the draft's own note records that 0.3.0 moved scores with
`WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` untouched, so a rubric-only
field under-reports incomparability. And it gates only the score, because a
version that hid the whole comparison would make the feature useless in its
commonest case — audit in March, audit again in September after two releases.
Version 1.0 overreached by calling that finding movement “still correct”: stable
ids establish identity, not unchanged detector semantics. Version 1.1 keeps the
raw id and record diff but uses `changed` and baseline/current-only labels across
generator versions, never improved/regressed or new/resolved.

**RQ-CMP-07: Do artifact findings from 0.8.0 appear in the report?**
*Resolved (1.0): no, and no field is reserved for them.* `OQ-ART-07` settled this
upstream: a user-supplied finding is not reproducible from DNS, and a diff of two
of them compares two different kinds of claim. A reserved-but-empty field would
be a standing invitation to fill it, so the schema has none. The exclusion is
asserted rather than assumed, against `artifactFindingCatalogIds()`.

**RQ-CMP-08: Can a finding be reported as resolved when its protocol was never
observed?**
*Resolved (1.0), corrected (1.1): no — comparability is per protocol and is an
explicit audit fact.* Raised during the 1.0 review
rather than in the 0.3 draft. 0.2.0's resilient optional checks mean a domain can
be `audited` with one protocol unobserved, and the draft's `incomparable` was
per-domain only, so those findings would have been reported as `resolved` — the
comparison telling someone a problem is fixed when the tool simply did not look.
Section 5 carries the design. Version 1.0's proposed derivation was incomplete:
MX and DANE failures appear only inside `dns.checks-unverified`, and an
unverified sub-check does not necessarily make its whole protocol unobserved.
Version 1.1 therefore makes observability a closed, explicit audit projection
rather than reverse-engineering it from score pillars and finding confidence.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.2 | 2026-09-03 | **Final, amended during implementation of commit 1.** §5's option-to-protocol mapping was incomplete: it named only the five dedicated advanced protocols, but `advanced` also gates `spfLookups`, `spfSubnets` and `reportAuth`, which nine finding ids depend on — eight on `protocol: 'spf'` and `dmarc.external-unverifiable`. Under 1.1 a comparison across an `advanced` mismatch would have reported all eight SPF findings as `resolved`, the exact `RQ-CMP-08` harm, in the protocol carrying the most findings. The mapping now covers `spf`, `dmarc` and `reporting`; both are `unproven` rather than `not-run` with `advanced` off, since their records are still retrieved. No product decision reopened. Found by Codex review of the commit-1 working tree and reproduced against `src/audit/audit-domain.js` before the amendment. |
| 1.1 | 2026-09-03 | **Final, amended after Codex review.** Kept the eight product decisions but corrected their implementable contract. Moved `APP_VERSION` to the permitted `src/runtime.js` composition owner and split it from the audit commit; added the omitted `deepChecks` option and a closed option-to-protocol mapping; replaced the lossy `score.unproven`/finding-confidence inference with an explicit total `observability` map that represents unscored MX and DANE failures; qualified cross-generator finding movement as baseline/current-only with domain status `changed`; made the normalized record path, scalar type, nullability, enum and canonical-order contracts plus their bidirectional whitelist test normative; added `incomparableReasons` and a deterministic severity/count/score status order; removed the producer-incompatible 4096-character string ceiling and the unnecessary privacy-policy implication; and removed incorrect SARIF and CycloneDX precedent claims. Findings and their reproductions are recorded in `CODEX Review - docs-report-comparison-spec-review.md`. |
| 1.0 | 2026-09-03 | **Final.** Resolved every open question and reconciled the schema against what `v0.8.1` actually produces. The schema is now a named projection with an explicit exclusion table, rather than the result object: `score` uses the real `pts`/`breakdown.pillars` shape, the invented `records` block is replaced by the real result fields, findings carry their real nine comparable fields, and display state, locale routing, the Tree Walk query trace and the unrelated `txt`/`verifications` material are excluded by decision. `rubricVersion` becomes `analysisVersion` gating the score delta only (`RQ-CMP-06`); the import domain cap becomes `MAX_DOMAINS` = 200 and the size questions are settled by measurement (`RQ-CMP-01`, `RQ-CMP-02`); no integrity field ships (`RQ-CMP-03`); comparison overlays the results table (`RQ-CMP-04`); two reports only (`RQ-CMP-05`); artifact findings are excluded with no reserved field (`RQ-CMP-07`). Added `RQ-CMP-08`, per-protocol comparability, so an unobserved protocol is never reported as fixed. Corrected acceptance criterion 4, which was untestable while `generatedAt` was export time, and criterion 6, which contradicted `PRIVACY.md`. Recorded that `generator.version` has no runtime source today. |
| 0.3 | 2026-09-01 | Recorded the settled 0.8.0 provenance boundary: user-supplied artifact findings are excluded from the versioned JSON comparison report. `OQ-CMP-07` now carries that upstream decision into this draft rather than presenting it as open. No other report question was resolved. |
| 0.2 | 2026-08-31 | Renumbered the target to 0.9.0 and rebased the implementation on `src/ui/report.js`, `src/ui/events.js` and the shipped injection boundary. Assigned pure schema and comparison work to a UI sibling, kept scoring-version ownership in `src/audit/`, prohibited a reverse UI-to-audit import, updated finding stability to begin at 0.7.0, and made the 0.8.0 artifact provenance decision an explicit dependency. No open question was resolved. |
| 0.1 | 2026-08-20 | Initial draft. |
