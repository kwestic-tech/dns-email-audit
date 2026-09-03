# Spec: Stateless report export and comparison

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Final) |
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

The constraint that shapes the solution is that nothing may be stored. The tool's
privacy claim rests on results never leaving the browser and never being written
anywhere. Server-side history is out of the question, and browser-side history
would contradict `PRIVACY.md`, which currently states that `localStorage` holds
at most one key, the language preference. So the comparison has to be stateless:
the user holds the files, supplies two, and gets a diff that exists only until
the page reloads.

## Scope

1. A versioned JSON report schema carrying normalized evidence, not display text.
2. Export of that schema alongside the existing CSV and HTML exports.
3. Strictly validated import with size and structure limits.
4. In-memory comparison of two reports.
5. New, resolved, regressed, improved and unchanged classification, with
   per-protocol comparability so an unobserved protocol is never reported as
   fixed.
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
| `APP_VERSION` | new `src/version.js` |

Both new UI modules remain within the existing `ui/` sibling edge. The UI must
not import `src/audit/scoring.js`; the composition boundary passes version
metadata with completed audit facts.

Implementation is split into directory-bound commits, in this order, because
each is a different owner and two of them can move a published surface:

1. `src/version.js` and `ANALYSIS_VERSION` in `src/audit/scoring.js`, plus the
   audit-output metadata that carries them. No UI change, no behavior change.
2. `src/ui/report-data.js` — pure schema, validation and comparison. No DOM.
3. `src/ui/report.js` — `exportJSON()` beside the existing two exports.
4. `src/ui/events.js` — import controls, comparison mode, rendering, filters.
5. `locales/en.json` and all thirteen translations.

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
               "wildcard": false, "advanced": true, "selectors": [] },
  "domains": [
    {
      "domain": "example.com",
      "organizationalDomain": "example.com",
      "state": "audited",
      "unproven": ["dkim"],
      "score": { "pts": 72, "max": 100, "grade": "A", "parked": false,
                 "unproven": ["dkim"],
                 "pillars": [{ "key": "dmarc", "pts": 25, "max": 30 }] },
      "records": {
        "ns": [], "mx": [], "spf": "", "spfRecords": [],
        "dmarc": "", "dmarcAtDomain": "",
        "dmarcDiscovery": { "foundAt": "", "labelsUp": 0, "terminated": "",
                            "organizationalDomain": "", "policyDomain": "",
                            "psdBoundary": "" },
        "dkim": { "found": true, "confidence": "confirmed", "scanMode": "",
                  "selectors": [], "missingSelectors": [],
                  "revokedSelectors": [], "keyProfile": {} },
        "advanced": { "bimi": {}, "caa": {}, "dnssec": {}, "mtaSts": {},
                      "mxHealth": {}, "reportAuth": {}, "spfLookups": {},
                      "spfSubnets": {}, "tlsRpt": {}, "tlsa": {} }
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
carries no `score`, `records`, `findings` or `remediationPlan`.

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
options and says so rather than reporting a phantom regression.

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

What `analysisVersion` deliberately does **not** gate is the finding diff. A
version that blocked the whole comparison would make the feature useless in its
commonest case — audit in March, audit again in September, two releases later.
Findings compare across versions on their stable ids; an id the current build
does not recognize is displayed by id (section 4), and a renamed id ships with an
alias map (see Risks).

`APP_VERSION` in `src/version.js` is separate and is human context only. It has
no comparison semantics. The package version currently reaches only the bundle's
comment banner in [`tools/build-bundle.mjs`](../../tools/build-bundle.mjs), so
nothing readable at runtime exists today; a hand-maintained constant bumped by
the release commit, with a test asserting it equals `package.json`, matches how
this project already cuts releases.

### 3. Export

`exportJSON()` sits beside the existing two export buttons in
[`index.html`](../../index.html). It builds the structure from the in-memory
`results` array and downloads it through the existing download capability
already passed into `src/ui/report.js`.

The exported filename includes a UTC date so two exports do not collide in a
downloads folder: `dns-email-audit-2026-08-20.json`.

Measured size, from
[`fixtures/report-size-measurement-0.9.0.md`](fixtures/report-size-measurement-0.9.0.md):
6,103 bytes per domain, **1.16 MB at the 200-domain maximum**, against an 8 MB
import limit. The corpus is synthetic and understates real records, so the
headroom is roughly sevenfold rather than exact.

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
| Byte length before parse | 8 MB | ~7x the measured 200-domain export |
| `domains` array length | **200** | `MAX_DOMAINS` in `src/ui/events.js` |
| `findings` per domain | 200 | |
| `evidence` per finding | 20 | |
| Any string value | 4096 characters | |
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
    schemaVersionsMatch, analysisVersionsMatch, optionsMatch,
    optionDifferences: string[],
    baselineGeneratedAt, currentGeneratedAt,
    baselineAppVersion, currentAppVersion,
  },
  domains: [{
    domain,
    status: 'added' | 'removed' | 'improved' | 'regressed' | 'unchanged' | 'incomparable',
    scoreDelta: number | null,
    scoreComparable: boolean,
    gradeChange: { from, to } | null,
    incomparableProtocols: [{ protocol, reason, side }],
    findings: {
      new: [id], resolved: [id], unchanged: [id], unknown: [id],
      severityChanged: [{ id, from, to }],
    },
    recordChanges: [{ path, from, to }],
  }],
  summary: { added, removed, improved, regressed, unchanged, incomparable },
}
```

Domain identity is the domain name. Finding identity is the finding `id`, which
is why 0.7.0's stable id namespace is a hard prerequisite: comparing on locale
keys or on message text would report every finding as new the moment a
translation changed.

`improved` and `regressed` are decided on the finding set first and the score
second. A domain whose score is unchanged but which resolved a critical finding
and gained a low one has improved, and saying so requires reading the findings
rather than the number.

#### Per-protocol comparability

A finding missing from the current report has two possible causes, and calling
both of them `resolved` tells someone a problem is fixed when it is not. This is
the same error `incomparable` exists to prevent, one level down, and the industry
precedent is explicit about it: SARIF 2.1.0's `baselineState` separates `absent`
from a fixed result for exactly this reason.

The application produces the second cause routinely. 0.2.0's resilient optional
checks mean a failed lookup degrades one check rather than discarding the audit,
so a domain can be `audited` with one protocol unobserved. The result already
says so, in two places: `score.unproven` names the zeroed pillars, and a finding
with `confidence: 'unverified'` names a check that reported without proving.

Each domain therefore exports an `unproven` array of **protocol tokens** — the
`PROTOCOLS` vocabulary from `src/audit/findings.js`, not the pillar keys — built
from the union of:

- `score.unproven`, mapped pillar key to protocol token (`mtaSts` → `mta-sts`,
  `tlsRpt` → `tls-rpt`; the rest are identical); and
- the `protocol` of every finding with `confidence: 'unverified'`.

Comparison then applies, per protocol and per side:

- a protocol unproven on **either** side is `incomparable` for that protocol;
- its findings are reported as `unknown`, never as `new` or `resolved`;
- `incomparableProtocols` records the protocol, the reason and which side;
- the domain's own status is still decided from the protocols that **are**
  comparable, so one failed DKIM lookup does not blank the DMARC diff.

`scoreComparable` is false when `analysisVersion` differs, and `scoreDelta` is
then `null`. The score is a single number over all pillars, so an unproven
protocol also makes it unsafe: `scoreComparable` is false when either side has a
non-empty `unproven` array.

A domain is `incomparable` outright in three cases: mismatched `analysisVersion`
with no comparable finding movement, mismatched `options` making a protocol's
findings absent rather than resolved, and a domain that was `unregistered` or
`error` in one report and `audited` in the other. Each is reported with its
reason.

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
for `improved`, `regressed`, `added` and `removed`. Paired baseline and current
values go in the existing per-row detail row — the `.detail-row` element the
static report already expands — rather than doubling every cell in the main grid.

A comparison summary replaces the existing stats grid while in comparison mode.

An incomparable protocol is marked in the row, with its reason, using the same
visual treatment as the existing unproven-pillar grade marker. It is never
rendered as a zero delta.

Leaving comparison mode discards the imported report from memory. So does
reloading, which is the point.

## Localization impact

Roughly 40 to 50 new keys: export button, import controls, the six comparison
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
`dmarcDiscovery.steps`, `issues`, `suggestions`, `dnsProvider`, `emailProvider`.
A test that only checks the wanted fields are present would pass on a dump.

Artifact exclusion: export from a session with supplied MTA-STS and BIMI
material and assert no id from `artifactFindingCatalogIds()` and no
`source: 'user-supplied'` string appears anywhere in the file.

Size: re-run the measurement in
[`fixtures/report-size-measurement-0.9.0.md`](fixtures/report-size-measurement-0.9.0.md)
against the projection the implementation actually emits, and assert the
200-domain projection stays under the 8 MB import limit.

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
| DKIM unproven in the current report | DKIM findings `unknown`, DMARC diff intact, domain not blanked |
| DKIM unproven in the baseline | Same, `side: 'baseline'` |
| Every protocol unproven on one side | Domain `incomparable` |
| A `confidence: 'unverified'` finding present on one side | Its protocol incomparable, not `resolved` |
| Baseline in Japanese, current in German | Identical result to two English reports |
| Unknown finding id in the baseline | Displayed by id, counted in the diff |
| `unregistered` in one report, `audited` in the other | `incomparable`, reason `state` |

Hostile import fixtures, each asserting rejection or safe rendering:

| Fixture | Expectation |
| --- | --- |
| `{"__proto__": {"polluted": true}}` | Rejected; `({}).polluted` is undefined |
| `constructor`/`prototype` as object keys | Rejected |
| A finding id of `__proto__` | Looked up on a null-prototype map, no resolution |
| 20 MB file | Rejected before `JSON.parse` |
| 100,000 domains | Rejected on array length |
| 201 domains | Rejected on array length |
| A 10 MB string in one field | Rejected on string length |
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

`APP_VERSION` assertion: `src/version.js` equals `package.json`'s `version`.

## Acceptance criteria

1. Reloading the page removes every imported report and comparison.
2. Malicious strings in imported JSON render as text and never execute.
3. Prototype pollution through an imported report is impossible, asserted by
   test.
4. Two exports of the same audit run, taken in different languages, are
   byte-identical.
5. A comparison across mismatched analysis versions or options reports
   `scoreDelta: null` or `incomparable` rather than a delta, and still produces
   the finding diff where the finding diff is meaningful.
6. A protocol that was unproven on either side reports its findings as `unknown`,
   never as `resolved`, and does not blank the other protocols' diff.
7. No artifact finding, and no `user-supplied` provenance, appears in an exported
   report.
8. No excluded field from section 1 appears in an exported report.
9. `localStorage` holds no key other than `dns-email-audit-lang` after a full
   comparison session.
10. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

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
every baseline report from 0.9.0 shows it as resolved and its replacement as new.
Mitigation: finding ids are treated as public API from 0.7.0 onward, and a rename
ships with an alias map that the comparison consults.

**The exported file is a disclosure.** It carries a domain's full published
mail-security posture, its MX hosts, its DKIM selectors and its DMARC report
addresses. All of it is public DNS, so this is a convenience risk rather than a
confidentiality one, but `PRIVACY.md` should say plainly what leaves the browser
when someone clicks Export JSON. The excluded `txt` and `verifications` fields
are the part that would have been a genuine disclosure.

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
cap; measured, that is 8.62 MB against its own 8 MB pre-parse limit, so the tool
could emit files it would then reject. Two things fix it and neither is a
compromise on content. The projection in section 1 drops display state, locale
routing, the query trace and the unrelated TXT records, which brings a domain
from 9,035 to 6,103 bytes. The domain cap becomes `MAX_DOMAINS` — 200 — because
the application cannot produce more, which puts a full export at 1.16 MB with
roughly sevenfold headroom.

**RQ-CMP-03: Should the exported report be signed or checksummed?**
*Resolved (1.0): neither.* An embedded SHA-256 is recomputed by anyone who edits
the file, so it detects accident, not tampering — and `JSON.parse` already
detects the accidents that matter. Real integrity needs a signature over a key
this application does not have and could not manage in a browser with no
identity. The industry precedent agrees: SARIF has no integrity field, and
CycloneDX puts signatures outside the document (detached JSF) rather than inside
it. If this is ever revisited, RFC 8785 JSON Canonicalization is the
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
*Resolved (1.0): one `analysisVersion`, gating the score delta only.* Section 2
carries the design. Two things were decided. It covers discovery as well as the
rubric, because the draft's own note records that 0.3.0 moved scores with
`WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` untouched, so a rubric-only
field under-reports incomparability. And it gates only the score, because a
version that gated the whole comparison would make the feature useless in its
commonest case — audit in March, audit again in September after two releases —
where the finding diff on stable ids is exactly what the user wants and is still
correct.

**RQ-CMP-07: Do artifact findings from 0.8.0 appear in the report?**
*Resolved (1.0): no, and no field is reserved for them.* `OQ-ART-07` settled this
upstream: a user-supplied finding is not reproducible from DNS, and a diff of two
of them compares two different kinds of claim. A reserved-but-empty field would
be a standing invitation to fill it, so the schema has none. The exclusion is
asserted rather than assumed, against `artifactFindingCatalogIds()`.

**RQ-CMP-08: Can a finding be reported as resolved when its protocol was never
observed?**
*Resolved (1.0): no — comparability is per protocol.* Raised during this review
rather than in the 0.3 draft. 0.2.0's resilient optional checks mean a domain can
be `audited` with one protocol unobserved, and the draft's `incomparable` was
per-domain only, so those findings would have been reported as `resolved` — the
comparison telling someone a problem is fixed when the tool simply did not look.
SARIF 2.1.0 separates `absent` from fixed for the same reason. Section 5 carries
the design; the signal already exists in `score.unproven` and in
`confidence: 'unverified'`, so this reads facts the audit already produces rather
than adding a check.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-09-03 | **Final.** Resolved every open question and reconciled the schema against what `v0.8.1` actually produces. The schema is now a named projection with an explicit exclusion table, rather than the result object: `score` uses the real `pts`/`breakdown.pillars` shape, the invented `records` block is replaced by the real result fields, findings carry their real nine comparable fields, and display state, locale routing, the Tree Walk query trace and the unrelated `txt`/`verifications` material are excluded by decision. `rubricVersion` becomes `analysisVersion` gating the score delta only (`RQ-CMP-06`); the import domain cap becomes `MAX_DOMAINS` = 200 and the size questions are settled by measurement (`RQ-CMP-01`, `RQ-CMP-02`); no integrity field ships (`RQ-CMP-03`); comparison overlays the results table (`RQ-CMP-04`); two reports only (`RQ-CMP-05`); artifact findings are excluded with no reserved field (`RQ-CMP-07`). Added `RQ-CMP-08`, per-protocol comparability, so an unobserved protocol is never reported as fixed. Corrected acceptance criterion 4, which was untestable while `generatedAt` was export time, and criterion 6, which contradicted `PRIVACY.md`. Recorded that `generator.version` has no runtime source today. |
| 0.3 | 2026-09-01 | Recorded the settled 0.8.0 provenance boundary: user-supplied artifact findings are excluded from the versioned JSON comparison report. `OQ-CMP-07` now carries that upstream decision into this draft rather than presenting it as open. No other report question was resolved. |
| 0.2 | 2026-08-31 | Renumbered the target to 0.9.0 and rebased the implementation on `src/ui/report.js`, `src/ui/events.js` and the shipped injection boundary. Assigned pure schema and comparison work to a UI sibling, kept scoring-version ownership in `src/audit/`, prohibited a reverse UI-to-audit import, updated finding stability to begin at 0.7.0, and made the 0.8.0 artifact provenance decision an explicit dependency. No open question was resolved. |
| 0.1 | 2026-08-20 | Initial draft. |
