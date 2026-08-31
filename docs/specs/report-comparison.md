# Spec: Stateless report export and comparison

| Field | Value |
| --- | --- |
| Spec version | 0.2 (Draft, rebased after 0.6.0) |
| Target release | 0.9.0 |
| Status | Awaiting review |
| Depends on | [findings-and-remediation](implemented/findings-and-remediation.md), which defines finding identity, plus the 0.8.0 decision on user-supplied artifact findings |
| Blocks | Nothing |
| Slug for open questions | `CMP` |
| Last updated | 2026-08-31 |

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
exactly one key, the language preference. So the comparison has to be stateless:
the user holds the files, supplies two, and gets a diff that exists only until
the page reloads.

## Scope

1. A versioned JSON report schema carrying normalized evidence, not display text.
2. Export of that schema alongside the existing CSV and HTML exports.
3. Strictly validated import with size and structure limits.
4. In-memory comparison of two reports.
5. New, resolved, regressed, improved and unchanged classification.
6. No persistence of any report or comparison.

## Non-goals

- **No HTML import.** Only the JSON schema is accepted. The exported HTML report
  is a human artifact and is never parsed back.
- **No persistence.** No `localStorage`, no `IndexedDB`, no cache, no service
  worker. Reloading the page discards everything.
- **No network.** Reports come from the user's file picker. No upload, no
  download from a URL, no sharing feature.
- **No trend analysis across three or more reports.** Two at a time. See
  `OQ-CMP-05`.
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
| Scoring/analysis version source | `src/audit/scoring.js`, carried in audit output or injected capabilities |

Both new UI modules remain within the existing `ui/` sibling edge. The UI must
not import `src/audit/scoring.js`; the composition boundary passes version
metadata with completed audit facts. If review chooses an `analysisVersion`
rather than `rubricVersion` in `OQ-CMP-06`, its owner and transport follow the
same rule. Implementation is split into directory-bound commits, with any
audit-output metadata addition separate from UI behavior and schema work.

### 1. Schema

```json
{
  "schema": "dns-email-audit/report",
  "schemaVersion": 1,
  "generatedAt": "2026-08-20T04:12:00Z",
  "generator": { "version": "0.9.0", "rubricVersion": 3 },
  "resolver": "https://cloudflare-dns.com/dns-query",
  "options": { "dkim": true, "dkimComprehensive": false, "www": true,
               "wildcard": false, "advanced": true, "selectors": [] },
  "domains": [
    {
      "domain": "example.com",
      "state": "audited",
      "score": { "points": 72, "max": 100, "grade": "A", "parked": false,
                 "unproven": [], "pillars": [{ "key": "dmarc", "points": 25, "max": 30 }] },
      "records": {
        "ns": [], "mx": [], "spf": "", "dmarc": "",
        "dmarcFoundAt": "", "dkim": [{ "selector": "", "queryName": "",
                                       "keyType": "rsa", "keyBits": 2048 }],
        "caa": [], "bimi": "", "mtaSts": "", "tlsRpt": "", "tlsa": [],
        "dnssec": { "state": "secure", "keys": [], "ds": [] }
      },
      "findings": [
        { "id": "dmarc.policy-none", "severity": "high",
          "confidence": "confirmed", "args": [],
          "evidence": [{ "kind": "txt", "queryName": "_dmarc.example.com",
                         "value": "v=DMARC1; p=none" }] }
      ]
    }
  ]
}
```

Three properties of this schema matter.

**No display text.** Every finding is an id. Every state is a token. A report
exported in Japanese and a report exported in German are byte-identical for the
same audit, which is what makes cross-language comparison possible and what stops
the schema from drifting with the locale files.

**`rubricVersion` is explicit.** The scoring rubric changes across releases. A
report generated under one rubric and compared against another produces score
deltas that reflect the rubric change rather than any change in the domain.
`rubricVersion` is owned by `src/audit/scoring.js`, bumped in the
same commit as any change to `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS`,
`calcDmarcScore()` or `calcSpfScore()`. A test asserts that the constant changes
whenever those definitions change, by hashing them.

**`options` is recorded.** A report generated without the DKIM check and a report
generated with it are not comparable on DKIM. The comparison detects mismatched
options and says so rather than reporting a phantom regression.

`schemaVersion` is an integer. An importer accepts its own version and any
earlier version it has an explicit upgrade path for, and rejects anything newer
with a clear message rather than attempting a partial parse.

### 2. Export

`exportJSON()` sits beside the existing two export buttons in
[`index.html`](../../index.html). It builds the structure from the in-memory
`results` array and downloads it through the existing download capability
already passed into `src/ui/report.js`.

The exported filename includes a UTC date so two exports do not collide in a
downloads folder: `dns-email-audit-2026-08-20.json`.

### 3. Import and validation

Import is the entire attack surface of this release, since the file is
attacker-supplied by construction: a hostile report could be handed to someone as
"last month's audit".

```js
function parseReport(text) → { ok: true, report } | { ok: false, errors: [] }
```

Enforced in order, each failing closed:

| Limit | Value |
| --- | --- |
| Byte length before parse | 8 MB |
| `domains` array length | 1000 |
| `findings` per domain | 200 |
| `evidence` per finding | 20 |
| Any string value | 4096 characters |
| Object nesting depth | 8 |
| `schema` value | Exactly `dns-email-audit/report` |
| `schemaVersion` | Integer, at most the current version |

Validation is a hand-written structural walk, not a schema library, keeping the
runtime dependency-free. Every field is checked for type and range. Unknown
fields are dropped rather than carried, so a future field cannot smuggle content
through an older importer.

Two rules that are easy to get wrong and are not optional:

- **`JSON.parse` with a reviver that rejects `__proto__`, `constructor` and
  `prototype` as keys.** Prototype pollution through a parsed report is a real
  and cheap attack, and the reviver is three lines.
- **Every string from an imported report is rendered as a text node.** The 0.2.3
  renderer makes this the default rather than a discipline, which is why this
  release is scheduled after it. Imported values are treated exactly like DNS
  values: untrusted input from a stranger.

A finding id in an imported report that the current build does not recognize is
displayed by id with a note that this build has no description for it, rather
than being dropped. That preserves the diff's completeness when comparing across
tool versions.

### 4. Comparison

```js
function compareReports(baseline, current) → {
  meta: {
    schemaVersionsMatch, rubricVersionsMatch, optionsMatch,
    optionDifferences: string[],
    baselineGeneratedAt, currentGeneratedAt,
  },
  domains: [{
    domain,
    status: 'added' | 'removed' | 'improved' | 'regressed' | 'unchanged' | 'incomparable',
    scoreDelta: number | null,
    gradeChange: { from, to } | null,
    findings: {
      new: [id], resolved: [id], unchanged: [id],
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

`incomparable` covers three cases: mismatched `rubricVersion` making score deltas
meaningless, mismatched `options` making a protocol's findings absent rather than
resolved, and a domain that was `unregistered` or errored in one report and
audited in the other. Each is reported with its reason. Silently presenting a
phantom regression because DKIM was switched off in one run is the failure mode
this field exists to prevent.

`recordChanges` reports the raw record deltas: an SPF record that changed, a
DMARC policy that moved, a DKIM selector that appeared. This is often more
useful than the finding diff, because it shows what someone actually did.

### 5. Interface

Comparison mode is entered by importing a baseline report while results are on
screen, or by importing two reports with no audit running.

The results table gains a delta column and per-row change indicators, reusing the
existing filter mechanism in `src/ui/events.js` with new filter
values for `improved`, `regressed`, `added` and `removed`.

A comparison summary replaces the existing stats grid while in comparison mode.

Leaving comparison mode discards the imported report from memory. So does
reloading, which is the point.

## Localization impact

Roughly 30 to 40 new keys: export button, import controls, the six comparison
statuses, the incomparable reasons, delta labels, the summary tiles, the filter
options, and the import error messages.

Never translated: `JSON`, `schemaVersion`, `rubricVersion`, finding ids, and any
schema field name. Always translated: every status, reason and instruction.

The import error messages deserve care. "This file is not a report from this
tool" and "This report was made by a newer version" are different problems with
different actions, and both will be read by someone who has just been handed a
file by a colleague.

## Testing

Round-trip: export a fixture audit, import it, assert the parsed structure equals
the exported structure field for field.

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
| Different `rubricVersion` | `incomparable`, reason `rubric` |
| Baseline in Japanese, current in German | Identical result to two English reports |
| Unknown finding id in the baseline | Displayed by id, counted in the diff |

Hostile import fixtures, each asserting rejection or safe rendering:

| Fixture | Expectation |
| --- | --- |
| `{"__proto__": {"polluted": true}}` | Rejected; `({}).polluted` is undefined |
| 20 MB file | Rejected before `JSON.parse` |
| 100,000 domains | Rejected on array length |
| A 10 MB string in one field | Rejected on string length |
| 50-level nesting | Rejected on depth |
| `<img src=x onerror=alert(1)>` as a domain name | Rendered as text, no execution |
| `"schema": "something-else"` | Rejected with a specific message |
| `"schemaVersion": 99` | Rejected as too new |
| Valid JSON, wrong shape | Rejected, no partial state |
| Truncated JSON | Rejected, no partial state |
| HTML file renamed `.json` | Rejected |

Persistence assertion: after an import and a comparison, `localStorage` contains
exactly one key, `dns-email-audit-lang`, and `indexedDB.databases()` is empty.

`rubricVersion` assertion: hash the source text of the scoring constants and
functions and compare against a committed value; a mismatch fails the test with a
message saying to bump `rubricVersion`.

## Acceptance criteria

1. Reloading the page removes every imported report and comparison.
2. Malicious strings in imported JSON render as text and never execute.
3. Prototype pollution through an imported report is impossible, asserted by
   test.
4. Reports exported in different languages from the same audit are byte-identical.
5. A comparison across mismatched rubric versions or options reports
   `incomparable` rather than a delta.
6. `localStorage` holds exactly one key after a full comparison session.
7. `npm test` and `npm run locale:gate` pass, 13/13 locales complete.

## Risks

**The schema is a compatibility commitment.** Once users have exported reports,
the importer has to keep reading them. Mitigation: `schemaVersion` from day one,
an explicit upgrade path per version, and a policy that fields are added and
deprecated, never repurposed.

**Comparison invites persistence requests.** "Just remember last month's report
for me" is the obvious next ask and would end the privacy claim. Mitigation: the
stateless design is stated in `PRIVACY.md` and in the interface, and the
acceptance criteria make it testable.

**Finding id churn breaks old reports.** If a later release renames a finding,
every baseline report from 0.9.0 shows it as resolved and its replacement as new.
Mitigation: finding ids are treated as public API from 0.7.0 onward, and a rename
ships with an alias map that the comparison consults.

**Report size on large estates.** A 1000-domain report with full evidence could
be tens of megabytes. Mitigation: measure it, and if it is a problem, make
evidence inclusion an export option rather than compressing, since a compressed
format would need a decompressor on import and that is a dependency.

## Open questions

**OQ-CMP-01: How much evidence goes in the export?**
Full evidence makes a report self-contained and verifiable by a third party, and
makes it large. Findings-only makes it small and makes the reader trust the tool's
conclusions without being able to check them. A middle option exports evidence
only for findings above a severity threshold. This draft exports full evidence
and asks for the file size to be measured on a realistic estate before the
decision is locked in.

**OQ-CMP-02: Does the report include the raw records, the findings, or both?**
Both, in this draft, because `recordChanges` is arguably the more useful half of
the diff and needs the raw material. That roughly doubles the file. The
alternative is findings only, which makes the report a conclusions document
rather than an evidence document.

**OQ-CMP-03: Should the exported report be signed or checksummed?**
A report handed between parties has no integrity protection. A SHA-256 of the
canonicalized content, embedded in the file, would let a recipient detect casual
tampering, and would not stop anyone who recomputes it. It costs a canonical
serialization, which is fiddly to get right. Worth it, or security theatre?

**OQ-CMP-04: Is comparison a separate mode or an overlay on the results table?**
An overlay reuses the whole table, filter and sort apparatus and keeps one mental
model. A separate view can be designed for the diff specifically, showing paired
values side by side. This draft overlays. The counterargument is that a table
built for one audit does not naturally show two.

**OQ-CMP-05: Two reports, or more?**
Comparing three or more would show a trend, which is what someone auditing
quarterly actually wants. It also multiplies the interface complexity and the
incomparability cases. This draft does two. Is a trend view a later release, or
never?

> **Note added 2026-08-24, from 0.3.0's spec review.** This question now has a
> confirmed instance rather than a hypothetical one. `dmarcbis-tree-walk` (0.3.0)
> reached `1.0 (Final)` with the Tree Walk replacing the PSL at both call sites,
> and its own Resolved-questions section records that **scores will move with no
> rubric change**: a domain whose policy is found at a different name than the
> PSL chose scores differently, and a domain with duplicate records at one name
> may now inherit a valid policy from higher in the tree where it previously
> scored zero. `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` are untouched.
> Whatever this question resolves to must therefore classify a 0.2.3 → 0.3.0
> comparison correctly, and "the rubric is unchanged so the scores are
> comparable" is demonstrably not sufficient.

**OQ-CMP-06: What is `rubricVersion` when the rubric has not changed but
discovery has?**
0.3.0 changes DMARC discovery without touching the rubric, and scores move.
A comparison across that boundary reports real-looking regressions caused by the
tool getting better. Options: bump `rubricVersion` on any change that can move a
score, which conflates two things; add a separate `discoveryVersion`; or accept
the noise and document it. This draft leans toward a single
`analysisVersion` covering both, renamed from `rubricVersion`. Decide before the
schema is frozen, because this field cannot be repurposed later.

**OQ-CMP-07: Do artifact findings from 0.8.0 appear in the report?**
Cross-referenced from `OQ-ART-07`. This draft excludes them, since a
user-supplied finding is not reproducible from DNS and a diff of two of them
compares two different kinds of claim. Confirm, because the schema must reserve
or omit the field now.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.2 | 2026-08-31 | Renumbered the target to 0.9.0 and rebased the implementation on `src/ui/report.js`, `src/ui/events.js` and the shipped injection boundary. Assigned pure schema and comparison work to a UI sibling, kept scoring-version ownership in `src/audit/`, prohibited a reverse UI-to-audit import, updated finding stability to begin at 0.7.0, and made the 0.8.0 artifact provenance decision an explicit dependency. No open question was resolved. |
| 0.1 | 2026-08-20 | Initial draft. |
