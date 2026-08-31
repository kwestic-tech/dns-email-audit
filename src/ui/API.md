# `src/ui/` — API contract

Required by spec [§12](../../docs/specs/implemented/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Presentation. Turning a completed audit's facts into DOM,
into a CSV, into a standalone HTML report, and into the events that drive a
run. **It decides nothing about a domain's security posture** — no finding, no
severity, no score and no protocol verdict originates here.

**Complete since Task 5.6:** `render.js` (converted in Phase 2), `report.js`
(5.5) and `events.js` (5.6).

## Allowed edges

| May import | May not |
| --- | --- |
| `ui/` siblings, `i18n/` | `audit/`, any `core/`, `providers/`, `src/data/`, the platform |

Audit reaches this directory as **callbacks passed in**, never as an import:
`createUi()` receives `analyzeDomain` and `checkConnectivity` from the runtime,
along with `mount` — the runtime's single mount function, which the UI's
`DOMContentLoaded` listener calls. `dns-transport.test.mjs` §5 asserts the
direction.

**`runtime.js` is what reaches this directory**, which is §12's matrix exactly:
the entry point's row is `runtime.js`, `platform/`, `data/` and does not include
`ui/`.

> **The transitional edge, and how it ended.** Task 5.5 moved the exported CSV
> and report here while `src/main.js` still held the UI body and was their only
> caller — a `main.js -> ui` edge the matrix does not grant. It was admitted in
> `ALLOWED_EDGES` as transitional rather than pretended away, and written
> **self-removing**: an assertion that the exemption was still NEEDED. At Task
> 5.6 that assertion failed, and the entry came out with it. The matrix was
> never amended.

## Public exports

### `render.js`

The element builder and row renderer. Covered by `tools/render.test.mjs`.

### `events.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `createUi(capabilities)` | factory | Wires the page and returns a test-accessible UI object. Constructing it registers the one `DOMContentLoaded` listener. |

**It receives the audit, it does not import it.** `analyzeDomain` and
`checkConnectivity` — the two supported facade members — arrive as callbacks,
and `mount` is the runtime's. This module imports no `audit/`, no `core/`, no
`providers/` and no `src/data/`; its single import is its sibling `report.js`.

#### One boot, one connectivity probe

There is exactly **one** `DOMContentLoaded` listener in `src/`, registered
here. It wires every control, calls `mount()`, and probes connectivity once to
raise the sandbox banner.

A second boot path would run the language init twice and put a second probe on
every page load — a figure `PRIVACY.md` publishes and one of the five
equivalence surfaces measures. `runtime.test.mjs` §2b asserts the count
structurally, and that the entry point registers none. It is a lexical scan and
says so: it counts registration sites, not runtime behaviour.

#### Reached by import, not by a published name

`createUi()` returns the page's internals, and **production owns them**:
`src/runtime.js` holds the object as `runtime.ui`. `tools/render.test.mjs` and
`tools/export.test.mjs` reach it through the harness's `loadUi()`, which
composes a real runtime and hands back what it built.

**No global is involved.** Through Task 6.1 these members were published as
`window.__APP_TEST__` by a marked adapter in `src/main.js`; Task 6.2 retired
the adapter, and both suites kept their counts — 329 and 199 — across the
move.

### `report.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `createReport(capabilities)` | factory | Returns `{ exportCSV, exportHTML, buildCsvRows, toCsvText, neutralizeCsvCell, buildReportDocument }`. |
| `serializeDocument(doc)` | pure | `<!DOCTYPE html>` plus the serialized tree. |
| `styleElement(D, css)` | pure | A `<style>` whose every `<` is the CSS escape `\3c `. |

`serializeDocument` and `styleElement` are exported because
`buildLearnMorePage()` — in the sibling `events.js` — emits a standalone
document too. `<style>` is a raw-text element, so a `</style>` inside the CSS
would end it early and everything after would parse as markup. That rule exists
**once**.

## What the export formats, and what it must not do

It formats **completed audit facts** — `score.grade`, `spfStatus.status`,
`advanced.caa.found` and their siblings — into cells and nodes. It **does not
reinterpret protocol records**: every value it writes was decided by a
`core/<protocol>/` owner and carried through `audit/issues.js` or
`audit/scoring.js`.

The same ruling that governs those two governs this one. The owner decides what
a record MEANS; `audit/` decides what a meaning is WORTH and worth SAYING; this
directory decides how it is SPELLED. Three jobs, and only the first is parsing
— which is why no name from here belongs in `dns-transport.test.mjs` §3b either.

## Dependencies, stated rather than implied

Every one is a real dependency of the exported bytes, and every one is passed:

| Dependency | Why the export needs it |
| --- | --- |
| **i18n** — `t`, `tRaw`, `lang`, plus the English bundle | Every header, label and issue message is a locale lookup. `csv.headers` is **positional**, so the English bundle backfills per index: English defines the column count and a translation fills what it has. Without it, a locale predating a column would misalign every row it exports. |
| **renderer** (`R`) | The report is built as a detached tree with the same element builder the page uses, and `R.hygieneOf()` produces the `record_hygiene` column. |
| **document** | `implementation.createHTMLDocument()` for the report, `createElement('a')` for the download. Passed, never reached for — `platform.test.mjs`'s ambient scan would report a bare `document` as a reach. |
| **platform** | `Blob`, `URL`, `setTimeout`, `fetch` and `formatDateTime`. Spec §11: the composition root owns the window. |
| Row formatters — `label`, `issueMessage`, `spfRecordCell`, `dkimKeyBitsCell`, `rowHygieneValues` | A CSV cell must be spelled exactly as the table spells it. These belong to the table renderer in the sibling `events.js`; they are passed rather than imported so the two modules stay acyclic. |
| `getResults` | An **accessor**, not the array. `events.js` REPLACES `results` on each run, so a captured reference would export the previous run's data. |
| `showToast`, `$` | The page feedback and element lookup the two entry points use. |

## The exported report's own policy

```
default-src 'none'; style-src 'unsafe-inline'; img-src data:
```

A standalone file someone opens from their downloads folder gets no script, no
network and no font. **Asserted twice, and both survive the move:**
`tools/csp.test.mjs` §5 reads it out of this file — and first asserts the
builder is actually here, so a source check cannot go green against a file the
code has left — and `equivalence.validate.mjs` weakens it as a mutation and
requires the `report` surface to move and every other surface to hold.

The policy is constructed in exactly one place, which is asserted.

## CSV bytes are a published interface

- **Columns are positional and APPENDED, never inserted.** A consumer's column
  index must keep meaning what it meant last release.
- **Neutralize first, quote second.** The quoting is RFC 4180 transport; the
  neutralization is about what a spreadsheet does after parsing.
- **A BOM leads the file** so Excel reads UTF-8 on Windows.
- **Display caps never reach the data.** The truncated remainder is revealed in
  the export rather than dropped from it.
- **OQ-SEC-11:** data columns carry the published bytes exactly as received.
  Rewriting a cell to a sentinel would break anyone piping this into a script;
  the record-hygiene warning goes in its own appended column instead.

`tools/export.test.mjs` is the standing surface — **199 assertions**, unchanged
by Task 5.5 — and asserts these at the string level as well as the tree level,
because a serializer bug does not show up in a shim's model of a tree.

## Moved, not redesigned

`src/main.js`'s export block, unchanged apart from the two-space dedent, the
`export` keywords and the factory wrapper. No column moved, no byte of CSV
changed, no policy edited. Both five-surface equivalence subjects report zero
differences.
