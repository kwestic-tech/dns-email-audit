# Capture: Gate 2 evidence

| Field | Value |
| --- | --- |
| For | [modular-architecture-and-production-build](../modular-architecture-and-production-build.md) |
| Records | The Gate 2 conditions: all source is ESM, the adapter count is shrinking, and five-surface equivalence is clean through the bundle |
| Captured | 2026-08-28 |
| Platform | macOS (darwin arm64), Node v26.7.0, ICU 78.3, Unicode 17.0 |
| Baseline | `v0.5.0`, commit `5c08364cc3270101f07c2d1b925a6d584e551527` |
| Spec | `1.4 (Final)` — amended at Task 2.7; see [Revision history](../modular-architecture-and-production-build.md#revision-history) |
| Head | `1905ab1` |

## Gate 2, as the plan states it

> All source is ESM. Adapter sentinels counted and shrinking. Test layout
> follows the settled `OQ-ARCH-09` hybrid. Five-surface equivalence clean
> through the bundle.

## Result

| Condition | Evidence |
| --- | --- |
| All source is ESM | Every file under `src/` and the one remaining under `js/` declares `import` or `export`. No IIFE wrapper survives anywhere. |
| Adapter sentinels shrinking | **3 → 2**: `src/data/legacy-globals.js` and `src/main.js`. `src/entry-legacy.js` and `src/legacy-bridge.js` retired at Task 2.6. |
| Test layout | `tests/` holds build, contract, integration and fixture suites; unit suites stay with their owners. No `*.test.*` path in `metafile.inputs` or the source map. |
| Five-surface equivalence | **30 cases, 5 surfaces, 0 differences**, working tree and `_site/` |
| `npm test` | **2,726**, 0 failed |
| `npm run inventory` | 80 passed, every area covered |
| `npm run test:file-url` | 28 passed, real headless Chrome |
| `npm run locale:gate` | 13/13, 0 errors, 0 warnings |
| State-matrix coverage | 427 of 427 rows covered, 0 uncovered |
| Documentation | 41 tracked markdown files, 0 broken links |

## 1. The browser surface, at each of the three commits

The two authorized compatibility deltas both landed in this phase, each as its
own commit and each named in
[`compatibility-deltas.json`](../../../tests/fixtures/equivalence/compatibility-deltas.json)
before it was performed.

| | Globals | `DnsAudit` members | Adapters |
| --- | ---: | ---: | ---: |
| `v0.5.0` | 24 | 95 | — |
| After Task 2.6 | 24 | 95 | 2 |
| After Task 2.7 | 24 | **2** | 2 |
| After Task 2.8 | **10** | 2 | 2 |

**Ten, not one.** The plan's Task 2.8 authorizes removal of the fourteen
unsupported `js/app.js` function globals and nothing else. The nine names beside
the facade are marked adapters with repository consumers or no ESM owner yet:

| Remaining | Why it stays | Retires |
| --- | --- | --- |
| `DnsAudit` | The supported facade. `analyzeDomain`, `checkConnectivity`. | never — it is the API |
| `__APP_TEST__` | `tools/render.test.mjs` (329) and `tools/export.test.mjs` (199) read it, and §10 says it becomes a direct ESM import — which needs a module that is not the entry, because the entry's exports *are* the facade | Phase 5, with `src/ui/report.js` and `src/ui/events.js` |
| `i18n`, `t`, `tp`, `tRaw`, `R` | Internal wiring, no reader left since Task 2.6 | no later than Task 6.2 |
| `__PUBLIC_SUFFIX_RULES__`, `__DKIM_SELECTOR_CATALOG__`, `__I18N_EN__` | §10's transition inputs; read by `parity.test.mjs` §5 and by the `file://` suite | no later than Task 6.2, with `src/data/legacy-globals.js` |

The fourteen are probed for **absence** in real Chrome, not merely left
unlisted: a browser is the last place a removed name could still be hiding.

## 2. The facade, proven on three surfaces from one checked-in file

[`src/facade.expected.json`](../../../src/facade.expected.json) is checked in
rather than derived. A test that read the expected list out of the bundle would
agree with the bundle by construction.

| Reader | What it compares |
| --- | --- |
| `tests/contract/state-matrix.test.mjs` | the entry point's declared exports, syntactically |
| `tests/build/parity.test.mjs` | the source module's exports **and** the built bundle's global — exactly, in both directions |
| `tests/build/file-url.test.mjs` | what Chrome sees at a `file://` URL |

Negative controls: a widened facade and a narrowed one are both caught. The
narrowing control had to **replace** the namespace rather than delete from it —
esbuild's `__export` installs non-configurable getters, so
`delete DnsAudit.checkConnectivity` is a silent no-op and the first control
written passed while testing nothing. Measured, and now asserted as a property.

esbuild also adds a non-enumerable `__esModule`. It is recorded in
`facade.expected.json` and pinned, because an artifact that is written down is a
fact about the build and one that is not is a surface nobody is watching.

## 3. The oracle has two executions, and why

Spec §8 as of `1.4`. `globalName: 'DnsAudit'` makes the bundle global esbuild's
export namespace — non-configurable accessors, and **not** the engine object
`src/main.js` calls. Measured against the built artifact:

```text
descriptor: get=function set=undefined configurable=false
assignment: THREW -> Cannot set property analyzeDomain of [object Object]
                     which has only a getter
occurrences of `window.DnsAudit` in the artifact: 0
```

The runner captured the result surface by wrapping that global. It cannot any
more, and that is the namespace boundary working rather than a bundler defect.
So the five surfaces are bound to one deterministic **case** captured by two
isolated executions — the facade's `analyzeDomain` for the result, the real UI
controls for the other four — with separate subjects, runtimes, caches and
fixtures.

**No exclusion was added.** `tests/lib/canonical.mjs`'s exclusion manifest is
still empty. The result execution's queries belong to a different instrument
execution; the emitted trace is the UI execution's complete trace.

What one process image used to guarantee is now asserted. The binding compares
domain set, grade, score, issue count and suggestion count — all read
structurally from the DOM.

**The rule that shapes it:** only fields that *cannot* differ because the code
under test changed may go in the binding. Found by writing it wrong. The first
version read the score from the CSV's `Score` column, and the validator's own
"reorder two CSV columns" mutation — which must move the `csv` surface and
nothing else — crashed the runner instead of being reported. A CSV with swapped
columns is a CSV bug, and the instrument has a place to say so.

Validated before it was trusted: run over all 30 baseline cases the rule matched
79 domains and 77 graded scores with zero mismatches, and
`equivalence.validate.mjs` §5 proves every clause can fail, in both directions,
by damaging a **real** pair rather than a hand-written literal.

The issue **token** set is not compared, and that is a limitation rather than a
choice: `src/main.js:1240` renders issues as translated prose with no token
attribute, so the tokens are not observable on the UI side.

## 4. The trace moved by one query per case, and it is the honest one

The driver clicks `#auditBtn`, `#exportCsvBtn` and `#exportHtmlBtn` instead of
calling three of the globals Task 2.8 removed. That required firing
`DOMContentLoaded`, because `src/main.js` wires every control inside that
listener — and firing it runs the boot's own `checkConnectivity()`.

`checkConnectivity` passes `noCache: true`, so the boot check and `startAudit`'s
pre-flight are genuinely two queries. Measured against a `v0.5.0` recapture with
the same driver:

```text
120 changed lines in the baseline
  30 × "example.com A" count 1 -> 2
  30 × case total       n -> n+1
   0 × anything else
```

The runner had been measuring a page that never booted. Both sides move
together, so the comparison stays clean, and the trace is now what a visitor
actually pays.

**`PRIVACY.md` needs no edit, and that was checked rather than assumed.** Its
published figures are per-**domain** audit fan-out measured by
`tools/backtest.mjs`, which builds the engine directly and loads no page. The
boot check is a page-load cost that was always paid and never counted here. A
moved fan-out is a framework §6 trigger, so it was verified before being
dismissed.

The boot is **settled** before anything is clicked. An audit started while the
boot's request was still open would report a maximum concurrency that depended
on scheduling rather than on the application — nondeterminism in the instrument,
which is the worst kind. The fixture reports its in-flight count and the runner
drains until nothing is open and nothing new has started; bounded, and loud if
it does not converge.

## 5. Fixture identity is recorded, never inferred

Two kinds of subject now have to be measured by one instrument. `v0.5.0` exposes
all 95 engine members; the current artifact exposes two. The probe form is
chosen by capability and written into the manifest as `subject.fixtureIdentity`:

| Subject | Form |
| --- | --- |
| `v0.5.0` baseline | `engine` |
| Working tree and `_site/` | `binding` |

A run can never read as stronger evidence than it was. The same rule the runner
already applies to `--entry=esm`, which refuses to fall back silently because
that "would report the wrong subject".

Per spec §11 as of `1.4`, **neither form is an application-behavioural
fingerprint for the PSL**, and the reason is in the next section.

## 6. Two findings recorded rather than absorbed

**The public suffix list reaches nothing.** `getOrganizationalDomain()` is the
only reader of the PSL sets (`js/dns.js:335-355`) and no application code calls
it — zero call sites at `v0.5.0` and at `f1a2842`.
`result.organizationalDomain` comes from the RFC 9989 discovery walk, which
never consults the list. So 160.6 KB — **38.0% of a 422 KB bundle** — has no
path into any of the five surfaces.

It **stays in 0.6.0**. Removing shipped data is a behaviour-and-size decision,
which is what Risk R8 exists to refuse in passing, and there is a protocol
question underneath it that should be answered first: whether the missing call
site is a latent defect rather than dead code. Filed in
[`docs/maintenance-backlog.md`](../../maintenance-backlog.md).

One claim was corrected because of it. `parity.test.mjs` §6 was going to be
titled "the bundled PSL, observed through the facade". It would have been false.
The section is now about the DMARC tree walk, which is what it proves.

**`createWindow()` in `tools/lib/dom-shim.mjs` has no caller**, and had none at
`21c46ac` either — not stranded by this phase. Also filed.

## 7. What Phase 3 inherits

- `js/` holds `dns.js` and nothing else. It is already an ES module; Phase 3
  moves it, it does not convert it.
- Two adapters, both scheduled. `src/main.js` retires its remaining assignments
  as Phase 5 and Task 6.2 give each name an owner.
- The oracle costs one extra subject load and audit per case. A full run is
  still a phase gate, not a per-commit check.
- `src/main.js` is 1,801 lines of unchanged `js/app.js` body. Task 5.6 reduces
  it to composition; until then it is the file every UI change touches.
