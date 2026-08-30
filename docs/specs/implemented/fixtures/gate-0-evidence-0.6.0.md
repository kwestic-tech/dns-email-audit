# Capture: Gate 0 evidence

| Field | Value |
| --- | --- |
| For | [modular-architecture-and-production-build](../modular-architecture-and-production-build.md) |
| Records | The Gate 0 conditions of the implementation plan, met before any file under `js/` was touched |
| Captured | 2026-08-27 |
| Platform | macOS (darwin arm64), Node v26.7.0, ICU 78.3, Unicode 17.0 |
| Baseline | `v0.5.0`, commit `5c08364cc3270101f07c2d1b925a6d584e551527` |

Captures go stale. This one states its platform and tool versions because the
equivalence baseline is bound to them: a baseline captured under a different ICU
is not a baseline.

## Gate 0, as the plan states it

> Spec `1.0 (Final)`. Spike numbers recorded. Full §12.1 state registry/matrix
> and all three identity profiles exist. Corpus, five-surface runner and
> committed baseline reproduce from a clean clone. **No file under `js/` has
> been edited.**

## Result

| Condition | Evidence |
| --- | --- |
| Spec `1.0 (Final)` | Unchanged; no amendment was needed |
| Spike numbers recorded | [esbuild-legacy-bundle-spike-0.6.0](esbuild-legacy-bundle-spike-0.6.0.md) |
| §12.1 registry | `tests/state-algebras.json` — 74 algebras, **427 members**, 17 non-enum shapes, 124 axes — *corrected to 75 / 430; see the [addendum](#addendum--post-gate-0-inventory-correction-2026-08-28)* |
| §12.1 matrix | `tests/state-matrix.json` — 427 rows, **427 covered** — *corrected to 430 / 430* |
| Three identity profiles | `tests/lib/fixture-identity.mjs`; all three run in the equivalence runner, both directions asserted |
| Corpus | `tests/fixtures/equivalence/corpus.mjs` — **30 cases**, 5,840 fixture queries — *grown to 32 / 5,941* |
| Five-surface runner | `tests/build/equivalence.mjs`, validated against mutations before use |
| Committed baseline | `tests/fixtures/equivalence/baseline-v0.5.0.json` — reproduces byte-identically |
| `js/` untouched | `git diff main...HEAD -- js/ index.html css/ locales/` is empty |

## 1. The 427-member disposition

Every member of the reviewed registry is covered, and each is covered by
something that observes it rather than by something that mentions it.

| Covered by | Members |
| ---: | --- |
| A corpus case only | 266 |
| A suite only | 71 |
| Both | 90 |
| **Neither** | **0** |

**Corpus coverage is measured, not asserted.** `tests/build/coverage.mjs` runs
every case and walks its real results along the `resultPaths` each algebra
declares, so a case covers a member because the member was observed. An earlier
draft seeded the suite column by scanning the v0.5.0 suites for each member as a
string literal; that gave `ds`, `key`, `no` and `ok` credit for appearing
incidentally in unrelated assertions, and it was withdrawn. What remains in the
suite column points at named assertions.

### The 71 suite-only members, and why the corpus cannot reach them

Not a shortfall. Each is unreachable through `analyzeDomain()` for a structural
reason, and each is asserted by a direct call to an exported function — no test
seam, no fabricated result object.

| Member | Why the audit path cannot reach it |
| --- | --- |
| `dmarc.status: permerror` | The tree walk never passes `multiple`: RFC 9989 §4.10 step 2 discards duplicates and continues. `js/dns.js:1397` says so in its own comment. |
| `dmarc.version.reason: bad-value` | A record whose `v=` is not exactly `DMARC1` fails `isDmarcPolicyRecord()` and is never collected, so `analyzeDmarc` receives `''` and reports `absent`. |
| `dmarc.diagnosis: version-not-first`, `version-absent` | Internal to `diagnoseDmarcRecord()`; its output reaches the result as `observed[].why`, which the corpus does cover. |
| `dmarc.appliedBranch: np`, `weakest` | Both need domain existence `no` or `unknown`. An NXDOMAIN NS probe returns the unregistered shape at `js/dns.js:5370` before any DMARC work happens, so existence is always `yes` by the time `applyInheritance()` runs. |
| `dmarc.reportAuth.record.reason` (3) | `checkExternalReportAuth()` reports a destination-level state and never the per-record reason. |
| `dnssec.ds.unverifiableReason: invalid-owner` | `parseDomains()` in `js/app.js` rejects a label over 63 octets before `startAudit()` queues it. Measured: the corpus case produced no result at all. |
| `dnssec.error: cancelled` | An abort during the DNSSEC lookups aborts every other in-flight query, their `optionalCheck()` wrappers re-throw `AbortError`, and the audit produces no result to observe. |
| The ten transport kinds, thrown paths, cache and retry sets | Transport-layer states that no result field carries. |

### `unbuildable-key` — classified unreachable, invariant covered

`dnssec.ds.unverifiableReason: unbuildable-key` is **dead code** in the
implementation as it stands. `matchDsToDnskeys()` selects candidates with
`key.valid === true` (`js/dns.js:3841`); every valid key has decodable base64,
so `dnskeyRdata()` always builds. `digestsComputed` can therefore only be zero
when there were no candidates — which returns `no-matching-key` earlier — or
when every computation failed, which returns `runtime-unavailable` first.

Per the decision of 2026-08-27: the branch is **preserved unchanged** through
the behavior-neutral refactor, no fixture is invented for it, and it is **not
counted as a reachable state**. What is covered is its *reachability invariant* —
`legacy-shapes.test.mjs` §5d asserts that every key the parser calls valid can
be rebuilt, so a change that made a valid key unbuildable fails there before the
branch goes live.

### Platform-dependent members

Four corpus cases run under a substituted platform primitive rather than the
host's own Web Crypto. Recorded per case in the baseline manifest, so a run
under one profile cannot be silently compared against another.

| Profile | Reaches | Native Node |
| --- | --- | --- |
| `crypto-import-rejects` | `dkim.key.cryptoValidated: false`, `key-structure-invalid` | Cannot produce it |
| `crypto-import-accepts` | The negative control that isolates the refusal | — |
| `crypto-digest-unavailable` | `dnssec.ds.unverifiableReason: runtime-unavailable` | Cannot produce it |

**This is not native-Node coverage and is not described as such anywhere.**
Nothing is fabricated: production code constructs each state itself when the
injected primitive rejects, exactly as a stricter browser would make it. The §6
decision authorising this is recorded in `tests/state-algebras.json` on
`dkim.key.cryptoValidated`.

### Two registry rows corrected by measurement

Both were wrong when first written and both were settled by running the code,
not by re-reading it.

| Row | Correction |
| --- | --- |
| `dnssec.error` | **Added `nxdomain`.** `dnssecLookupStatus()` counts only `success` and `nodata` as completed, so an NXDOMAIN NS probe yields `indeterminate` with error `nxdomain`. |
| `dmarc.reportAuth.error` | **Removed `cancelled` and `undefined`.** The cancelled path re-throws as `AbortError`; every other throw goes through `dnsError()`, which always sets a kind, and a raw fetch rejection becomes `network-error` inside `dohFetch` before this catch sees it. |

## 2. Corpus

30 cases, 5,840 fixture queries, deterministic by construction — every answer
comes from `tools/lib/doh-fixture.mjs` and never from the network.

Key material is real. RSA and Ed25519 keys are generated with `node:crypto` and
pasted verbatim into `tests/fixtures/equivalence/keys.mjs`; the DS digests are
**computed** over the canonical owner name in wire format followed by the
DNSKEY's RDATA, per RFC 4034 §5.1.4. The first draft used hand-invented base64
that looked like a key and was not one — `derReadRsaPublicKey()` refused it,
every fixture reported `unparseable-key`, and the DKIM key axes stayed uncovered
while the cases sat there looking correct. A fabricated DS digest would have
made `confirmed` unreachable and turned every DS in the corpus into an orphan.

## 3. `tests/inventory.json`

The coverage gate, enforced by `tests/contract/inventory.test.mjs`
(`npm run inventory`): every area has a passing suite, every recorded count
matches what the suite printed, and `npm test` runs exactly the suites the
inventory names.

**The gate is the area list, not the number.** The spike settled that
empirically: `tools/scoring.test.mjs` reported `1535 passed, 0 failed` while
running against a silently swapped public suffix list, and the count was
byte-identical to the correct baseline.

| Suite | Assertions |
| --- | ---: |
| `tools/check-locales.mjs` | reports findings, not a count |
| `tools/scoring.test.mjs` | 1,535 |
| `tools/interpolate.test.mjs` | 17 |
| `tools/render.test.mjs` | 329 |
| `tools/export.test.mjs` | 199 |
| `tools/csp.test.mjs` | 41 |
| `tests/contract/legacy-shapes.test.mjs` | 125 |
| `tests/contract/canonicalization.test.mjs` | 108 |
| `tests/contract/state-matrix.test.mjs` | 20 |
| `tests/build/equivalence.validate.mjs` | 42 |
| **Total** | **2,416** |

Baseline at `v0.5.0`: **2,121**. Delta **+295**, and nothing was removed — the
increase is entirely new contract suites.

## 4. The `v0.5.0` baseline

Captured with `git worktree`, never `git checkout` — the tag does not contain
the runner that the next command invokes.

```bash
git worktree add ../dea-v050 v0.5.0
node tests/build/equivalence.mjs --subject-root=../dea-v050 --emit \
  > tests/fixtures/equivalence/baseline-v0.5.0.json
git worktree remove ../dea-v050
```

**These run in sequence.**

| Property | Value |
| --- | --- |
| Size | 5,048 KB raw, **515 KB gzipped** |
| Cases | 30, five surfaces each |
| Subject | commit `5c08364`, `git describe` → `v0.5.0` |
| Inputs hashed | 9 — `index.html`, seven scripts, `css/style.css`, SHA-256 each |
| Environment | Node v26.7.0, ICU 78.3, Unicode 17.0 |
| Fixed inputs | instant `2026-01-15T12:00:00.000Z`, locale `en`, timezone `UTC` |
| Exclusions | **none** — the manifest is empty |

**Reproducibility.** Three independent captures produced byte-identical output,
including the committed file:

```text
f78bc3528b70fba54826bc57ec64550873957a7c245d9e995e8780d0ff58810e
```

**The working tree against it: 30 cases, 5 surfaces, 0 differences.**

Time and locale are controlled *inputs*, not excluded outputs — spec Design §8
permits no timestamp wildcard. Timezone was added to that set after measurement:
`toLocaleString` uses the host zone, and the first capture rendered a 12:00 UTC
instant as `8:00:00 PM` because this machine resolves `Asia/Taipei`. A baseline
captured here and a CI run in UTC would have disagreed about a report the code
produced identically.

## 5. The instrument was validated before it was trusted

Framework §4, and not optional. `tests/build/equivalence.validate.mjs`:

- two runs against one root move **no** surface;
- each of the five surfaces **distinguishes** cases — they are five instruments,
  not one with four decorations;
- seven mutations, each caught on the surfaces it should be **and on no others**:
  a `WEIGHTS` flip, a `WEIGHTS` ceiling that reaches less far, an array reorder,
  an issue-token rename, a dropped DNS query, a **cache narrowing that moves only
  the trace** (R10 — identical result, changed fan-out, a published `PRIVACY.md`
  figure), a CSV column reorder that moves only the CSV, and a report CSP
  weakening that moves only the report;
- a stylesheet-only edit moves the report and nothing else, which is what proves
  a subject is a complete root rather than its JavaScript;
- a script listed in `index.html` but absent is **refused**, not skipped;
- a subject whose generated data was substituted is **refused, not measured** —
  verified by dropping the four-rule fixture PSL into `js/public-suffixes.js`.

It runs against a **stated** six-case subset, because it tests the instrument
rather than the corpus, and section 1 asserts that subset still exercises all
five surfaces. The complete corpus validates the release at every phase gate.

## 6. Cost, and what measuring it changed

| Corpus | Full five-surface run | Emitted document |
| ---: | ---: | ---: |
| 8 cases | 3.6–4.7 s | 1.3 MB |
| 30 cases | **38 s** | 13 MB → **5 MB** |

Framework §3 says to decide the verification rhythm by measuring. At eight cases
the reading was "seconds, so it runs on every commit". At thirty it is not, and
the reading was revised rather than defended: **equivalence runs at every phase
gate**, recorded in `tests/inventory.json` with its reason, while the six-case
oracle validation stays in `npm test`.

Two changes came out of the same measurement:

- The **DOM surface is one line per node** rather than a nested object.
  Identical information — every element, every attribute, exact text, document
  order — in a form a diff can point at. Invisible characters are escaped,
  because `JSON.stringify` leaves U+200B and U+202E literal and a diff that
  changed one would have looked identical to a diff that changed none. Those are
  exactly the characters the hygiene sentinels exist for.
- The **CSV surface is one line per row**, so a diff names the row instead of
  printing the whole export twice. `lines.join('\n')` reconstructs it byte for
  byte.

## 7. Locale gate

`npm run locale:gate` reports **13/13 complete**, 0 errors, 0 warnings. No key
in `locales/en.json` was added, changed or removed — which is the cleanest proof
the localization contract survived, and the reason the strict gate has nothing
to say until the end of the release.

## 8. `js/` is untouched

```bash
git diff main...HEAD -- js/ index.html css/ locales/
```

Empty. The only file outside `tests/` and `package.json` that changed is
`tools/lib/dom-shim.mjs`, which gained a no-op `click()` so the runner measures
the real `exportCSV()` and `exportHTML()` rather than a re-implementation of
them.

---

## Addendum — post-Gate-0 inventory correction, 2026-08-28

**This section corrects the totals above. It does not rewrite them.** The
figures in the original capture were true of the registry as it stood when Gate
0 closed; one owner was missing from it, and the honest record is that the gap
existed at the gate and was found later — not that the gate measured something
it did not.

**Found:** Phase 3, Task 3.6, and recorded in
`CODEX follow-up review for Transport Exception Edges.md`
§4. Carried into the spec as [`1.6`](../modular-architecture-and-production-build.md#revision-history).

### What changed

| | At Gate 0 | Corrected |
| --- | ---: | ---: |
| Algebras | 74 | **75** |
| Members | 427 | **430** |
| Matrix rows | 427 | **430** |
| Covered | 427 | **430** |
| Uncovered | 0 | **0** |
| Corpus cases | 30 | **32** |
| Fixture queries | 5,840 | **5,941** |

### The missing owner

`advanced.reportAuth[].exactKind` had **no algebra at all**. The field is
constructed at two sites in `checkExternalReportAuth()` and reaches the audit
result, so it is exactly the kind of discriminant §12.1 exists to close, and the
Gate 0 claim that the registry was "the minimum closed vocabulary" was
therefore short by one owner and three members.

It is now `dmarc.reportAuth.exactKind`, owned by `core/dmarc`, with three
members: `success`, `nodata`, `nxdomain`.

**Three, not the two the corpus had produced.** The corpus reached `success`
and `nodata`; `nxdomain` is reachable because the inline usability gate in
`checkExternalReportAuth()` admits it exactly as `requireUsable()` does, so an
absent authorization name lands on the `unauthorized` branch carrying its kind
rather than on the `unverifiable` branch a failed lookup takes. Defining a
two-member algebra from what had been observed would have been the same mistake
as the empty `resultPaths` below — describing a measurement as though it were a
reachability claim.

### The empty `resultPaths`

`dns.transport.kind` declared `"resultPaths": []`, which asserts the algebra is
not observable in an audit result. It is, on eleven typed paths, now listed in
the algebra and in spec §3's kind-propagation inventory. 66 of the registry's 74
algebras already declared their paths; this was one of the eight that did not,
and the only one where the omission was a false claim rather than an absence.

### Two corpus cases, and why they were added rather than waived

`dmarc-report-auth-absent` and `spf-lookup-query-error`. The first reaches
`exactKind: 'nxdomain'`; the second reaches `advanced.spfLookups.queryError`,
the eleventh propagation path, which the source has always been able to produce
and the corpus had never asked for.

Both were **captured from the unmodified `v0.5.0` subject first**, which is what
makes them evidence of pre-existing behaviour rather than of anything this
release does. The expansion is purely additive: all thirty pre-existing cases
are **byte-identical** in the recaptured baseline, and the manifest and
environment blocks are unchanged.

> An unobserved but reachable path is a corpus finding, not permission to omit
> the path. Coverage was closed by measurement — 430 of 430, from 32 real cases
> — and not by assigning it on inspection.

### What is deliberately NOT in `resultPaths`

The DMARC walk's kind is also copied into the `dmarc-unverified` issue's
arguments. That is a **derived presentation mirror** and it is tested against
that issue key, not added to the algebra: the coverage reader treats every
matching string as a member, so a bare `issues[].args[]` pattern would let an
unrelated argument equal to `timeout` earn transport coverage — the vacuous
credit the measured matrix was built to remove.

The thrown audit `error.kind` also stays out. It is not a result, and §12.1
already owns it as a thrown path.

### Zero equivalence exclusions

None was added. `tests/lib/canonical.mjs`'s exclusion manifest is still empty,
and the run is **32 cases, 5 surfaces, 0 differences** through both the working
tree and `_site/`.
