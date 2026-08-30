# Gate 5 evidence — 0.6.0

| Field | Value |
| --- | --- |
| Gate | **5** — audit coordination and UI |
| Date | 2026-08-30 |
| Branch | `spec/modular-architecture-production-build` |
| Spec | [modular-architecture-and-production-build](../modular-architecture-and-production-build.md) `1.6 (Final)` |
| Tasks | 5.1 context, 5.2 coordinator, 5.3 scoring, 5.4 issues, 5.5 report, 5.6 events |

> **Gate 5.** Weights byte-identical. Coordinator holds no parsing rule. No
> protocol interpretation under `src/ui/`. Markup-sink allowlist still empty.

All four conditions are met. Each is evidenced below by a command and its
output, not by an assertion that it holds.

---

## 1. The scoring rubric is identical to `v0.5.0`

### The instrument

Values, not source text: the scoring blocks dedented by two spaces when they
left the IIFE, so a raw text diff would report a difference that is not one.
Both sides are evaluated and serialized with `JSON.stringify`, and the
resulting strings are compared byte for byte — the same shape as the Gate 4
token diff after its reference-identity defect was corrected.

**It reads `git show`, so it is deliberately NOT part of `npm test`:** the
suite has to work in a checkout without history, and a gate instrument that
silently skips is worse than one run deliberately. What IS in the suite is
`src/audit/scoring.test.js` §1, which pins the literals this diff confirmed and
keeps working without the tag.

Save as `weights-diff.mjs` in the repository root and run `node weights-diff.mjs`:

```js
/**
 * Gate 5, condition 1: the scoring constants are byte-identical to v0.5.0.
 *
 * VALUES, not source text: the blocks dedented by two spaces when they left the
 * IIFE, so a raw text diff would report a difference that is not one. Both
 * sides are evaluated and serialized with JSON.stringify, and the resulting
 * strings are compared byte for byte — the same instrument the Gate 4 token
 * diff used after its reference-identity defect was corrected.
 *
 *   node weights-diff.mjs
 */
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const REPO = process.cwd();
const NAMES = ['WEIGHTS', 'PARKED_WEIGHTS', 'GRADE_THRESHOLDS', 'POLICY_RANK'];

// The v0.5.0 side, read straight out of the tag.
const v050 = execFileSync('git', ['show', 'v0.5.0:js/dns.js'], { cwd: REPO, encoding: 'utf8', maxBuffer: 1 << 28 });
const dir = mkdtempSync(join(tmpdir(), 'v050-'));
const shim = join(dir, 'v050.mjs');
// v0.5.0's js/dns.js is an IIFE over `window`; the constants are plain
// declarations inside it. Lift each one by its declaration text, which is the
// only thing this comparison needs and avoids evaluating 5,704 lines.
const lifted = NAMES.map(name => {
  const re = new RegExp(`^\\s*(?:var|const|let)\\s+${name}\\s*=\\s*`, 'm');
  const at = v050.search(re);
  if (at < 0) throw new Error(`${name} not found in v0.5.0:js/dns.js`);
  const from = v050.indexOf('=', at) + 1;
  // Walk to the balanced end of the initializer.
  let depth = 0, i = from, end = -1;
  for (; i < v050.length; i++) {
    const c = v050[i];
    if (c === '{' || c === '[') depth++;
    else if (c === '}' || c === ']') depth--;
    else if (c === ';' && depth === 0) { end = i; break; }
  }
  return `export const ${name} = ${v050.slice(from, end).trim()};`;
}).join('\n');
writeFileSync(shim, lifted);

const before = await import('file://' + shim);
const after = {
  ...await import('file://' + join(REPO, 'src/audit/scoring.js')),
  ...await import('file://' + join(REPO, 'src/core/dmarc/record.js')),
};

let differences = 0;
for (const name of NAMES) {
  const a = JSON.stringify(before[name]);
  const b = JSON.stringify(after[name]);
  const same = a === b;
  if (!same) differences++;
  console.log(`${same ? 'IDENTICAL' : 'DIFFERS  '}  ${name.padEnd(17)} ${a.length} bytes`);
  if (!same) console.log(`    v0.5.0: ${a}\n    now:    ${b}`);
}
console.log(`\n${NAMES.length} constants compared, ${differences} differences`);
process.exit(differences ? 1 : 0);
```

### The output

```
$ node weights-diff.mjs
IDENTICAL  WEIGHTS           83 bytes
IDENTICAL  PARKED_WEIGHTS    42 bytes
IDENTICAL  GRADE_THRESHOLDS  446 bytes
IDENTICAL  POLICY_RANK       36 bytes

4 constants compared, 0 differences
```

### Proven to fail before it was believed

Framework §1 rule 3. With `spf: 15` changed to `spf: 14` in
`src/audit/scoring.js`:

```
DIFFERS    WEIGHTS           83 bytes
    v0.5.0: {"dmarc":30,"spf":15,"dkim":15,"dnssec":15,"caa":10,"mtaSts":8,"bimi":4,"tlsRpt":3}
    now:    {"dmarc":30,"spf":14,"dkim":15,"dnssec":15,"caa":10,"mtaSts":8,"bimi":4,"tlsRpt":3}
IDENTICAL  PARKED_WEIGHTS    42 bytes
IDENTICAL  GRADE_THRESHOLDS  446 bytes
IDENTICAL  POLICY_RANK       36 bytes

4 constants compared, 1 differences
```

Exit code 1. The mutation was reverted immediately.

### Two notes on scope

- **`POLICY_RANK` is not `src/audit/`'s.** It moved to
  `core/dmarc/record.js` at Task 4.6; the implementation plan lists it under
  Task 5.3 because it was still in `js/dns.js` when the plan was written. It is
  in the diff regardless, and the test asserts it from its real owner.
- **The rubric is NOT frozen, and must not be.** `const` prevents rebinding
  only. `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` are legacy engine
  members published as plain objects and a plain array; freezing them would
  change the observable legacy surface — a compatibility delta under the word
  "constant". The guarantee is that their **serialized values and ordering**
  match `v0.5.0`. `scoring.test.js` §1 asserts both halves, including
  `Object.isFrozen === false` for all three.

---

## 2. The issue-token vocabulary is identical to `v0.5.0`

Gate 4's recorded command, re-run verbatim after Task 5.4 moved the builders:

```
v0.5.0 issue tokens: 106
HEAD    issue tokens: 106
added:   (none)
removed: (none)
byte-identical key list: true
tokens whose English content moved: (none)
registry algebra matches HEAD: true
registry algebra matches v0.5.0: true
```

**That comparison is necessary and not sufficient for a code move**, which is
worth stating plainly: it reads `locales/en.json`, and a code move does not
edit that file. A key silently dropped while relocating the builder would leave
all 106 tokens in place and simply stop being emitted.

So a second comparison, over the `key: '…'` literals the builders actually
emit. **The pre-move side is read from an immutable commit** — `2df5dfc`, the
parent of the Task 5.4 extraction `92aa12a`, and the last commit at which
`js/dns.js` still held both builders. `HEAD` is post-move and cannot reproduce
it.

Save as `emitter-diff.mjs` in the repository root and run `node emitter-diff.mjs`:

```js
/**
 * Gate 5, condition 2b: moving the issue builders emitted the same keys.
 *
 * The locale diff watches `locales/en.json`, which a code move does not edit —
 * so a key silently dropped while relocating the builder would leave all 106
 * tokens in place and simply stop being emitted. This watches the EMITTER.
 *
 * The pre-move side is read from an immutable commit: `2df5dfc` is the parent
 * of `92aa12a`, the Task 5.4 extraction, and is the last commit at which
 * `js/dns.js` still contained both builders. `HEAD` would not reproduce it.
 *
 *   node emitter-diff.mjs
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const PRE_MOVE = '2df5dfc';                 // 92aa12a^ — before Task 5.4
const KEY = /key: '([a-z0-9-]+)'/g;
const keys = source => [...source.matchAll(KEY)].map(m => m[1]);

const before = keys(execFileSync('git', ['show', `${PRE_MOVE}:js/dns.js`], { encoding: 'utf8', maxBuffer: 1 << 28 }));
const after = [
  ...keys(readFileSync('src/audit/issues.js', 'utf8')),
  ...keys(readFileSync('js/dns.js', 'utf8')),
];

const sorted = a => [...a].sort();
const lost = before.filter(k => !after.includes(k));
const gained = after.filter(k => !before.includes(k));

// The issue builder alone, split from the suggestion builder: they resolve
// into different locale namespaces and only the first is the issue vocabulary.
const issuesSource = readFileSync('src/audit/issues.js', 'utf8');
const cut = issuesSource.indexOf('export function buildSuggestions(');
const issueLiterals = [...new Set(keys(issuesSource.slice(0, cut)))];
const registry = JSON.parse(readFileSync('tests/state-algebras.json', 'utf8'))
  .algebras.find(a => a.id === 'audit.issue.key').members;

console.log(`pre-move source: ${PRE_MOVE}:js/dns.js  (92aa12a^, before Task 5.4)`);
console.log(`key: literal occurrences, both builders, before: ${before.length}`);
console.log(`key: literal occurrences, both builders, after:  ${after.length}`);
console.log(`identical multiset: ${JSON.stringify(sorted(before)) === JSON.stringify(sorted(after))}`);
console.log(`lost:   ${lost.length ? lost.join(', ') : '(none)'}`);
console.log(`gained: ${gained.length ? gained.join(', ') : '(none)'}`);
console.log(`key: literals left in js/dns.js: ${keys(readFileSync('js/dns.js', 'utf8')).length}`);
console.log('');
console.log(`distinct DIRECT issue-key literals in buildIssues: ${issueLiterals.length}`);
console.log(`reviewed audit.issue.key vocabulary:               ${registry.length}`);
console.log(`emitted only through non-literal mechanisms:       ${registry.filter(k => !issueLiterals.includes(k)).length}`);
```

```
$ node emitter-diff.mjs
pre-move source: 2df5dfc:js/dns.js  (92aa12a^, before Task 5.4)
key: literal occurrences, both builders, before: 98
key: literal occurrences, both builders, after:  98
identical multiset: true
lost:   (none)
gained: (none)
key: literals left in js/dns.js: 0

distinct DIRECT issue-key literals in buildIssues: 92
reviewed audit.issue.key vocabulary:               106
emitted only through non-literal mechanisms:       14
```

Three numbers, and they are three different things:

| Number | What it counts |
| --- | --- |
| **98** | `key: '…'` literal OCCURRENCES across both builders — the multiset that must survive a move unchanged |
| **92** | DISTINCT direct issue-key literals in `buildIssues` (the rest of the 98 are repeats and the seven `buildSuggestions` tip keys, which resolve through `suggestion.*`) |
| **14** | issue keys emitted only through the four non-literal mechanisms |

**A literal scan sees only 92 of the 106 issue keys.** Fourteen are emitted
without ever being written as a literal, by four mechanisms — the DKIM
confidence ternary (2), the `DIAGNOSIS_KEYS` table (3), `pushKeyFinding()` (3),
and forwarding from the closed `spf.warnings` owner algebra (6).
`src/audit/issues.test.js` §3b holds that inventory, pins it against
`audit.issue.key` in both directions, and exercises all four emission paths;
`tests/contract/legacy-shapes.test.mjs` §6 is the registry-side control.

---

## 3. The coordinator holds no parsing rule

Spec §5: `auditDomain()` "does not parse records." Enforced by
`tests/contract/dns-transport.test.mjs` **§3b**, a named structural contract.

| Rule | Owner |
| --- | --- |
| Which TXT records are SPF records, and whether there is more than one | `core/spf/`'s `selectSpfRecords` |
| BIMI selection and status shaping | `core/bimi/`'s `summarizeBimi` |
| MTA-STS and TLS-RPT, the same | `core/transport/`'s `summarizeMtaSts`, `summarizeTlsRpt` |
| Verification-record selection | `providers/`'s `selectVerifications` |
| `startsWithCI`, `versionCandidates`, `leadingVersionMatches` | `core/shared/record-selection.js` |

§3b asserts none of those names is declared in `src/audit/audit-domain.js` and
each is declared by the owner named for it, with the classifier proven in both
directions. **It is a lexical scan over `function NAME` declarations and says
so:** it would not catch the same rule written as an arrow function or under
another name. It is defence against the specific regression that Task 5.2
actually shipped and review caught.

The two derived-fact boundaries are contracted beside it:
`audit/scoring.js` and `audit/issues.js` read owner-produced FACTS — including
`spfStatus.warnings` — and never record contents. Both contracts assert it the
same way: fabricated facts with no parser behind them, and a record attached to
the same facts changes nothing, **including one that contradicts them**.
`spfRecords` is the instructive case: its CARDINALITY is consumed as evidence
for `spf-multiple-records`, and its contents never are.

---

## 4. No protocol interpretation under `src/ui/`

Enforced by `tests/contract/dns-transport.test.mjs` **§3c**, added at Gate 5.

```
ui/events.js  ui/render.js  ui/report.js
no parser or selector declared          — none
no finding or scoring builder declared  — none
issue tokens from the reviewed vocabulary emitted — none
severities assigned                     — none
```

`ui/events.js` does write `key: 'BIMI'`, `'MTA-STS'`, `'TLS-RPT'`, `'CAA'` and
`'DNSSEC'`. Those are the protocol NAMES that label the advanced-check status
dots, chosen off booleans an owner produced. A label is not a finding, which is
why the check is against the reviewed issue vocabulary rather than against the
string `key:` — and the scan asserts it does see those five, so it is not
passing by matching nothing.

`src/ui/`'s only import is `ui/report.js` from `ui/events.js`. It imports no
`audit/`, no `core/`, no `providers/` and no `src/data/`; `analyzeDomain` and
`checkConnectivity` arrive as callbacks, which §12 requires and
`dns-transport.test.mjs` §5 asserts.

---

## 5. The markup-sink allowlist is empty

`tools/csp.test.mjs` §4:

```js
const ALLOWLIST = [];
eq('the allowlist is empty', ALLOWLIST.length, 0);
```

The scan covers every hand-written file under `js/` and `src/` — excluded by a
mechanical `.test.js` SUFFIX rule, never by a named-file list — and the built
`dist/app.min.js`, which is what the browser actually runs. Its `SINK_CASES`
array proves the scan catches `el.innerHTML += x` before the scan is trusted
over the source tree.

---

## 6. The gates

Run at the Gate 5 boundary, on `1c829f1` plus the §3c contract:

| Command | Result |
| --- | --- |
| `npm test` | **4,429** passed, 0 failed, 46 suites |
| `npm run inventory` | **240** passed, total **4,429** |
| `npm run locale:gate` | 13/13, 771/771 keys each, 0 errors |
| `npm run build` | `dist/app.min.js` + `_site/` |
| `node tests/build/equivalence.mjs --subject-root=.` | 32 cases, 5 surfaces, **0 differences** |
| `node tests/build/equivalence.mjs --subject-root=_site` | 32 cases, 5 surfaces, **0 differences** |
| `npm run test:file-url` | **28** passed, real Chrome over `file://` |
| `npm run coverage` | cases 32, rows 430, covered **430**, uncovered 0 |
| Markdown relative links | 56 tracked files, 0 broken |

`tools/scoring.test.mjs` reports **1,535** assertions — unchanged since before
Phase 5 — which is the evidence that the observed legacy engine surface did not
move while five modules were extracted out from under it.

### The mutation probes still exercise the moved code

All eight apply exactly once, read out of the real instrument rather than a
reimplementation of it:

```
applies exactly once  src/audit/scoring.js         flip one WEIGHTS value (spf 15 -> 14)
applies exactly once  src/audit/scoring.js         flip a WEIGHTS value that is a ceiling only (dmarc 30 -> 29)
applies exactly once  src/audit/scoring.js         reorder one array (the scoring pillars)
applies exactly once  src/audit/issues.js          change one issue token (spf-missing -> spf-absent)
applies exactly once  src/audit/audit-domain.js    drop one DNS query (the AAAA lookup at the apex)
applies exactly once  src/core/dmarc/tree-walk.js  narrow the cache (noCache on the DMARC walk)
applies exactly once  src/ui/report.js             reorder two CSV columns
applies exactly once  src/ui/report.js             weaken the exported report's own CSP
```

`equivalence.validate.mjs` §2b's negative control — which applies the largest
mutation WITHOUT rebuilding and requires that no surface moves — follows the
weights too. It is not in the `MUTATIONS` array, so a search for probe targets
does not find it, and after Task 5.3 it would have gone green for the wrong
reason: editing a file the artifact no longer sources the weights from is
indistinguishable from the "not rebuilt" condition it exists to prove.

---

## What Gate 5 leaves for Phase 6

- `js/dns.js` is **373 lines**, from 5,704 — the transitional composition root,
  five compatibility wrappers and the legacy engine-surface assembly. Task 6.1
  deletes it.
- `src/main.js` is **222 lines**, from 1,819 in `js/app.js`. Composition, the
  two marked-adapter global assignments and the two facade exports.
- **Two marked adapters** remain, unchanged: `src/data/legacy-globals.js` and
  `src/main.js`. Task 6.2 asserts zero.
- **Five compatibility wrappers** in `js/dns.js` preserve observed legacy
  signatures — four string-taking DKIM members and the three-argument
  `detectEmailProvider`. Adapters, not architecture.
- **One localization finding**, pre-existing and needing separate
  authorization: `checks-unverified` joins `'BIMI'`, `'SPF'`, `'MX'`, `'TLSA'`
  and `'Website'`. The first four are protocol names that must never be
  translated; "Website" is an ordinary English noun that should be. Fixing it
  adds an `en.json` key, which under `AGENTS.md` means thirteen translations in
  the same change.
