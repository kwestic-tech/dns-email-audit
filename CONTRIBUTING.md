# Contributing

Thanks for helping out. There are three common kinds of contribution, in rough order of how often they're needed.

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 1. Adding a translation

This is the contribution we most want, and it requires **no JavaScript** — one JSON file and one line in a registry.

### The process

**Step 1 — copy the English file.**

```bash
cp locales/en.json locales/fr.json
```

Use the correct [BCP 47](https://www.w3.org/International/articles/language-tags/) tag as the filename. Use a plain language code where the language is written one way (`fr`, `de`, `it`, `ja`, `ko`), and a region- or script-qualified tag where it isn't (`zh-CN` for Simplified, `zh-TW` for Traditional, `pt-BR` vs `pt-PT`).

**Step 2 — translate the values, never the keys.**

```jsonc
{
  "btn": {
    "runAudit": "🔎 Lancer l'audit",   // ✅ value translated
    "auditRunning": "Audit en cours…"
  }
}
```

Update the `meta` block at the top with your language's code, English name and native name.

**Step 3 — register it** in `locales/index.json`, moving the entry out of `planned` into `locales`:

```jsonc
{ "code": "fr", "name": "French", "nativeName": "Français", "label": "🌐 FR", "dir": "ltr" }
```

Set `"dir": "rtl"` for right-to-left languages.

**Step 4 — check your work.**

```bash
npm run check
```

This reports how complete your file is, flags keys that don't exist in `en.json` (usually a typo), and errors on placeholder mismatches.

**Step 5 — open a pull request.** Please say which language you're contributing and whether you're a native speaker.

### Rules that matter

**Placeholders must survive.** `{0}`, `{1}` are filled in at runtime. Keep every one that appears in the English string — you may reorder them if your language needs different word order.

```jsonc
"fileLoaded": "Loaded {0}"      // en
"fileLoaded": "{0} chargé"      // fr — reordered, still present ✅
"fileLoaded": "Fichier chargé"  // ❌ {0} dropped — the filename vanishes
```

**Inline HTML must survive.** A few strings contain markup — `<code>`, `<strong>`, `<a href>`, `<br>`. Translate the text between the tags and leave the tags themselves alone. Don't add new tags.

**Plurals use CLDR categories.** Countable strings are objects, not strings:

```jsonc
"count": { "one": "{0} domain", "other": "{0} domains" }
```

Supply exactly the categories your language uses — `other` alone is correct for Chinese, Japanese and Korean; Russian and Polish need `one`/`few`/`many`/`other`; Arabic uses all six. The [CLDR plural rules chart](https://www.unicode.org/cldr/charts/latest/supplemental/language_plural_rules.html) is the reference. `other` is always required as the fallback.

**Don't translate protocol terms.** SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, CAA, DNSSEC, and DNS record syntax (`v=spf1`, `p=reject`, `-all`) stay as they are — they're literal values people paste into a DNS panel. The same goes for provider names: Cloudflare, Google Workspace, Microsoft 365.

**Do translate the comments inside example records.** The lines beginning with `;` in `fixCode` blocks are explanations, not syntax:

```
; Null MX — tells senders this domain accepts no mail:   ← translate this
@    MX     0 .                                          ← leave this exactly
```

**Emoji stay put.** They're part of the visual language of the UI and are already positioned for it.

### A partial translation is welcome

Missing keys fall back to English automatically. Translating the ~120 chrome and issue-message keys first — and leaving the five long-form guides under `learnMore` for later — produces a genuinely useful build. Open the PR; someone else may finish the guides.

The largest sections, roughly by size:

| Section | Keys | What it is |
| --- | --- | --- |
| `issue.*` | ~68 | Issue messages plus the "Show me" explainer for each |
| `learnMore.*` | ~90 | Five long-form guides (BIMI, MTA-STS, TLS-RPT, CAA, DNSSEC) |
| everything else | ~140 | Buttons, labels, table headers, filters, toasts |

---

## 2. Changing English text

`locales/en.json` is the source of truth. After editing it, regenerate the inlined offline bundle — CI fails if you forget:

```bash
npm run build:fallback
npm run check
```

Never edit `src/data/locales-en.js` by hand; it's generated.

If you **add** a key, other locales simply fall back to English until translated. If you **rename or remove** one, `npm run check` will flag the now-orphaned keys in every other locale so they can be cleaned up in the same PR.

---

## 3. Changing the app

The application is ES modules under `src/`, bundled to one artifact by esbuild
— the only build dependency, exact-pinned, and the only direct dependency.
There is still no framework and nothing at runtime. Please keep it that way;
it's what lets the app be forked, self-hosted and read end-to-end in one
sitting.

```
src/main.js            entry point — build the platform, construct one runtime
src/runtime.js         composition: the DoH layer, the audit, i18n, the page
src/core/dns/          DoH transport, cache, resolver, errors, cancellation
src/core/<protocol>/   one protocol each: spf, dkim, dmarc, dnssec, mx, caa,
                       bimi, transport — plus shared/ for pure helpers
src/audit/             which checks run, scoring, findings, per-audit state
src/providers/         DNS, email and hosting detection
src/ui/                render.js, report.js (CSV + HTML), events.js
src/i18n/index.js      translation loader and rich-text tokenizer
src/data/              generated tables — never hand-edited
```

`AGENTS.md` carries the full ownership table and the allowed-import matrix,
which a contract test enforces: **an edge that is not in the table is a test
failure, not a judgement call.**

**The first hard rule: nothing under `src/` assigns to `innerHTML` or
`outerHTML`.** Build nodes with `R.el` / `R.text` / `R.value` from
`src/ui/render.js` instead, and put every DNS-derived value through `R.value()`
so it gets the malformed-record handling. Reading `outerHTML` to serialize a
document you just built is fine; writing either property is not. `npm test`
scans for it — the source tree AND the built artifact — and the allowlist is
empty, so there is no exception to request.

**The second hard rule: no user-facing English below `src/ui/`.** The protocol
and audit layers return stable tokens (`'@none'`, `'spf-missing'`,
`'noteWildcard'`); the i18n layer maps them to text through `t()`. If you add a
new issue, provider or status, add the token where it is produced and the
wording in `locales/en.json`.

Common, welcome additions:

- **A DNS or email provider** — one line in `detectDNSProvider()` /
  `detectEmailProvider()` in `src/providers/detectors.js`. Proper nouns are
  returned literally and need no locale entry.
- **A DKIM selector** — add to `DKIM_SELECTORS` in `src/core/dkim/dkim.js`.
  Each selector costs two DNS queries per domain, so it should be one a real
  provider uses by default.
- **A new issue check** — add the detection to `buildIssues()` in
  `src/audit/issues.js`, then add `issue.<your-key>` to `locales/en.json` with
  `msg`, and ideally `what`, `fix` and `fixCode` so the "Show me" explainer
  works. The issue-key vocabulary is a closed, reviewed set: add your key to
  `tests/state-algebras.json` too, or the state-matrix contract will fail.

Commit locally as you go — freely, one commit per finished step. **Do not push
every commit;** push once the work is tested and reviewed, and integrate with a
**squash merge**, so intermediate commits never reach `main`. Open the pull
request at that point rather than at the start: review reads the working tree,
and a PR opened early is only a stale review target to keep fresh.

**A release is cut on the same branch**, as the last commit before the push —
there is no separate release branch and no second pull request. See
[`AGENTS.md`](AGENTS.md#committing-pushing-and-when-the-pr-opens) and
[Cutting the release](AGENTS.md#cutting-the-release-on-the-same-branch).

### Getting set up, and what each command does

Every command below was run to write this list.

```bash
npm ci             # installs esbuild and its one platform binary — see below
npm test           # builds the bundle, then locale integrity and every suite
npm run build      # dist/app.min.js plus the deployable _site/
npm start          # serves the app at http://127.0.0.1:8080
```

**`npm ci` installs two packages** on a given platform: `esbuild` and the
binary for your architecture. esbuild is the only direct dependency, and it is
exact-pinned. It declares a `postinstall` script, but `package.json`'s
`allowScripts` gate sets `esbuild: false`, so the install runs no scripts —
the optional platform package supplies the binary.

**`npm test` builds first.** `pretest` runs `npm run build:bundle`, because
several suites assert against `dist/app.min.js` — a source-only run would be
testing something the browser never sees.

### The test layout

Tests live beside what they test:

| Where | What |
| --- | --- |
| `src/**/*.test.js` | co-located unit tests — run one directly, e.g. `node src/core/spf/spf.test.js` |
| `tests/contract/` | cross-cutting contracts: allowed imports, transport kinds, the state registry, the namespace |
| `tests/build/` | the built artifact, source-to-bundle parity, five-surface equivalence, `file://` in real Chrome |
| `tools/` | the older whole-engine suites — scoring, rendering, exports, CSP |

`npm run inventory` runs every suite as a subprocess and compares each one's
assertion count against `tests/inventory.json`. **A count that moves without
the record moving with it fails**, in both directions: a silent decrease is
coverage quietly leaving, and a silent increase is work nobody recorded.

### `file://` works, and it is tested

After `npm run build`, `index.html` opens straight from disk with no server.
That is why the bundle is a classic script rather than `type="module"` — a
module script is blocked by CORS under `file://` — and why the English locale
is inlined into the artifact rather than fetched. `npm run test:file-url`
drives a real Chrome over `file://` and asserts it, so the property cannot rot
silently.

Other locales still need a server: browsers block fetching `locales/*.json`
from disk, and the app falls back to English.

### Before opening a PR

```bash
npm test             # every suite, with the bundle built first
npm run locale:gate  # must report 13/13 before the PR opens
npm start            # then click through: run an audit, expand a row,
                     # switch language, export CSV and the HTML report
```

**When cutting a release** — which happens on the feature branch, as its last
commit — read the assertion count out of the `npm test` run and update the
figure in `README.md`'s command table from that output rather than typing it
from memory. It drifted from 174 to 489 unnoticed once already. Also add the
release to `ROADMAP.md`'s **Shipped releases and their specs** table, and verify
that the immediately preceding release is present there. The package version,
roadmap row and implemented-spec link must describe the same release before the
release commit is made.

**Write these three from the finished state, once, before the PR opens.** They
are what a human reads afterwards, not a log of what happened on the branch, and
nothing fails if they go stale — a reviewer simply reads something untrue.
If a review round then lands on an open PR, re-check them at the end of that
round:

| | Why it goes stale |
| --- | --- |
| `CHANGELOG.md` | The `## [Unreleased]` section is written once and then forgotten. Later commits on the same branch — review fixes especially — change what the release actually does. Describe the release as it finally is, not the route it took. |
| The PR description | GitHub keeps the body you opened the PR with. If a review makes you reverse a decision, the body still argues the old one. |
| `README.md` | The assertion count moves whenever tests are added, and behaviour statements go stale when a review changes behaviour. Read the count out of a real `npm test` run. |
| `ROADMAP.md` | A release can be marked complete in its workstream while still being omitted from the shipped-releases table. Match the table's newest row and implemented-spec link to `package.json`, and confirm the preceding release is present. |

The failure mode is not hypothetical. On PR #18 the body stated that CSV formula
injection was *"not addressed here"* while a later commit on the same branch
neutralized it — the description contradicted the diff a reviewer was reading.
The assertion count in the same body was two revisions behind.

How to write the description — and the rule that a round landing on an
already-open PR is **appended, never overwritten** — is in
[`AGENTS.md`](AGENTS.md#release-artifacts-are-written-once-at-the-end-and-written-well).
Do not restate it here; that section is the authority for both humans and
agents.

After building, please also confirm `index.html` still opens correctly straight
from disk (`file://`) in English.

---

## Reporting bugs

Include the domain you audited (if it's public), what you expected, what you saw, and your browser. A wrong result for a real domain is the most useful bug report there is — DNS is full of edge cases and provider detection is heuristic.

## License

Contributions are accepted under the [MIT License](LICENSE).
