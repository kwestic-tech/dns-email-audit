# Agent contract

Applies to any coding agent working in this repo — Claude Code, Codex, or
otherwise. `CLAUDE.md` points here so both toolchains read the same rules.

## Localization is part of the change, not a follow-up

`locales/en.json` is the source of truth. Thirteen other locales track it:
German, Spanish, French, Indonesian, Italian, Japanese, Korean, Dutch, Polish,
Brazilian Portuguese, Turkish, Simplified Chinese, Traditional Chinese.

**If your change adds or edits a key in `locales/en.json`, translating it into
all thirteen locales is part of that same change.** Not a TODO, not a follow-up
issue, not a note in the PR description. The reason is mechanical: a missing
translation is invisible at runtime — the UI silently falls back to English —
so nothing ever fails loudly enough to make anyone go back and fix it. A
124-key gap sat in seven locales for months exactly this way.

You are a capable translator. Do the translation yourself, in-session.

### The loop

```bash
npm run build:fallback              # after any en.json edit — keeps js/locales-en.js in sync
npm run locale:sync                 # scaffold new keys, recompute state
npm run locale:todo                 # what is outstanding, per locale
npm run locale:todo -- de --json    # machine-readable work order for one locale
```

`locale:todo --json` gives you, for each unit: the target language by name,
the English source, and the placeholders and inline tags that must survive.
Translate them, then write a patch file:

```json
{ "de": { "issue.spf-large-subnet.msg": "…", "th.domain": "…" },
  "fr": { "issue.spf-large-subnet.msg": "…" } }
```

```bash
npm run locale:set -- /tmp/translations.json --translator=<your model id>
npm run locale:gate                 # must pass before you open the PR
```

`locale:set` refuses any unit whose `{0}`/`{1}` placeholders or inline
`<code>`/`<em>`/`<strong>` tags do not match the English, and tells you which.
It writes nothing for a refused unit, so a rejection is safe to re-run.

Work one locale at a time. Batches of roughly 40 units keep quality up and
keep a failed patch cheap to redo.

## Translation rules

**Never translate:**

- DNS record types and mechanisms — `TXT`, `MX`, `CNAME`, `CAA`, `SPF`,
  `DKIM`, `DMARC`, `BIMI`, `MTA-STS`, `TLS-RPT`, `DNSSEC`, `include:`, `a`,
  `mx`, `ip4`, `ip6`, `all`, `redirect=`
- Tag names and their values — `v=DMARC1`, `p=reject`, `rua=`, `ruf=`, `fo=`,
  `pct=`, `adkim=`, `aspf=`, `sp=`, `np=`, `t=y`
- Example domains and hostnames — `example.com`, `_dmarc`, `_domainkey`
- Anything inside a `fixCode` block except its `;` comment lines. The record
  syntax is literal; the comments around it are prose and should be translated.
- Error and status tokens that mirror protocol output — `Permerror`,
  `SERVFAIL`, `NXDOMAIN`, `NOERROR`
- Record-hygiene sentinel markers — `‹RLO›`, `‹ZWSP›`, `‹U+0007›` and the rest.
  They name Unicode code points, which are the same in every language, and a
  translated marker would break the property that two auditors reading the
  same record in different languages see the same evidence. They are generated
  in `js/render.js` and never appear in a locale file; the surrounding
  `render.hygiene.*` prose is ordinary translatable text.

**Always preserve exactly:**

- `{0}`, `{1}` placeholders — same set, same digits. Word order may move
  around them; the tokens themselves may not change.
- Inline `<code>`, `<em>`, `<strong>` tags, including which words they wrap.
- Leading status glyphs — `✓`, `✗`, `⚠`, `🔴`, `·`, `—`.

**Register:** second person, direct, practical. This is a diagnostic tool read
by sysadmins mid-incident, not marketing copy. Use the formal register where a
language distinguishes one (German *Sie*, French *vous*, Spanish *usted*,
Japanese です・ます, Korean 합쇼체).

**Terms that stay English but take native grammar around them:** SPF, DKIM,
DMARC and friends are borrowed as-is in all eight locales. In CJK do not
transliterate them into kana or characters.

**Plurals follow CLDR, not English.** A countable key is an object of plural
categories, and a language supplies exactly the ones it uses — Indonesian needs
only `other`, Polish needs `one`/`few`/`many`/`other`, Arabic all six. The
tooling preserves categories `en.json` does not have; `js/i18n.js` resolves
them through `Intl.PluralRules`. Never trim a locale's plural forms to match
English. See CONTRIBUTING.md for the full rule.

**Terms that must be translated, including in CJK:** interface vocabulary —
"Domain", "Status", "Hosting", "Provider", "Score", "Warning", "Error",
"Copy", "Export". A CJK locale showing "Domain" in Latin script is a bug, not
a deliberate borrowing.

**Identical-to-English is a real answer, but state it deliberately.** Some
strings genuinely do not change — `SPF`, `—`, `✓ -all`, `N/A` in several
locales. When that is the right call, still put the value through
`locale:set`; that records it as a decision rather than leaving it looking
untranslated forever.

## State model

`locales/translation-status.json` tracks every key in every locale, using the
XLIFF 2.1 `state` vocabulary:

| state | meaning |
|---|---|
| `initial` | no translation — the locale is holding an English placeholder |
| `translated` | translated, not yet reviewed by a human |
| `reviewed` | a human has checked it |
| `final` | signed off; tooling leaves it alone |

Plus a namespaced `subState`, the way XLIFF intends extensions:

| subState | meaning |
|---|---|
| `kwestic:mt` | machine/LLM translated, never human-reviewed |
| `kwestic:stale` | the English changed after this translation was written |

`kwestic:stale` is the same idea as gettext auto-marking an entry `fuzzy`.
Agents write `translated`. Only a human promotes to `reviewed` or `final`
(`npm run locale:set -- file.json --state=reviewed`).

State is *derived from the files*, not trusted from the database: `locale:sync`
fingerprints both the English and the translation, so editing either one is
detected on the next run. Never hand-edit `translation-status.json`.

## Other repo rules

- `npm test` must pass before you open a PR. `npm run locale:gate` too.
- After editing `locales/en.json`, run `npm run build:fallback` or
  `check-locales.mjs` will fail on `js/locales-en.js` being out of sync.
- Never edit while on `main`; branch first.
- `tmp/` is scratch and git-ignored.

## PR description change log

A pull request description is a living document, not a frozen snapshot taken at
open time. When a PR goes through external review — Codex, Gemini, or a human —
the original description stays intact. Updates are **appended, never
overwritten**.

**On opening a PR:** write the description as normal (what changed, why, how it
was tested). It lives in `pr-description.md`, untracked and listed in
`.git/info/exclude`, structured like
[PR #4](https://github.com/kwestic-tech/dns-email-audit/pull/4).

**After any review round that produces new commits:** append a dated entry below
a `---` separator.

```
## Update — YYYY-MM-DD
**Reviewed by:** [Codex / Gemini / Ian]

- **Addressed:** [finding] — fixed in [commit sha]
- **Declined:** [finding] — [one-line reason]
- **Verified against codebase:** [yes/no, and note any reviewer claim that did
  not hold up]
```

**Rules**

- **Never edit or delete the original description text. Append only.** A reader
  coming to the PR later must be able to see what the submission originally
  claimed as well as what it claims now. If a review reverses a decision, the
  original reasoning stays visible and the update says it was reversed — the
  same instinct as the Revision history tables in `docs/specs/`.
- **Every declined finding needs a reason**, even a short one. This mirrors the
  Resolved-questions discipline in [`docs/specs/README.md`](docs/specs/README.md):
  the reasoning survives for whoever later wonders why an obvious-looking
  suggestion was not taken.
- **Verify before folding in.** An external reviewer's finding is a claim, not a
  fact. Reproduce it against the real code — grep the referenced function, run
  the case — before changing anything. Reviewers in this project have cited
  functions and paths that do not exist. Only confirmed points get fixed, and a
  claim that did not hold up is recorded as such rather than silently ignored.
- **Editing the description is its own step**, independent of pushing commits.
  Pushing updates the diff and touches nothing else:

  ```bash
  gh pr edit <number> --body-file pr-description.md
  ```

- **Resolve the review threads you acted on**; reply and leave open the ones you
  deliberately did not, with the one-line reason from the update entry.

Adding a commit updates none of the release artifacts. See the pull-request
checklist in [`CONTRIBUTING.md`](CONTRIBUTING.md) for the three that go stale
silently — `CHANGELOG.md`, this description, and `README.md`.
