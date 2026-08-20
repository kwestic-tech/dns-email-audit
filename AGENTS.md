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
