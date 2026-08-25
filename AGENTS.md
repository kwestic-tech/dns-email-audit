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

## Committing, pushing, and when the PR opens

**Commit locally as often as the work warrants. Do not push every commit.**

Local commits are free and they are the right unit of work: one per finished
step, one per review finding fixed, one per test suite brought green. Push is
not free — it costs a round trip, it triggers CI, and on a branch that is going
to be squashed anyway it publishes history that never reaches `main`.

| | |
| --- | --- |
| **Commit** | Freely, locally, throughout. |
| **Push** | Once the work is tested and reviewed. |
| **Open the PR** | At the same time, or after. Not before. |
| **Cut the release** | On the same branch, as the last commit before pushing. |
| **Merge** | **Squash.** Ian says when. |

**Open the pull request at the end, not the start.** External review reads the
working tree, not GitHub — Codex is handed a branch and a decision log, not a
URL. A PR opened before review is a stale review target that has to be kept
fresh with pushes that exist only to keep it accurate. Opening it when the work
is done removes that obligation entirely.

**The merge is Ian's call, not a step you run when the gates go green.** Push,
open the PR, say it is ready, and stop. He will say when to squash and merge.

## Cutting the release on the same branch

**There is no `chore/release-*` branch.** Releases through 0.4.0 used one, which
meant two pull requests per release: the feature work, then a second PR that
only bumped a version and flipped some status fields. One branch, one PR, one
squashed commit is the whole release.

The version bump and the documentation status changes are the **last commit on
the feature branch**, made after the work is finished and before the push:

1. Finish the work. Gates green: `npm test`, `npm run locale:gate`, and the
   backtest for anything that could move a score.
2. Write the release artifacts from the finished state — `CHANGELOG.md`,
   `README.md`, the PR description. See the section below.
3. **Cut the release, as its own commit:** bump `package.json`, promote
   `## [Unreleased]` to `## [<version>] — <date>` and add the compare links,
   and set the released status in `docs/specs/implemented/<spec>.md`,
   `docs/specs/README.md`, `ROADMAP.md` and the phase marker in
   `docs/async-development-handoff.md`.
4. Push once, open the PR, and stop.
5. Ian says when to squash and merge. **Tag after the merge**, annotated, on the
   squashed commit: `git tag -a v<version> -m "<version> — <subject>"`.

Read the assertion count for `README.md` out of a real `npm test` run rather
than typing it from memory — it drifted from 174 to 489 unnoticed once already.

**One field cannot be known before the merge.** The spec header and the
`docs/specs/README.md` row have recorded the merge commit SHA, and under this
flow that SHA does not exist until after Ian merges. Record the **release tag**
instead: it is known in advance, it is what a reader actually looks for, and it
survives a rebase. The SHAs already recorded for 0.2.x through 0.4.0 stay as
they are — they were true when written.

### Moving a spec to `implemented/`

This used to be split across the two branches: the feature PR moved the file and
the release commit flipped its status. With one branch it is one step, and all
of it belongs in the release commit described above.

`docs/specs/README.md` says only that "a spec that has shipped moves to
`implemented/`", which reads as a single tidy rename. It is not. In order:

1. `git mv` the spec into `docs/specs/implemented/`, **and any `fixtures/`
   directory belonging to it** — keeping the fixtures beside the spec means its
   own relative links do not change.
2. Re-depth every link in the moved file: repo-root links gain a level
   (`../../js` → `../../../js`), siblings already in `implemented/` lose their
   prefix, and specs still awaiting implementation gain `../`.
3. Fix inbound references repo-wide, then **run a link check over every
   markdown file.** The 0.4.0 move broke nine inbound links across `ROADMAP.md`,
   three sibling specs and the spec index.
4. Add the **As implemented** section: what was built differently from the spec
   and why. Preserve the spec's original text — amendments are inline
   blockquotes pointing at that section, never edits to what the spec said.
5. Bump the spec version, set the status to released, and add the
   **Revision history** row.

The exception is a push requested as an **off-machine backup** — when work is
pausing and the branch should survive the laptop. Ask-driven, not habitual.
Local commits live in the repository's object store and survive worktree
removal, but they are not backed up anywhere.

Because the branch is squashed, the *branch* history is working material and the
*release* artifacts are the deliverable. Which means:

## Release artifacts are written once, at the end, and written well

`CHANGELOG.md`, `README.md` and the PR description are the things a human reads
afterwards. They are not a running log of what happened on the branch.

**Write them when the work is finished**, from the finished state, in one pass:

- **`CHANGELOG.md`** — what the release does and why, in the voice of the
  finished thing. Not "added X, then reverted X, then added X differently".
  A reader wants the decision, not the path to it.
- **`README.md`** — read the assertion count out of an actual `npm test` run
  rather than typing it from memory, and re-check any behaviour statement the
  work changed.
- **The PR description** — `pr-description.md`, untracked and listed in
  `.git/info/exclude`, structured like
  [PR #4](https://github.com/kwestic-tech/dns-email-audit/pull/4). One finished
  document: what changed, why, how it was verified, with real numbers.

Updating these mid-branch is churn. The decisions, the reversals and the review
findings belong in the places built to hold them — the spec's **Revision
history** and **As implemented** sections, and the `CODEX review for PR#<n>.md`
decision log — not in a PR body edited eleven times.

### When review arrives after the PR is already open

Sometimes it will: a human reviews a PR that is up, or the work turns out to
need another round. Then, and only then, the description becomes a living
document and updates are **appended, never overwritten** — a dated entry below a
`---` separator.

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
  same instinct as the Revision history tables in `docs/specs/`. This applies
  to a description that has already been published; a description not yet
  opened is simply rewritten until it is right.
- **Every declined finding needs a reason**, even a short one. This mirrors the
  Resolved-questions discipline in [`docs/specs/README.md`](docs/specs/README.md):
  the reasoning survives for whoever later wonders why an obvious-looking
  suggestion was not taken.
- **Verify before folding in.** An external reviewer's finding is a claim, not a
  fact. Reproduce it against the real code — grep the referenced function, run
  the case — before changing anything. Reviewers in this project have cited
  functions and paths that do not exist. Only confirmed points get fixed, and a
  claim that did not hold up is recorded as such rather than silently ignored.
- **One update per review round, not per commit.** A round is a set of findings
  answered together. Fixing four findings is one entry naming four outcomes, not
  four entries.
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

Push at the end of a round rather than per commit, so what a reviewer reads
always matches the code, without a push for every intermediate step.
