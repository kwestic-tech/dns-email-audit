# Spec: Locale translation pipeline

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Implemented, superseding design) |
| Target release | 0.2.1 |
| Status | Implemented and released |
| Released in | `v0.2.1`, 2026-08-20 |
| Pull request | [#14](https://github.com/kwestic-tech/dns-email-audit/pull/14) |
| Implementation commit | `9e1f221` |
| Merge commit | `ec1983f` — also the `v0.2.1` tag |
| Depends on | Nothing |
| Blocks | Every later spec. The localization contract in [`AGENTS.md`](../../../AGENTS.md) originates here. |
| Slug for open questions | `LOCALE` |
| Last updated | 2026-08-20 |

> **Retrospective spec, and a correction.** The original working specification
> designed a Markdown-packet round-trip. What shipped is an XLIFF 2.1 state
> model, which is a different mechanism reached for different reasons. This
> document records the problem and the constraints as originally stated, then
> states the shipped design in the **As implemented** section and explains why
> the original was abandoned mid-flight. It is filed as implemented because the
> problem was solved; it is not filed as though the original design shipped,
> because it did not.

## Problem

New issue types and interface strings arrive in `locales/en.json` as part of
normal feature work. Nothing propagated those keys into the other locale files.
`tools/check-locales.mjs` reported the gap but was warn-only by design, so gaps
accumulated silently.

A missing translation is invisible at runtime, because the interface falls back
to English without complaint. That is the right runtime behavior and it is
exactly why the problem went unnoticed: **124 keys were missing across seven
locales for months**, introduced by the RFC 9989 DMARC work, and nobody saw it
until someone ran a manual audit.

## Scope

1. No key present in `en.json` is ever structurally absent from another locale.
2. Every untranslated key is tracked in one manifest that survives across
   commits and is visible in a pull request.
3. A translator — human or model — can be handed exactly the outstanding work
   with everything needed to do it, and the result applied back mechanically
   with placeholder integrity enforced.
4. A pull request states its localization status accurately and automatically,
   rather than from memory.

## Non-goals

- **Missing strings stay non-blocking at runtime.** The English fallback is
  correct behavior and is not being removed.
- **Not a machine-translation service.** The pipeline moves work in and out; it
  takes no position on who or what does the translating, only that the result is
  validated and its provenance recorded.

## As implemented

The shipped design replaces the original in full. Each substitution was made for
a stated reason.

### What was originally designed, and why it was abandoned

The original design was a Markdown packet: `tools/scaffold-locales.mjs` copies
missing keys into each locale as English placeholders,
`locales/pending-translations.json` records them with a hash of the English
source, `generate-translation-packet.mjs` writes
`tmp/locale_updates_for_translation.md` for a translator to fill in,
`apply-translation-packet.mjs` parses it back, and `pr-readiness.mjs` writes a
status block.

Three defects killed it.

**It never named the target language.** The packet was one file with a section
per locale. A model asked to fill it in has to infer from a filename which
language each section wants, which is exactly the kind of ambiguity that
produces a French string in the Italian file.

**Fenced Markdown blocks are lossy for this content.** The values being
translated contain newlines, DNS record syntax, and inline `<code>`, `<em>` and
`<strong>` tags. Round-tripping them through fenced blocks and a hand-written
parser is a source of silent corruption in precisely the strings a user is meant
to copy into a DNS control panel.

**Present-but-English is not a state, it is the absence of one.** The original
manifest could record only that a key was pending. It could not distinguish a
machine translation awaiting review from a reviewed one, and it could not
express *this was translated correctly, and then the English moved underneath
it* without a bespoke hash comparison bolted on the side. That problem has a
standard answer, and reinventing it badly was not worth it.

### What shipped

**`locales/translation-status.json`** tracks every key in every locale using the
XLIFF 2.1 `state` vocabulary verbatim — `initial`, `translated`, `reviewed`,
`final` — plus a namespaced `subState`: `kwestic:mt` for machine-translated and
`kwestic:stale` for a translation whose English moved underneath it, the same
idea as gettext's `fuzzy`.

**State is derived, not trusted.** Both sides are fingerprinted, so editing
either the English or a translation is detected on the next sync. The database
records what the files say; it is not an authority that can drift from them.

**Four commands drive it:**

| Command | Does |
| --- | --- |
| `npm run locale:sync` | Scaffolds missing keys and recomputes state from fingerprints |
| `npm run locale:todo` | Emits a per-locale work order as **JSON**, carrying the target language by name, the English source, and the placeholders and inline tags that must survive |
| `npm run locale:set` | Applies a patch file, and **refuses any unit** whose `{0}`/`{1}` placeholders or `<code>`/`<em>`/`<strong>` tags do not match the English |
| `npm run locale:gate` | Blocks a pull request while any key is still `initial` |

`tools/pr-readiness.mjs` (`npm run pr:prep`) summarizes state for a pull request
description — the one component that survived from the original design.
`tools/lib/locale-utils.mjs` holds the shared flatten, placeholder-extraction
and load/save helpers, also as originally specified.
`tools/check-locales.mjs` was reworked to validate against the state database,
with the `--strict` mode that `locale:gate` invokes.

The JSON work order replaces the Markdown packet for all three reasons above: it
names the language explicitly, it carries multi-line values without a parser,
and `locale:set` can reject a unit on placeholder mismatch before it ever
reaches a locale file.

### Scope that grew during implementation

**Every locale was completed.** The eight existing translations went from
409–413 keys to 533 — **988 previously untranslated keys filled**.

**Five languages were added**: Brazilian Portuguese, Polish, Turkish, Indonesian
and Dutch, landing complete. That is 3,663 new translations in total, and
thirteen locales plus English.

**Polish carries more keys than English.** 543 against 533 at release, because
CLDR gives Polish `one`/`few`/`many`/`other` where English has two plural
categories. The tooling preserves categories English does not have rather than
flattening to the English shape. (Current counts have since grown to 538 and
548.)

**`AGENTS.md` was created** — one contract shared by every coding agent working
in the repository, covering the translation loop, the terminology that must stay
literal (record types, tag names, example domains, `fixCode` record syntax),
register per language, and the CLDR plural rule. `CLAUDE.md` points at it so
both toolchains read the same rules. This is the file every later spec means
when it says the localization contract is not optional.

**Arabic and Hindi were considered and deliberately deferred.** Arabic is a
layout problem rather than a translation one: 140 strings carry DNS syntax that
reorders visually under RTL, and a block meant to be pasted into a DNS panel
must not read scrambled. Hindi was deferred on editorial grounds — DNS
terminology has little settled Hindi convention.

## Localization impact

This release *is* the localization impact: 3,663 new translations across
thirteen locales. No runtime code changed — `js/`, `css/`, `index.html` and
`locales/en.json` are untouched by it.

## Testing

`npm test` passes unmodified, confirming the `check-locales.mjs` rework did not
change scoring behavior. `npm run locale:gate` reports 13/13 locales complete
under strict mode.

The mechanical walkthrough: add a throwaway key to `en.json`, `locale:sync`,
confirm it appears in all thirteen locales and as `initial` in the status
database; `locale:todo`, confirm it appears in the work order with the target
language named; apply a valid translation and confirm it lands and flips state;
apply a deliberately placeholder-broken translation and confirm `locale:set`
**rejects** it rather than writing it; `pr:prep`; revert the throwaway key.

`tmp/` is git-ignored and confirmed absent from `git status`.

## Acceptance criteria

All met at merge.

1. No key in `en.json` is structurally missing from any locale. ✅
2. Untranslated state is tracked in a committed, PR-visible manifest. ✅
3. State is derived from file fingerprints, not trusted from the database. ✅
4. A placeholder or inline-tag mismatch is refused, not written. ✅
5. `locale:gate` blocks on any `initial` key. ✅
6. 13/13 locales complete. ✅
7. `npm test` passes; no runtime code changed. ✅

## Risks

**A state database that drifts from the files it describes is worse than no
database,** because it reports confidence that is not there. Mitigated by
deriving every state from a fingerprint of both sides on each sync, so the
database cannot assert anything the files do not support.

**Machine translation recorded as though reviewed.** Mitigated by `kwestic:mt`,
which keeps the provenance visible instead of laundering it into `translated`.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| `OQ-LOCALE-01` | Markdown packet or a structured work order? | Structured JSON. The packet never named the target language, was lossy for values carrying newlines and DNS syntax, and could not express state beyond present/absent. Reversed during implementation. | 1.0 |
| `OQ-LOCALE-02` | Invent a state vocabulary, or adopt one? | Adopt XLIFF 2.1 verbatim, with a namespaced `kwestic:` subState for the two things it does not cover. Translation state is a solved problem. | 1.0 |
| `OQ-LOCALE-03` | Does a missing translation block CI? | Not at runtime and not in `check`; the English fallback is correct. But `locale:gate` blocks a **pull request** while any key is `initial`. Tracking and closing the gap fast, not gating deploys on it. | 1.0 |
| `OQ-LOCALE-04` | Is a locale allowed more keys than English? | Yes. Polish needs four CLDR plural categories where English has two. The tooling preserves categories English does not have. | 1.0 |
| `OQ-LOCALE-05` | Arabic and Hindi? | Deferred. Arabic is an RTL layout problem for 140 DNS-syntax strings, not a translation problem; Hindi lacks settled DNS terminology. Both need their own spec. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-08-20 | Retrospective record of the shipped 0.2.1 release, reconciled against `9e1f221`. Supersedes the original Markdown-packet design, which was abandoned during implementation; reasons recorded under **As implemented**. |
