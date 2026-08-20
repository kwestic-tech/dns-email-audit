# Spec: Repository hygiene and community health files

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Implemented) |
| Target release | 0.2.0 |
| Status | Implemented and released |
| Released in | `v0.2.0`, 2026-08-20 |
| Pull request | [#13](https://github.com/kwestic-tech/dns-email-audit/pull/13) |
| Implementation commit | `41c29fc` |
| Merge commit | `d1677ff` — also the `v0.2.0` tag |
| Depends on | [privacy-documentation](privacy-documentation.md), for the `SECURITY.md` the Code of Conduct points at |
| Blocks | Nothing |
| Slug for open questions | `HYGIENE` |
| Last updated | 2026-08-20 |

> **Retrospective spec.** Written after the work shipped. This is the release
> that set the project's version number, so it is the answer to *when did the
> version change* for everything merged before it.

## Problem

A full documentation audit of `main` found one correctness defect and four
conventional gaps.

The defect: `package.json` read `"version": "1.0.0"` while `CHANGELOG.md` still
carried a note beginning *while the project is at 0.x*, with a latest dated
entry of `0.1.0`. The two files disagreed about whether the project had shipped
1.0.0. Since the locale key structure was explicitly not frozen — the whole
point of that translator note — `1.0.0` was wrong, and it had been wrong since
the repository was first restructured.

The gaps: a leftover `COMMIT_MSG.txt` scratch file, no badges in `README.md`, no
`CODE_OF_CONDUCT.md`, no issue templates, and a `package.json` with no
repository, homepage, bugs or author metadata.

## Scope

Documentation and repository metadata only. Zero runtime code changes.

1. Resolve the version disagreement.
2. Delete `COMMIT_MSG.txt`.
3. Add CI and licence badges to `README.md`.
4. Add a Contributor Covenant 2.1 `CODE_OF_CONDUCT.md`, linked from
   `CONTRIBUTING.md`.
5. Add GitHub issue forms for the two contribution types the documentation
   already names.
6. Fill in `package.json` metadata.

## Non-goals

- No changes to `js/`, `css/`, `index.html`, `locales/*.json` or any test file.
- No changes to the content of `PRIVACY.md`, `SECURITY.md` or
  `THIRD_PARTY_NOTICES.md`.
- No changes to the `[Unreleased]` changelog bullet points — only the heading
  they sit under.

## Design

**Version.** Two options were put: set `package.json` back to a `0.x` number and
keep the translator note, or move `[Unreleased]` into a `1.0.0` section and drop
the note. The recommendation was the first, on the grounds that nothing in the
unreleased content read as a deliberate 1.0 milestone — it was bug fixes and a
new advisory check, not a locale-key freeze announcement.

**Badges.** A CI badge and an MIT licence badge directly under the H1, before
the descriptive paragraph. GitHub Actions badges only populate after the
workflow has run at least once on the default branch, so the badge is verified
after merge rather than before.

**Code of Conduct.** Stock Contributor Covenant 2.1, with the enforcement
contact pointed at the repository's GitHub Security Advisory channel — the same
place `SECURITY.md` already directs to — rather than a personal address, since
none is published anywhere in the repository.

**Issue forms.** GitHub's YAML issue-form format, not the legacy Markdown
templates, matching the project's otherwise-modern tooling. Two forms, for the
two contribution types `CONTRIBUTING.md` and `README.md` already name:
`bug_report.yml` collecting domains tested, expected versus actual, browser, and
whether it reproduces on the live demo or only locally; and `translation.yml`
collecting the locale code, whether it is a new translation or a correction, and
the relevant locale file.

No `config.yml`. Blank issues stay enabled — keep it simple.

## As implemented

**1. The version landed at `0.2.0`, not `0.1.0`.** The spec's recommended option
said `0.1.0`, *or bump to `0.2.0` to reflect everything shipped since, at the
maintainer's discretion*. The discretion was exercised: `1.0.0` → `0.2.0` in
this commit, and `v0.2.0` was tagged at the merge.

That makes this release the version boundary for everything merged before it.
[unproven-controls-scoring](unproven-controls-scoring.md) (#10),
[spf-subnet-and-redundancy](spf-subnet-and-redundancy.md) (#11) and
[privacy-documentation](privacy-documentation.md) (#12) were all merged while
`package.json` still read `1.0.0`; none of them changed it; all three shipped to
users as part of `0.2.0`. This is the answer to the question *did the version
change during that session* for all three: not in their own pull requests, but
here, immediately after.

**2. Everything else shipped as specified.** Verified in the current tree:
badges present at `README.md:3`–`4`; `CODE_OF_CONDUCT.md` present;
`.github/ISSUE_TEMPLATE/bug_report.yml` and `translation.yml` present with no
`config.yml`; `COMMIT_MSG.txt` gone; and `package.json` carrying `repository`,
`homepage`, `bugs` and `author`.

## Localization impact

None. No locale file is touched by this release.

## Testing

`npm test` and `npm run build` must pass unchanged — this release touches no
code, so any movement in either would mean something unintended was edited.
`README.md` verified as rendering on GitHub with badges resolving and no broken
relative links. `git status` verified clean, confirming `COMMIT_MSG.txt` was
actually deleted rather than merely staged.

## Acceptance criteria

All met at merge.

1. `package.json` and `CHANGELOG.md` agree on the version. ✅ — `0.2.0`.
2. `COMMIT_MSG.txt` deleted. ✅
3. Badges render on GitHub. ✅
4. `CODE_OF_CONDUCT.md` present and linked from `CONTRIBUTING.md`. ✅
5. Both issue forms present in YAML form format. ✅
6. `package.json` metadata complete. ✅
7. `npm test` and `npm run build` unchanged. ✅

## Risks

**Publishing a version number that implies a stability guarantee the project has
not made.** This is exactly the defect being fixed, and the reason `0.2.0` was
chosen over `1.0.0`: the locale key structure is not frozen, and under semantic
versioning a key rename after 1.0.0 would be a breaking change requiring a major
release. The `0.x` translator note in `CHANGELOG.md` stays until that freeze is
a deliberate decision.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| `OQ-HYGIENE-01` | Is the project at `1.0.0` or `0.x`? | `0.x`. Set to `0.2.0`, reflecting everything shipped since `0.1.0` rather than reverting to `0.1.0` flat. Nothing in the unreleased content was a 1.0 milestone. | 1.0 |
| `OQ-HYGIENE-02` | Whose address is the Code of Conduct enforcement contact? | The repository's GitHub Security Advisory channel, consistent with `SECURITY.md`. No personal address is published anywhere in the repository and none is invented here. | 1.0 |
| `OQ-HYGIENE-03` | Are blank issues disabled? | No. No `config.yml`; blank issues stay available alongside the two forms. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-08-20 | Retrospective record of the shipped 0.2.0 change, reconciled against `41c29fc`. |
