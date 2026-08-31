# Spec: 1.0 product contract and release readiness

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | 1.0.0 |
| Status | Awaiting review |
| Depends on | 0.7.0 structured findings, 0.8.0 local artifact validation, and 0.9.0 stateless report comparison |
| Blocks | Stable 1.x compatibility and support claims |
| Slug for open questions | `ONE` |
| Last updated | 2026-08-31 |

## Problem

The roadmap defines feature work through 0.9.0 and defers external intelligence
until after 1.0, but it does not define the release called 1.0.0. Without an
explicit gate, the version would communicate stability while leaving the actual
promise implicit: which browser environments are supported, which exported
formats and identifiers are compatibility contracts, what accessibility has
been verified, and which known limitations are accepted.

The application already has unusually strong internal contracts: one production
bundle, a two-member browser facade, an enforced import matrix, deterministic
equivalence fixtures, strict localization completeness, a documented privacy
boundary, and tests inventoried by assertion count. The missing work is to turn
those internal guarantees into a bounded public 1.x contract and verify the
finished product as a user receives it.

## Scope

1. Define the public compatibility surfaces for the 1.x line.
2. State and execute a supported-browser verification matrix.
3. Complete a keyboard, focus, semantics and readable-status accessibility pass.
4. Verify a clean install, production build, direct `file://` use and deployed
   static-site use from released artifacts.
5. Reconcile `README.md`, `PRIVACY.md`, `SECURITY.md`, `CONTRIBUTING.md`, the
   roadmap and in-app limitations with the behavior that actually ships.
6. Finalize external intelligence as an explicit pre-1.0 product decision.
7. Triage every open maintenance item as blocking, accepted for 1.0, or scheduled
   after 1.0.
8. Cut 1.0.0 as a dedicated release with no new protocol or scoring behavior.

## Non-goals

- **No new DNS or artifact analysis.** Feature work ends with 0.9.0 for this
  release train.
- **No scoring change.** A graduation release does not move grades.
- **No new network destination, persistence or telemetry.** The privacy
  boundary is part of the 1.0 contract.
- **No framework migration, dependency program or architecture rewrite.** The
  0.6.0 architecture is the production architecture being graduated.
- **No promise of perpetual schema or facade immutability.** Compatibility is
  governed by explicit versioning and migration rules, not by freezing defects.

## Design

### 1. Public 1.x contract

The release documentation names each surface and its compatibility rule:

| Surface | 1.x rule proposed by this draft |
| --- | --- |
| Browser facade | `DnsAudit.analyzeDomain` and `DnsAudit.checkConnectivity` remain supported; incompatible changes require 2.0 |
| JSON report | `schemaVersion` is authoritative; older versions remain readable through explicit upgrade functions |
| Finding ids | Stable identity once exported; a rename requires an alias/migration map |
| CSV | Existing columns keep position and meaning; new columns append |
| HTML report | Human-readable artifact, not an import or machine-compatibility format |
| Audit result object | Internal unless separately documented; no accidental public promise through test access |
| Privacy boundary | One documented DoH destination, no audit/report persistence, no telemetry |

The contract is written once in `README.md` or a dedicated compatibility
document and linked from the report-schema documentation. Tests continue to
enforce the facade, CSV and schema rules at their owning boundaries.

### 2. Supported environments

Verification covers the environments the project is willing to name publicly,
not every browser that can parse the bundle. For each supported environment the
same release artifact must:

- load over the deployed HTTPS site;
- complete the connectivity probe and one deterministic fixture-driven audit;
- change language and retain only the language preference;
- export CSV, HTML and JSON;
- import and compare JSON reports;
- accept local artifact input without a network or storage side effect;
- remain operable by keyboard at narrow and wide viewport widths.

Exact browser names and minimum versions are an open decision because they are a
support commitment, not a test implementation detail. See `OQ-ONE-02`.

### 3. Accessibility graduation pass

Every interactive control has an accessible name, visible focus, correct native
semantics or an equivalent keyboard contract, and a usable focus order. Status
is never communicated by color alone. Expanding a result, switching finding
views, entering comparison mode, reporting import errors and opening the local
artifact panel all expose their state to assistive technology.

The pass records its method and evidence. A checker may assist, but automated
output alone is not acceptance: keyboard operation and focus behavior are
executed in a real browser.

### 4. Release reproducibility

From a clean checkout at the release commit:

```bash
npm ci
npm test
npm run inventory
npm run locale:gate
npm run build
npm run test:file-url
npm run pr:prep
```

The generated site is checked for an untracked or stale artifact, and the
deployed artifact is byte-associated with the release commit. Any command whose
real name changes before 1.0 is updated here during review rather than emulated.

Because 1.0.0 adds no audit semantics, the deterministic equivalence corpus is
captured at `v0.9.0` and must report zero differences across its full result,
query trace, CSV, HTML, JSON and DOM surfaces. The JSON surface is added by
0.9.0; the 1.0 review confirms the equivalence harness actually includes it.

### 5. Documentation and decision closure

The release description states what the tool can prove and what it cannot:
resolver-attributed DNSSEC, DNS-published DANE rather than SMTP validation,
user-supplied artifact provenance, stateless comparison, and the single-resolver
privacy boundary. Every quantitative statement is re-measured from the finished
artifact.

`external-intelligence.md` is reviewed to Final as either a deliberate refusal
or a bounded post-1.0 proposal before 1.0.0 ships. `docs/maintenance-backlog.md`
is triaged line by line. An accepted item remains visible with its reason; it is
not deleted to manufacture an empty list.

## Localization impact

The intended release has no new feature copy. Documentation corrections do not
touch locale files. If the accessibility or compatibility review finds an
in-app wording defect, that correction follows the full fourteen-locale loop in
`AGENTS.md` and is made before the release commit.

## Testing

- Run every command in the reproducibility sequence from a clean checkout.
- Prove every new release-readiness check fails against a deliberate negative
  fixture before trusting it.
- Replay the `v0.9.0` deterministic corpus through source and production bundle,
  including the 0.9.0 JSON surface.
- Execute the supported-browser matrix against the production artifact and
  record browser versions, operating systems and results.
- Execute a keyboard-only workflow covering audit, detail expansion, finding
  view, exports, imports, comparison exit and artifact validation.
- Inspect storage and network activity after the complete workflow: only the
  language key persists and only the documented DoH endpoint is contacted by
  the application.
- Validate every Markdown link after moving the final four specs into
  `docs/specs/implemented/`.

## Acceptance criteria

1. The 0.7.0, 0.8.0 and 0.9.0 specs are released and moved to `implemented/`.
2. Every public 1.x surface has a written compatibility or migration rule.
3. The agreed browser matrix passes against the production artifact with
   recorded versions and no undocumented exception.
4. The complete keyboard workflow is usable, focus remains visible and status
   does not depend on color alone.
5. The clean-checkout command sequence passes, including inventory and strict
   localization.
6. Deterministic comparison with `v0.9.0` reports zero unintended movement on
   every published surface.
7. `PRIVACY.md`, `SECURITY.md`, the CSP and observed network/storage behavior
   agree.
8. External intelligence is Final as a decision document.
9. Every maintenance-backlog item is dispositioned; no release blocker remains.
10. Release artifacts quote assertion, size, fan-out and compatibility figures
    only from measurements made on the finished branch.

## Risks

**A ceremonial release that tests nothing new.** Renaming 0.9.0 to 1.0.0 would
create no evidence for the stability claim. Mitigation: a dedicated artifact,
browser, accessibility, documentation and compatibility gate.

**An accidental forever-contract.** Calling every current object public would
make internal cleanup a breaking change. Mitigation: enumerate supported
surfaces; everything else stays internal unless deliberately promoted.

**A browser matrix too broad to maintain.** “All modern browsers” is not a
testable support statement. Mitigation: name a small matrix with real versions
and publish the boundary plainly.

**Late feature creep.** Readiness review tends to accumulate attractive fixes.
Mitigation: defects required to satisfy an acceptance criterion may be fixed in
directory-bound commits; new capability returns to a post-1.0 spec.

## Open questions

**OQ-ONE-01: Is 1.0.0 a dedicated release after 0.9.0?**
This draft says yes. It gives the compatibility, accessibility and production
checks a stable `v0.9.0` baseline and keeps them separate from the report-schema
feature. The alternative is to graduate the completed 0.9 work directly as
1.0.0, saving a release but combining a new public schema with its stability
declaration.

**OQ-ONE-02: What browser matrix does 1.x support?**
A bounded default would be current and previous major Chrome, Firefox and Edge,
plus current Safari on macOS and iOS. Exact minimum versions and whether mobile
Chrome is separate from desktop Chrome must be decided from environments the
project can actually execute and maintain.

**OQ-ONE-03: Are all three proposed machine interfaces public?**
This draft treats the two-member facade, JSON schema and finding-id namespace as
public, while keeping the full audit result object internal. Confirm that this
is the intended support burden for 1.x.

**OQ-ONE-04: What accessibility target is claimed?**
The draft requires concrete keyboard and semantic behavior but names no formal
conformance level. Claiming WCAG 2.2 AA requires a criterion-by-criterion audit;
anything weaker should avoid implying certification. Decide whether 1.0 records
an internal accessibility baseline or a formal target.

**OQ-ONE-05: Must external intelligence be Final before 1.0?**
This draft says yes because “post-1.0” has no meaning until the pre-1.0 product
has explicitly accepted the boundary. The alternative is to leave the decision
draft open without blocking release.

**OQ-ONE-06: Which maintenance items block graduation?**
Severity labels alone are insufficient. Review the actual backlog and define the
release-blocking class: security/privacy contract defects, data-loss or wrong
result defects, broken supported environments, and compatibility violations are
the proposed minimum.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-31 | Initial draft. Defines 1.0.0 as a dedicated compatibility, accessibility, reproducibility and decision-closure release after the three remaining feature releases. |
