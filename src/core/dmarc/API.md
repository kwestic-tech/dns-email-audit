# `src/core/dmarc/` — API contract

Required by spec [§12](../../../docs/specs/modular-architecture-and-production-build.md#12-module-apis-and-the-allowed-edge-matrix):
each owning directory checks in `API.md` in the same commit that creates it.

**Responsibility.** Two specifications, kept distinct because they answer
different questions and disagree in at least one place:

- **RFC 9989** (DMARCbis, May 2026) — record parsing, the DNS Tree Walk, the
  organizational domain, and the inheritance rules. What policy applies to a
  name, and how it was found.
- **RFC 9990 §4** — external report authorization. Whether a destination
  outside the organizational domain has agreed to receive reports.

This directory emits no finding, severity, score or locale key.

## Allowed edges

| May import | May not |
| --- | --- |
| `core/shared/`, siblings in this directory | everything else — including `core/dns/`, `src/data/`, another protocol directory, `audit/`, `ui/` and the platform |

Both the resolver and the **Public Suffix List** are passed. The PSL is
generated data, and §12 gives a protocol directory no edge to `src/data/`.

## Four modules

| Module | Takes | Responsibility |
| --- | --- | --- |
| `record.js` | nothing | The tag vocabulary and the parsers. Pure and domain-agnostic. |
| `org-domain.js` | `publicSuffixRules` | The organizational domain. |
| `tree-walk.js` | resolver | Discovery, selection and inheritance. |
| `report-auth.js` | resolver + one collaborator | RFC 9990 §4 authorization. |

`report-auth.js` receives `discoverDmarc` as an argument rather than importing
it. It could import the sibling — but the caller has already built that
factory, and passing what exists beats constructing a second walk with its own
state.

It does **not** take `getOrganizationalDomain`. The Task 4.6 extraction
accepted, passed and documented it and never read it: the destination org
domains this module resolves come from `discoverDmarc()`'s own walk, not from
the PSL. A declared-and-unused capability is a false statement about what a
module can reach, and it was removed. `org-domain.js`, the PSL, its runtime
construction and the legacy engine member are all untouched — PSL retirement is
a separately recorded finding, not this.

## Public exports

### `record.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `analyzeDmarc(record, multiple)` | pure | The full status — see the state table below. `malformed` is separate from `status`, because a record that is there and cannot be applied is not the same as no record. |
| `emptyDmarcStatus(status)` | pure | The same shape with nothing in it, carrying whatever state the caller names. `policy` is `''`, not `null`. |
| `parseDmarcTag`, `normalizePolicy`, `validateDmarcVersion`, `parseDmarcUriList`, `parseTagList` | pure | The pieces `analyzeDmarc` is built from, each an engine member in its own right. |
| `POLICY_RANK` | table | `none` 0, `quarantine` 1, `reject` 2. |
| `DMARC_TAGS_RFC9989`, `DMARC_TAGS_REMOVED` | arrays | RFC 9989's tag names, and the three DMARCbis removed. **Reference vocabularies, not state algebras** — see below. |

### `org-domain.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `createOrgDomain({ publicSuffixRules })` | factory | Returns `getOrganizationalDomain(domain)`. Two factories over two lists share nothing. |

### `tree-walk.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `createDmarcDiscovery({ dohFetch, dnsError, cleanAnswerData })` | factory | Returns `discoverDmarc(domain, queryOpts, opts)`. |
| `dmarcWalkTargets`, `domainLabels`, `oneLabelBelow` | pure | Targets carry the **domain**, not the `_dmarc.` query name. |
| `isDmarcPolicyRecord`, `diagnoseDmarcRecord` | pure | Recognize, then say why a near-miss was not accepted. `diagnoseDmarcRecord` returns `null` for a good record and a reason string otherwise. |
| `selectOrganizationalDomain`, `selectAppliedRecord`, `applyInheritance`, `weakerPolicy` | pure | Selection happens **after** the whole walk. |

### `report-auth.js`

| Export | Kind | Contract |
| --- | --- | --- |
| `createReportAuth({ dohFetch, dnsError, cleanAnswerData, optionalCheck, discoverDmarc })` | factory | Returns `{ resolveDestinationOrgDomains, checkExternalReportAuth }`. |
| `reportDestinationHosts`, `planReportDestinations`, `findExternalReportDestinations`, `parseReportAuthRecord` | pure | The plan reports `external`, `total` and `omitted`, so a capped list is visible rather than silently short. |
| `REPORT_AUTH_STATES`, `REPORT_AUTH_EXACT_KINDS`, `REPORT_AUTH_VIA` | frozen arrays | `dmarc.reportAuth.state`, `.exactKind`, `.via`. |

## The status algebra

Registry algebra `dmarc.status`, six members, produced by two functions:

| State | Produced by | Meaning |
| --- | --- | --- |
| `ok` | `analyzeDmarc()` | A record that parses and applies. |
| `warn` | `analyzeDmarc()` | Applies, with something worth saying about it. |
| `present` | `analyzeDmarc()` | A record is there and cannot be applied. |
| `missing` | `emptyDmarcStatus()` | No record. |
| `unknown` | `emptyDmarcStatus()` | The lookup did not complete. |
| `permerror` | `emptyDmarcStatus()` | Retained as the documented **legacy direct-call** state. |

`present` and `missing` are the pair that must not be collapsed: the first
means the operator published something, and telling them to publish a record
they already have sends them to the wrong place.

## The two raw-kind readers

`discoverDmarc()` and `checkExternalReportAuth()` are the last two of spec §3's
six allowed raw-kind readers, moved here from `js/dns.js` by Task 4.6. Both
**inline the usability gate** rather than calling `requireUsable()`, and that
is deliberate and unchanged:

- the **walk** records the kind of every step, including the failed ones, and
  layer 2 throws those away. A failed walk and an absence are indistinguishable
  after normalization and mean opposite things to an operator;
- **report authorization** keeps the exact response kind on `exactKind`, and
  its `catch` is an internal one under a static `[]` fallback rather than an
  `optionalCheck()` fallback factory. Spec §3 asserts those as three distinct
  mechanisms.

## Two duplicate rules, pointing opposite ways

Both are correct. Neither should be "fixed" to match the other.

| Where | Rule | Source |
| --- | --- | --- |
| Tree Walk | more than one policy record at a name **discards them all**, and the walk continues | RFC 9989 §4.10 step 2 |
| Report auth | **at least one** valid record in the set authorizes | RFC 9990 §4 step 8 |

Different names, different RFCs, different questions.

## The eight-query budget

§4.10 step 4 shortens a subject of eight or more labels back to seven rather
than aborting, so a thirteen-label name is queried once in full, cut to seven,
and then walks one label at a time — landing on the TLD on query eight exactly.
There is deliberately **no `query-limit` termination state**, because running
out of queries before running out of labels cannot happen.

## The preserved `mailto:` divergence

`parseDmarcUriList()` validates a report destination with its own rule —
`/^[^\s@]+\.[^\s@.]+$/` on the domain — rather than through
`core/shared/uri.js`'s `isMailtoUri()`. The two **disagree**: a space in the
local part is refused by RFC 6068 and accepted here.

**Ruled at Task 4.0 and reaffirmed at 4.6: this behaviour is PRESERVED.**
Reconciling them is a behaviour change and is outside 0.6.0 unless separately
authorized. The equivalence instrument DETECTS such a change; it does not
authorize one, and a green run is not permission to have made it.
`record.test.js` asserts the disagreement as a fact about today, not as a
correctness claim.

## Reference vocabularies, not state algebras

`DMARC_TAGS_RFC9989` and `DMARC_TAGS_REMOVED` are RFC 9989's tag **name**
lists. No result field ranges over either: `unknownTags` and `removedTags` are
computed by filtering a record's tags *against* them, so they are the input to
a comparison rather than the range of a field. The registry models the answers
— `dmarc.tagState` is `absent`/`valid`/`invalid`, and `dmarc.policy` has five
members because the field can also be null or empty.

[`tests/contract/state-matrix.test.mjs`](../../../tests/contract/state-matrix.test.mjs)
excuses them by name, in a **closed inventory**. There is no shape test and
there cannot be one: a reference vocabulary and a state vocabulary are both
arrays of strings, so the reviewed list is the whole control. The same
clarification as Task 4.5's numeric-keyed tables, arriving in a different
shape.

## Moved, not redesigned

`js/dns.js`'s DMARC blocks and the PSL, unchanged apart from the two-space
dedent, the `export` keywords, three factories naming their capabilities, and
the published state constants. Every parsing rule, walk step, selection rule
and authorization verdict is byte-identical; both five-surface equivalence
subjects report zero differences.
