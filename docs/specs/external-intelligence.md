# Spec: External intelligence, and why it is deferred

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | Post-1.0, conditional |
| Status | Decision pending. This document exists to make the deferral explicit rather than accidental. |
| Depends on | Everything. This is the last thing considered, if it is considered at all. |
| Blocks | Nothing |
| Slug for open questions | `EXT` |
| Last updated | 2026-08-20 |

## Position

Certificate transparency lookups, blocklist and reputation queries, SMTP
connection tests, and retrieval of policy artifacts from URLs published in a
third party's DNS records stay outside this product. They are not on the
roadmap, and this document exists so that the omission reads as a decision
rather than as an oversight.

The reason is structural, not squeamish. Every capability in that list requires
the browser to contact a host chosen by the domain under investigation, or a
third-party service, and to disclose to that host that a specific person is
auditing a specific domain at a specific time. The current design makes exactly
one network destination, `https://cloudflare-dns.com`, documented in
[`PRIVACY.md`](../../PRIVACY.md) and enforced by the `connect-src` directive in
[`index.html:7`](../../index.html). That single-destination property is the
product's distinguishing characteristic, and it is the kind of property that is
either true or not; there is no partially private version of it.

Three specific harms make this concrete.

**Disclosure to the audited party.** Fetching
`https://mta-sts.<target>/.well-known/mta-sts.txt` tells the target's
infrastructure that someone is examining them, from a particular IP address, at a
particular moment. For a security researcher, a journalist, or someone
investigating a domain that is impersonating their employer, that is a material
risk and not a theoretical one.

**Disclosure to a third party.** A blocklist or reputation query hands a domain
list to an operator whose retention and correlation practices are outside this
project's control and outside the user's knowledge. A user auditing 200 domains
would be sending their organization's entire estate to a service they never chose.

**Attacker-controlled destinations.** A BIMI `l=` value or an MTA-STS hostname is
a URL published by whoever controls the audited domain. Fetching it means making
requests to URLs a stranger wrote. That is a server-side request forgery pattern,
executed from the user's browser and their network position, which may be inside
a corporate perimeter.

Against this sits a real benefit. Certificate transparency would show whether a
CAA record is actually being honored. A reputation lookup would connect
configuration to outcome. Verifying an MTA-STS policy would let the tool award
the other four points it currently withholds. Those are genuine improvements and
they are not worth the property they cost.

## What is done instead

Two mitigations already exist and are the intended permanent answer.

[local-artifact-validation](local-artifact-validation.md), the 0.7.0 release,
lets the user supply the artifact themselves. The person auditing their own
domain has the file. The person auditing a third party can fetch it by whatever
means they judge appropriate, from a network position they choose, and paste the
result. The tool validates locally and marks every resulting finding
`source: 'user-supplied'`. That recovers most of the analytical value with none
of the disclosure.

For everything else, the tool offers a link the user can choose to open. A
finding about a CAA record can name the certificate transparency search that
would confirm it. Opening a link in a new tab is the user's decision, made
knowingly, with their own browser and their own judgment about whether the lookup
is safe to make. That is categorically different from the tool making the request
on their behalf while they read a results table.

## Conditions if it is ever built

If a compelling case emerges, these are the conditions. They are stated in
advance so that a future proposal is measured against a standard set while the
reasoning is fresh, rather than against whatever seems reasonable at the time.

1. **A separate mode, off by default, per session.** Not a preference, not a
   remembered setting, not a URL parameter. An explicit action each time,
   because a persisted opt-in becomes an invisible default within a week.

2. **A pre-query disclosure naming the exact destination.** Before any request,
   the user sees the full URL, the host that will receive it, and what that host
   will learn. A generic "this may contact external services" warning is not
   sufficient and would not be accepted.

3. **A separate network policy.** External lookups run under their own CSP, and
   the default mode's `connect-src` remains exactly
   `'self' https://cloudflare-dns.com`. A user who never enables the mode must be
   able to verify, from the policy alone, that nothing else was contacted.

4. **Excluded from the default score.** No grade depends on data the tool
   obtained by contacting a third party. A grade must remain reproducible from
   public DNS by anyone, in any network position, without side effects.

5. **A separate privacy disclosure.** `PRIVACY.md` gains a distinct section, and
   the mode is unavailable until the user has seen it.

6. **A hard destination allowlist.** Never a URL taken from a DNS record without
   validation. A hostname derived from the audited domain by a fixed rule, such
   as `mta-sts.<domain>`, is arguably acceptable. A `https://` value copied out of
   a stranger's BIMI record is not, under any circumstances.

7. **No new runtime dependencies and no proxy.** A server-side fetch proxy would
   move the disclosure from the user to this project's infrastructure and create
   a log this project would then be responsible for. That is worse, not better.

Failing any one of these is disqualifying, not a trade-off to be weighed.

## Consequences accepted

Stating these plainly so the deferral is honest about its costs.

- MTA-STS scores half credit forever for domains whose owners do not supply the
  policy, per `calcScore()` at [`js/dns.js:1795`](../../js/dns.js).
- BIMI conformance is unknown unless the user supplies the SVG.
- CAA is checked for what it says, never for whether certificate authorities
  honored it.
- DANE is validated for syntax and chain protection, never against an actual
  certificate presented by a mail server.
- The tool cannot tell a user whether their domain is on a blocklist.

Every one of these is documented under Known limitations in
[`README.md`](../../README.md), and that section should be kept accurate as the
list grows rather than allowed to drift.

## Open questions

**OQ-EXT-01: Are informational links acceptable, and how are they presented?**
A link to a certificate transparency search for the audited domain is inert until
clicked, but the URL contains the domain name and clicking it discloses the
lookup to that service. Options: include such links with a one-line explanation
of what clicking discloses; include them with no explanation, treating a link as
self-evidently a user action; include none at all, on the grounds that the tool
should not suggest lookups it would not make. This draft includes them with the
explanation. Confirm.

**OQ-EXT-02: Is `mta-sts.<domain>` special?**
That hostname is derived from the audited domain by a fixed rule in RFC 8461, not
copied from a record the target wrote, so condition 6 does not exclude it. It is
also the single highest-value external fetch available, worth four points per
domain and a real correctness answer. It still discloses the audit to the target.
Is a narrowly scoped exception for exactly this one derived hostname, under all
seven conditions, worth reconsidering, or does one exception make the property
untrue?

**OQ-EXT-03: Does the deferral get restated in the interface, or only in the
documents?**
A user who wonders why MTA-STS shows half credit has to read `README.md` to find
out. A one-line note in the detail panel would answer it in place and would also
advertise the privacy property to someone who never opens the documentation. It
would also add a permanent apologetic sentence to the interface. This draft adds
the note. Reviewers may reasonably prefer the interface stay quiet.

**OQ-EXT-04: Who decides, and does this document ever get closed?**
This is the only spec in the roadmap with no target release. It could stay open
indefinitely as a standing position, or it could be marked Final as a decision
not to build, and reopened only by a new spec. This draft proposes marking it
Final as a deliberate refusal, which makes any future proposal an argument
against a recorded decision rather than a fresh idea.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-20 | Initial draft. |
