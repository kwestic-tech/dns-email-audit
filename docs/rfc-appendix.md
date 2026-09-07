# RFC Appendix

Every RFC (and the handful of non-RFC standards) the audit engine leans on,
grouped by the control it governs, with a note on **how** each one is applied
in this codebase. Paths point to the primary module that consumes the standard;
adjacent test files (`*.test.js`) and the string catalogue (`src/data/locales-en.js`)
generally cite the same RFC and are not repeated here.

Descriptions reflect what the code actually does with each RFC — not the full
scope of the RFC itself. Section references (§) are those cited in the source.

## A note on the DMARCbis-era and DNSSEC-guidance RFCs

This engine is written against a **May 2026** standards baseline. DMARC has been
re-standardized as the DMARCbis series — **RFC 9989** (core protocol),
**RFC 9990** (aggregate reporting), and **RFC 9991** (failure reporting) —
obsoleting **RFC 7489** and **RFC 9091**. DNSSEC algorithm guidance has likewise
moved to **RFC 9904/9905/9906/9558/9563**, superseding **RFC 8624**. For these
newer RFCs the code comments describe the role but do not restate an official
title, so the Title column below records the role the code assigns rather than
inventing a formal title. BIMI has no assigned RFC and is cited throughout as
"the BIMI draft" (an Internet-Draft); it borrows the MTA-STS/TLS-RPT record
rules by analogy — see the BIMI section.

---

## SPF

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 7208 | Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1 | `src/core/spf/spf.js`, `src/core/shared/record-selection.js`, `src/audit/audit-domain.js` | Whole SPF term grammar. Enforces §4.5 (>1 `v=spf1` record ⇒ permerror), §5.3 dual-CIDR grammar for `a`/`mx`, and §5.5 advice to ignore `ptr:` (implemented as outright exclusion). |
| 4291 | IP Version 6 Addressing Architecture | `src/core/spf/spf.js`, `src/core/shared/ip.js` | §2.5.4 justifies treating `/64` as the standard IPv6 single-subnet size when sizing `ip6:` mechanisms; §2.2.3 decodes an embedded dotted-quad IPv4 tail in an IPv6 literal. |

## DKIM

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 6376 | DomainKeys Identified Mail (DKIM) Signatures | `src/core/dkim/dkim.js` | The DKIM key-record model: parses the §3.2 tag-list grammar, treats empty `p=` as revocation and unrecognized `k=` as "must ignore" (§3.6.1), enforces per-selector uniqueness (§3.6.2.2), and decodes DKIM-Quoted-Printable for `n=`. |
| 8463 | A New Cryptographic Signature Method for DomainKeys Identified Mail (DKIM) | `src/core/dkim/dkim.js` | Validates that a `k=ed25519` key's `p=` is exactly a raw 32-byte public key (not DER/SPKI); models RSA/Ed25519 double-signing. |
| 8017 | PKCS #1: RSA Cryptography Specifications Version 2.2 | `src/core/dkim/dkim.js` | §3.1 rules validate the decoded RSA `n`/`e` fields (positive, minimally encoded, both odd, `n` a product of distinct odd primes); §A.1 corroborates the ASN.1 OID check. |
| 3279 | Algorithms and Identifiers for the Internet X.509 PKI Certificate and CRL Profile | `src/core/dkim/dkim.js` | §2.3.1 requires the ASN.1 parameters field be NULL for RSA — confirms the key's OID before decoding an RSA `p=` SPKI structure. |
| 8301 | Cryptographic Algorithm and Key Usage Update to DKIM | `src/audit/issues.js` | Sets the 1024-bit RSA floor (critical below it, informational at exactly 1024) and forbids SHA-1 as the sole hash in a key's `h=` list. |

## DMARC

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 9989 | DMARCbis — core protocol (May 2026; obsoletes RFC 7489/9091) | `src/core/dmarc/record.js`, `src/core/dmarc/tree-walk.js`, `src/audit/audit-domain.js`, `src/audit/issues.js`, `src/audit/scoring.js` | Defines the complete 11-tag vocabulary (`DMARC_TAGS_RFC9989`), the §4.7 tag grammar (`v` first/case-sensitive, `t=` test mode, `psd=`, dropped `pct=`/`rf=`/`ri=`), and the §4.10 DNS Tree Walk (organizational-domain discovery, duplicate-record discard, 8-label shortening) that replaced the Public-Suffix-List heuristic. |
| 9990 | DMARCbis — aggregate reporting | `src/core/dmarc/report-auth.js`, `src/audit/audit-domain.js`, `src/core/dmarc/tree-walk.js` | Implements §4 external-report-authorization (queries the confirming TXT record at the destination, parses per step 6, "authorized if at least one record parses" per step 8) and §3.5 per-destination URI ordering/limits. |
| 9991 | DMARCbis — failure reporting | `src/data/locales-en.js` | Cited to note that `ruf=` failure reports carry message content and are sent by fewer receivers; no failure-report parsing is implemented (out of scope per `dmarcbis-tree-walk.md`). |
| 7489 | Domain-based Message Authentication, Reporting, and Conformance (DMARC) — *obsoleted by 9989* | `src/core/dmarc/record.js`, `src/audit/issues.js`, `src/audit/scoring.js`, `src/core/shared/record-selection.js` | Treated as obsoleted; retained to explain that `pct=` still behaves differently for receivers who have not migrated, and for the case-insensitive tag-name rule shared with SPF. |
| 9091 | Experimental DMARC Extension for PSDs — *obsoleted by 9989* | `src/data/locales-en.js`, `src/core/dmarc/record.js` | Attributes the origin of the `np=` (non-existent-subdomain policy) tag that DMARCbis absorbed. |

## MX / routing

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 7505 | A "Null MX" No Service Resource Record for Domains That Accept No Mail | `src/core/mx/mx.js`, `src/audit/audit-domain.js`, `src/audit/artifacts.js`, `src/providers/detectors.js` | `isNullMx()` detects the exact `0 .` record and enforces §3 (a null MX must be the only MX present), gating provider detection and deep MX/TLSA checks. |
| 1035 | Domain Names — Implementation and Specification | `src/core/mx/mx.js` | §3.3.9: MX RDATA is a `<domain-name>` — used to skip the preference-range check and to flag an MX target written as a bare address rather than a hostname. |
| 5321 | Simple Mail Transfer Protocol | `src/core/mx/mx.js`, `src/audit/artifacts.js`, `src/audit/issues.js`, `src/core/transport/mta-sts-policy.js` | §5.1 recognizes both multiple MX records and multihomed targets as sources of alternative delivery addresses, requires senders to try the relevant addresses, defines "implicit MX" when a domain has no MX but has a usable address record, and requires random selection among equal-preference exchangers; with RFC 2181, an MX target must not be a CNAME. §4.1.4 supports treating failed reverse DNS as advisory-only. |
| 2181 | Clarifications to the DNS Specification | `src/audit/issues.js` | §10.3, paired with RFC 5321 §5.1, is the basis for flagging an MX record whose target is a CNAME. |
| 6890 | Special-Purpose IP Address Registries | `src/core/shared/ip.js` | Underpins `ipScope()`'s classification of MX-host addresses (global/private/loopback/documentation/shared/…), driving `mx-unroutable` / `mx-partially-routable` findings. |
| 5737 | IPv4 Address Blocks Reserved for Documentation | `docs/specs/implemented/mx-host-validity.md` | Names the documentation-space sub-registry that RFC 6890 covers (cited in the spec/tests, not directly in `src/`). |
| 6598 | IANA-Reserved IPv4 Prefix for Shared Address Space | `docs/specs/implemented/mx-host-validity.md` | Names the shared/CGN-space sub-registry that RFC 6890 covers (cited in the spec/tests, not directly in `src/`). |

## CAA

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 8659 | DNS Certification Authority Authorization (CAA) Resource Record | `src/core/caa/caa.js`, `src/audit/issues.js` | §4.1–§4.4 ABNF for `issue`/`issuewild`/`iodef`: tag grammar, the Issuer-Critical flag bit, `issuewild` fallback to `issue`, and that `;` or empty authorizes no issuer (including the `%%%%%` edge case from §4.2's own example). |
| 9495 | CAA "issuemail" Property | `src/core/caa/caa.js` | §3 defines the `issuemail` property; the code is explicit that `contactemail`/`contactphone` (also parsed) are **not** from this RFC. |

## DNSSEC

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 4034 | Resource Records for the DNS Security Extensions | `src/core/dnssec/records.js`, `src/core/dnssec/matching.js` | Parses DNSKEY/DS wire formats (§2.1), computes the Appendix B key-tag, performs §5.1.4 canonical-owner-name digest matching for DS↔DNSKEY, and applies §6.2 ASCII-only case-folding (excluding U+212A KELVIN SIGN). |
| 5011 | Automated Updates of DNS Security (DNSSEC) Trust Anchors | `src/core/dnssec/records.js`, `src/audit/issues.js` | §2.1 justifies naming the DNSKEY REVOKE flag `hasRevokeFlag` rather than "isRevoked" — true revocation requires a validated self-signature this app does not compute. |
| 6840 | Clarifications and Implementation Notes for DNS Security (DNSSEC) | `src/core/dnssec/records.js`, `src/audit/issues.js` | §5.5 corrects the algorithm-1 (RSAMD5) key-tag calculation (overriding RFC 4034 App. B.1's erroneous example); §5.11 justifies treating an orphan DS as informational; §6.2 justifies naming the SEP bit `hasSep` rather than `isKsk`. |
| 3658 | Delegation Signer (DS) Resource Record (RR) | `src/core/dnssec/matching.js`, `src/core/dnssec/records.js` | DS digest-type 0 is reserved/"Not for use" — named explicitly rather than treated as a possible future assignment. |
| 6605 | Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC | `src/core/dnssec/records.js` | §4 ECDSA P-256/P-384 raw-point key lengths (64/96 octets) used in key-structure validation. |
| 8080 | Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC | `src/core/dnssec/records.js` | §3 Ed25519 (32-octet) / Ed448 (57-octet) key lengths used the same way. |
| 3110 | RSA/SHA-1 SIGs and RSA KEYs in the DNS | `src/core/dnssec/records.js` | §2 canonical exponent-and-modulus RSA encoding; §3 base 512-bit RSA/SHA-1 modulus floor for RSA DNSKEY structure. |
| 5702 | Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC | `src/core/dnssec/records.js` | §2.1 repeats the 512-bit floor for RSA/SHA-256; §2.2 raises it to 1024 bits for RSA/SHA-512 — the modulus-floor check is per-algorithm because of this. |
| 8624 | Algorithm Implementation Requirements and Usage Guidance for DNSSEC — *superseded here by 9905/9906* | `src/core/dnssec/records.js` | Referenced only as the document RFC 9905/9906 supersede. |
| 9904 | DNSSEC algorithm guidance (per project code) | `src/core/dnssec/records.js` | Reserves a specific digest-type value so it cannot be read as a future assignment. |
| 9905 | DNSSEC algorithm guidance — supersedes RFC 8624 (per project code) | `src/core/dnssec/records.js` | §3.1 marks RSASHA1-family algorithms and SHA-1 digests as deprecated (not prohibited) for inspected delegations. |
| 9906 | DNSSEC DS digest guidance (per project code) | `src/core/dnssec/records.js` | Paired with 9905 to deprecate SHA-1 / GOST-R-34.11-94 DS digest types. |
| 9558 | DNSSEC algorithm registration (per project code) | `src/core/dnssec/records.js` | Registers algorithm 23 (ECC-GOST12) as current/non-deprecated, distinct from the deprecated algorithm 12 (ECC-GOST). |
| 9563 | DNSSEC SM2SM3 algorithm (per project code) | `docs/specs/implemented/dnssec-evidence.md` | Documents algorithm 17 (SM2SM3); the `src/` algorithm-name table lists `17: 'SM2SM3'` without citing the number inline. |

## MTA-STS / TLS-RPT / DANE (transport)

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 8461 | SMTP MTA Strict Transport Security (MTA-STS) | `src/core/transport/mta-sts.js`, `src/core/transport/mta-sts-policy.js`, `src/core/shared/record-fields.js`, `src/audit/artifacts.js` | Validates the `_mta-sts` TXT record (§3.1: discard non-`v=STSv1;` records, require exactly one), parses the policy body (§3.2: `key: value` lines, later-duplicate handling for non-`mx` fields), and implements §8.3 withdrawal (`mode: none` with short `max_age`). |
| 8460 | SMTP TLS Reporting | `src/core/transport/tls-rpt.js`, `src/core/shared/record-fields.js` | Validates the `_smtp._tls` TXT record against the same "exactly one versioned record" rule (§3), reusing the MTA-STS extension-name grammar and importing RFC 3986 for report-URI values. |
| 6698 | The DNS-Based Authentication of Named Entities (DANE) TLSA Protocol | `src/core/transport/tlsa.js`, `src/ui/report-data.js` | §2.1.1–2.1.3 define the TLSA presentation-format fields the parser reads (usage/selector/matching-type/data) and their display order. |
| 7671 | The DANE Protocol: Updates and Operational Guidance | `src/core/transport/tlsa.js` | §4 defines the SMTP-usable subset of TLSA usage/selector/matching-type combinations validated against. |

## BIMI

BIMI has **no assigned RFC** in this codebase; it is cited as "the BIMI draft"
(an Internet-Draft). It borrows two RFCs by analogy for its record-handling rules.

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 8461 | SMTP MTA Strict Transport Security (MTA-STS) | `src/core/bimi/bimi.js`, `src/core/shared/record-fields.js`, `src/core/transport/ext-value.js` | The BIMI "duplicate published records ⇒ not present" rule is modeled on MTA-STS §3.1; BIMI reuses the shared extension-name grammar (its extension-*value* grammar diverges — it omits the `=`-exclusion the other two share). |
| 8460 | SMTP TLS Reporting | `src/core/bimi/bimi.js` | Same duplicate-record rule, mirrored from TLS-RPT §3. |

## DNS fundamentals / encoding / shared

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 4592 | The Role of Wildcards in the Domain Name System | `src/audit/audit-domain.js`, `src/core/dmarc/report-auth.js` | §2.2.1/§2.3 (a wildcard should not synthesize below an existing node) justify probing for `_domainkey` wildcard poisoning, and explain why a literal wildcard-owner query answers a different question than resolver synthesis in the report-authorization check. |
| 4648 | The Base16, Base32, and Base64 Data Encodings | `src/core/shared/base64.js` | The canonical base64 decoder shared by DKIM and DNSSEC key parsing, including the rule that unused pad bits must be zero. |
| 3986 | Uniform Resource Identifier (URI): Generic Syntax | `src/core/shared/uri.js` | Implements the `host` production (§3.2.2: IP-literal/IPv4/reg-name), IPv6 literal parsing with embedded IPv4 tail, and §2.1 percent-encoding validation shared across CAA `iodef`, TLS-RPT, and mailto. |
| 6068 | The 'mailto' URI Scheme | `src/core/shared/uri.js` | The `mailtoURI` grammar validating DMARC `rua=`/`ruf=` and CAA `iodef` mailto values, including a UTF-8 percent-encoded IDN and reserved-character escaping. |

## Report comparison / output

| RFC | Title | Applied in | How it is applied |
| --- | --- | --- | --- |
| 3339 | Date and Time on the Internet: Timestamps | `src/ui/report-data.js` | A `RFC3339` regex validates the report's `generatedAt` is a canonical UTC `YYYY-MM-DDTHH:mm:ss.sssZ` timestamp; malformed values are rejected during report comparison. |
| 4180 | Common Format and MIME Type for CSV Files | `src/ui/report.js`, `src/ui/events.js` | Governs the CSV export's quoting/escaping. The code notes RFC 4180 quoting alone does not stop formula execution, so it neutralizes formula-leading cells (`=`, `+`, `-`, `@`) before applying RFC 4180 quoting. |
| 8785 | JSON Canonicalization Scheme (JCS) | `docs/specs/implemented/report-comparison.md` | Mentioned only as a possible future approach to a stable JSON identity — **not implemented** in `src/`. |
