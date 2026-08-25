# Live DNSSEC state evidence for 0.5.0

Evidence for the `dnssec-evidence` spec review. Captured 2026-08-25 against
`https://cloudflare-dns.com/dns-query` with `accept: application/dns-json`, the
only resolver this project talks to. Cross-checked against `dns.google` where
noted.

Companion to
[`implemented/fixtures/doh-shapes-0.4.0.md`](../implemented/fixtures/doh-shapes-0.4.0.md),
which captured the *presentation* shapes of `DS`, `DNSKEY` and `TLSA`. This
file captures the *states*, because the six-state classifier cannot be reviewed
against reasoning alone — three of the states below were found only by looking.

## 1. `do=1` answers carry RRSIG alongside the record

```
name=ietf.org type=DS      Answer: [43, 46]
name=ietf.org type=DNSKEY  Answer: [48, 48, 46]
```

Type 46 is `RRSIG`. **Both parsers must filter on the numeric type** — `43` for
`DS`, `48` for `DNSKEY` — exactly as `checkTlsa()` filters on `52` for the
CNAME case in the 0.4.0 capture. An unfiltered `parseDs()` reads the RRSIG
presentation string `DS 8 2 3600 1788794710 …` as a DS record: key tag `NaN`,
algorithm 8, digest type 2, digest `3600…`. That is not an error, it is a
plausible-looking DS record that matches no DNSKEY, and it would raise a
`mismatch` verdict on **every signed domain audited**.

## 2. A long RSA `DNSKEY` is not wrapped

The 0.4.0 capture observed no newline wrapping but sampled only algorithm 13
(ECDSA, 97-character keys). Re-measured against RSA:

```
name=verisigninc.com type=48
data: "256 3 8 AwEAAd0QrBPRbxNYnFgWuM4MagnO2sYGEOgRJMN47TcPPd/Rfe…"   len 184
data: "257 3 8 AQPLlfqzd99gPy3T8xVnbkuhXYo9jPoafadiW9bjC3KrSqEWSO…"   len 352
```

No parentheses, no newlines, exactly three spaces — the field separators. The
key field is contiguous at every observed length.

**The base64 is case-sensitive and contains `+`, `/` and `=`.** `parseDs()` may
reuse `parseTlsaRecord()`'s normalization (`replace(/\s+/g,'').toLowerCase()`)
because a hex digest is case-insensitive. `parseDnskey()` **may not**:
lowercasing the key field destroys it, every digest then fails to match, and the
result is a `mismatch` verdict on a healthy zone. This is the single most
likely way to ship the defect the spec's Risks section names.

## 3. `dsAuthenticated` cannot do the job the draft gives it

Draft §5 proposes `dsAuthenticated`, the AD flag on the `DS` response, to
separate a parent that authoritatively denies a DS from a lookup that simply did
not establish one. Measured against an unsigned zone under a signed TLD:

```
name=amazon.com type=DS      Status 0  AD False  Answer: []  Authority: [6, 46, 50, 46, 50, 46]
name=amazon.com type=DNSKEY  Status 0  AD False  Answer: []  Authority: [6]
```

The NSEC3 records (type 50) and their RRSIGs (46) in the **Authority** section
are the authenticated denial of existence. Cloudflare still returns `AD: false`,
because the answer describes an insecure delegation. So the AD flag on a DS
response is `false` both when the parent proves there is no DS and when nothing
was established — it does not distinguish the two.

The evidence that *would* distinguish them lives in the Authority section, which
`fetchDohOnce()` at [`js/dns.js:170`](../../../js/dns.js) does not return: it
keeps `Answer`, `AD`, `Status` and nothing else.

## 4. `secure` and locally-confirmed are independent — proof

```
name=servfail.nl type=DS      Status 0  AD True   43 present
name=servfail.nl type=DNSKEY  Status 0  AD True   48, 48 present
name=servfail.nl type=NS      Status 2  (SERVFAIL)
```

Locally computed: DS key tag 15438, algorithm 13, digest type 2 →
**`confirmed`** against the KSK. Every piece of local evidence agrees, and the
zone is bogus. This is draft §5's rule — never assemble `secure` out of local
evidence alone — demonstrated on a live name rather than argued.

```
name=dnssec-failed.org type=DS      Status 0  AD True   43 present
name=dnssec-failed.org type=DNSKEY  Status 2  (SERVFAIL)
name=dnssec-failed.org type=NS      Status 2  (SERVFAIL)
```

Three of the draft's six state rules claim this domain at once — `mismatch` (DS
present, no matching DNSKEY), `indeterminate` (a transport failure) and `bogus`
(SERVFAIL then `cd=1`). It is the canonical bogus test domain, so `bogus` is the
right answer, and the draft has no precedence rule that produces it.

## 5. A healthy zone can publish a DS that matches nothing

```
name=paypal.com type=DS  AD True
  7037  13 2 9778f2ff96889ebed549795deaa40a6113f1899af7ca8dd7947fddfeca9a190b   → confirmed
  34800 13 2 d9e64ba8c8718fd93b596f9d109d9dac47c3f557312201dfcce5dd4128c08f50   → no-matching-key
```

Stable across repeated queries and corroborated against `dns.google`.
`paypal.com` validates (`AD: true`), mail is delivered, nothing is wrong with
it — and it publishes one good DS beside one orphan, the ordinary appearance of
a key rollover or a stale registrar record.

`paypal.com` is in the 40-domain backtest sample in
[`tools/backtest.mjs`](../../../tools/backtest.mjs).

Note also that `dns.google` returns the digest in **uppercase** hex where
Cloudflare returns lowercase. Not a live concern — the resolver is fixed — but
a digest comparison must normalize case regardless, and it is a datum for
`OQ-SEC9-04`.

## 6. Key tag and digest, verified against live zones

RFC 4034 Appendix B key tag and §5.1.4 digest, implemented in ~20 lines and run
against live answers:

| Domain | DNSKEY | DS | Verdict |
| --- | --- | --- | --- |
| `ietf.org` | ZSK 34505, KSK 2371 (alg 13) | 2371 13 2 | `confirmed` |
| `cloudflare.com` | ZSK 34505, KSK 2371 (alg 13) | 2371 13 2 | `confirmed` |
| `verisigninc.com` | ZSK 61291, KSK 64326 (alg 8, RSA) | 64326 8 2 | `confirmed` |
| `gov.uk` | ZSK 52549, KSK 695 (alg 8, RSA) | 695 8 2 | `confirmed` |
| `nic.cz` | ZSK 37235, KSK 54415 (alg 13) | 54415 13 2 | `confirmed` |
| `servfail.nl` | ZSK 45916, KSK 15438 (alg 13) | 15438 13 2 | `confirmed`, zone bogus |
| `paypal.com` | ZSK 34374, ZSK 36858, KSK 7037 | 7037 → ok, 34800 → orphan | mixed |

The computed KSK tag for `ietf.org` and `cloudflare.com` is 2371, matching the
DS key tag in the 0.4.0 shape capture independently. The algorithm is sound; the
risk in this release is not the arithmetic.

## 7. A live domain for every state

The draft's Testing section says a domain in `unanchored` and `mismatch` should
be found "if one can be found". They can:

| State | Live domains | Evidence |
| --- | --- | --- |
| `secure` | `cloudflare.com`, `ietf.org`, `gov.uk`, `verisigninc.com` | DS confirms DNSKEY, AD true |
| `insecure` | `amazon.com`, `godaddy.com`, `python.org`, `gnu.org` | no DNSKEY, no DS, AD false |
| `unanchored` | **`quad9.net`** (3 DNSKEY, 0 DS), **`fsf.org`** (2 DNSKEY, 0 DS) | AD false on NS |
| orphan DS beside a good one | `paypal.com` | §5 above |
| `bogus` | `dnssec-failed.org`, `servfail.nl` | §4 above |

`quad9.net` is a DNS security provider whose own zone is signed and unanchored,
which is a fair illustration of why the state deserves its own name: the state
is common, it is invisible today, and it is reached by careful operators.

Signed share of the 40-domain backtest sample, measured by the AD flag on `NS`:
**11 of 40** — `cloudflare.com`, `paypal.com`, `irs.gov`, `nasa.gov`, `nih.gov`,
`gov.uk`, `europa.eu`, `stanford.edu`, `harvard.edu`, `salesforce.com`,
`slack.com`. The other 29 exercise none of this release's new code, so the
sample must be extended with the names above before the backtest can be read as
a guard on it.
