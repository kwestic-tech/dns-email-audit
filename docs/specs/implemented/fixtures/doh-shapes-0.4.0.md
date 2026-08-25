# Captured DoH JSON shapes for `DS`, `DNSKEY` and `TLSA`

Evidence for `OQ-DEPTH-01`. Captured 2026-08-25 against
`https://cloudflare-dns.com/dns-query` with `accept: application/dns-json`,
which is the only resolver this project talks to.

**Do not write the parsers against anything but these.** The three types come
back in three different shapes from the same resolver, and the differences are
exactly the kind that produce a confidently wrong empty answer rather than an
error.

## `DS` — plain fields, lowercase hex

```
name=cloudflare.com type=43
data: "2371 13 2 32996839a6d808afe3eb4a795a0e6a7a39a76fc52ff228b22b76f6d63826f2b9"
```

Four whitespace-separated fields: key tag, algorithm, digest type, digest.
Digest is **lowercase** hex, unparenthesised, unquoted.

## `DNSKEY` — plain fields, case-sensitive base64

```
name=cloudflare.com type=48
data: "256 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="
data: "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
```

Four fields: flags, protocol, algorithm, public key. The key is base64 and is
**case-sensitive**, and contains `+`, `/` and `=`. Anything that lowercases this
value destroys the key.

## `TLSA` — parenthesised, UPPERCASE hex

```
name=_25._tcp.mx01.posteo.de type=52
data: "3 1 1 ( 13815B2C03F7BD63C54869706428442EDAB706D5B018A27575CA989129A196D5 )"
data: "3 1 1 ( 2A2413F46C23290866A3FB9C1658A404BCF6A71373D002A29D67C23ED8DF298D )"
```

Three numeric fields, then the association data **wrapped in parentheses with
spaces inside them**, in **uppercase** hex. This is the trap: a parser written
against the `DS` shape and reused here splits to `['3','1','1','(']` and reads
the digest as an empty string, with no error raised.

Confirmed identical in shape across `mx1.bund.de` (`3 0 1`),
`mail.protonmail.ch`, `mx.soverin.net` and `mail2.ietf.org`. No newline
wrapping was observed in any record, at any length, for any of the three types.

## A `TLSA` query can also return a `CNAME`

```
name=_25._tcp.mx.soverin.net type=52
Answer[0]: type=5  data: "_dane.soverin.net."
Answer[1]: type=52 data: "3 1 1 ( A6EB48052B5A83AA9D40E71CEAA20F6818C3A632D3B182A6246501B64D63724D )"
```

Pointing `_25._tcp.<host>` at a shared `_dane.<zone>` name is ordinary DANE
practice. The answer array mixes record types, so the TLSA path must filter on
`a.type === 52`. `dohQuery()` already filters by type; `dohAll()` does not, and
must not be used here.

## `cleanAnswerData()` needs no change

The existing non-TXT branch is `value.replace(/^"|"$/g, '').trim()`. It does not
lowercase, so the case-sensitive `DNSKEY` base64 survives it intact, and the
quote-stripping is a no-op because none of these three types come back quoted.
The draft spec's concern that these values "must not be quote-stripped or
lowercased" is therefore already satisfied; no bypass is needed, unlike the CAA
path.
