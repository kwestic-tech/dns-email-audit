/**
 * Real RSA and Ed25519 key material for the fixtures, generated once with
 * node:crypto and pasted verbatim.
 *
 * Shared between the equivalence corpus and tests/contract/legacy-shapes.test.mjs
 * so the focused assertions and the corpus cases are talking about the same key.
 * The first draft of the corpus used hand-invented base64 that looked like a key
 * and was not one: the DER walk refused it, every fixture reported
 * `unparseable-key`, and the DKIM key axes stayed uncovered while the cases sat
 * there looking correct.
 */
export const RSA_2048_SPKI = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm3ovjn5TjXf7GUkRFDfc3KdWa/B+Ya7UoqAD75o/LXkmgE7hFEDjwwTjk7aV2exev6VkkszC7vop8lUlEyz7diplxlFGihLU7FUTTpoY9cDw9rcckphBZYgCjBpdgmEO+G8i72wTMlDKB67I2p2p8PRZI/bjU/mkFOUg0XiZcGrThx9wY1bgxLj83aBcQegoAjPgaP9PuNkVAsiLKUCj0UVAbEF4fR55ukv2qL1X4azFJJh1Hh7CFAXiTLj1A157KDY+DLtr0nS7HAN1UhRaqNdUhD2PSunTqrkDpq27MmP2FIvDYdUMp4Tbf4Ul63kv/BZq69Waooduw04eS/7FCwIDAQAB';
export const RSA_2048_PKCS1 = 'MIIBCgKCAQEAm3ovjn5TjXf7GUkRFDfc3KdWa/B+Ya7UoqAD75o/LXkmgE7hFEDjwwTjk7aV2exev6VkkszC7vop8lUlEyz7diplxlFGihLU7FUTTpoY9cDw9rcckphBZYgCjBpdgmEO+G8i72wTMlDKB67I2p2p8PRZI/bjU/mkFOUg0XiZcGrThx9wY1bgxLj83aBcQegoAjPgaP9PuNkVAsiLKUCj0UVAbEF4fR55ukv2qL1X4azFJJh1Hh7CFAXiTLj1A157KDY+DLtr0nS7HAN1UhRaqNdUhD2PSunTqrkDpq27MmP2FIvDYdUMp4Tbf4Ul63kv/BZq69Waooduw04eS/7FCwIDAQAB';
export const RSA_1024_SPKI = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDw4QII4k5WU1mkSGyLXZ6I2PpmA5V/zmo4USHk5zEMh0KfXZJRMaqDDm1J4vcF69IzwhEgQvIFDYQh2e9LqkxpCp8IJ9H6ECvWAPvKOWRS91SNKX/Nti7mAvcsgJiqVvx3IOVp/nqmyToj2SIkpZNSL+JMCDsPmk2uVLWUorGfQIDAQAB';
export const RSA_1024_PKCS1 = 'MIGJAoGBAMPDhAgjiTlZTWaRIbItdnojY+mYDlX/OajhRIeTnMQyHQp9dklExqoMObUni9wXr0jPCESBC8gUNhCHZ70uqTGkKnwgn0foQK9YA+8o5ZFL3VI0pf822LuYC9yyAmKpW/Hcg5Wn+eqbJOiPZIiSlk1Iv4kwIOw+aTa5UtZSisZ9AgMBAAE=';
export const RSA_512_SPKI = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALScBci2wSLdlXaBCGFwHa4I0brbudMRLny9c7tCQDu+PPyFRygUn12zLltVkSf6vOFx3mr+AX1x19skj30vj6ECAwEAAQ==';
export const RSA_512_PKCS1 = 'MEgCQQC0nAXItsEi3ZV2gQhhcB2uCNG627nTES58vXO7QkA7vjz8hUcoFJ9dsy5bVZEn+rzhcd5q/gF9cdfbJI99L4+hAgMBAAE=';
export const ED25519_RAW = '2xc8yU6s4V1dZt0hXDZJvZGsyz17LMt89VVd0JILrcg=';
export const RSA_2048_SPKI_EVEN_E = 'MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAm3ovjn5TjXf7GUkRFDfc3KdWa/B+Ya7UoqAD75o/LXkmgE7hFEDjwwTjk7aV2exev6VkkszC7vop8lUlEyz7diplxlFGihLU7FUTTpoY9cDw9rcckphBZYgCjBpdgmEO+G8i72wTMlDKB67I2p2p8PRZI/bjU/mkFOUg0XiZcGrThx9wY1bgxLj83aBcQegoAjPgaP9PuNkVAsiLKUCj0UVAbEF4fR55ukv2qL1X4azFJJh1Hh7CFAXiTLj1A157KDY+DLtr0nS7HAN1UhRaqNdUhD2PSunTqrkDpq27MmP2FIvDYdUMp4Tbf4Ul63kv/BZq69Waooduw04eS/7FCwIBBA==';

/**
 * A structurally valid RSASHA256 zone-signing key, in RFC 3110 §2 form:
 * a three-octet exponent length prefix, exponent 65537, then a 256-octet
 * modulus with non-zero leading and trailing octets. `dnskeyStructure()`
 * accepts it and `dnskeyKeyTag()` computes tag 62148.
 *
 * The DS digests beside it are COMPUTED over the canonical owner name in wire
 * format followed by this key's RDATA, per RFC 4034 §5.1.4 — not invented. A
 * fabricated digest would make `confirmed` unreachable and every DS in the
 * corpus would silently be an orphan.
 */
export const DNSSEC_ZONE_KEY = '257 3 8 AwEAAcGrq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq48=';
export const DNSSEC_KEY_TAG = 62148;
/** SHA-256 over dnsWireName('secure.dnssec.test') + this key's RDATA. */
export const DS_MATCHING_SECURE = '62148 8 2 4486b590210fff9c53b6f09d2d3ee395a3769ee84ce2c5731ecc03fc03cf898f';
/** The same digest computed for a DIFFERENT owner, so it cannot match here. */
export const DS_MISMATCHED = '62148 8 2 d0ade101741816d7827bd0c757b9970864c81d085ef3c8c3706702569745cf91';
