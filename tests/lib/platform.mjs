/**
 * Deterministic platform profiles for equivalence subjects.
 *
 * A profile substitutes an ambient browser primitive and nothing else. It is
 * the same move this project already makes with `fetch` — `tools/lib/doh-fixture.mjs`
 * states the standing rule that `js/dns.js` gets no test seam and that tests
 * substitute at the lowest primitive instead — and spec §11 names `crypto` one
 * of the primitives the browser platform adapter owns.
 *
 * ── Why this file exists ──────────────────────────────────────────────────
 *
 * `dkim.key.cryptoValidated: false` and its issue token `key-structure-invalid`
 * are set by `validateDkimKeyStructure()` (js/dns.js:1067-1071) only when
 * `crypto.subtle.importKey` REJECTS a key the project's own DER walk has
 * already accepted. That window is narrow by construction: `derReadRsaPublicKey()`
 * (js/dns.js:801) requires an odd modulus, an odd exponent of at least 3,
 * strictly below the modulus, minimally encoded, with no trailing content.
 *
 * **Native Node Web Crypto cannot currently produce this state.** Measured, not
 * assumed — every probe inside that window imported successfully on Node
 * v26.7.0: 16-bit, 64-bit, 256-bit, 1017-bit and 2048-bit moduli, with `e=3`
 * and `e=65537`. The probes Node might have refused — `e=1`, an even exponent,
 * an even modulus — are rejected by the DER walk first and never reach the
 * import at all. A stricter browser implementation does reject keys in this
 * window, which is why the production branch exists.
 *
 * So corpus coverage of these two states DEPENDS ON THE EXPLICIT PROFILE below.
 * It is not native-Node coverage and must never be described as such. Nothing
 * here fabricates a result: the production code constructs the state itself
 * when the injected `importKey` rejects, exactly as it would in a browser.
 *
 * The profile is recorded in the equivalence manifest per case, so a baseline
 * captured under one profile cannot be silently compared against another.
 * Subject binding is strengthened by this, not weakened: `native` is the
 * default and every other profile has to name itself.
 */

/**
 * A rejection shaped like the one a browser raises.
 *
 * `DataError` is what `SubtleCrypto.importKey` throws for key data it cannot
 * interpret. The name matters: `validateDkimKeyStructure()` catches anything,
 * but a caller reading the error should see the real thing rather than a
 * generic `Error` invented by a test.
 */
function dataError(message) {
  const error = new Error(message);
  error.name = 'DataError';
  return error;
}

/**
 * Wrap the real Web Crypto, overriding `subtle.importKey` only.
 *
 * `subtle.digest` is delegated untouched, and that is load-bearing: the DNSSEC
 * DS-to-DNSKEY matcher computes digests through it (js/dns.js:3749), so a
 * profile that replaced the whole of `subtle` would move the DNSSEC surface as
 * well and the case would be measuring two changes at once.
 */
function wrapSubtle(override) {
  const real = globalThis.crypto;
  const subtle = Object.create(null);
  for (const name of ['digest', 'generateKey', 'sign', 'verify', 'exportKey', 'encrypt', 'decrypt']) {
    if (typeof real.subtle?.[name] === 'function') {
      subtle[name] = (...args) => real.subtle[name](...args);
    }
  }
  subtle.importKey = override;
  return {
    subtle,
    getRandomValues: (...args) => real.getRandomValues(...args),
    randomUUID: () => real.randomUUID(),
  };
}

export const PLATFORM_PROFILES = {
  /**
   * The host's own Web Crypto, unwrapped. The default, and what every case
   * that does not name a profile runs under.
   */
  native: {
    id: 'native',
    describe: 'the host Web Crypto, unmodified',
    crypto: () => globalThis.crypto,
  },

  /**
   * `importKey` rejects every key. Reaches `cryptoValidated: false`,
   * `key-structure-invalid` and the `dkim-key-malformed` finding.
   */
  'crypto-import-rejects': {
    id: 'crypto-import-rejects',
    describe: 'Web Crypto whose subtle.importKey rejects, as a strict browser does for a key in the DER walk\'s accepted window',
    crypto: () => wrapSubtle(async () => {
      throw dataError('unsupported key data');
    }),
  },

  /**
   * The negative control, and it is not decoration.
   *
   * Same wrapper, same delegation, `importKey` delegated to the real one. It
   * exists so the pair of corpus cases differs in exactly one thing — whether
   * the import succeeds — and so a reader can see that the wrapper itself is
   * inert. Without it, `crypto-import-rejects` proves only that SOMETHING about
   * the substituted platform changed the result.
   */
  'crypto-import-accepts': {
    id: 'crypto-import-accepts',
    describe: 'the same wrapper with subtle.importKey delegated — the control that proves the wrapper is inert',
    crypto: () => wrapSubtle((...args) => globalThis.crypto.subtle.importKey(...args)),
  },
};

/** Resolve a profile by name, refusing an unknown one rather than defaulting. */
export function platformProfile(name) {
  const profile = PLATFORM_PROFILES[name || 'native'];
  if (!profile) {
    throw new Error(
      `platform: unknown profile ${JSON.stringify(name)}. ` +
      `Known: ${Object.keys(PLATFORM_PROFILES).join(', ')}. ` +
      `Defaulting would run a case under a platform it did not ask for.`);
  }
  return profile;
}
