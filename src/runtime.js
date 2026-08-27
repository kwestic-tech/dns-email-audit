/**
 * The composition root. Spec §11, implementation Task 2.5.
 *
 * One function, and it is the only place the application's parts are wired
 * together. Everything it needs is passed in; it imports the modules that hold
 * logic and imports **no** generated data and **no** platform.
 *
 * ── Importing this module does nothing ───────────────────────────────────
 *
 * No DOM is touched, no request is made, no global is written, and no instance
 * is created until `createAuditRuntime()` is called. That is an acceptance
 * criterion — "importing it neither mounts the UI nor performs network I/O" —
 * and `tests/contract/runtime.test.mjs` asserts it by importing this file into
 * a process with no browser globals at all and watching nothing happen.
 *
 * ── Lifetimes ───────────────────────────────────────────────────────────
 *
 * | Scope        | Holds                                          | Constructed |
 * | ---          | ---                                            | ---         |
 * | Runtime/page | the DoH cache, generated data, resolver, i18n  | once per call here |
 * | Audit        | options in force, accumulated result, cancel   | per analyzeDomain() |
 * | Call         | per-query retry and timeout state              | per resolver call |
 *
 * **The DoH cache belongs to the runtime, not to an audit.** It is closure
 * state inside the engine, so one runtime is one cache, and
 * `src/legacy-bridge.js` builds exactly ONE runtime for the page — which
 * reproduces v0.5.0's page lifetime exactly. `tools/scoring.test.mjs:1888-1891`
 * asserts a first DMARC walk issues 3 queries and a sibling issues 1, and
 * `PRIVACY.md:30-33` publishes the consequence as "roughly 41 queries for a
 * typical domain". Narrowing that scope raises a published figure, so it is a
 * privacy-facing change and not a refactor — spec correction 3.
 *
 * **Node's ESM module cache is not a dependency-injection mechanism.** Test
 * isolation comes from calling this function again, never from cache-busted
 * imports or module-level mutation. Two runtimes share nothing, and a contract
 * test proves both halves: sibling audits through one runtime reuse cached
 * answers, and two runtimes do not.
 */

import { createI18n } from './i18n/index.js';
import { createRenderer } from './ui/render.js';
import { createDnsEngine } from '../js/dns.js';

/**
 * Build one audit runtime.
 *
 * The three generated tables and the platform are PASSED. Spec §11's table:
 * public suffix rules, DKIM selector catalog and English bundle are passed
 * because a module that imports its own generated data can never be handed
 * different data by a test — the spike measured a four-rule fixture being
 * silently replaced by the real 10,239-rule list while 1,535 assertions still
 * passed. Protocol modules and scoring constants are imported, because they are
 * pure logic with no ambient state and their byte-identity is asserted.
 */
export function createAuditRuntime({
  publicSuffixRules,
  dkimSelectorCatalog,
  englishBundle,
  platform,
} = {}) {
  if (!platform) throw new Error('runtime: createAuditRuntime needs a platform');

  const i18n = createI18n({ englishBundle, platform });
  const renderer = createRenderer(() => platform.document, i18n);
  const engine = createDnsEngine({ publicSuffixRules, dkimSelectorCatalog, platform });

  return {
    /**
     * The supported facade. Two members, from a 95-member surface — the only
     * two `js/app.js` calls. Spec §10 derives the facade from actual consumers
     * rather than from what looked exportable, and everything else is either
     * internal or test surface that an import serves better than a global ever
     * did.
     */
    analyzeDomain: (domain, options) => engine.analyzeDomain(domain, options),
    checkConnectivity: () => engine.checkConnectivity(),

    /**
     * Wire this runtime to its page.
     *
     * Today that is the language boot: pick a locale, load it, paint the DOM.
     * Task 2.6 moves the `DOMContentLoaded` control wiring out of `js/app.js`
     * and into here, at which point this owns the whole mount.
     *
     * `src/legacy-bridge.js` deliberately does NOT call it yet — `js/app.js`
     * still boots i18n itself from its own listener, and calling it here as
     * well would run the boot twice.
     */
    mount: () => i18n.init(),

    /**
     * The parts, for the Phase 2 adapter that still has to publish them as
     * globals. Not facade members: `src/facade.expected.json` (Task 2.7) names
     * the supported surface, and these are not on it. Each disappears as its
     * last consumer migrates, and Phase 6 asserts no adapter remains.
     */
    i18n,
    renderer,
    engine,
  };
}
