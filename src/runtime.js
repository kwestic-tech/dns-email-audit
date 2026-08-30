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
import { createUi } from './ui/events.js';
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

  /**
   * The page. Task 5.6, and the moment the docstring on `mount()` below
   * described from Task 2.5 onward.
   *
   * §12 gives THIS module the edge to `ui/` and gives `src/main.js` only
   * `runtime.js`, `platform/` and `data/`. So the UI is wired here, from the
   * layer whose job wiring is, and the entry point composes a runtime and
   * nothing else. `mount()` owns the whole mount, exactly as promised.
   *
   * The two supported facade members reach the UI as CALLBACKS — §12: no UI
   * module imports `audit/`, and these two are all it needs from the audit.
   * Constructing the UI registers ONE `DOMContentLoaded` listener; that
   * listener wires every control, calls `mount()` and probes connectivity
   * once. There is no second boot path, which is a privacy figure and not
   * merely a tidiness one.
   */
  const ui = createUi({
    platform,
    i18n,
    renderer,
    analyzeDomain: (domain, options) => engine.analyzeDomain(domain, options),
    checkConnectivity: () => engine.checkConnectivity(),
    mount: () => i18n.init(),
    englishBundle,
  });

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
     * The language boot: pick a locale, load it, paint the DOM. **Called by
     * the UI's single `DOMContentLoaded` listener**, which this module now
     * registers — so this runtime owns the whole mount, which is what this
     * docstring promised from Task 2.5 and what Task 5.6 delivered.
     *
     * Nothing else calls it. A second caller would boot i18n twice and, more
     * to the point, would put a second connectivity probe on every page load —
     * a figure `PRIVACY.md` publishes and one of the five equivalence surfaces
     * measures.
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
    ui,
  };
}
