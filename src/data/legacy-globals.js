/**
 * Publish the three generated tables as compatibility globals.
 *
 *   LEGACY_ADAPTER
 *
 * TEMPORARY — Phase 6 deletes it and asserts that no adapter remains.
 *
 * **Nothing in the application reads these globals.** Every consumer takes its
 * data as an argument: `createAuditRuntime()` is handed the three tables and
 * passes them down, and `src/ui/report.js` receives the English bundle for its
 * positional `csv.headers` backfill. The IIFEs that once read them are gone.
 * What this module preserves is the browser-visible NAMES, because removing a
 * published global is a compatibility decision and this release has already
 * made the two it authorized.
 *
 * Generated data is INJECTED, never imported by the modules that consume it.
 * The spike measured why: bundling `js/public-suffixes.js` into the scoring
 * sandbox silently replaced a four-rule fixture with the real 10,239-rule list
 * and the suite still reported `1535 passed, 0 failed`. A consumer that imports
 * its own data can never be handed different data by a test.
 *
 * ── Why a separate module, historically ─────────────────────────────────
 *
 * Kept because it explains the shape rather than the need. The first version
 * of this adapter put the three assignments in the entry point's body above
 * the `import '../js/i18n.js'` lines, with a comment saying the order was
 * load-bearing. The comment was right and the code was wrong: a module's
 * imports are all evaluated before any of its own body runs, so every IIFE
 * would have executed against undefined globals. Textual order in the entry
 * point says nothing about evaluation order; a side-effect module does.
 *
 * **That hazard is historical.** No consumer depends on this evaluating first
 * any more, because no consumer reads these globals.
 */

import { PUBLIC_SUFFIX_RULES } from './public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from './dkim-selectors.js';
import { LOCALE_EN } from './locales-en.js';

window.__PUBLIC_SUFFIX_RULES__ = PUBLIC_SUFFIX_RULES;
window.__DKIM_SELECTOR_CATALOG__ = DKIM_SELECTOR_CATALOG;
window.__I18N_EN__ = LOCALE_EN;
