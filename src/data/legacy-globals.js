/**
 * Install the generated tables as the globals the remaining IIFEs read.
 * TEMPORARY — deleted in Phase 6 when the last consumer takes them as
 * arguments instead.
 *
 *   LEGACY_ADAPTER
 *
 * **This is a separate module because ES imports are hoisted.**
 *
 * The first version of this adapter put these three assignments in the entry
 * point's body, above the `import '../js/i18n.js'` lines, with a comment
 * explaining that the order was load-bearing. The comment was right and the
 * code was wrong: a module's imports are all resolved and evaluated before any
 * of its own body runs, so every IIFE would have executed against undefined
 * globals — `js/dns.js` building empty public-suffix sets and `js/i18n.js`
 * finding no English bundle. Textual order in the entry point says nothing
 * about evaluation order.
 *
 * A side-effect module does say it. Imports are evaluated in the order they are
 * written, so importing this one first is a real ordering guarantee rather than
 * an apparent one.
 *
 * Generated data is INJECTED, never imported by the modules that consume it.
 * The spike measured why: bundling `js/public-suffixes.js` into the scoring
 * sandbox silently replaced a four-rule fixture with the real 10,239-rule list
 * and the suite still reported `1535 passed, 0 failed`. A consumer that imports
 * its own data can never be handed different data by a test. This module and
 * `createAuditRuntime()` (Task 2.5) are the only places the tables are bound.
 */

import { PUBLIC_SUFFIX_RULES } from './public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from './dkim-selectors.js';
import { LOCALE_EN } from './locales-en.js';

window.__PUBLIC_SUFFIX_RULES__ = PUBLIC_SUFFIX_RULES;
window.__DKIM_SELECTOR_CATALOG__ = DKIM_SELECTOR_CATALOG;
window.__I18N_EN__ = LOCALE_EN;
