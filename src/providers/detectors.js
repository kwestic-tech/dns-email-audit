/**
 * Provider detection. Spec Design §4 and §12, Task 4.9 — the last extraction
 * of Phase 4.
 *
 * Names, from records. Which DNS operator serves a zone, which mail provider
 * an MX set points at, which host answers for the website. Every answer is a
 * stable token (`@custom`, `@null-mx`, `@no-web`) or a proper noun that is
 * passed through untranslated by design — this directory emits no finding,
 * severity, score or locale key, and decides nothing about security posture.
 *
 * ── The null-MX collaborator ────────────────────────────────────────────
 *
 * `detectEmailProvider()` needs to know whether an MX set is RFC 7505's
 * `0 .`, and that predicate is MX semantics owned by
 * [`core/mx/`](../core/mx/API.md). §12 gives `src/providers/` an edge to
 * `core/shared/` only.
 *
 * **Ruled at Task 4.0, finding 4:** `providers/` receives the null-MX
 * determination rather than importing `core/mx/`. So `isNullMx` arrives as an
 * injected capability and the composition root supplies it — the same
 * arrangement `core/dkim/` has for SPF's `spfReferencedCatalogKeys`.
 *
 * **What is still owed.** The ruling's end state is audit passing the derived
 * FACT — a boolean — not the predicate. That cannot be built here:
 * `detectEmailProvider(mx, domain, addressRecords)` is a legacy engine member
 * whose three-argument form is asserted directly by `tools/scoring.test.mjs`,
 * and there is no `src/audit/` to derive the fact in until Phase 5. Injecting
 * the predicate removes the forbidden EDGE today and leaves the signature
 * untouched; Phase 5 extracts audit, derives the boolean there, and the
 * parameter goes away with the same move that retires the SPF collaborator.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s provider-detection block, unchanged apart from the two-space
 * dedent, the `export` keywords, and becoming the body of a factory. Every
 * pattern, every token and every fallback order is byte-identical. `cap()`
 * stays private; it has one reader and was never an engine member.
 */

/**
 * Build the detectors over the null-MX determination.
 *
 * One capability, and it is the only reason this is a factory at all.
 */
export function createDetectors(capabilities) {
  // Destructured in the BODY, matching every other owner: a destructured
  // PARAMETER is not a declaration to `platform.test.mjs`'s ambient scan.
  const { isNullMx } = capabilities;

  function cap(s) { return s ? s[0].toUpperCase() + s.slice(1) : s; }

  function detectDNSProvider(ns, domain) {
    if (!ns.length) return '@unknown';
    const n = ns.join(' ').toLowerCase();
    if (n.includes('cloudflare')) return 'Cloudflare';
    if (n.includes('porkbun')) return 'Porkbun';
    if (n.includes('awsdns')) return 'AWS Route 53';
    if (n.includes('googledomains') || n.includes('.google.com')) return 'Google Domains';
    if (n.includes('squarespacedns')) return 'Squarespace';
    if (n.includes('namecheap')) return 'Namecheap';
    if (n.includes('godaddy')) return 'GoDaddy';
    if (n.includes('dnsmadeeasy')) return 'DNS Made Easy';
    if (n.includes('ultradns')) return 'UltraDNS';
    if (n.includes('name.com')) return 'Name.com';
    if (n.includes('hover')) return 'Hover';

    // Self-hosted: nameservers live on the same domain being audited
    if (domain && ns.some(s => {
      const h = s.toLowerCase().replace(/\.$/, '');
      return h === domain || h.endsWith('.' + domain);
    })) return '@self-hosted';

    // Extract provider name, handling ccSLDs like .com.tw .co.uk .com.au
    const ccSLDs = new Set(['com', 'co', 'net', 'org', 'edu', 'gov', 'ac', 'ne', 'or', 'biz', 'nom']);
    const parts = ns[0].replace(/\.$/, '').split('.');
    if (parts.length >= 3) {
      const penultimate = parts[parts.length - 2].toLowerCase();
      const idx = ccSLDs.has(penultimate) && parts.length >= 4
        ? parts.length - 3   // ccSLD: step past second-level label (e.g. .com.tw, .co.uk)
        : parts.length - 2;  // standard TLD: e.g. "cloudns" from ns1.cloudns.net
      return cap(parts[idx]);
    }
    return '@custom';
  }

  function detectEmailProvider(mx, domain, addressRecords) {
    if (isNullMx(mx)) return '@null-mx';
    if (!mx.length) return addressRecords && addressRecords.length ? '@implicit-mx' : '@none';
    const m = mx.join(' ').toLowerCase();
    if (m.includes('aspmx.l.google') || m.includes('smtp.google') || m.includes('googlemail')) return 'Google Workspace';
    if (m.includes('icloud') || m.includes('mail.icloud')) return 'Apple iCloud';
    if (m.includes('protection.outlook') || m.includes('mail.protection')) return 'Microsoft 365';
    if (m.includes('zoho')) return 'Zoho Mail';
    if (m.includes('mxroute')) return 'MXroute';
    if (m.includes('fastmail')) return 'Fastmail';
    if (m.includes('protonmail')) return 'Proton Mail';
    if (m.includes('mailgun')) return 'Mailgun';
    if (m.includes('sendgrid')) return 'SendGrid';
    if (m.includes('porkbun')) return '@porkbun-forwarding';
    if (m.includes('forwardemail')) return 'Forward Email';
    if (m.includes('messagelabs')) return 'Symantec/MessageLabs';

    // Self-hosted: MX points back to the same domain
    if (domain && mx.some(r => {
      const host = r.replace(/^\d+\s+/, '').toLowerCase().replace(/\.$/, '');
      return host === domain || host.endsWith('.' + domain);
    })) return '@self-hosted';

    return '@custom-unknown';
  }

  function detectHosting(aRecs, wwwCname, domain) {
    const a = aRecs.join(' ');
    const c = wwwCname.join(' ').toLowerCase();
    if (c.includes('odoo.com')) return 'Odoo';
    if (c.includes('shopify')) return 'Shopify';
    if (c.includes('webflow')) return 'Webflow';
    if (c.includes('squarespace')) return 'Squarespace';
    if (c.includes('wix.com')) return 'Wix';
    if (c.includes('wpengine') || c.includes('wordpress.com')) return 'WordPress';
    if (c.includes('netlify')) return 'Netlify';
    if (c.includes('vercel') || c.includes('now.sh')) return 'Vercel';
    if (c.includes('github.io')) return 'GitHub Pages';
    if (c.includes('pages.dev')) return 'Cloudflare Pages';
    if (c.includes('porkbun')) return 'Porkbun Hosting';
    if (c.includes('fastly')) return 'Fastly';
    if (c.includes('icloudmailadmin')) return '@dash';
    if (a.includes('104.21') || a.includes('172.67') || a.includes('104.18')) return '@cloudflare-proxied';
    if (a.includes('185.199.')) return 'GitHub Pages';
    if (a.includes('76.76.21') || a.includes('76.223')) return 'Vercel';
    if (!aRecs.length && !wwwCname.length) return '@no-web';
    return '@custom';
  }

  return { detectDNSProvider, detectEmailProvider, detectHosting };
}
