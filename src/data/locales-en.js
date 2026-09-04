/* AUTO-GENERATED — DO NOT EDIT.
 * Source: locales/en.json
 * Regenerate with: npm run build:fallback
 *
 * English is inlined here so the app works when index.html is opened directly
 * from disk (file://), where fetching locales/*.json is blocked by the browser.
 */

export const LOCALE_EN = {
  "meta": {
    "code": "en",
    "name": "English",
    "nativeName": "English",
    "dir": "ltr"
  },
  "doc": {
    "title": "DNS & Email Security Auditor — Free SPF, DKIM, DMARC & DNSSEC Checker",
    "description": "Free browser-based DNS and email security auditor. Instantly check SPF, DKIM, DMARC, BIMI, MTA-STS, CAA, and DNSSEC for up to 200 domains at once. No signup, no data stored — runs entirely in your browser."
  },
  "topbar": {
    "title": "DNS & Email Auditor",
    "subtitle": "· free · no signup · no data sent to Kwestic",
    "langTitle": "Language"
  },
  "btn": {
    "howItWorks": "📖 How it works",
    "exportCsv": "⬇ Export CSV",
    "exportHtml": "⬇ Export Report",
    "runAudit": "🔎 Run Audit",
    "auditRunning": "Auditing…",
    "cancelAudit": "Cancel audit",
    "uploadFile": "📄 Upload .txt file",
    "loadExamples": "Load examples",
    "clearResults": "🗑 Clear results",
    "learnMore": "Learn more →",
    "exportJson": "⬇ Export JSON",
    "importReport": "⬆ Compare with a saved report",
    "exitCompare": "Exit comparison"
  },
  "input": {
    "heading": "Enter domains to audit",
    "desc": "One domain per line, or upload a .txt file. Up to 200 domains at once.",
    "placeholder": "example.com\nmycompany.org\nanother-domain.net"
  },
  "artifact": {
    "heading": "Validate a local MTA-STS policy or BIMI logo",
    "separation": "DNS audit results above came from public DNS. Everything in this panel comes only from files or text you supply.",
    "privacy": "Nothing supplied here is fetched, uploaded, stored, or added to your DNS score. Analysis happens locally in this browser and is discarded on reload. See <a href=\"https://github.com/kwestic-tech/dns-email-audit/blob/main/PRIVACY.md\" target=\"_blank\" rel=\"noopener\">Privacy</a>.",
    "domainLabel": "Audited domain",
    "noDomains": "Run a DNS audit first",
    "policyHeading": "MTA-STS policy",
    "policyHelp": "Paste the body of mta-sts.txt or choose a text file. Maximum 64 KiB.",
    "policyPlaceholder": "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400",
    "policyFile": "Choose .txt file",
    "svgHeading": "BIMI SVG logo",
    "svgHelp": "Paste the SVG source or choose an SVG file. Maximum 32 KiB. The logo is inspected, never displayed.",
    "svgPlaceholder": "Paste the contents of your logo SVG file",
    "svgFile": "Choose .svg file",
    "analyze": "Analyze supplied material",
    "clear": "Clear supplied material",
    "schemaNote": "BIMI checks cover security rejections and named SVG Tiny PS diagnostics; they are not full RNC-schema certification or a guarantee that a mailbox provider will display the logo.",
    "reportHeading": "Local artifact analysis",
    "userSupplied": "User supplied",
    "resultsFor": "Local analysis for {0}",
    "noFindings": "No issue was found in the supplied material.",
    "complete": {
      "one": "Local analysis complete: {0} finding.",
      "other": "Local analysis complete: {0} findings."
    },
    "policyLabel": "MTA-STS policy",
    "svgLabel": "BIMI SVG",
    "errorNoDomain": "Run a DNS audit and select a completed domain first.",
    "errorNoInput": "Paste or choose at least one policy or SVG file.",
    "errorTooLarge": "{0} is larger than the {1} KiB limit. It was not parsed.",
    "errorFileTooLarge": "{0} is larger than the {1} KiB limit. It was not read.",
    "errorWrongType": "The selected file declares type {0}; this input accepts {1}.",
    "errorFileRead": "The browser could not read {0}.",
    "fileLoaded": "Loaded {0} locally. Nothing was uploaded.",
    "token": {
      "malformed-line": "The line is not a key: value field.",
      "blank-line": "Blank lines are not permitted inside the policy.",
      "invalid-version": "version must be exactly STSv1.",
      "invalid-mode": "mode must be exactly enforce, testing, or none.",
      "invalid-mx": "mx must be a valid domain or a wildcard covering only the complete left-most label.",
      "invalid-max-age": "max_age must be an integer from 0 through 31557600.",
      "missing-version": "The policy must contain a version field.",
      "missing-mode": "The policy must contain a mode field.",
      "missing-max-age": "The policy must contain a max_age field.",
      "missing-mx": "An enforce or testing policy must contain at least one mx field.",
      "duplicate-field": "Only the first occurrence of a repeated non-mx field is used.",
      "bom-present": "A UTF-8 byte-order mark was removed from the start of the policy.",
      "wrong-case-field": "Registered field names are case-sensitive; this spelling is treated as an unknown extension.",
      "doctype-present": "DOCTYPE declarations are refused before XML parsing.",
      "entity-declaration": "Entity declarations are refused before parsing because expansion can exhaust memory.",
      "malformed-xml": "The source is not well-formed XML.",
      "bad-root": "The document root must be an exactly named svg element.",
      "script-element": "Script elements are not permitted in a BIMI logo.",
      "event-handler": "Event-handler attributes such as onload are not permitted.",
      "foreign-object": "foreignObject can embed non-SVG content and is not permitted.",
      "external-reference-element": "image and use elements are refused because they can reference other resources.",
      "external-reference": "External or empty href references are not permitted; only same-document fragments are allowed.",
      "link-element": "Clickable link elements are not permitted.",
      "external-style": "Styles may not import or reference another resource with url().",
      "animation": "Animation elements are outside the accepted static-logo profile.",
      "namespace-not-svg": "The root svg element must use the SVG namespace.",
      "base-profile-not-tiny-ps": "baseProfile must be exactly tiny-ps.",
      "version-not-1-2": "version must be exactly 1.2.",
      "title-missing": "The root must contain one non-empty direct-child title element.",
      "title-not-unique": "The root must contain exactly one direct-child title element.",
      "desc-empty": "A desc element, when present, must not be empty.",
      "viewbox-missing": "viewBox must contain four numbers with positive width and height.",
      "viewbox-not-square": "viewBox width and height must be equal.",
      "root-has-position": "The root svg must not carry x or y positioning attributes.",
      "raster-data-uri": "Raster image data is outside the vector-only profile.",
      "data-uri-reference": "A url() reference names a data: URI; the profile permits paint references only to local fragments.",
      "unsupported-attribute": "A constrained SVG Tiny PS attribute has a value the profile does not permit."
    }
  },
  "opt": {
    "dkim": "Check DKIM selectors",
    "dkimComprehensive": "Comprehensive DKIM scan (max 5 domains)",
    "dkimComprehensiveTitle": "Uses all 1,677 vetted exact selectors from the catalog; limited to five domains per run",
    "www": "Detect website hosting",
    "wildcard": "Detect wildcard TXT records",
    "dkimSelectors": "Additional DKIM selectors",
    "footer": "DNS via Cloudflare DoH · No data stored · <a href=\"https://github.com/kwestic-tech/dns-email-audit/blob/main/PRIVACY.md\" target=\"_blank\" rel=\"noopener\">Privacy</a>",
    "deepChecks": "Deep protocol checks (MX health, TLSA)",
    "deepChecksTitle": "Resolves every MX host and looks for TLSA records; adds roughly 7 DNS queries per domain",
    "deepChecksAutoDisabled": "Deep protocol checks are off for this run: they add about 7 DNS queries per domain, and this run has {1} domains against a limit of {0}. Tick the box again to run them anyway."
  },
  "help": {
    "title": "How it works:",
    "body": "Runs in your browser via the <a href=\"https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/\" target=\"_blank\" rel=\"noopener\">Cloudflare DNS-over-HTTPS API</a>. No data is sent to Kwestic or stored by this app; DNS query names are sent directly to Cloudflare and are subject to Cloudflare's privacy policy. Checks: NS, MX, SPF, provider-aware or comprehensive DKIM selectors, DMARC, BIMI, MTA-STS, TLS-RPT, CAA, DNSSEC, and SPF lookup depth. No cookies are set; the only thing written to your browser is your language preference, which never leaves your device and never expires on its own — see <a href=\"https://github.com/kwestic-tech/dns-email-audit/blob/main/PRIVACY.md\" target=\"_blank\" rel=\"noopener\">Privacy</a> for details."
  },
  "netbanner": {
    "title": "⚠️ Network access blocked — DNS queries cannot reach the internet from here",
    "body": "This app uses the <code>cloudflare-dns.com</code> DNS-over-HTTPS API, which is blocked when the page is running inside a sandboxed iframe (e.g. an AI assistant's built-in preview panel). To use the auditor, serve the folder over HTTP or host it on any free static site:<br><br>• <strong>Quickest:</strong> Drag the project folder onto <a href=\"https://app.netlify.com/drop\" target=\"_blank\" rel=\"noopener\">app.netlify.com/drop</a> → live URL in ~60 seconds.<br>• <strong>Own domain:</strong> Deploy to <a href=\"https://pages.cloudflare.com\" target=\"_blank\" rel=\"noopener\">Cloudflare Pages</a> or <a href=\"https://pages.github.com\" target=\"_blank\" rel=\"noopener\">GitHub Pages</a> for free.<br>• <strong>Locally:</strong> Run <code>npx serve</code> (or <code>python3 -m http.server</code>) inside the project folder."
  },
  "progress": {
    "heading": "Querying DNS records…",
    "querying": "Querying {0}…",
    "error": "Error on {0}: {1}",
    "cancelled": "Cancelled by user",
    "cancelledDomain": "Cancelled {0}"
  },
  "search": {
    "placeholder": "🔎 Filter domains…"
  },
  "th": {
    "domain": "Domain",
    "grade": "Grade",
    "dns": "DNS Provider",
    "email": "Email Provider",
    "spf": "SPF",
    "dkim": "DKIM",
    "dmarc": "DMARC",
    "advanced": "Advanced",
    "hosting": "Hosting",
    "delta": "Change"
  },
  "filter": {
    "all": "All domains",
    "warn": "⚠️ Has warnings",
    "crit": "🔴 Has issues",
    "noEmail": "No email",
    "noDmarc": "Missing DMARC",
    "noDkim": "Missing DKIM",
    "noSpf": "Missing SPF",
    "hasBimi": "Has BIMI",
    "noCaa": "Missing CAA",
    "noDnssec": "No DNSSEC",
    "improved": "Improved",
    "regressed": "Regressed",
    "changed": "Changed",
    "added": "New domains",
    "removed": "Removed domains"
  },
  "empty": {
    "text": "No domains match your filter."
  },
  "footer": {
    "text": "DNS-over-HTTPS via <a href=\"https://cloudflare-dns.com\" target=\"_blank\" rel=\"noopener\">Cloudflare</a> &bull; No data sent to Kwestic or stored by this app &bull; Query names are sent to Cloudflare &bull; Free to use &amp; self-host &bull; <a href=\"https://github.com/kwestic-tech/dns-email-audit/blob/main/PRIVACY.md\" target=\"_blank\" rel=\"noopener\">Privacy</a> &bull; <a href=\"https://github.com/kwestic-tech/dns-email-audit/blob/main/SECURITY.md\" target=\"_blank\" rel=\"noopener\">Security</a>"
  },
  "labels": {
    "issues": "Issues",
    "suggestions": "💡 Recommendations",
    "advanced": "Advanced Security",
    "nameservers": "Nameservers",
    "mx": "MX Records",
    "spf": "SPF Record",
    "spfLookups": "DNS Lookups",
    "dmarc": "DMARC Record",
    "dkim": "DKIM Selectors",
    "verifications": "Verifications (TXT)",
    "wildcardApexTitle": "ℹ Wildcard TXT record",
    "wildcardApexText": "A wildcard TXT record answers queries for undefined subdomains one label deep. It does not reach DKIM selector lookups on this domain, and every other check here matches a version prefix, so nothing is affected. Some domains publish this deliberately so mail from invented subdomains meets a real SPF policy.",
    "wildcardDkimTitle": "⚠ Wildcard TXT reaches DKIM",
    "wildcardDkimText": "A wildcard TXT record answers queries under _domainkey, so a DKIM selector that does not exist returns the wildcard value instead of nothing. Selectors you publish still resolve, but the absence of a selector cannot be confirmed, so DKIM coverage is reported as unknown rather than scored.",
    "status": "Status",
    "none": "None",
    "na": "N/A",
    "dash": "—",
    "caa": "CAA Policy",
    "tlsa": "TLSA (DANE)",
    "dnssec": "DNSSEC Chain"
  },
  "render": {
    "showMore": "Show {0} more characters",
    "showLess": "Show less",
    "moreRecords": {
      "one": "{0} more record not shown",
      "other": "{0} more records not shown"
    },
    "hygieneTitle": "Record hygiene",
    "hygiene": {
      "bidiOverride": "Bidirectional control characters, which can visually reverse a hostname",
      "zeroWidth": "Invisible or zero-width characters, which do not render",
      "controlChar": "Control characters",
      "loneSurrogate": "Invalid UTF-8, shown as U+FFFD",
      "punycode": "Punycode (xn--) name, shown exactly as published",
      "formulaLeading": "Begins with a character a spreadsheet runs as a formula; neutralized in the CSV export"
    },
    "rowFailed": "This result could not be displayed. The other results are unaffected."
  },
  "showme": {
    "open": "Show me ▾",
    "close": "Show me ▴",
    "whatItIs": "What it is",
    "whatItNeeds": "What it needs to be"
  },
  "stat": {
    "domains": "Domains",
    "haveEmail": "Have Email",
    "wildcardDkim": "⚠ Wildcard over DKIM"
  },
  "badge": {
    "notRegistered": "Not registered / NXDOMAIN",
    "noEmail": "✗ No Email",
    "noDkim": "✗ None",
    "dkimUnverified": "? No Domain Key Found in tested selectors",
    "dkimUncommon": "⚠ Uncommon ({0})",
    "notChecked": "Not checked",
    "auditError": "Audit indeterminate",
    "cancelled": "Cancelled",
    "renderError": "Display error"
  },
  "provider": {
    "unknown": "Unknown",
    "custom": "Custom",
    "customUnknown": "Custom/Unknown",
    "selfHosted": "Self-hosted",
    "none": "None",
    "nullMx": "Null MX (mail disabled)",
    "implicitMx": "Implicit MX (no MX record)",
    "noWebPresence": "No web presence",
    "cnameLoop": "⚠ CNAME Loop",
    "cloudflareProxied": "Cloudflare (proxied)",
    "porkbunForwarding": "Porkbun Forwarding",
    "dnsError": "⚠ Lookup failed"
  },
  "spf": {
    "missing": "✗ Missing",
    "issues": "⚠ Issues",
    "hardfail": "✓ -all",
    "softfail": "~ ~all",
    "present": "✓ Present",
    "meterOver": "{0}/10 🔴 OVER LIMIT",
    "meterNear": "{0}/10 ⚠ Near limit",
    "meterOk": "{0}/10 ✓",
    "meterSuffix": "DNS lookups",
    "permerror": "🔴 Permerror",
    "conflictingRecords": "{0} conflicting records — none of them applies:"
  },
  "dmarc": {
    "missing": "✗ Missing",
    "unverified": "⚠ Not verified",
    "reject": "✓ reject",
    "quarantine": "✓ quarantine",
    "none": "⚠ none (monitor)",
    "set": "✓ Set",
    "invalid": "⚠ Invalid p=",
    "pctSuffix": "({0}%)",
    "permerror": "🔴 Multiple records",
    "inheritedFrom": "Inherited from {0}",
    "testMode": "⚠ {0} (test mode, not applied)",
    "discoveryFoundAt": "Policy found at {0} after {1} lookups",
    "discoveryNotFound": "No policy found in {0} lookups",
    "discoverySteps": "Tree Walk",
    "showWalk": "Show the Tree Walk",
    "stepSelected": "record",
    "stepApplied": "record applied",
    "stepKind": {
      "success": "no DMARC record",
      "nodata": "no TXT records",
      "nxdomain": "name does not exist",
      "servfail": "SERVFAIL",
      "refused": "refused",
      "timeout": "timed out",
      "error": "lookup failed"
    },
    "terminated": {
      "psd-y": "stopped at a public suffix (psd=y)",
      "psd-n": "stopped at an organizational domain (psd=n)",
      "root": "walked to the top-level domain",
      "error": "stopped early — a lookup failed"
    }
  },
  "dkim": {
    "uncommon": "Uncommon ({0})",
    "noDomainKeyFound": "No Domain Key Found ({0})",
    "txtRecord": "TXT record",
    "cnameTarget": "CNAME target",
    "viaSpf": "via SPF: {0}",
    "noteWildcard": "Wildcard TXT bug may be interfering",
    "noteNotFound": "No active DKIM key found among {0} tested selectors.",
    "noteNotFoundWithErrors": "No active DKIM key found among {0} completed selector checks; {1} DNS queries failed.",
    "keyLabel": "Key",
    "keyRsaBits": "RSA {0}-bit",
    "keyRevoked": "revoked",
    "keyUnreadable": "does not decode",
    "keyUnknownType": "unrecognized key type",
    "keyStructureInvalid": "structure rejected",
    "keyTesting": "testing mode"
  },
  "adv": {
    "configured": "✓ Configured",
    "unverified": "TXT valid; policy unverified",
    "notConfigured": "Not configured",
    "tip": {
      "bimiOn": "Record: {0}",
      "bimiOff": "Not configured — display your logo in Gmail & Apple Mail",
      "mtaStsOn": "Configured — TLS forced on inbound delivery",
      "mtaStsUnverified": "The TXT record is valid, but the HTTPS policy file is not verified by this browser-only audit",
      "mtaStsOff": "Not configured — publish _mta-sts TXT to force TLS on inbound mail",
      "tlsRptOn": "Configured — TLS failure reports enabled",
      "tlsRptOff": "Not configured — companion to MTA-STS; publish _smtp._tls TXT",
      "caaOn": "Found at {0}: {1}",
      "caaOff": "Not found — add CAA records to restrict which CAs can issue certs for this domain",
      "dnssecOn": "AD flag set — DNS responses are cryptographically verified",
      "dnssecOff": "Not detected — enable DNSSEC in your DNS provider to prevent cache poisoning",
      "bimiDup": "Multiple records — BIMI ignored, logo will not display",
      "mtaStsDup": "Multiple records — senders treat this domain as having no MTA-STS policy",
      "tlsRptDup": "Multiple records — senders treat this domain as not implementing TLS-RPT"
    },
    "duplicated": "⚠ Multiple records"
  },
  "rows": {
    "count": {
      "one": "{0} domain",
      "other": "{0} domains"
    },
    "showing": "Showing {0} of {1}",
    "critical": {
      "one": "{0} critical",
      "other": "{0} critical"
    },
    "warning": {
      "one": "{0} warning",
      "other": "{0} warnings"
    },
    "suggestion": {
      "one": "{0} suggestion",
      "other": "{0} suggestions"
    }
  },
  "toast": {
    "noDomains": "Paste at least one domain name.",
    "tooMany": "Max 200 domains per run.",
    "tooManyComprehensiveDkim": "Comprehensive DKIM scanning is limited to {0} domains per run.",
    "csvExported": "CSV exported",
    "htmlExported": "HTML report exported",
    "htmlExportFailed": "Could not build the standalone report — serve the app over HTTP and try again.",
    "fileLoaded": "Loaded {0}",
    "fileTooLarge": "File is too large. Maximum upload size is 1 MB.",
    "examplesLoaded": "Examples loaded — click Run Audit",
    "auditDone": {
      "one": "✅ Audit complete — {0} domain analyzed",
      "other": "✅ Audit complete — {0} domains analyzed"
    },
    "auditCancelled": "Audit cancelled",
    "langChanged": "Language changed",
    "langFailed": "Could not load that language — staying on English.",
    "jsonExported": "JSON exported",
    "reportImported": "Report imported — showing what changed",
    "comparisonCleared": "Comparison cleared",
    "importFailed": "That file could not be imported",
    "importDuringRun": "Wait for the audit to finish before importing a report"
  },
  "csv": {
    "unknown": "Unknown",
    "txtOnly": "Valid TXT; HTTPS policy unverified",
    "headers": [
      "Domain",
      "Registered",
      "Grade",
      "Score",
      "DNS Provider",
      "Email Provider",
      "SPF Status",
      "SPF Record",
      "DKIM Found",
      "DKIM Selectors",
      "DMARC Status",
      "DMARC Policy",
      "DMARC Test Mode (t=)",
      "DMARC sp",
      "DMARC np",
      "DMARC pct",
      "DMARC adkim",
      "DMARC aspf",
      "DMARC RUA",
      "DMARC RUF",
      "BIMI",
      "MTA-STS",
      "TLS-RPT",
      "CAA",
      "DNSSEC",
      "SPF Lookups",
      "Issues",
      "Suggestions",
      "Record Hygiene",
      "DMARC Found At",
      "DMARC Labels Up",
      "DMARC Discovery Terminated",
      "DKIM Key Type",
      "DKIM Key Bits",
      "DKIM Revoked Selectors",
      "CAA Issuers",
      "CAA Wildcard Issuers",
      "MX Dangling",
      "MX Host Count",
      "TLSA Present",
      "Finding IDs",
      "Finding Severities",
      "Remediation Step 1",
      "Artifact Finding IDs",
      "Artifact Severities",
      "Artifact Evidence (User Supplied)"
    ],
    "yes": "Yes",
    "no": "No",
    "yesAt": "Yes ({0})"
  },
  "report": {
    "title": "DNS & Email Security Audit Report",
    "generated": "Generated {0} · {1} domains",
    "note": "Static report generated locally by the DNS & Email Security Auditor. Audit results were not sent to Kwestic or stored by the app; DNS query names were sent to Cloudflare's resolver."
  },
  "issue": {
    "wildcard-txt-apex": {
      "msg": "A wildcard TXT record answers undefined subdomains, but does not reach DKIM lookups. No effect on the checks here.",
      "what": "A wildcard TXT record (<code>* IN TXT \"...\"</code>) makes your DNS server answer <em>any</em> subdomain query one label deep, even names you never defined. It was probed at that depth and again under <code>_domainkey</code>, where DKIM selectors live. It did not reach the deeper name, so DKIM discovery on this domain is unaffected. Every other check here matches a version prefix first — <code>v=DMARC1</code>, <code>v=STSv1</code>, <code>v=BIMI1</code>, <code>v=spf1</code> — so a wildcard string is discarded before it can be mistaken for a policy.",
      "fix": "No action required. Some domains publish a wildcard SPF redirect on purpose, so that mail claiming to come from an invented subdomain meets a real policy instead of finding none. Keep it if that is the intent; remove it if it is left over from something else.",
      "fixCode": "; Reproduce both probes yourself — the second is the one that matters:\ndig +short TXT \"*.yourdomain.com\"\ndig +short TXT nonexistent-selector-zzz9._domainkey.yourdomain.com"
    },
    "wildcard-txt-dkim": {
      "msg": "A wildcard TXT record answers DKIM selector lookups, so missing selectors cannot be distinguished from published ones. DKIM is reported as unknown.",
      "what": "A wildcard TXT record here answers queries under <code>_domainkey</code>, where DKIM selectors live. A verifier looking up a selector you never published gets the wildcard value instead of \"no record found\". Selectors you do publish still resolve correctly and still verify, so this does not break signed mail. What it breaks is the negative answer: neither a verifier nor this audit can tell an absent selector from a synthesized one, so DKIM coverage is scored as unknown rather than as present or missing.",
      "fix": "Scope the wildcard so it cannot cover <code>_domainkey</code>, either by narrowing it to the subdomains that need it or by publishing an empty <code>_domainkey</code> node. Under RFC 4592 section 2.2.1 a wildcard does not synthesize below an existing node, though not every nameserver honours that — verify with the dig command below after changing anything.",
      "fixCode": "; Confirm the wildcard reaches DKIM selector depth:\ndig +short TXT nonexistent-selector-zzz9._domainkey.yourdomain.com\n\n; After scoping the wildcard, the same query should return nothing."
    },
    "dns-loop": {
      "msg": "The www CNAME chain contains a cycle — the website name cannot resolve.",
      "what": "The auditor followed the <code>www</code> CNAME chain and encountered a hostname it had already visited. That creates a DNS resolution cycle, so visitors cannot obtain a final A or AAAA address.",
      "fix": "Replace the looping CNAME with a direct A record pointing to your server's IP, or a CNAME pointing to your hosting provider's own domain name.",
      "fixCode": "; Option 1 — point directly to your server IP:\nwww    A      203.0.113.10\n\n; Option 2 — point to your host's domain:\nwww    CNAME  yoursite.netlify.app"
    },
    "no-mx": {
      "msg": "No MX records. Add null MX (0 .) + SPF -all + DMARC p=reject to block spoofing of parked domain.",
      "what": "This domain has no MX records, meaning no mail server is configured to receive email for it. Parked or unused domains with no email setup are prime spoofing targets — attackers send phishing emails \"from\" your domain because there's nothing in DNS to stop them.",
      "fix": "For a domain that will never send or receive email, publish a null MX (which explicitly says \"no mail accepted here\") plus a blocking SPF and DMARC policy.",
      "fixCode": "; Null MX — tells senders this domain accepts no mail:\n@    MX     0 .\n\n; SPF — block all senders:\n@    TXT    \"v=spf1 -all\"\n\n; DMARC — reject any spoofed mail:\n_dmarc    TXT    \"v=DMARC1; p=reject;\""
    },
    "spf-multiple-records": {
      "msg": "{0} SPF records found — SPF fails permanently (permerror) for all mail from this domain, and none of them applies.",
      "what": "RFC 7208 §4.5 allows exactly one <code>v=spf1</code> TXT record per domain. When a receiver finds two, it returns <code>permerror</code> and stops — it does not merge them, and it does not pick the stricter one. The practical effect is worse than having no SPF at all: your record looks correct in the DNS panel, but every message from your domain fails SPF authentication. This usually happens when a second mail service is onboarded and adds its own record instead of editing the existing one.",
      "fix": "Merge the records into one. Take every <code>include:</code>, <code>ip4:</code> and <code>ip6:</code> mechanism from all records, put them in a single <code>v=spf1</code> record, and delete the others. Watch the 10-lookup limit while merging — combining records is a common way to exceed it.",
      "fixCode": "; Before — two records, SPF fails for everything:\n@    TXT    \"v=spf1 include:_spf.google.com -all\"\n@    TXT    \"v=spf1 include:sendgrid.net -all\"\n\n; After — one record with both senders:\n@    TXT    \"v=spf1 include:_spf.google.com include:sendgrid.net -all\""
    },
    "dmarc-multiple-records": {
      "msg": "Multiple DMARC records at {0} — every receiver ignores all of them, and no policy applies.",
      "what": "RFC 9989 §4.10 is explicit: <em>\"If multiple DMARC Policy Records are returned for a single target, they are all discarded.\"</em> Receivers do not pick one — they drop the whole set and keep walking up the DNS tree. Nothing is published above this name either, so the end result is that your domain has no DMARC policy at all, while looking fully configured. You also stop receiving aggregate reports, which removes the one signal that would have told you.",
      "fix": "Delete all but one TXT record at <code>_dmarc</code>. If the duplicates name different report addresses, keep one record and list both addresses in a single <code>rua=</code> tag, separated by a comma.",
      "fixCode": "; Before — two records at _dmarc, both discarded:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n_dmarc    TXT    \"v=DMARC1; p=none; rua=mailto:reports@vendor.example;\"\n\n; After — one record, both report destinations:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com,mailto:reports@vendor.example;\""
    },
    "mta-sts-multiple-records": {
      "msg": "Multiple MTA-STS records found — senders treat your domain as having no MTA-STS policy, so inbound TLS is not enforced.",
      "what": "RFC 8461 §3.1 is explicit: records that don't begin with <code>v=STSv1;</code> are discarded, and if the number remaining is not exactly one, senders <strong>MUST</strong> assume the domain has no MTA-STS policy. Your policy file is never fetched. Inbound mail falls back to opportunistic STARTTLS, which an attacker on the network path can strip — the downgrade attack MTA-STS exists to prevent. The control is inactive while appearing configured.",
      "fix": "Delete the extra TXT record at <code>_mta-sts</code> so exactly one remains. Bump the <code>id=</code> value afterwards so sending servers refresh their cached policy rather than waiting out the old TTL.",
      "fixCode": "; Before — two records, MTA-STS ignored entirely:\n_mta-sts    TXT    \"v=STSv1; id=20240101000000Z;\"\n_mta-sts    TXT    \"v=STSv1; id=20240615000000Z;\"\n\n; After — one record, id bumped to force a refresh:\n_mta-sts    TXT    \"v=STSv1; id=20260817000000Z;\""
    },
    "tls-rpt-multiple-records": {
      "msg": "Multiple TLS-RPT records found — senders treat your domain as not implementing TLS-RPT, so no reports are sent.",
      "what": "RFC 8460 §3 states that if the number of <code>v=TLSRPTv1;</code> records is not exactly one, senders <strong>MUST</strong> assume the domain does not implement TLS-RPT. No reports are generated for any destination, including the address in the first record. This matters most when it is paired with MTA-STS: TLS-RPT is how you find out that a policy is misconfigured or a certificate has expired, so a broken record means those failures happen silently.",
      "fix": "Delete the extra record at <code>_smtp._tls</code>. If you need reports at more than one address, list them in a single <code>rua=</code> tag separated by commas.",
      "fixCode": "; Before — two records, no reports sent at all:\n_smtp._tls    TXT    \"v=TLSRPTv1; rua=mailto:tls@yourdomain.com;\"\n_smtp._tls    TXT    \"v=TLSRPTv1; rua=mailto:soc@vendor.example;\"\n\n; After — one record, both destinations:\n_smtp._tls    TXT    \"v=TLSRPTv1; rua=mailto:tls@yourdomain.com,mailto:soc@vendor.example;\""
    },
    "bimi-multiple-records": {
      "msg": "Multiple BIMI records found — BIMI processing stops, so your logo will not display.",
      "what": "The BIMI specification (Assertion Record Discovery) mirrors DMARC: records without a <code>v=BIMI1</code> tag are discarded, and if the remaining set contains more than one record, discovery terminates and BIMI processing is not performed. Your logo won't appear in Gmail, Apple Mail or Yahoo, and because BIMI failures are silent there's nothing to indicate why — including if you paid for a Verified Mark Certificate.",
      "fix": "Delete the extra TXT record at <code>default._bimi</code> so exactly one remains.",
      "fixCode": "; Before — two records, BIMI never evaluated:\ndefault._bimi    TXT    \"v=BIMI1; l=https://yourdomain.com/logo.svg;\"\ndefault._bimi    TXT    \"v=BIMI1; l=https://cdn.example/old-logo.svg;\"\n\n; After — one record:\ndefault._bimi    TXT    \"v=BIMI1; l=https://yourdomain.com/logo.svg; a=https://yourdomain.com/vmc.pem;\""
    },
    "dkim-multiple-records": {
      "msg": "Multiple DKIM key records on selector(s): {0} — signature verification is undefined and may fail.",
      "what": "RFC 6376 §3.6.2.2 requires that key records be unique for a given selector: \"if there are multiple records in an RRset, the results are undefined.\" Different verifiers resolve this differently — some take the first record, some the last, some fail outright. The result is intermittent DKIM failures that vary by recipient and are painful to diagnose, because the same message passes at one provider and fails at another. This most often happens after a key rotation where the old record was never removed.",
      "fix": "Delete the stale key record so exactly one remains per selector. If you are mid-rotation and genuinely need two keys live, use two different selectors — that is what selectors are for — rather than two records under one name.",
      "fixCode": "; Before — two keys on the same selector, undefined behaviour:\ngoogle._domainkey    TXT    \"v=DKIM1; k=rsa; p=MIIBIjANBg...OLD\"\ngoogle._domainkey    TXT    \"v=DKIM1; k=rsa; p=MIIBIjANBg...NEW\"\n\n; After — one key per selector; rotate via a second selector instead:\ngoogle._domainkey     TXT    \"v=DKIM1; k=rsa; p=MIIBIjANBg...NEW\"\ns2._domainkey         TXT    \"v=DKIM1; k=rsa; p=MIIBIjANBg...NEXT\""
    },
    "spf-missing": {
      "msg": "No SPF record — sender authentication impossible.",
      "what": "SPF (Sender Policy Framework) is a DNS record that lists which mail servers are authorized to send email from your domain. Without it, any server in the world can send email claiming to be from you, and receiving mail servers have no way to verify whether it's legitimate.",
      "fix": "Add a TXT record at your domain root listing your authorized mail senders. Start with ~all (softfail) while testing, then tighten to -all once confirmed.",
      "fixCode": "; For Google Workspace:\n@    TXT    \"v=spf1 include:_spf.google.com -all\"\n\n; For Microsoft 365:\n@    TXT    \"v=spf1 include:spf.protection.outlook.com -all\"\n\n; For a parked/unused domain:\n@    TXT    \"v=spf1 -all\""
    },
    "spf-softfail": {
      "msg": "SPF: ~all softfail — harden to -all.",
      "what": "Your SPF record ends with <code>~all</code> (tilde-all), known as a \"soft fail.\" It signals that mail from unlisted servers is <em>probably</em> unauthorized — but it's just a hint. Most receiving servers will deliver the message anyway, perhaps marking it as spam. It offers only partial protection against spoofing.",
      "fix": "Once you've confirmed your SPF record lists all your legitimate sending sources, harden it from <code>~all</code> to <code>-all</code> (hard fail). This tells receivers to outright reject mail from any server not in your list.",
      "fixCode": "; Change from:\n@    TXT    \"v=spf1 include:_spf.google.com ~all\"\n\n; To:\n@    TXT    \"v=spf1 include:_spf.google.com -all\""
    },
    "spf-all-permit": {
      "msg": "SPF: +all permits everyone — insecure.",
      "what": "Your SPF record ends with <code>+all</code>, which authorizes <em>every server on the internet</em> to send mail as your domain. This completely defeats the purpose of SPF — it is equivalent to having no SPF at all, and is almost certainly a misconfiguration.",
      "fix": "Replace <code>+all</code> with <code>-all</code> (hard fail) to reject unauthorized senders.",
      "fixCode": "; Remove +all, replace with -all:\n@    TXT    \"v=spf1 include:_spf.google.com -all\""
    },
    "spf-neutral": {
      "msg": "SPF: ?all neutral — no protection.",
      "what": "Your SPF record ends with <code>?all</code> (question mark all), which is a \"neutral\" result — SPF takes no position on whether unlisted servers are authorized. Receiving mail servers treat this the same as having no SPF record at all, so it provides zero spoofing protection.",
      "fix": "Replace <code>?all</code> with <code>-all</code> (hard fail) to block unauthorized senders.",
      "fixCode": "; Change from:\n@    TXT    \"v=spf1 include:_spf.google.com ?all\"\n\n; To:\n@    TXT    \"v=spf1 include:_spf.google.com -all\""
    },
    "spf-missing-google": {
      "msg": "SPF: missing Google Workspace include.",
      "what": "Your domain uses Google Workspace for email, but your SPF record doesn't include Google's mail servers (<code>_spf.google.com</code>). Google's sending servers are not authorized in your SPF policy, so legitimate outbound emails from your Google Workspace mailboxes may fail SPF checks and land in recipients' spam folders.",
      "fix": "Add Google's SPF include to your TXT record.",
      "fixCode": "; Add Google's include:\n@    TXT    \"v=spf1 include:_spf.google.com -all\"\n\n; If you also use other senders:\n@    TXT    \"v=spf1 include:_spf.google.com include:sendgrid.net -all\""
    },
    "spf-missing-icloud": {
      "msg": "SPF: missing iCloud include.",
      "what": "Your domain appears to use Apple iCloud Mail (iCloud+ Custom Domain), but your SPF record doesn't authorize Apple's sending servers. Emails sent through iCloud may be rejected or flagged as spam by recipients because your SPF record doesn't vouch for Apple's servers.",
      "fix": "Add Apple's SPF include to your record.",
      "fixCode": "@    TXT    \"v=spf1 include:icloud.com -all\""
    },
    "spf-missing-microsoft": {
      "msg": "SPF: missing Microsoft 365 include.",
      "what": "Your domain uses Microsoft 365 for email, but your SPF record doesn't include Microsoft's sending servers (<code>spf.protection.outlook.com</code>). Outbound mail from your Microsoft 365 mailboxes may fail SPF checks at the recipient's mail server and be treated as spam or rejected.",
      "fix": "Add Microsoft's SPF include to your TXT record.",
      "fixCode": "@    TXT    \"v=spf1 include:spf.protection.outlook.com -all\""
    },
    "dkim-missing": {
      "msg": "DKIM not configured. {0}",
      "what": "DKIM (DomainKeys Identified Mail) attaches a cryptographic signature to every outgoing email, allowing recipients to verify that the message genuinely came from your domain and wasn't altered in transit. Without it, your emails are more likely to be flagged as spam, and your domain is more vulnerable to impersonation. DKIM is also required before you can enforce DMARC.",
      "fix": "DKIM setup happens inside your email provider's admin console — they generate a public/private key pair and give you a TXT record to publish in your DNS. You don't create the key yourself.",
      "fixCode": "; Google Workspace: Admin → Apps → Google Workspace → Gmail\n;   → Authenticate email → Generate Key → copy the TXT record\n;\n; Microsoft 365: Admin → Settings → Domains → select domain\n;   → DNS records → enable DKIM\n;\n; The TXT record will look something like:\ngoogle._domainkey    TXT    \"v=DKIM1; k=rsa; p=MIIBIj...\""
    },
    "dkim-unverified": {
      "msg": "No tested DKIM selector was found. {0} Scored as if DKIM is not configured. If you know your DKIM selector, add it to \"Additional DKIM selectors\" and re-run the audit to get credit for it."
    },
    "dkim-not-checked": {
      "msg": "DKIM was not checked this run. Scored as if DKIM is not configured. Enable \"Check DKIM selectors\" and re-run to be scored on DKIM."
    },
    "implicit-mx": {
      "msg": "No MX record is published. SMTP may fall back to this domain's A/AAAA address as an implicit MX, which is fragile and often unintended."
    },
    "dmarc-missing": {
      "msg": "No DMARC record — domain can be freely spoofed without policy enforcement.",
      "what": "DMARC (Domain-based Message Authentication, Reporting &amp; Conformance) is a policy that tells receiving mail servers what to do when an email fails SPF or DKIM — quarantine it, reject it, or let it through. Without a DMARC record, even a perfect SPF + DKIM setup doesn't prevent someone from spoofing your domain in the visible \"From:\" address.",
      "fix": "Start with a monitoring-only policy (<code>p=none</code>) to collect reports without blocking mail, then tighten the policy after reviewing the data.",
      "fixCode": "; Step 1 — monitoring only (safe starting point):\n_dmarc    TXT    \"v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com;\"\n\n; Step 2 — quarantine (mark failing mail as spam):\n_dmarc    TXT    \"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com;\"\n\n; Step 3 — reject (block failing mail entirely):\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-none": {
      "msg": "DMARC p=none is monitoring only. Upgrade to p=quarantine then p=reject.",
      "what": "Your DMARC record is set to <code>p=none</code>, which is monitoring-only mode. It instructs receiving servers to collect data and send you reports, but to take <em>no action</em> on failing emails — spoofed messages still get delivered. <code>p=none</code> is a diagnostic tool meant as a temporary first step, not a final configuration.",
      "fix": "Review your DMARC aggregate reports (rua=) to confirm all your legitimate mail sources are passing. Once confident, upgrade the policy to quarantine, then reject.",
      "fixCode": "; Step 1 — quarantine (sends failing mail to spam):\n_dmarc    TXT    \"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com;\"\n\n; Step 2 — reject (blocks failing mail entirely):\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-quarantine": {
      "msg": "DMARC p=quarantine sends spoofed mail to spam but still delivers it. p=reject is the end state.",
      "what": "Your DMARC policy is <code>p=quarantine</code>, which is genuine enforcement — mail that fails authentication gets routed to the spam folder rather than the inbox. But it is still <em>delivered</em>. A convincing phishing message impersonating your domain remains one click away in a folder people do check, and some receivers apply quarantine inconsistently. <code>p=reject</code> instructs receiving servers to refuse the message outright, so it never reaches the recipient at all.",
      "fix": "Review your DMARC aggregate reports (<code>rua=</code>) over a few weeks and confirm every legitimate sending source is passing SPF or DKIM alignment. Once no genuine mail is failing, change the policy to <code>p=reject</code>. If you want a cautious step first, publish <code>p=reject; t=y</code> — RFC 9989 test mode keeps reports flowing while receivers hold off on enforcing — then remove <code>t=y</code>. Do not ramp with <code>pct=</code>: RFC 9989 removed it, so it now behaves differently from one receiver to the next.",
      "fixCode": "; Current policy — failing mail goes to spam:\n_dmarc    TXT    \"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com;\"\n\n; Optional cautious step — publish reject, receivers do not apply it yet:\n_dmarc    TXT    \"v=DMARC1; p=reject; t=y; rua=mailto:dmarc@yourdomain.com;\"\n\n; End state — reject all failing mail:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-no-rua": {
      "msg": "DMARC has no rua= address — you won't receive aggregate reports.",
      "what": "Your DMARC record doesn't include an <code>rua=</code> tag. This is the email address where ISPs and mail providers send aggregate reports showing who is sending mail from your domain and whether it's passing authentication. Without it, you have no visibility into your email traffic — you won't know if something breaks or if someone is spoofing your domain.",
      "fix": "Add an <code>rua=</code> address to your DMARC record. It can be any mailbox you monitor.",
      "fixCode": "; Add rua= to your existing DMARC record:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com;\""
    },
    "dmarc-weak-sp": {
      "msg": "DMARC subdomain policy is sp={0} while the domain itself is p={1} — subdomains are less protected.",
      "what": "Your record sets <code>sp={0}</code>, which explicitly overrides the policy for subdomains. Without that tag, subdomains would inherit your stricter <code>p={1}</code> policy automatically. As written, an attacker can spoof <code>anything.yourdomain.com</code> and receive the weaker treatment — and recipients rarely scrutinise the subdomain part of a sender address. Subdomain spoofing is a common phishing technique precisely because organisational policies often stop at the apex.",
      "fix": "Unless you have a specific reason to treat subdomains differently — for example a marketing platform sending from a subdomain that isn't fully authenticated yet — remove the <code>sp=</code> tag so subdomains inherit your main policy, or raise it to match.",
      "fixCode": "; Simplest — delete sp= so subdomains inherit p:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n\n; Or set it explicitly to match:\n_dmarc    TXT    \"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-weak-np": {
      "msg": "DMARC non-existent-subdomain policy is np={0} while the domain is p={1} — unused subdomains are less protected.",
      "what": "The <code>np=</code> tag (RFC 9091) sets the policy for subdomains that don't exist in DNS at all. Yours is <code>np={0}</code>, weaker than your <code>p={1}</code>. Non-existent subdomains are the attacker's favourite target — there's no legitimate mail to disrupt, so nobody notices, and addresses like <code>billing.yourdomain.com</code> look entirely plausible to a recipient.",
      "fix": "Set <code>np=reject</code>. Nothing legitimate sends from a subdomain that doesn't exist, so this is one of the few DMARC changes with essentially no deliverability risk.",
      "fixCode": "; Reject mail from subdomains that don't exist:\n_dmarc    TXT    \"v=DMARC1; p=reject; np=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-partial-pct": {
      "msg": "DMARC pct={0} — receivers still on RFC 7489 apply your policy to only {0}% of failing mail, delivering the other {1}% normally.",
      "what": "The <code>pct=</code> tag was removed in RFC 9989, but receivers that have not yet migrated continue to honour it. At <code>pct={0}</code> those receivers apply your policy to {0}% of messages that fail authentication and fall back to the next weaker action for the remaining {1}%, so a spoofed message has roughly a {1} in 100 chance of landing untouched. Receivers on the new specification ignore the tag and enforce in full — meaning your enforcement is currently inconsistent across the internet, which is a worse position than either setting alone.",
      "fix": "Check your aggregate reports to confirm no legitimate senders are failing, then remove <code>pct=</code> entirely. Use <code>t=y</code> if you still need a staged rollout.",
      "fixCode": "; Remove pct= — defaults to 100:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n\n; Or state it explicitly:\n_dmarc    TXT    \"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-bad-pct": {
      "msg": "DMARC pct= value is not a valid number between 0 and 100 — legacy receivers may reject the whole record.",
      "what": "The <code>pct=</code> tag was removed in RFC 9989, so receivers on the current specification ignore it whatever it says. Receivers still implementing RFC 7489 require an integer from 0 to 100, and some treat a malformed value as grounds for discarding the entire DMARC record — leaving your domain unprotected at exactly those receivers. The safe move is the same either way.",
      "fix": "Remove the tag. It no longer has a defined meaning, and removing it resolves both behaviours at once.",
      "fixCode": "; Remove the malformed pct= entirely:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-invalid-policy": {
      "msg": "DMARC p= value is not one of none, quarantine or reject — the record is malformed and offers no protection.",
      "what": "The <code>p=</code> tag must be exactly <code>none</code>, <code>quarantine</code> or <code>reject</code>. Yours is something else — a typo, a stray character, or an unsupported value. Receiving servers cannot act on a policy they don't recognise, so in practice your domain is treated as having no DMARC record at all, and can be freely spoofed.",
      "fix": "Correct the <code>p=</code> value. If you're unsure where to start, publish <code>p=none</code> with an <code>rua=</code> address, review the reports for a few weeks, then tighten.",
      "fixCode": "; Monitoring only, safe starting point:\n_dmarc    TXT    \"v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com;\"\n\n; Full enforcement:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "porkbun-forward": {
      "msg": "Porkbun forwarding doesn't support DKIM — forwarded mail often fails at destination.",
      "what": "Porkbun's email forwarding relays incoming messages to another address but doesn't sign them with DKIM. When the forwarded message arrives at the destination, it fails DKIM (the signature is absent or broken by forwarding) and may also fail SPF (the message was re-sent from Porkbun's servers, not yours). This causes high spam delivery rates and there's no DNS fix for it — it's a fundamental limitation of the forwarding architecture.",
      "fix": "For reliable email, switch to a proper hosted email service that supports DKIM signing. Several options are available at low cost.",
      "fixCode": "; Good alternatives to Porkbun forwarding:\n;\n; Google Workspace — full DKIM support\n; Microsoft 365 — full DKIM support\n; Fastmail — full DKIM support\n; Proton Mail for Business — full DKIM support\n;\n; For simple catch-all forwarding with DKIM:\n; ImprovMX (free tier) or Forward Email (free, open-source)"
    },
    "spf-over-limit": {
      "msg": "SPF exceeds 10 DNS lookup limit (found ~{0}) — legitimate mail will fail SPF.",
      "what": "SPF allows a maximum of 10 DNS lookups during evaluation — each <code>include:</code>, <code>mx</code>, <code>a</code>, <code>exists</code>, and <code>redirect</code> mechanism counts toward this limit. Your record exceeds it. When a receiving server hits lookup #11, the SPF spec requires it to return \"permerror,\" which receivers treat as an SPF failure. Legitimate mail from your domain fails SPF.",
      "fix": "Reduce your lookup count by removing unused senders or by \"flattening\" your SPF record — replacing <code>include:</code> entries with their resolved IP addresses, eliminating the sub-lookups.",
      "fixCode": "; Before (too many include: lookups):\n\"v=spf1 include:_spf.google.com include:sendgrid.net include:mailchimp.com include:amazonses.com -all\"\n\n; After flattening (use a tool to get your actual IPs):\n; Tools: MXToolbox SPF Analyzer, AutoSPF, dmarcian\n\"v=spf1 ip4:209.85.220.0/22 ip4:167.89.0.0/17 ip4:199.255.192.0/22 -all\""
    },
    "spf-near-limit": {
      "msg": "SPF approaching 10-lookup limit (~{0} counted) — adding more senders may break it.",
      "what": "Your SPF record is approaching the 10-lookup limit. Adding any more email sending services, or if an existing provider changes their SPF infrastructure, could push you over — causing legitimate emails to fail SPF authentication without any warning.",
      "fix": "Audit your SPF record and remove any services you no longer use. If you genuinely need all current senders, consider flattening to reduce lookup depth.",
      "fixCode": "; Audit: which of these are you still using?\n\"v=spf1 include:_spf.google.com include:sendgrid.net include:... -all\"\n;\n; Remove unused includes, or flatten with a tool like:\n; AutoSPF (autospf.com), dmarcian, or MXToolbox"
    },
    "spf-cycle": {
      "msg": "SPF include/redirect cycle detected through {0}; SPF evaluation can return permerror."
    },
    "spf-indeterminate": {
      "msg": "The SPF lookup total is indeterminate because the record uses macros, excessive depth, or an invalid included policy."
    },
    "spf-large-subnet": {
      "msg": "SPF authorizes large IP ranges: {0} — confirm you control all of that space.",
      "what": "Every address inside an <code>ip4:</code> or <code>ip6:</code> block is allowed to send mail as your domain, and these blocks are large: an IPv4 <code>/24</code> is 256 addresses, a <code>/16</code> is 65,536, and an IPv6 <code>/48</code> or shorter is a site-to-ISP scale allocation. That is fine when the range is yours — plenty of large organizations publish their own netblocks this way. It stops being fine when the range belongs to a shared host or a provider whose other customers you do not control, because every one of those neighbours can then pass SPF as you. This audit reports the size only; it cannot tell you who owns the block, so the judgement is yours.",
      "fix": "Check who actually owns each range listed. If it is your own allocation, no change is needed. If it belongs to a shared platform, replace the broad block with the specific sending addresses, or with the provider's own <code>include:</code> — that way the provider maintains the list and you are not authorizing their entire estate.",
      "fixCode": "; Broad — every host in 256 addresses can send as you:\n\"v=spf1 ip4:203.0.113.0/24 -all\"\n\n; Narrow — only the hosts that actually send:\n\"v=spf1 ip4:203.0.113.10 ip4:203.0.113.11 -all\"\n\n; Or let the provider maintain the list:\n\"v=spf1 include:_spf.provider.example -all\""
    },
    "spf-medium-subnet": {
      "msg": "SPF authorizes mid-sized IP ranges: {0} — worth confirming each range is yours."
    },
    "spf-redundant-mechanism": {
      "msg": "The {0} mechanism resolves only to addresses {1} already authorizes — removing it takes your SPF lookup count from {2} to {3}.",
      "what": "SPF allows a maximum of 10 DNS lookups, and <code>a</code> and <code>mx</code> mechanisms each spend one. Every address this mechanism resolves to — across both IPv4 and IPv6 — is already inside an <code>ip4:</code> or <code>ip6:</code> block written into the same record, so the lookup buys no authorization you do not already have. Removing it changes nothing about which servers can send as you, and gives you back a lookup toward the ceiling.",
      "fix": "Delete the mechanism from your SPF record. Re-check afterwards if the hosts behind it get new addresses later, since the block would then need to cover those too.",
      "fixCode": "; Before — mx spends a lookup to authorize addresses the block already covers:\n\"v=spf1 mx ip4:203.0.113.0/28 include:_spf.provider.example -all\"\n\n; After — same senders authorized, one lookup cheaper:\n\"v=spf1 ip4:203.0.113.0/28 include:_spf.provider.example -all\""
    },
    "spf-redundant-mechanism-nocount": {
      "msg": "The {0} mechanism resolves only to addresses {1} already authorizes — removing it frees one of the 10 SPF DNS lookups."
    },
    "spf-partial-coverage": {
      "msg": "{0} of {1} addresses behind the {2} mechanism are already covered by your ip4:/ip6: blocks — keep the mechanism, it still authorizes the rest."
    },
    "dnssec-bogus": {
      "msg": "DNSSEC validation appears bogus: validation failed although the answer is available when checking is disabled."
    },
    "dnssec-indeterminate": {
      "msg": "DNSSEC status could not be determined because the validating query failed. Scored as unsigned. Re-run the audit — this is usually a transient resolver issue. If it keeps happening on a domain you have confirmed is signed at your registrar or DNS provider, open a GitHub issue with the domain, your registrar/DNS provider, and a screenshot showing DNSSEC enabled."
    },
    "dnssec-unanchored": {
      "msg": "Your zone is signed but the parent publishes no DS record — DNSSEC protects nothing until you publish it at your registrar.",
      "what": "DNSSEC works as a chain, and signing your zone is only half of it. Your registrar has to publish a DS record in the parent zone that points at your signing key. Without it, resolvers have no reason to trust your signatures and treat the zone as unsigned — so every record here can still be forged in transit, exactly as if you had never signed anything.",
      "fix": "Ask your DNS provider for the DS record, then publish it with your domain registrar. Most registrars label this <em>DNSSEC</em> in the domain settings. Wait for the old TTLs to expire and re-run this audit — the chain is live once the parent answers with the DS."
    },
    "dnssec-mismatch": {
      "msg": "The DS record at the parent matches no key your zone publishes — validating resolvers will refuse this domain.",
      "what": "The DS record at your parent zone is a fingerprint of one of your DNSKEY records. When they disagree, a validating resolver cannot build the chain and returns a failure instead of your records. That is worse than being unsigned: mail and web traffic break for everyone whose resolver validates, and it looks like an outage rather than a configuration error.",
      "fix": "This is almost always a key rollover that stopped halfway. Either publish the DNSKEY the current DS points at, or update the DS at your registrar to match the key you are signing with now. Do not simply stop signing while the DS is still published — that leaves the same failure in place."
    },
    "dnssec-ds-orphan": {
      "msg": "DS record {0} at the parent matches no key in your zone. Your chain still validates through another DS, so nothing is broken.",
      "what": "A parent zone can carry several DS records, and the standard explicitly allows one of them to point at a key that is no longer published. Another DS matches a live key here, so validation succeeds and this costs you nothing today. It is usually left over from a key rollover that nobody tidied up afterwards.",
      "fix": "Remove the stale DS record at your registrar once you are sure the key it names is gone for good. There is no urgency — leaving it in place is harmless, but it makes the next rollover harder to reason about."
    },
    "dnssec-deprecated-algorithm": {
      "msg": "Your zone signs with a deprecated algorithm: {0}.",
      "what": "Signing algorithms are retired as they age. A deprecated one still validates today, because resolvers are required to keep verifying delegations that already exist, but it may no longer be used for new signing and support will eventually be withdrawn. RSASHA1 and the DSA family are the usual cases.",
      "fix": "Ask your DNS provider to roll the zone onto a current algorithm. <code>ECDSAP256SHA256</code> is the common choice and produces far smaller records than RSA. The rollover changes your DS record, so the new one has to reach your registrar as part of the same operation."
    },
    "dnssec-deprecated-digest": {
      "msg": "Your DS record uses a deprecated digest type: {0}.",
      "what": "The DS record identifies your key by a hash of it. SHA-1 is still accepted for validating delegations that already exist, but it must not be used for new ones, and GOST R 34.11-94 is deprecated outright. This does not break anything today.",
      "fix": "Ask your registrar to replace the DS record with a SHA-256 one. Your DNS provider can generate it from the key you already have, so no key rollover is needed — only the DS at the parent changes."
    },
    "dnssec-revoke-flag": {
      "msg": "DNSKEY {0} is published with the REVOKE flag set. Confirming a revocation needs a signature check this audit does not perform."
    },
    "dnssec-key-algorithm-ineligible": {
      "msg": "DS record {0} points at a key whose algorithm may not be used to sign a zone, so the delegation cannot anchor."
    },
    "dnssec-key-not-zone-key": {
      "msg": "DS record {0} points at a key that is not marked as a zone key, so it may not verify records and the delegation cannot anchor."
    },
    "dnssec-key-malformed": {
      "msg": "DS record {0} points at a key whose material is not valid for its algorithm, so no resolver can use it."
    },
    "mta-sts-invalid": {
      "msg": "The MTA-STS TXT record is malformed or missing its required id= tag."
    },
    "mta-sts-policy-unverified": {
      "msg": "The MTA-STS TXT record is valid, but the DNS-only audit did not fetch its HTTPS policy. Supply the policy in the local artifact panel to validate it without a network request."
    },
    "tls-rpt-invalid": {
      "msg": "The TLS-RPT record is malformed or has no valid rua= destination."
    },
    "bimi-invalid": {
      "msg": "The BIMI record is malformed or does not contain a valid HTTPS logo URL."
    },
    "dmarc-version-missing": {
      "msg": "The DMARC record at {0} does not start with v=DMARC1 — receivers must ignore it entirely.",
      "what": "RFC 9989 §4.7 requires the <code>v=</code> tag to be the first tag in the record. A record without it is not a DMARC record at all, whatever else it contains. Receiving servers discard it and treat your domain as having no DMARC policy, so the record gives you the appearance of protection with none of the substance.",
      "fix": "Rewrite the record so it begins with <code>v=DMARC1;</code> followed by your policy.",
      "fixCode": "; Wrong — no version tag:\n_dmarc    TXT    \"p=reject; rua=mailto:dmarc@yourdomain.com;\"\n\n; Right:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-version-not-first": {
      "msg": "v=DMARC1 is present at {0} but is not the first tag — receivers must ignore the whole record.",
      "what": "RFC 9989 §4.7 says <code>v=</code> MUST be the first tag in the list, not merely present somewhere. Tag order is otherwise free, which makes this easy to get wrong when a record is edited by hand or assembled by a script. A receiver that follows the spec stops parsing and treats the domain as unprotected.",
      "fix": "Move <code>v=DMARC1;</code> to the front of the record. Nothing else needs to change.",
      "fixCode": "; Wrong — v= is not first:\n_dmarc    TXT    \"p=reject; v=DMARC1; rua=mailto:dmarc@yourdomain.com;\"\n\n; Right:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-version-bad-value": {
      "msg": "The DMARC version value at {0} is not exactly \"DMARC1\" — the value is case sensitive and the record is ignored.",
      "what": "Almost every value in a DMARC record is case-insensitive, but RFC 9989 §4.7 makes <code>v=</code> the exception: the only accepted spelling is <code>DMARC1</code>, in capitals. <code>v=dmarc1</code> or <code>v=DMARC2</code> causes the entire record to be ignored. This is a common copy-paste casualty because DNS panels often lower-case values on entry.",
      "fix": "Set the value to exactly <code>DMARC1</code> and re-check what your DNS panel actually stored afterwards.",
      "fixCode": "; Wrong — lower case:\n_dmarc    TXT    \"v=dmarc1; p=reject;\"\n\n; Right:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-duplicate-tags": {
      "msg": "DMARC record repeats the same tag ({0}) — the record is malformed and may be ignored.",
      "what": "A DMARC record may contain each tag at most once. Yours repeats {0}. The specification gives no rule for choosing between the values, so behaviour is receiver-dependent: some take the first, some the last, some discard the record outright. Whatever protection you think you have configured, you cannot rely on it.",
      "fix": "Delete the duplicate tags so each appears exactly once. If two values were intended for <code>rua=</code>, combine them into one comma-separated list instead.",
      "fixCode": "; Wrong — p= twice:\n_dmarc    TXT    \"v=DMARC1; p=none; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n\n; Right:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-test-mode": {
      "msg": "DMARC is in test mode (t=y) — your p={0} policy is published but not applied.",
      "what": "The <code>t=</code> tag is new in RFC 9989 and replaces <code>pct=</code> as the supported way to roll out DMARC gradually. <code>t=y</code> tells receivers the domain owner is still evaluating and that the policy should <em>not</em> be enforced. Aggregate reports keep arriving, which is the point of the mode — but for spoofing purposes <code>p=reject; t=y</code> protects you exactly as much as <code>p=none</code>. Dashboards that read only <code>p=</code> will show this domain as fully enforced.",
      "fix": "Once your aggregate reports show no legitimate senders failing, remove <code>t=y</code> (or set <code>t=n</code>) to turn the published policy into a real one.",
      "fixCode": "; Testing — policy published, not applied:\n_dmarc    TXT    \"v=DMARC1; p=reject; t=y; rua=mailto:dmarc@yourdomain.com;\"\n\n; Live — remove t= entirely (defaults to n):\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-bad-t": {
      "msg": "DMARC t= value is not y or n — receivers may ignore the tag or the record.",
      "what": "RFC 9989 defines exactly two values for the test-mode tag: <code>y</code> and <code>n</code>, with <code>n</code> as the default. Anything else is a syntax error. Depending on the receiver you may get the default behaviour, or the record may be rejected as malformed — you cannot tell which from the outside.",
      "fix": "Set <code>t=y</code> while testing, <code>t=n</code> when live, or remove the tag entirely since <code>n</code> is the default.",
      "fixCode": "; Remove the malformed tag — n is the default:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-rua-invalid": {
      "msg": "DMARC rua= destination is unusable ({0}) — aggregate reports cannot be delivered.",
      "what": "Report destinations must be DMARC URIs: <code>mailto:</code> addresses, optionally followed by a size limit such as <code>!10m</code>. A bare address with no <code>mailto:</code> prefix, a malformed address, or a scheme receivers do not support all produce the same outcome — no reports. Because DMARC fails silently, an unusable <code>rua=</code> looks identical to a domain nobody is spoofing.",
      "fix": "Correct the destination to a full <code>mailto:</code> URI. Separate multiple destinations with commas.",
      "fixCode": "; Wrong — missing the mailto: scheme:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=dmarc@yourdomain.com;\"\n\n; Right — one or more mailto: URIs:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com,mailto:reports@vendor.example!10m;\""
    },
    "dmarc-ruf-invalid": {
      "msg": "DMARC ruf= destination is unusable ({0}) — failure reports cannot be delivered.",
      "what": "The <code>ruf=</code> tag takes the same DMARC URI format as <code>rua=</code>: <code>mailto:</code> addresses with an optional <code>!</code> size limit. Yours does not parse, so no failure reports will arrive. Note that failure reports (RFC 9991) contain message content and are sent by relatively few receivers — losing them is less severe than losing aggregate reports, but a broken tag is still worth fixing or removing.",
      "fix": "Correct the destination to a full <code>mailto:</code> URI, or remove <code>ruf=</code> if you do not intend to collect failure reports.",
      "fixCode": "; Right — a full mailto: URI:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; ruf=mailto:forensics@yourdomain.com;\""
    },
    "dmarc-fo-without-ruf": {
      "msg": "DMARC fo= is set but there is no ruf= — receivers must ignore it.",
      "what": "The <code>fo=</code> tag controls <em>when</em> failure reports are generated, so RFC 9989 states its content must be ignored when no <code>ruf=</code> tag is present. The tag is doing nothing. This usually means a <code>ruf=</code> was removed at some point and <code>fo=</code> was left behind, which can give the impression that failure reporting is still configured.",
      "fix": "Add a <code>ruf=</code> destination if you want failure reports, or remove <code>fo=</code> to leave the record saying what it means.",
      "fixCode": "; Either add a destination:\n_dmarc    TXT    \"v=DMARC1; p=reject; fo=1; rua=mailto:dmarc@yourdomain.com; ruf=mailto:forensics@yourdomain.com;\"\n\n; Or drop the inert tag:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-bad-fo": {
      "msg": "DMARC fo= contains a value that is not 0, 1, d or s.",
      "what": "The failure-reporting options tag accepts a colon-separated subset of four values: <code>0</code> (report when everything fails), <code>1</code> (report when anything fails), <code>d</code> (DKIM failed) and <code>s</code> (SPF failed). Anything else is a syntax error, and <code>fo=1</code> is what most operators actually want — the default <code>fo=0</code> only reports when SPF and DKIM both fail.",
      "fix": "Use a valid combination, most commonly <code>fo=1</code>.",
      "fixCode": "; Report whenever any mechanism fails:\n_dmarc    TXT    \"v=DMARC1; p=reject; fo=1; rua=mailto:dmarc@yourdomain.com; ruf=mailto:forensics@yourdomain.com;\"\n\n; Multiple options are colon-separated:\n_dmarc    TXT    \"v=DMARC1; p=reject; fo=d:s; rua=mailto:dmarc@yourdomain.com; ruf=mailto:forensics@yourdomain.com;\""
    },
    "dmarc-external-reporting": {
      "msg": "DMARC reports go to an outside domain ({0}) — that domain must authorize them or the reports are discarded.",
      "what": "When a report destination is outside your organizational domain — a DMARC vendor, a consultant, a sister company — RFC 9990 §4 requires the receiving domain to publish a record granting permission. Without it, conformant receivers silently discard the reports bound for that destination. Authorization is evaluated per destination, so an unauthorized vendor does not break your DMARC record or stop reports reaching your other addresses; that one destination just goes quiet. This audit did not verify the record — enable the advanced checks to have it looked up automatically.",
      "fix": "Ask the destination domain to publish an authorization record for your domain, in the form <code>&lt;your-domain&gt;._report._dmarc.&lt;their-domain&gt;</code>.",
      "fixCode": "; Your record sends reports to a vendor:\n_dmarc.yourdomain.com    TXT    \"v=DMARC1; p=reject; rua=mailto:you@vendor.example;\"\n\n; The VENDOR must publish this in their zone:\nyourdomain.com._report._dmarc.vendor.example    TXT    \"v=DMARC1\""
    },
    "dmarc-bad-psd": {
      "msg": "DMARC psd= value is not y, n or u.",
      "what": "The <code>psd=</code> tag is new in RFC 9989 and tells the DNS Tree Walk whether this domain is a Public Suffix Domain. It accepts exactly three values: <code>y</code>, <code>n</code> and <code>u</code> (the default, meaning normal discovery applies). An invalid value is a syntax error in a tag that controls how receivers locate your policy.",
      "fix": "Remove the tag unless you operate a public suffix — <code>u</code> is the default and is correct for essentially every ordinary domain.",
      "fixCode": "; Ordinary domains do not need psd= at all:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-removed-tags": {
      "msg": "DMARC record contains tags removed by RFC 9989 ({0}) — they no longer do anything.",
      "what": "RFC 9989 removed several tags carried over from RFC 7489. Receivers implementing the current specification ignore them. They are harmless in the sense that they will not break the record, but they are misleading: anyone reading the record later will assume they are in effect.",
      "fix": "Delete the obsolete tags. Reporting cadence and format are no longer configurable from the DMARC record — see RFC 9990 for how aggregate reporting works now.",
      "fixCode": "; Obsolete tags removed:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-unknown-tags": {
      "msg": "DMARC record contains tags that are not part of the standard ({0}).",
      "what": "RFC 9989 defines this complete tag set: <code>v</code>, <code>p</code>, <code>sp</code>, <code>np</code>, <code>adkim</code>, <code>aspf</code>, <code>fo</code>, <code>rua</code>, <code>ruf</code>, <code>psd</code> and <code>t</code>. Unknown tags MUST be ignored, so these are inert rather than dangerous — but they are usually a typo in a real tag name, which means the setting you intended is not applied. A misspelled <code>rua</code> is an unknown tag <em>and</em> a missing report destination.",
      "fix": "Check each unrecognised tag for a typo, then remove anything that is genuinely not needed.",
      "fixCode": "; A typo is silently ignored — this record has NO report destination:\n_dmarc    TXT    \"v=DMARC1; p=reject; rau=mailto:dmarc@yourdomain.com;\"\n\n; Corrected:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-external-unauthorized": {
      "msg": "DMARC reports to {0} are being discarded — that domain has not authorized your reports.",
      "what": "When a report destination sits outside your organizational domain, RFC 9990 §4 requires the receiving domain to publish a record granting permission. We looked, and it is not there. Conformant receivers therefore drop every report bound for {0}: nothing errors and nothing bounces, you simply get less data than you think you do — which is easy to mistake for \"nobody is spoofing us\". Authorization is checked per destination, so any other addresses in your record keep working normally; only this one is being dropped.",
      "fix": "Ask the operator of {0} to publish an authorization record for your domain. Most reporting vendors do this automatically when you add a domain, so if you have just set this up it is worth checking the vendor dashboard first — the record may only appear once the domain is verified on their side.",
      "fixCode": "; The DESTINATION domain publishes this in its own zone,\n; naming the domain whose reports it accepts:\nyourdomain.com._report._dmarc.{0}    TXT    \"v=DMARC1\"\n\n; Vendors accepting many customers usually publish the wildcard form instead:\n*._report._dmarc.{0}    TXT    \"v=DMARC1\""
    },
    "dmarc-external-override-mismatch": {
      "msg": "{0} authorized your reports but then redirected them to a third party ({1}) — receivers send to neither address, so you get nothing.",
      "what": "This destination published the authorization record correctly, and then used its <code>rua=</code> to override where your reports should go — which RFC 9990 §4 permits, but only to an address at the same host. This override points somewhere else. The RFC is explicit about the consequence: <em>\"if the confirming record includes a URI whose host is again different than the domain publishing that override, the Mail Receiver generating the report MUST NOT generate a report to either the original or the override URI.\"</em> The rule exists to stop a chain of redirections being used to flood a third party. So this is worse than an unauthorized destination: everything looks configured and authorized, and conformant receivers send nothing at all — to your address or to theirs.",
      "fix": "This is your reporting vendor's record to fix, not yours. Ask them to remove the <code>rua=</code> override from their <code>_report._dmarc</code> record, or to point it at an address on their own host. Until then, treat this destination as receiving no reports and check whether you have another <code>rua=</code> address that is working.",
      "fixCode": "; Published by the DESTINATION, in the vendor's own zone — note that the owner name carries YOUR domain, because that is the name the receiver queries:\n\n; Broken — the override names a different host, so nothing is sent:\nyourdomain.com._report._dmarc.vendor.example    TXT    \"v=DMARC1; rua=mailto:collector@some-other-host.example;\"\n\n; Fine — an override on the vendor's own host:\nyourdomain.com._report._dmarc.vendor.example    TXT    \"v=DMARC1; rua=mailto:collector@vendor.example;\"\n\n; Also fine — no override at all, reports go to your own rua= address:\nyourdomain.com._report._dmarc.vendor.example    TXT    \"v=DMARC1;\""
    },
    "dmarc-external-unverifiable": {
      "msg": "Could not verify report authorization for {0} — the DNS lookup did not complete.",
      "what": "Reports sent outside your organizational domain need the destination to authorize them, and we check that by querying the destination for an authorization record. That query failed — a timeout, a SERVFAIL, or a resolver hiccup — so we cannot tell you whether the record exists. This is a gap in our result, not a finding against your configuration: treat it as unknown rather than as a problem, and re-run the audit before acting on it.",
      "fix": "Re-run the audit. If it keeps failing, query the name directly to see whether the record is there.",
      "fixCode": "; Check the authorization record by hand:\ndig +short TXT yourdomain.com._report._dmarc.{0}\n\n; And the wildcard form most vendors publish:\ndig +short TXT \"*._report._dmarc.{0}\""
    },
    "checks-unverified": {
      "msg": "Some checks could not be completed ({0}) — they are scored as if the record is not published.",
      "what": "One or more DNS lookups for this domain did not return a usable answer, usually a SERVFAIL or a timeout from the resolver. That can be a genuinely broken nameserver, but it is just as often a transient hiccup that clears within minutes. The rest of the audit completed normally and is accurate. The affected checks are scored as zero, because a grade this tool cannot stand behind is worth less than a grade that is simply strict — so a failed lookup does cost you points until it is re-run.",
      "fix": "Re-run the audit first — a transient failure clears on its own and the points come back. If the same checks keep failing, query the affected names directly to see whether your nameservers answer them. A server that returns SERVFAIL instead of NXDOMAIN for names that do not exist will trip this repeatedly.",
      "fixCode": "; Check whether your nameservers answer a name that should not exist.\n; A healthy server returns NXDOMAIN; a broken one returns SERVFAIL:\ndig +short does-not-exist-test.yourdomain.com\n\n; Ask your authoritative servers directly, bypassing the resolver:\ndig @ns1.yourprovider.com www.yourdomain.com A"
    },
    "dmarc-multiple-records-inherited": {
      "msg": "Multiple DMARC records at {0} — all of them are ignored. The policy at {1} ({2}) governs this domain instead.",
      "what": "RFC 9989 §4.10 discards every record when more than one is returned for a name: <em>\"If multiple DMARC Policy Records are returned for a single target, they are all discarded.\"</em> The Tree Walk then continues upwards, and a valid record higher in the tree is what receivers actually apply — so this domain is not unprotected. What you have lost is local control: the policy you wrote here has no effect, and the inherited one may be weaker, may point reports elsewhere, or may change without warning when the parent domain is edited.",
      "fix": "Delete all but one TXT record at <code>_dmarc</code>. Once a single record remains it takes precedence over the inherited one. If you meant to inherit, delete both and let the parent's policy apply deliberately.",
      "fixCode": "; Before — two records here, both discarded, the parent's policy applies:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n_dmarc    TXT    \"v=DMARC1; p=none;\"\n\n; After — one record, and it governs this domain again:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-at-apex": {
      "msg": "A DMARC record is published on the domain itself instead of under _dmarc — no receiver will ever look there.",
      "what": "A DMARC policy lives at the name <code>_dmarc.yourdomain.com</code>, not at <code>yourdomain.com</code>. RFC 9989 §4.10.1 says policy discovery <em>\"starts with a query for a valid DMARC Policy Record at the name created by prepending the label '_dmarc' to the Author Domain\"</em> — receivers query that name and nowhere else. A correctly written record on the apex is invisible: the domain is treated as having no DMARC policy at all. This usually happens when a DNS panel silently ignores the host field, or when the record is pasted into the same box as SPF.",
      "fix": "Republish the record as a TXT record on the host <code>_dmarc</code>, and delete it from the apex — a stray DMARC string in the apex TXT set does nothing but confuse the next person to read it.",
      "fixCode": "; Wrong — on the domain itself:\nyourdomain.com    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n\n; Right — under the _dmarc host:\n_dmarc            TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-bad-sp": {
      "msg": "sp= is set to \"{0}\", which is not a policy value — subdomains fall back to p= instead.",
      "what": "RFC 9989 §4.7 allows exactly three values for <code>sp=</code>: <code>none</code>, <code>quarantine</code> and <code>reject</code>. Anything else is not a policy, so receivers ignore the tag and subdomains inherit <code>p=</code>. That may be stricter or weaker than you intended, and the record reads as though a deliberate subdomain policy is in force when none is.",
      "fix": "Correct the value, or remove <code>sp=</code> entirely if you are happy for subdomains to inherit <code>p=</code>.",
      "fixCode": "; Wrong — typo, silently ignored:\n_dmarc    TXT    \"v=DMARC1; p=reject; sp=rejcet;\"\n\n; Right:\n_dmarc    TXT    \"v=DMARC1; p=reject; sp=reject;\""
    },
    "dmarc-bad-np": {
      "msg": "np= is set to \"{0}\", which is not a policy value — non-existent subdomains fall back to sp= or p= instead.",
      "what": "RFC 9989 §4.7 allows exactly three values for <code>np=</code>: <code>none</code>, <code>quarantine</code> and <code>reject</code>. Anything else is ignored, and the policy for names that do not exist falls back through <code>sp=</code> to <code>p=</code>. Non-existent subdomains are the cheapest thing for an attacker to spoof, so a tag that looks set and is not is worth correcting.",
      "fix": "Correct the value, or remove <code>np=</code> and let the fallback chain apply deliberately.",
      "fixCode": "; Wrong — not a policy value:\n_dmarc    TXT    \"v=DMARC1; p=reject; np=nope;\"\n\n; Right:\n_dmarc    TXT    \"v=DMARC1; p=reject; np=reject;\""
    },
    "dmarc-bad-adkim": {
      "msg": "adkim= is set to \"{0}\" — the only values are r and s, so DKIM alignment stays relaxed.",
      "what": "RFC 9989 §4.7 defines two DKIM alignment modes and two spellings: <code>r</code> for relaxed and <code>s</code> for strict. A value like <code>strict</code> or <code>1</code> is not recognised, and receivers fall back to relaxed. The record reads as strict to whoever wrote it while behaving as relaxed in practice, which is the worst of both — a subdomain of your organizational domain can pass alignment when you believed only an exact match would.",
      "fix": "Use <code>adkim=s</code> for strict alignment, or remove the tag to state relaxed alignment explicitly.",
      "fixCode": "; Wrong — spelled out, so it is ignored:\n_dmarc    TXT    \"v=DMARC1; p=reject; adkim=strict;\"\n\n; Right:\n_dmarc    TXT    \"v=DMARC1; p=reject; adkim=s;\""
    },
    "dmarc-bad-aspf": {
      "msg": "aspf= is set to \"{0}\" — the only values are r and s, so SPF alignment stays relaxed.",
      "what": "RFC 9989 §4.7 defines two SPF alignment modes and two spellings: <code>r</code> for relaxed and <code>s</code> for strict. An unrecognised value is ignored and receivers fall back to relaxed, so the record claims a strictness it does not have. Under relaxed alignment any subdomain of your organizational domain can satisfy the SPF half of a DMARC pass.",
      "fix": "Use <code>aspf=s</code> for strict alignment, or remove the tag to state relaxed alignment explicitly.",
      "fixCode": "; Wrong — spelled out, so it is ignored:\n_dmarc    TXT    \"v=DMARC1; p=reject; aspf=loose;\"\n\n; Right:\n_dmarc    TXT    \"v=DMARC1; p=reject; aspf=s;\""
    },
    "dmarc-np-not-applied": {
      "msg": "np={0} is published but does not apply here — this name exists, so sp={1} governs it.",
      "what": "RFC 9989 §4.10.1 splits the inherited policy in two: the <code>sp=</code> tag applies <em>\"if the Author Domain exists\"</em> and <code>np=</code> applies <em>\"if the Author Domain does not exist\"</em>. Existence is a DNS question — RFC 9989 Appendix A.4 says that if any record exists for a name, the name exists — and this name resolved, so it is the <code>sp=</code> branch that governs. This is informational: nothing is misconfigured. It is here because the reported policy would otherwise look inconsistent with the record you can read.",
      "fix": "No change needed. If you intended this stricter policy to apply to real subdomains too, set <code>sp=</code> to match <code>np=</code>.",
      "fixCode": "; np= covers names that do not exist; sp= covers the ones that do:\n_dmarc    TXT    \"v=DMARC1; p=reject; sp=quarantine; np=reject;\""
    },
    "dmarc-unverified": {
      "msg": "DMARC could not be checked — a DNS lookup failed ({0}). This is not the same as having no DMARC record.",
      "what": "Discovering a DMARC policy under RFC 9989 means walking from this name up towards the top-level domain, and one of those lookups failed rather than answering. A failed lookup is not evidence of a missing record: the policy may be published and perfectly healthy. This audit will not guess either way, so the DMARC score is withheld and the grade is marked as resting on a check that did not complete. Resolver errors of this kind are usually transient.",
      "fix": "Re-run the audit. If it keeps failing for this domain, query <code>_dmarc</code> directly against a second resolver to find out whether the name really is unreachable or whether it was our lookup that was unlucky.",
      "fixCode": "; Check it yourself, from a shell:\ndig +short TXT _dmarc.yourdomain.com\ndig +short TXT _dmarc.yourdomain.com @1.1.1.1\ndig +short TXT _dmarc.yourdomain.com @8.8.8.8"
    },
    "dmarc-at-apex-ignored": {
      "msg": "A stray DMARC record sits on the domain itself as well as under _dmarc — no receiver reads it, and your real policy at {0} is unaffected.",
      "what": "A DMARC policy lives at <code>_dmarc.yourdomain.com</code>; receivers query that name and nowhere else. There is a second <code>v=DMARC1</code> string in this domain's own TXT set, which no receiver will ever look at. Your actual policy is the one found at {0} and it governs normally — so this is untidy rather than dangerous. It usually means an older copy was left behind after the record was moved to the right name.",
      "fix": "Delete the <code>v=DMARC1</code> string from the domain's own TXT records. Leave the one under <code>_dmarc</code> exactly as it is.",
      "fixCode": "; Delete this — nothing reads it:\nyourdomain.com    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n\n; Keep this — this is your policy:\n_dmarc            TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-report-destinations-truncated": {
      "msg": "Only {0} of {1} report destinations were checked — this audit stops at 10. Not checked: {2}",
      "what": "Your record names more report destinations than this audit will follow. Each one outside your organizational domain costs a DNS tree walk plus an authorization lookup, and the number of them is set by the record itself — so an audit will not let a single record decide how much DNS traffic it generates. RFC 9990 §3.5 anticipates exactly this, saying reports go to every URI <em>\"up to the Receiver's limits on supported URIs\"</em>, and real receivers impose their own limits too. This notice exists so the verdicts above are not mistaken for a complete list.",
      "fix": "Nothing is wrong with the record. If you want every destination audited, split the domains across separate runs. If the list has simply grown over time, it is worth pruning: destinations you no longer read are destinations a receiver still has to try."
    },
    "dkim-key-weak": {
      "msg": "DKIM key below 1024 bits: {0} — the signature is forgeable and receivers may ignore it.",
      "what": "RFC 8301 sets 1024 bits as the absolute floor for an RSA DKIM key and recommends 2048. A modulus below that floor can be factored by an attacker with modest resources, and anyone who factors it can sign mail that passes DKIM as your domain — which also means it passes DMARC, because DMARC accepts a message whose DKIM signature aligns. Some receivers have stopped accepting short keys outright, so the same record can silently fail verification at one provider while passing at another.",
      "fix": "Generate a new 2048-bit key and publish it under a <strong>new</strong> selector, switch your signing service to that selector, and only then remove the old record. Rotating in place breaks every message still in flight that was signed with the old key.",
      "fixCode": "; A receiver queries s2026._domainkey.example.com for this key\n; Publish the new key first, under a new selector:\ns2026._domainkey    TXT    \"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B...\"\n\n; Switch signing to s2026, wait for mail in flight to clear,\n; then delete the old short-key record:\ns2020._domainkey    TXT    \"v=DKIM1; k=rsa; p=MFwwDQYJKoZIhvcNAQEB...\""
    },
    "dkim-key-1024": {
      "msg": "DKIM key is 1024 bits: {0} — valid today, but 2048 is the current recommendation.",
      "what": "RFC 8301 names 1024 bits as the minimum and 2048 as the recommended size for RSA DKIM keys. A 1024-bit key is not broken and is not being rejected by mainstream receivers — this is genuinely common, and plenty of large senders still publish one. It is listed here as a rotation to schedule rather than an incident to work, which is why it sits with the suggestions and not with the failures.",
      "fix": "Fold a move to 2048 bits into your next planned key rotation. There is nothing to do urgently. Publish the new key under a new selector, switch signing to it, then retire the old record."
    },
    "dkim-key-revoked": {
      "msg": "DKIM selector published with an empty key: {0} — the selector is revoked and signs nothing.",
      "what": "RFC 6376 §3.6.1 defines a <code>p=</code> tag with an empty value as key revocation: a receiver that finds it treats every signature made with that selector as permanently invalid. That is the correct way to retire a selector. It becomes a problem when the selector is still configured somewhere as a signing key, because the mail goes out signed, the receiver looks up the selector, and the signature fails — which looks identical to a forgery.",
      "fix": "Confirm nothing still signs with this selector. If the selector is genuinely retired, the revocation record can stay indefinitely or be removed once no mail signed with it is still in flight. If something is still signing with it, publish the real public key or move that service to a live selector.",
      "fixCode": "; A revocation — empty p=, deliberately:\nold2019._domainkey    TXT    \"v=DKIM1; k=rsa; p=\"\n\n; A live selector, for comparison:\ns2026._domainkey      TXT    \"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B...\""
    },
    "dkim-key-unparseable": {
      "msg": "DKIM public key does not decode: {0} — no receiver can verify a signature from this selector.",
      "what": "The record is present and the selector is found, so the domain looks configured — but the <code>p=</code> value is not a key any verifier can read. Much the most common cause is a truncated record: a DNS TXT string is limited to 255 characters, a 2048-bit key is longer than that, and a key pasted into a control panel that does not split it correctly loses its tail. The failure is completely silent. Nothing warns you, the record resolves, and every signature simply fails.",
      "fix": "Re-publish the key, letting your DNS provider split it into multiple quoted strings rather than truncating it. Compare the published value against the key your signing service holds — they must match character for character, including case, because the value is base64 and case-sensitive.",
      "fixCode": "; One TXT record, split into quoted strings the resolver rejoins:\ns2026._domainkey    TXT    ( \"v=DKIM1; k=rsa; \"\n                            \"p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\"\n                            \"...IDAQAB\" )"
    },
    "dkim-key-testing": {
      "msg": "DKIM selector is in testing mode: {0} — receivers are told to ignore its results.",
      "what": "The <code>t=y</code> flag tells receivers the domain is still testing DKIM and that they should treat signed and unsigned mail alike. It exists so a new deployment can be validated without risking delivery. Left in place after go-live it quietly cancels the protection: a receiver honouring the flag will not act on a signature failure, so the selector contributes nothing to DMARC.",
      "fix": "Remove the <code>t=y</code> flag once you have confirmed signatures verify. If you are genuinely still testing, leave it and revisit after go-live."
    },
    "dkim-key-mixed": {
      "msg": "DKIM selectors use different key strengths, from {0} to {1} bits — the weakest one sets your real strength.",
      "what": "An attacker picks which selector to attack, not you. If one selector signs at 1024 bits and another at 2048, the domain's practical DKIM strength is 1024, because forging a signature under the weaker selector produces mail that passes DKIM and DMARC just as convincingly. Different sizes usually mean a rotation that was started and never finished, or a second sending service set up separately from the first.",
      "fix": "Bring the weaker selectors up to the size of the strongest, or retire them if the service behind them no longer sends."
    },
    "dkim-key-sha1": {
      "msg": "DKIM key allows only SHA-1: {0} — RFC 8301 forbids SHA-1 for DKIM signatures.",
      "what": "The <code>h=</code> tag lists the hash algorithms a verifier may accept for this key. With <code>sha1</code> as the only entry, a conformant receiver has nothing acceptable to offer: RFC 8301 §3.1 removed SHA-1 from DKIM outright, on the strength of practical collision attacks. Receivers enforcing that will fail the signature. Listing <code>sha1</code> alongside <code>sha256</code> is fine and is not reported here — a verifier can simply choose the stronger one.",
      "fix": "Change <code>h=sha1</code> to <code>h=sha256</code>, or drop the <code>h=</code> tag entirely, which allows any hash the verifier supports. Confirm your signing service is producing SHA-256 signatures before you do.",
      "fixCode": "; Before — nothing a conformant receiver will accept:\ns2026._domainkey    TXT    \"v=DKIM1; k=rsa; h=sha1; p=MIIBIjANBgkqhkiG9w0B...\"\n\n; After:\ns2026._domainkey    TXT    \"v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkqhkiG9w0B...\""
    },
    "caa-blocks-all-issuance": {
      "msg": "CAA at {0} authorizes no certificate authority — no CA can issue a certificate for this domain.",
      "what": "An <code>issue</code> property whose value is <code>;</code> names no issuer, and RFC 8659 §4.2 reads that as authorizing nobody. Every conformant certificate authority will refuse. This is a legitimate and deliberate setting for a domain that must never have a certificate, so it is not necessarily wrong. It becomes an outage when it was not intended, and the outage is invisible until a renewal fails — the existing certificate keeps working right up to the day it expires.",
      "fix": "If this is deliberate, nothing to do. If it is not, add an <code>issue</code> property naming the certificate authority you use. Remember that CAA is inherited down the tree, so a record set at the parent governs this name too.",
      "fixCode": "; Blocks every CA:\nexample.com.    CAA    0 issue \";\"\n\n; Authorizes one CA:\nexample.com.    CAA    0 issue \"letsencrypt.org\""
    },
    "caa-unknown-critical-tag": {
      "msg": "CAA property not recognized, with the critical flag set: {0} — a conformant CA must refuse to issue.",
      "what": "RFC 8659 §4.1 defines the top bit of the flags byte as Issuer Critical. A certificate authority that encounters a property it does not understand with that bit set MUST refuse to issue, rather than ignoring the property and carrying on. So an unrecognized critical property is an issuance block, and it is one that will not be noticed until the next renewal. The same property without the critical bit is inert and would not be reported here.",
      "fix": "Check the property name for a typo against the registry — <code>issue</code>, <code>issuewild</code>, <code>iodef</code>, <code>issuemail</code>, <code>contactemail</code>, <code>contactphone</code>. If the property is intentional and non-standard, clear the critical flag by setting the flags byte to 0.",
      "fixCode": "; Critical and unrecognized — blocks issuance:\nexample.com.    CAA    128 issuewildcard \"letsencrypt.org\"\n\n; The registered property name:\nexample.com.    CAA    0 issuewild \"letsencrypt.org\""
    },
    "caa-malformed": {
      "msg": "CAA record could not be parsed: {0}",
      "what": "A CAA record is three fields: a flags byte from 0 to 255, a property tag, and a quoted value. A record that does not fit that shape may be ignored by a certificate authority, or may be treated as an unrecognized property — and if its flags byte happens to set the critical bit, that means refusing to issue. The behaviour is not something you want to leave to chance.",
      "fix": "Re-enter the record in the standard three-field form. Some DNS interfaces ask for the flags, tag and value in separate boxes and add the quotes for you; others take the whole line, in which case the value needs its own quotation marks."
    },
    "caa-no-iodef": {
      "msg": "CAA is published but has no iodef property — you will not hear about refused certificate requests.",
      "what": "The <code>iodef</code> property gives a certificate authority somewhere to report a request that your CAA policy made it refuse. Without one, a refusal is silent from your side: an attacker probing for a CA that will issue for your domain looks exactly like nothing happening, and so does a colleague who tried to get a certificate from the wrong provider.",
      "fix": "Add an <code>iodef</code> property pointing at a mailbox somebody reads. It costs one record and it is the only notification channel CAA has.",
      "fixCode": "example.com.    CAA    0 issue \"letsencrypt.org\"\nexample.com.    CAA    0 iodef \"mailto:security@example.com\""
    },
    "caa-single-issuer": {
      "msg": "CAA authorizes one certificate authority: {0} — changing provider will need a DNS change first.",
      "what": "A single authorized issuer is a perfectly good, tight policy and this is not a misconfiguration. It is worth knowing about at the moment it starts to matter: if that CA has an outage, or you need to move provider in a hurry, no other authority can issue until this record is updated — and whoever is trying to get the certificate is often not whoever can edit DNS.",
      "fix": "Nothing to change. Make sure the people who request certificates know the record exists and who can edit it. If you already have a fallback CA in mind, authorizing it now costs one record and removes a step from a bad day."
    },
    "mx-dangling": {
      "msg": "MX host does not resolve: {0} — mail routed there cannot be delivered.",
      "what": "An MX record names a hostname, and that hostname has to resolve to an address before any sending server can connect to it. This one does not: the name returns no A or AAAA record. A sending server that selects this host has nowhere to go — it will queue the message and retry, and eventually return it to the sender. If it is your only MX host, you are receiving no mail at all right now. If it is a backup, you are one failure away from that.",
      "fix": "Check the hostname for a typo, and check that the zone it lives in still publishes an address record for it. A host that has been decommissioned should have its MX record removed rather than left pointing at nothing — a dangling backup MX delays delivery on every retry cycle.",
      "fixCode": "; Every host named on the right must resolve to an address:\nexample.com.        MX     10 mail1.example.com.\nexample.com.        MX     20 mail2.example.com.\n\nmail1.example.com.  A      203.0.113.10\nmail2.example.com.  A      203.0.113.11"
    },
    "mx-cname-target": {
      "msg": "MX target is a CNAME: {0} — RFC 2181 and RFC 5321 both forbid this.",
      "what": "RFC 2181 §10.3 and RFC 5321 §5.1 both require that an MX record point at a name with an address record, not at an alias. It usually works anyway, because most sending servers follow the alias without complaining, which is exactly why the mistake survives in the wild. Where it breaks, it breaks specifically and confusingly: some servers refuse the alias outright, and the extra lookup adds a failure point on every delivery. It also interacts badly with DANE, where the TLSA record must be found under the right name.",
      "fix": "Point the MX record at the alias target directly, so the MX names a host that has its own address record.",
      "fixCode": "; Before — the MX names an alias:\nexample.com.        MX      10 mail.example.com.\nmail.example.com.   CNAME   host7.provider.example.\n\n; After — the MX names the host itself:\nexample.com.        MX      10 host7.provider.example."
    },
    "mx-single-host": {
      "msg": "Only one MX host is published: {0} — mail queues at the sender while it is unreachable.",
      "what": "With one MX host, any period where that host is unreachable is a period where inbound mail sits in other people's queues. Nothing is lost immediately — sending servers retry for days before returning a message — but delivery stops, and it stops for a maintenance window as readily as for a failure. Many hosted mail providers publish several MX hosts precisely to avoid this; a single one is more often a self-hosted setup or a provider entry that was only half-copied.",
      "fix": "Publish a second MX host at a higher preference number if your mail platform offers one. If your provider gave you several hostnames, check that all of them made it into DNS."
    },
    "mx-no-ipv6": {
      "msg": "No MX host has an IPv6 address — IPv6-only senders cannot reach your mail.",
      "what": "A sending server on an IPv6-only network reaches an IPv4-only mail host through whatever translation its operator provides, or not at all. This is not a security finding and it is not urgent: IPv4 mail delivery is not going away. It is a reachability note, and it also affects reputation, because some large receivers treat dual-stack availability as a signal of a well-maintained mail system.",
      "fix": "Add AAAA records for your MX hosts once the hosts themselves accept mail over IPv6. Publishing an AAAA record for a host that is not actually listening on IPv6 is worse than having none — senders will try it first and fail."
    },
    "mx-same-prefix": {
      "msg": "MX hosts share one address block, {0}: {1} — the redundancy is smaller than it looks.",
      "what": "Several MX hosts published at different preferences read as redundancy, but if every address sits in the same small block, they very likely share a rack, an uplink and a data centre. The failures that take out one will usually take out all of them, so the second host is protecting against a server fault and not against anything larger. This is normal for a single-site mail platform and worth knowing rather than fixing.",
      "fix": "If the redundancy is meant to survive a site failure, place at least one MX host in a different network. If the second host is only there to cover a server restart, nothing needs to change."
    },
    "mx-duplicate-preference": {
      "msg": "Two or more MX hosts share the same preference value: {0} — sending servers will load-balance across them.",
      "what": "Equal preference values are a deliberate feature: RFC 5321 §5.1 says a sender should pick among equal-preference hosts at random, which spreads inbound mail across them. That is what you want for two equivalent front ends. It is not what you want if one host was intended as a backup, because half your mail will go to the backup all the time.",
      "fix": "Nothing, if the hosts are equivalent. If one is meant to be a fallback, give it a higher preference number — higher means less preferred."
    },
    "mx-unroutable": {
      "msg": "MX host resolves only into unreachable address space: {0} ({1}) — no sending server on the internet can deliver to it.",
      "what": "An MX record names the host that accepts your mail, and that host has to be reachable from the public internet for anyone to deliver to it. This one resolves, so it does not look broken in any tool that only checks whether the name has an address record — but every address it returns is special-purpose space that is not globally routed: loopback, a private range, link-local, carrier-shared, documentation or reserved. A sending server that selects this host has an address it cannot route to. It will queue the message, retry for days, and return it. If this is your only MX host you are receiving no mail at all, and have not been since the record was published.\n\nThe usual cause is a zone that was meant to be internal being served to the outside world, or an internal address pasted into a public record. Either way the address also tells anyone who asks how your internal network is numbered.",
      "fix": "Publish the address the host answers on from outside your network. If the mail server genuinely sits behind a translator, the MX must name its public address, not its internal one. If this record was only ever meant for an internal view of the zone, it should not be in the public zone at all.",
      "fixCode": "; Wrong — the address is private, and no sender can route to it:\nmail.example.com.   A      10.0.0.4\n\n; Right — a public address the server answers on from outside.\n; 203.0.113.10 is an example value only: substitute your own public address.\nmail.example.com.   A      203.0.113.10"
    },
    "mx-partially-routable": {
      "msg": "MX host has both reachable and unreachable addresses: {0} — {1} cannot be reached from the internet.",
      "what": "This host publishes more than one address, and at least one of them is globally routable while at least one is not. Mail still arrives, which is what makes this worth reporting rather than obvious: a sending server picks among a host's addresses, so delivery succeeds for whoever happens to choose a routable one and stalls for whoever does not. The symptom is intermittent, correlates with nothing the sender can see, and is usually reported to you as \"your mail sometimes bounces\" long after it starts.\n\nIt is most often a leftover — an internal address added for testing, or an old address kept after a renumbering — sitting alongside the address that actually works.",
      "fix": "Remove the address records that are not reachable from outside your network, leaving only the addresses the server actually accepts mail on. If the extra address is deliberate and internal, it belongs in an internal view of the zone rather than the public one."
    },
    "mx-address-literal": {
      "msg": "MX record names an address instead of a hostname: {0} — RFC 1035 requires a domain name here.",
      "what": "The right-hand side of an MX record is a domain name, not an address. RFC 1035 §3.3.9 defines the field that way and RFC 5321 §5.1 requires that name to have an address record of its own, so a sending server takes what it finds here and looks it up as a hostname. An address written in this position is therefore treated as a name, and since the DNS root delegates no all-numeric top-level domain it cannot resolve to anything. Nothing is delivered.\n\nThis is worth separating from an ordinary unresolvable host because the fix is different. A dangling MX usually means a missing or mistyped address record somewhere; this one means the record is the wrong shape, and no address record can ever be added that would make it work.",
      "fix": "Give the mail server a hostname, publish its address on that name, and point the MX record at the name.",
      "fixCode": "; Wrong — an address where a name belongs:\nexample.com.        MX     10 203.0.113.10\n\n; Right — a name, and the address published on it.\n; 203.0.113.10 is an example value only: substitute your own public address.\nexample.com.        MX     10 mail.example.com.\nmail.example.com.   A      203.0.113.10"
    },
    "mx-null-conflict": {
      "msg": "A null MX is published alongside real MX records — the domain declares both that it accepts mail and that it accepts none.",
      "what": "RFC 7505 defines `0 .` as a null MX: an explicit statement that a domain receives no mail, which lets a sending server reject a message immediately instead of queueing and retrying it for days. RFC 7505 §3 requires it to be the only MX record in the set, precisely because it means something no other record can be true alongside.\n\nPublishing it next to a real MX host leaves two incompatible declarations, and which one a given sender acts on is not something you control. Some will honour the null MX and reject your mail outright; others will ignore it and deliver to the host. The half that reject do so permanently, so the messages are not retried and not recoverable.",
      "fix": "Decide which is true and publish only that. If the domain receives mail, remove the `0 .` record. If it does not, remove the other MX records and keep the null MX alone — that is the whole point of it.",
      "fixCode": "; Wrong — both declarations at once:\nexample.com.   MX   0 .\nexample.com.   MX   10 mail.example.com.\n\n; Right, if the domain receives mail:\nexample.com.   MX   10 mail.example.com.\n\n; Right, if it does not — and nothing else:\nexample.com.   MX   0 ."
    },
    "tlsa-published-unsigned": {
      "msg": "TLSA published without a validated DNSSEC chain: {0} — DANE offers no protection here.",
      "what": "DANE works by putting the certificate a mail server should present into DNS, and it is only worth anything if that DNS answer cannot be tampered with. Without DNSSEC, anyone able to intercept the lookup can strip the TLSA record — at which point the sending server sees a host with no DANE policy and delivers anyway — or replace it with a record matching their own certificate. The record still appears in every diagnostic as if DANE were configured, which is the reason this is worth saying out loud: it looks like protection, and it is not.",
      "fix": "Sign the zone the TLSA record lives in and get the DS record published at its parent. Until that is done, the TLSA record is decoration. If signing the zone is not on the cards, removing the TLSA record is more honest than leaving it there.",
      "fixCode": "; A sending server queries _25._tcp.mail1.example.com for this record,\n; and it must sit in a DNSSEC-signed zone to mean anything:\n_25._tcp.mail1.example.com.    TLSA    3 1 1 ( 87D109DD028655D5370B... )"
    },
    "tlsa-malformed": {
      "msg": "TLSA record is malformed: {0} — a sending server enforcing DANE may refuse to deliver.",
      "what": "A TLSA record is a certificate usage, a selector, a matching type and the association data, and the length of that data is fixed by the matching type — 32 bytes for SHA-256, 64 for SHA-512. A record that does not fit cannot be matched against any certificate. Under DANE that is not a soft failure: a sending server that finds a TLSA record it cannot use is required to treat delivery as failed rather than fall back to an unauthenticated connection, so a malformed record can stop mail arriving.",
      "fix": "Regenerate the record from the certificate the mail host actually presents, rather than editing the digest by hand. Check that the matching type matches the digest length you published."
    },
    "tlsa-partial-coverage": {
      "msg": "TLSA is published for {0} of {1} mail hosts — the hosts without it accept unauthenticated connections.",
      "what": "A sending server picks an MX host and looks for a TLSA record under that host's name. Where it finds one, the connection is authenticated; where it does not, delivery falls back to ordinary opportunistic TLS, which an attacker on the path can downgrade. So partial coverage means an attacker simply targets the host that has no record. The protection is only as good as its weakest MX host.",
      "fix": "Publish a TLSA record for every MX host, or remove the records until you can cover all of them. Each host needs its own record, under <code>_25._tcp</code> at that host's name."
    },
    "dkim-key-not-email": {
      "msg": "DKIM key published but not applicable to email: {0} — it does not count toward this domain's email signing.",
      "what": "A DKIM key record can restrict what it may be used for. An <code>s=</code> tag lists the services the key applies to, and a key scoped to something else — <code>s=tlsrpt</code>, for example, which RFC 8460 uses for TLS reporting — is not a key for ordinary mail. A key whose <code>k=</code> names an algorithm this tool does not recognize is in the same position: RFC 6376 §3.6.1 says a verifier must ignore it. These records are usually correct and deliberate. They are listed here so that a domain whose only DKIM records are of this kind is told why the audit reports no signing key, instead of being told nothing was found at a selector the operator knows they configured.",
      "fix": "Nothing, if the restriction is intended. If this selector was meant to sign ordinary mail, either remove the <code>s=</code> tag — an absent tag means the key applies to every service — or include <code>email</code> in its list. Check the <code>k=</code> value too: only <code>rsa</code> and <code>ed25519</code> are defined for DKIM.",
      "fixCode": "; Scoped to another service — valid, but not an email key:\ntlsrpt._domainkey    TXT    \"v=DKIM1; k=rsa; s=tlsrpt; p=MIIBIjANBgkqhkiG9w0B...\"\n\n; Applies to email, either by naming it or by omitting s= entirely:\ns2026._domainkey     TXT    \"v=DKIM1; k=rsa; s=email; p=MIIBIjANBgkqhkiG9w0B...\"\ns2027._domainkey     TXT    \"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B...\""
    },
    "dkim-key-malformed": {
      "msg": "DKIM key record is malformed: {0} — the key may decode, but the record around it does not parse.",
      "what": "This is separate from a key that fails to decode. The <code>p=</code> value here may be perfectly good; what is wrong is the record it sits in — an empty <code>h=</code>, <code>s=</code> or <code>t=</code> list where the tag is present but names nothing, a repeated tag, or a <code>v=</code> that is not <code>DKIM1</code>. RFC 6376 §3.6.1 defines each of those tags as a non-empty colon-separated list, and a verifier reading a record it cannot parse is entitled to ignore the key entirely. The selector still counts as published, because a broken record at a name you configured is a different problem from nothing being there at all — but it is not something to rely on.",
      "fix": "Compare the record against what your signing service generated. The usual causes are a tag left with no value after an edit — <code>s=</code> or <code>h=</code> with nothing following it — and a tag pasted twice. Remove an optional tag entirely rather than leaving it empty: an absent <code>s=</code> means the key applies to every service, and an absent <code>h=</code> means every hash is acceptable.",
      "fixCode": "; Malformed — the tags are present but empty:\ns2026._domainkey    TXT    \"v=DKIM1; k=rsa; h=; s=; p=MIIBIjANBgkqhkiG9w0B...\"\n\n; Correct — either name the values, or leave the tags out:\ns2026._domainkey    TXT    \"v=DKIM1; k=rsa; h=sha256; s=email; p=MIIBIjANBgkqhkiG9w0B...\"\ns2027._domainkey    TXT    \"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0B...\""
    }
  },
  "suggestion": {
    "bimiEligible": "BIMI-eligible: DMARC is enforced and DKIM is configured. Add a default._bimi TXT record with your SVG logo URL to display your brand logo in Gmail & Apple Mail.",
    "bimiPrereq": "BIMI (logo in inbox): requires DMARC at p=quarantine or p=reject + DKIM. Get those in place first, then add BIMI.",
    "mta-sts": "MTA-STS not configured. Publishing a _mta-sts TXT record and hosting a policy file forces TLS on inbound mail delivery, preventing downgrade attacks.",
    "tls-rpt": "TLS-RPT (_smtp._tls TXT) not configured. This companion to MTA-STS sends you reports when TLS negotiation fails — easy to add, zero downside.",
    "caa": "No CAA records — any certificate authority can issue SSL certs for this domain. Add CAA records naming only your preferred CA (e.g. Let's Encrypt, DigiCert).",
    "dnssec": "DNSSEC not detected. Signing your DNS records prevents cache poisoning and MX hijacking. Cloudflare and most modern DNS providers enable this with one click.",
    "dmarc-pct-obsolete": "Your DMARC record still uses pct=. As of RFC 9989 — DMARCbis, ratified May 2026 — pct= is no longer a supported tag and should be removed. Receivers that have adopted the new standard ignore it; receivers still on RFC 7489 do not, so leaving it in place means your enforcement differs from one receiver to the next. Use t=y if you need a staged rollout."
  },
  "learnMore": {
    "badge": "Email Security Guide",
    "close": "✕ Close tab",
    "footer": "Generated by DNS & Email Security Auditor — no data stored, no signup required",
    "bimi": {
      "title": "BIMI — Brand Indicators for Message Identification",
      "tagline": "Display your logo in Gmail, Apple Mail, and Yahoo inboxes.",
      "sections": [
        {
          "h": "What is BIMI?",
          "body": "BIMI is an email standard that lets your organization's logo appear directly in the recipient's inbox — next to your sender name, before the email is even opened. It is supported by Gmail, Apple Mail, Yahoo Mail, and Fastmail."
        },
        {
          "h": "Why it matters",
          "body": "Logo display builds immediate visual trust. Recipients can see at a glance that the email is genuinely from your organization, which increases open rates and reduces the chance of your mail being mistaken for phishing. BIMI also acts as a forcing function to get your full authentication stack (SPF + DKIM + DMARC) fully in order."
        },
        {
          "h": "Requirements before you can publish BIMI",
          "body": "• DMARC must be at <code>p=quarantine</code> or <code>p=reject</code> — <code>p=none</code> does not qualify<br>• DKIM must be configured and actively signing outbound mail<br>• An SVG logo in <strong>Tiny PS</strong> format hosted at a public HTTPS URL<br>• (For Gmail) A Verified Mark Certificate (VMC) from DigiCert or Entrust may be required for the blue checkmark"
        },
        {
          "h": "How to set it up",
          "body": "1. Confirm DMARC is enforced (<code>p=quarantine</code> or <code>p=reject</code>)<br>2. Confirm DKIM is configured and signing<br>3. Create your SVG logo in Tiny PS format (Canva, Adobe Illustrator, or <a href=\"https://bimigroup.org/bimi-generator/\" target=\"_blank\" rel=\"noopener\">the BIMI generator</a> can help)<br>4. Host the SVG at a public HTTPS URL — e.g. <code>https://yourdomain.com/logo.svg</code><br>5. Add the BIMI DNS record:",
          "code": "default._bimi    TXT    \"v=BIMI1; l=https://yourdomain.com/logo.svg;\""
        },
        {
          "h": "Testing",
          "body": "Validate your record at <a href=\"https://bimigroup.org/bimi-generator\" target=\"_blank\" rel=\"noopener\">bimigroup.org/bimi-generator</a>. Send a test email to a Gmail account and watch for your logo to appear in the inbox avatar."
        }
      ]
    },
    "mta-sts": {
      "title": "MTA-STS — Mail Transfer Agent Strict Transport Security",
      "tagline": "Force TLS encryption on all inbound email delivery to your domain.",
      "sections": [
        {
          "h": "What is MTA-STS?",
          "body": "MTA-STS is a standard (RFC 8461) that lets you publish a policy declaring that anyone sending email to your domain must use TLS encryption and must verify your mail server's certificate. Without it, network attackers can perform \"downgrade attacks,\" stripping TLS and reading email in transit."
        },
        {
          "h": "Why it matters",
          "body": "Standard STARTTLS encryption is negotiated opportunistically — a man-in-the-middle attacker can silently remove the STARTTLS offer and force plaintext delivery. MTA-STS fixes this by caching your policy on the sending server in advance, so it knows TLS is required and refuses to deliver without it."
        },
        {
          "h": "Part 1 — Publish the DNS TXT record",
          "body": "Add this TXT record to your DNS. Change the <code>id=</code> value any time you update the policy file.",
          "code": "_mta-sts    TXT    \"v=STSv1; id=20240101000000Z;\""
        },
        {
          "h": "Part 2 — Host the policy file",
          "body": "The policy file must be hosted at exactly this URL on your domain:<br><code>https://mta-sts.yourdomain.com/.well-known/mta-sts.txt</code><br><br>Example policy file content:",
          "code": "version: STSv1\nmode: testing\nmx: mail.yourdomain.com\nmx: *.google.com\nmax_age: 604800",
          "body2": "Start with <code>mode: testing</code> to observe without blocking. After reviewing TLS-RPT reports and confirming no failures, switch to <code>mode: enforce</code>."
        },
        {
          "h": "Testing",
          "body": "Use <a href=\"https://www.checktls.com\" target=\"_blank\" rel=\"noopener\">CheckTLS.com</a> or <a href=\"https://mxtoolbox.com/mta-sts.aspx\" target=\"_blank\" rel=\"noopener\">MXToolbox MTA-STS Check</a> to validate your policy. Pair this with TLS-RPT to receive failure reports (see the TLS-RPT recommendation)."
        }
      ]
    },
    "tls-rpt": {
      "title": "TLS-RPT — SMTP TLS Reporting",
      "tagline": "Get notified when TLS encryption fails for email delivered to your domain.",
      "sections": [
        {
          "h": "What is TLS-RPT?",
          "body": "TLS-RPT (SMTP TLS Reporting, RFC 8460) is a single DNS TXT record that tells sending mail servers where to email daily reports about TLS connection failures when delivering mail to your domain. Think of it as DMARC reporting for TLS/encryption failures."
        },
        {
          "h": "Why it matters",
          "body": "If your MTA-STS policy is misconfigured, your mail server's TLS certificate expires, or a network provider is stripping encryption, you'd never know without TLS-RPT. It turns invisible delivery failures into actionable reports in your inbox — and it's one of the easiest DNS records to publish."
        },
        {
          "h": "How to set it up",
          "body": "Add a single TXT record — replace the email with a mailbox you monitor:",
          "code": "_smtp._tls    TXT    \"v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com;\"",
          "body2": "Reports arrive daily as JSON-formatted attachments. Third-party DMARC platforms (Postmark, Valimail, dmarcian) also parse and visualize TLS-RPT reports alongside your DMARC data."
        },
        {
          "h": "What the reports tell you",
          "body": "Each daily report shows: which sending servers attempted mail delivery to your domain, whether TLS negotiation succeeded or failed, and the specific failure reason — expired certificate, policy mismatch, unsupported TLS version, etc. Essential visibility when you first deploy MTA-STS in testing mode."
        }
      ]
    },
    "caa": {
      "title": "CAA — Certification Authority Authorization",
      "tagline": "Control which certificate authorities can issue SSL/TLS certs for your domain.",
      "sections": [
        {
          "h": "What is CAA?",
          "body": "CAA (Certification Authority Authorization) DNS records let you specify which Certificate Authorities (CAs) are permitted to issue SSL/TLS certificates for your domain. Without CAA records, any of the hundreds of trusted CAs worldwide can issue a certificate for your domain — without your knowledge or consent."
        },
        {
          "h": "Why it matters",
          "body": "Certificate misissuance has occurred historically through CA errors or compromises. A fraudulently issued certificate for your domain could be used to impersonate your website, intercept HTTPS traffic, or run phishing pages that show a padlock. CAA records give you a hard enforcement layer: CAs that support the standard must check your CAA records before issuing, and reject the request if they're not listed."
        },
        {
          "h": "How to set it up",
          "body": "Add CAA records naming your authorized CAs. Use <code>issue</code> for normal certificates and <code>issuewild</code> for wildcard certificates.",
          "code": "; Allow only Let's Encrypt:\n@    CAA    0 issue \"letsencrypt.org\"\n@    CAA    0 issuewild \"letsencrypt.org\"\n\n; Allow Let's Encrypt and DigiCert:\n@    CAA    0 issue \"letsencrypt.org\"\n@    CAA    0 issue \"digicert.com\"\n@    CAA    0 issuewild \"letsencrypt.org\"\n\n; Optional — receive a report when a CA rejects an issuance:\n@    CAA    0 iodef \"mailto:ssl-alerts@yourdomain.com\""
        },
        {
          "h": "Finding your CA",
          "body": "Click the padlock in your browser's address bar on your website to see which CA issued your current certificate. Common choices: <strong>Let's Encrypt</strong> (free, automated), <strong>DigiCert</strong>, <strong>Sectigo</strong>, <strong>GlobalSign</strong>. Your hosting provider or Cloudflare typically manage certificate issuance — check their documentation for the correct CA hostname to list."
        }
      ]
    },
    "dnssec": {
      "title": "DNSSEC — Domain Name System Security Extensions",
      "tagline": "Cryptographically sign your DNS records to prevent tampering and hijacking.",
      "sections": [
        {
          "h": "What is DNSSEC?",
          "body": "DNSSEC adds cryptographic signatures to your DNS records. When a resolver queries a DNSSEC-signed zone, it can verify that the response was signed by the legitimate zone owner and hasn't been altered in transit. Without DNSSEC, an attacker who can intercept or poison DNS responses can silently redirect your traffic anywhere."
        },
        {
          "h": "Why it matters",
          "body": "DNS cache poisoning attacks can redirect visitors from your real website to a malicious one, intercept email by hijacking your MX records, or corrupt your SPF/DKIM/DMARC lookups — all without touching your server. DNSSEC makes DNS responses cryptographically verifiable so these attacks fail."
        },
        {
          "h": "How to enable it",
          "body": "DNSSEC is enabled at your DNS provider — they manage the signing keys. Steps vary by provider:",
          "code": "Cloudflare:  DNS tab → DNSSEC → Enable (adds DS record automatically)\nGoDaddy:     DNS → DNSSEC → Activate DNSSEC\nRoute 53:    Hosted zone → DNSSEC signing → Enable\nPorkbun:     DNS → DNSSEC → Enable\nName.com:    DNS → DNSSEC → Enable signing",
          "body2": "After enabling at your DNS provider, copy the DS (Delegation Signer) record values they give you and add them at your domain <strong>registrar</strong>. The DS record at the registrar is what completes the chain of trust from the root DNS down to your zone."
        },
        {
          "h": "Critical warnings",
          "body": "⚠ <strong>If you change DNS providers</strong>, disable DNSSEC first, migrate all records, then re-enable. Failing to do this in order causes DNS failures worldwide.<br><br>⚠ <strong>The DS record at the registrar must exactly match</strong> the values your DNS provider gives you. A mismatch breaks DNS resolution for your entire domain."
        },
        {
          "h": "Testing",
          "body": "Verify your DNSSEC chain of trust at <a href=\"https://dnssec-analyzer.verisignlabs.com\" target=\"_blank\" rel=\"noopener\">dnssec-analyzer.verisignlabs.com</a> or visualize it at <a href=\"https://dnsviz.net\" target=\"_blank\" rel=\"noopener\">dnsviz.net</a>. A valid chain shows green at every level from root → TLD → your domain."
        }
      ]
    },
    "dmarc-rfc9989": {
      "title": "RFC 9989 — What changed in DMARC",
      "tagline": "DMARCbis was ratified in May 2026. Here is what it removed, what it added, and what you need to change.",
      "sections": [
        {
          "h": "DMARC is now a standard",
          "body": "For its first decade DMARC was RFC 7489, an <em>Informational</em> document — widely deployed but never formally standardised. In May 2026 the IETF published the replacement set: RFC 9989 (the core protocol), RFC 9990 (aggregate reporting) and RFC 9991 (failure reporting). Together they obsolete RFC 7489 and RFC 9091, and promote DMARC to Proposed Standard on the standards track. Splitting reporting into its own documents means the report formats can now evolve without reopening the core spec."
        },
        {
          "h": "pct= was removed",
          "body": "The <code>pct=</code> tag let you apply your policy to only a percentage of failing mail. It was intended as a rollout aid, but it produced unpredictable results in practice — receivers implemented the sampling differently, and a message’s fate depended on which server happened to handle it. RFC 9989 removes the tag entirely. Receivers implementing the new specification ignore it.",
          "body2": "The catch during the transition: receivers still running RFC 7489 continue to honour <code>pct=</code>. So a record with <code>pct=25</code> is now enforced in full by some receivers and throttled to a quarter by others, and you have no way to know the mix. That is a worse position than either behaviour on its own, which is why removing the tag is the right move even before every receiver migrates."
        },
        {
          "h": "t= replaces it for staged rollout",
          "body": "RFC 9989 adds a test-mode tag. <code>t=y</code> tells receivers that you are still evaluating and that your policy should <em>not</em> be applied — while aggregate reports keep flowing normally. It is unambiguous in a way <code>pct=</code> never was: either the policy is being enforced or it is not.",
          "code": "; Step 1 — publish your target policy in test mode:\n_dmarc    TXT    \"v=DMARC1; p=reject; t=y; rua=mailto:dmarc@yourdomain.com;\"\n\n; Step 2 — once reports show no legitimate mail failing, drop t=:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"",
          "body2": "Be aware that <code>p=reject; t=y</code> gives you exactly as much spoofing protection as <code>p=none</code> — which is none. Test mode is a stage to pass through, not a resting place. Any dashboard that reads only <code>p=</code> will report such a domain as fully enforced."
        },
        {
          "h": "The complete tag set",
          "body": "RFC 9989 defines exactly eleven tags: <code>v</code>, <code>p</code>, <code>sp</code>, <code>np</code>, <code>adkim</code>, <code>aspf</code>, <code>fo</code>, <code>rua</code>, <code>ruf</code>, <code>psd</code> and <code>t</code>. Anything else — including <code>pct</code>, <code>rf</code> and <code>ri</code> — must be ignored by receivers. Note that unknown tags are silently discarded, so a typo such as <code>rau=</code> instead of <code>rua=</code> costs you your report destination with no error anywhere.",
          "body2": "Two other rules are stricter than people expect. <code>v=</code> must be the <em>first</em> tag, and its value is case sensitive — only <code>DMARC1</code> is accepted, so <code>v=dmarc1</code> causes the whole record to be ignored."
        },
        {
          "h": "Reporting to an outside domain",
          "body": "If your <code>rua=</code> or <code>ruf=</code> destination is outside your organizational domain — a DMARC vendor, a consultant, a sister company — the receiving domain must publish a record authorising it. Without that record, conformant receivers discard your reports silently. Nothing bounces and nothing errors; you simply see less data than you should.",
          "code": "; Your record sends reports to a vendor:\n_dmarc.yourdomain.com    TXT    \"v=DMARC1; p=reject; rua=mailto:you@vendor.example;\"\n\n; The VENDOR must publish this in their own zone:\nyourdomain.com._report._dmarc.vendor.example    TXT    \"v=DMARC1\"",
          "body2": "Most established vendors publish this automatically, but it is the usual explanation when a newly-added reporting destination shows no data."
        },
        {
          "h": "What to do now",
          "body": "Remove <code>pct=</code> from your DMARC record. If you were mid-rollout and relying on it, publish your target policy with <code>t=y</code> instead, watch your aggregate reports until no legitimate sender is failing, then remove <code>t=</code>. While you are editing the record, check that <code>v=DMARC1</code> is first and correctly capitalised, that every tag name is spelled right, and that any external reporting destination has authorised you."
        }
      ]
    }
  },
  "score": {
    "label": "Security score",
    "outOf": "{0} / {1}",
    "unproven": "{0} / {1} — checks that could not be verified scored zero: {2}. Open this row to see how to recover those points.",
    "parkedNote": "Parked domain — scored on SPF, DMARC, DNSSEC and CAA only",
    "pillar": {
      "dmarc": "DMARC",
      "spf": "SPF",
      "dkim": "DKIM",
      "dnssec": "DNSSEC",
      "caa": "CAA",
      "mtaSts": "MTA-STS",
      "bimi": "BIMI",
      "tlsRpt": "TLS-RPT"
    },
    "dmarcParts": {
      "label": "DMARC breakdown",
      "policy": "Policy (p=)",
      "subdomain": "Subdomain coverage",
      "rua": "Aggregate reports (rua=)",
      "alignment": "Strict alignment",
      "ruf": "Forensic reports (ruf=)",
      "uris": "Report destinations"
    }
  },
  "mx": {
    "doesNotResolve": "does not resolve",
    "notChecked": "not checked",
    "cnameTarget": "CNAME target"
  },
  "caa": {
    "issuers": "Certificate authorities",
    "wildcard": "Wildcards",
    "iodef": "Report to",
    "none": "none",
    "blocksAll": "No certificate authority is authorized",
    "wildcardBlocked": "No wildcard certificates",
    "wildcardViaIssue": "governed by the issue set",
    "unknownCritical": "Unrecognized critical property"
  },
  "tlsa": {
    "published": "Published, not proven active — DANE protects a connection only when the TLSA record is carried by a validated DNSSEC chain. Each mail host below reports whether the resolver authenticated its own answer.",
    "notPublished": "not published",
    "notChecked": "not checked",
    "authenticated": "published · DNSSEC-authenticated",
    "unauthenticated": "published · not DNSSEC-authenticated"
  },
  "dnssec": {
    "status": "Status",
    "keys": "Keys",
    "ds": "DS records",
    "chain": "Evidence",
    "state": {
      "secure": "Signed, and validated by the resolver",
      "insecure": "Not signed",
      "unanchored": "Signed, but the parent publishes no DS record",
      "mismatch": "The DS record matches no key this zone publishes",
      "bogus": "Validation is failing",
      "indeterminate": "Could not be determined"
    },
    "flag": {
      "sep": "SEP flag",
      "revoke": "REVOKE flag"
    },
    "match": {
      "confirmed": "matches a published key",
      "no-matching-key": "no published key carries this tag",
      "digest-mismatch": "does not match the key carrying this tag",
      "unverifiable-digest-type": "this digest type cannot be computed here",
      "unverifiable": "could not be checked"
    },
    "source": {
      "resolver": "Resolver",
      "local": "Computed here"
    },
    "claim": {
      "authenticated": "reports this answer as authenticated",
      "notAuthenticated": "does not report this answer as authenticated",
      "resolver-bogus": "answers only when validation is disabled, so validation is failing",
      "resolver-unreachable": "did not return a usable answer",
      "link-checked": "one link checked: this zone’s DNSKEY against the parent’s DS record",
      "dsConfirms": "DS {0} matches a published key by {1}",
      "dsVerdict": "DS {0} {1}",
      "lookupIncomplete": "the {0} lookup did not complete ({1})"
    }
  },
  "finding": {
    "dmarc-enforcement-without-auth": {
      "msg": "DMARC is enforcing while SPF or DKIM authentication is not fully in place — your own mail can be rejected.",
      "what": "DMARC acts only when a message fails BOTH SPF and DKIM — either one passing, aligned, is enough for the message to pass. With one method missing, the other carries every message alone, so any legitimate mail it does not cover — a forwarded message, a new sending service, an unsigned path — fails DMARC outright and is rejected or quarantined under <code>p=reject</code> or <code>p=quarantine</code>. Enforcement must follow authentication, never lead it.",
      "fix": "Confirm that both SPF and DKIM pass for your legitimate senders — publishing whichever is not yet in place — and watch the DMARC aggregate reports until they do, before relying on enforcement.",
      "fixCode": "; Step 1 — authenticate (example for Google Workspace)\n@            TXT    \"v=spf1 include:_spf.google.com -all\"\nselector._domainkey  TXT  \"v=DKIM1; k=rsa; p=...\"\n\n; Step 2 — only once reports are clean, enforce\n_dmarc       TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain\""
    },
    "mx-dangling-with-enforcement": {
      "msg": "An MX host does not resolve while DMARC enforces: {0}.",
      "what": "A mail exchanger that returns no address accepts no mail. On a domain that enforces DMARC there is no permissive fallback to absorb the gap, so delivery to the affected host simply fails. This is an outage, not a hygiene note.",
      "fix": "Correct or remove the MX records that point at a host with no A/AAAA record, and confirm every remaining MX host resolves."
    },
    "dkim-weak-with-enforcement": {
      "msg": "DKIM signs with an RSA key at or below 1024 bits while DMARC enforces: {0}.",
      "what": "A 1024-bit RSA key is below the RFC 8301 minimum and can be factored by a well-resourced attacker, who could then forge signatures that pass your enforced DMARC policy — the exact outcome enforcement is meant to prevent.",
      "fix": "Rotate the affected selectors to a 2048-bit RSA key (or Ed25519), publish the new public key, and retire the weak selector once mail has moved to it."
    },
    "bimi-without-enforcement": {
      "msg": "BIMI is published but DMARC is not enforced, so no mailbox provider will show your logo.",
      "what": "BIMI requires an enforced DMARC policy (<code>p=quarantine</code> or <code>p=reject</code>). With <code>p=none</code> or test mode set, mailbox providers ignore the BIMI record entirely, so the effort of publishing a logo returns nothing.",
      "fix": "Move DMARC to enforcement first; the BIMI record then becomes eligible for display."
    },
    "bimi-without-authority": {
      "msg": "BIMI has no VMC authority (<code>a=</code>), so major mailbox providers will not display the logo.",
      "what": "Gmail and other large providers require a Verified Mark Certificate, referenced by the BIMI record's <code>a=</code> tag, before they will render a logo. A BIMI record with only <code>l=</code> is valid but will not display where a VMC is mandatory.",
      "fix": "Obtain a VMC for your registered trademark and add its HTTPS URL as the <code>a=</code> tag alongside the existing <code>l=</code>."
    },
    "mta-sts-without-tls-rpt": {
      "msg": "MTA-STS is published without TLS-RPT, so TLS enforcement failures go unreported.",
      "what": "MTA-STS tells sending servers to require TLS, but without TLS-RPT there is no channel for them to report when a connection could not be secured. You get the policy without the visibility into whether it is working.",
      "fix": "Publish a TLS-RPT record so senders send you a daily report of any TLS negotiation failures.",
      "fixCode": "; Report TLS failures to a mailbox you monitor\n_smtp._tls   TXT    \"v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain\""
    },
    "tls-rpt-without-transport-policy": {
      "msg": "TLS-RPT is published but there is no transport policy (no MTA-STS, no authenticated DANE) for it to report on.",
      "what": "TLS-RPT reports how well a transport security policy is being honoured. With neither MTA-STS nor a DNSSEC-authenticated TLSA record in place, there is no policy to enforce, so the reports describe best-effort TLS rather than a commitment.",
      "fix": "Publish MTA-STS (or DANE, if your MX zone is DNSSEC-signed) so the reporting has a policy to measure."
    },
    "spf-redundant-with-enforcement": {
      "msg": "SPF authorizes a large address block while DMARC enforces: {0}.",
      "what": "Authorizing a wide range of addresses in SPF means any host in that range can send mail that passes SPF and your enforced DMARC policy. On an enforcing domain the blast radius of a shared or compromised host in that block is your own domain's reputation.",
      "fix": "Narrow the SPF mechanism to the specific senders you use, replacing a broad block with individual includes or tighter CIDR ranges."
    },
    "defensive-contradictory": {
      "msg": "This domain declares it accepts no mail (null MX) yet its SPF authorizes senders — a contradictory configuration.",
      "what": "A null MX (<code>0 .</code>) states the domain receives no mail, which is a deliberate hardening choice. Publishing an SPF record that authorizes senders — or references <code>mx</code> — on the same domain communicates confusion rather than intent, and usually means nobody owns the configuration.",
      "fix": "Decide what the domain is for. A parked domain that sends nothing should publish <code>v=spf1 -all</code> and no permissive mechanism; a domain that does send should not carry a null MX.",
      "fixCode": "; A parked domain that neither sends nor receives\n@            TXT    \"v=spf1 -all\"\n@            MX     0 ."
    },
    "reporting-blind": {
      "msg": "No reporting is configured — neither DMARC rua nor TLS-RPT — so authentication and delivery failures are invisible to you.",
      "what": "Without a DMARC <code>rua=</code> destination you never see who is sending mail as your domain or whether authentication passes; without TLS-RPT you never see TLS delivery failures. Reporting is how a configuration is proven correct rather than assumed to be.",
      "fix": "Add a DMARC <code>rua=</code> address, and a TLS-RPT record if you run a transport policy, so failures reach a mailbox you monitor.",
      "fixCode": "_dmarc       TXT    \"v=DMARC1; p=none; rua=mailto:dmarc@yourdomain\"\n_smtp._tls   TXT    \"v=TLSRPTv1; rua=mailto:tlsrpt@yourdomain\""
    },
    "mta-sts-policy-invalid": {
      "msg": "The supplied MTA-STS policy is invalid: {0}.",
      "what": "These parser tokens identify fields or lines that do not conform to RFC 8461. A sender cannot safely apply the policy while any error remains.",
      "fix": "Correct every named error in the supplied policy, then analyze it again before publishing the file."
    },
    "mta-sts-policy-hygiene": {
      "msg": "The supplied MTA-STS policy is valid but needs review: {0}.",
      "what": "These warnings do not invalidate the policy, but they usually identify editor artifacts, duplicate fields, or misleading field-name case.",
      "fix": "Clean up the named warnings so the published policy is unambiguous to both operators and software."
    },
    "mta-sts-policy-mx-mismatch": {
      "msg": "The supplied MTA-STS policy covers none of these delivery hosts: {0}.",
      "what": "In enforce mode, a sender refuses delivery when the selected MX hostname matches no mx pattern in the policy. This is a mail-delivery outage waiting to happen.",
      "fix": "Add an exact hostname or a valid one-label wildcard for every published delivery candidate."
    },
    "mta-sts-policy-mx-unused": {
      "msg": "These MTA-STS mx patterns cover no current delivery host: {0}.",
      "what": "An unused pattern is usually a stale provider hostname left behind after migration. It does not break current delivery, but it authorizes a host you no longer use.",
      "fix": "Confirm the old provider is retired, then remove each unused mx line."
    },
    "mta-sts-policy-on-null-mx": {
      "msg": "A policy was supplied for a domain that explicitly accepts no mail.",
      "what": "A null MX states that the domain accepts no SMTP delivery. A mail-handling policy on the same domain contradicts that published intent.",
      "fix": "Keep the null MX and remove the policy if the domain is parked, or restore real MX records if it should receive mail."
    },
    "mta-sts-policy-mx-unknown": {
      "msg": "The policy's mx patterns could not be compared with delivery hosts.",
      "what": "The audit did not establish a complete set of delivery candidates, so claiming either a match or a mismatch would be guesswork.",
      "fix": "Resolve the DNS audit failure or publish usable MX or A/AAAA records, then run the audit and local comparison again."
    },
    "mta-sts-mode-testing": {
      "msg": "The supplied policy uses mode: testing, so senders report failures but do not enforce them.",
      "what": "Testing mode is a deployment stage. Mail still arrives when TLS or hostname validation fails, so it is not transport enforcement.",
      "fix": "Review TLS-RPT reports, correct every legitimate failure, then change the policy to mode: enforce."
    },
    "mta-sts-mode-none": {
      "msg": "The supplied policy uses mode: none and withdraws MTA-STS protection.",
      "what": "Mode none tells senders to stop enforcing the previous policy. It is appropriate during the RFC-defined removal process, not as an end state for a protected domain.",
      "fix": "Use mode: enforce for an active policy, or complete the documented staged removal if withdrawal is intentional."
    },
    "mta-sts-max-age-short": {
      "msg": "The supplied policy has a short max_age of {0} seconds.",
      "what": "A short cache lifetime makes senders refresh the policy frequently and reduces protection during a policy-host outage.",
      "fix": "Use a longer max_age after testing is complete; 86400 seconds is the minimum threshold this audit recommends."
    },
    "bimi-svg-rejected": {
      "msg": "The supplied BIMI SVG was rejected: {0}.",
      "what": "The named constructs are unsafe or outside the deliberately narrow local-validation boundary. The logo is not rendered and no parsed node is inserted into this page.",
      "fix": "Remove every named construct and export a self-contained SVG Tiny PS logo with no scripts, external references, DTD, or entity declaration."
    },
    "bimi-svg-profile": {
      "msg": "The supplied BIMI SVG has profile diagnostics: {0}.",
      "what": "The logo passed the security rejection screen, but the named SVG Tiny PS requirements may prevent mailbox providers from displaying it.",
      "fix": "Correct each named profile diagnostic, then validate against the complete SVG Tiny PS schema in your publishing workflow."
    },
    "bimi-svg-valid": {
      "msg": "The supplied BIMI SVG passed this local security and profile screen.",
      "what": "No named rejection or profile diagnostic was found. This is not full RNC-schema certification and does not guarantee acceptance by any mailbox provider.",
      "fix": "No change is required by this screen. Keep full schema validation and provider-specific checks in the publishing workflow."
    }
  },
  "findings": {
    "viewSeverity": "By severity",
    "viewRemediation": "By remediation step",
    "step": "Step {0}",
    "evidence": "Evidence",
    "showMore": "Show {0} more",
    "showLess": "Show less",
    "blocked": "Waiting on {0}",
    "unblocks": "Unblocks {0}",
    "severity": {
      "critical": "Critical",
      "high": "High",
      "medium": "Medium",
      "low": "Low",
      "info": "Info"
    },
    "confidence": {
      "confirmed": "Confirmed",
      "probable": "Probable",
      "unverified": "Unverified"
    },
    "category": {
      "authentication": "Authentication",
      "policy": "Policy",
      "reporting": "Reporting",
      "transport": "Transport",
      "issuance": "Issuance",
      "resilience": "Resilience",
      "hygiene": "Hygiene"
    },
    "effort": {
      "trivial": "Trivial",
      "moderate": "Moderate",
      "involved": "Involved"
    },
    "rationale": {
      "foundation": "Fix these first — everything else depends on them",
      "afterPrereq": "Once the prerequisites above are in place",
      "cleanup": "No dependencies — do these whenever"
    }
  },
  "compare": {
    "heading": "Comparing two reports",
    "baselineLabel": "Baseline: {0}",
    "currentLabel": "Current: {0}",
    "chooseBaseline": "Choose a saved report to compare against",
    "status": {
      "added": "New",
      "removed": "Removed",
      "improved": "Improved",
      "regressed": "Regressed",
      "changed": "Changed",
      "unchanged": "Unchanged",
      "incomparable": "Not comparable"
    },
    "reason": {
      "state": "The domain was audited in only one of the two reports",
      "noComparableProtocol": "Neither report observed any protocol both could be compared on",
      "options": "The two runs used different options",
      "analysisVersion": "The two reports were scored by different versions of the analysis",
      "onlyIncomparableMovement": "Everything that changed belongs to a protocol one report did not observe"
    },
    "protocol": {
      "unproven": "{0} was checked but not established",
      "notRun": "{0} was not checked",
      "unknownInBaseline": "Not comparable: {0} was not observed in the baseline report",
      "unknownInCurrent": "Not comparable: {0} was not observed in the current report",
      "unknownBoth": "Not comparable: {0} was checked with different options in the two reports"
    },
    "delta": {
      "up": "+{0}",
      "down": "{0}",
      "none": "No change",
      "notComparable": "Scores are not comparable",
      "grade": "{0} → {1}"
    },
    "findings": {
      "new": "{0} new",
      "resolved": "{0} resolved",
      "unknown": "{0} unknown",
      "severityChanged": "{0} changed severity",
      "baselineOnly": "In the baseline only",
      "currentOnly": "In the current report only"
    },
    "meta": {
      "versionsDiffer": "These reports came from different versions of this tool, so changes are shown without a verdict.",
      "optionsDiffer": "The two runs used different options: {0}.",
      "unknownFinding": "This build has no description for {0}."
    },
    "import": {
      "invalidJson": "This file is not valid JSON.",
      "notReport": "This file is not a report from this tool.",
      "newerVersion": "This report was made by a newer version of this tool. Update, then try again.",
      "tooLarge": "This file is too large to be a report from this tool.",
      "tooManyDomains": "This report covers more domains than one audit can produce.",
      "malformed": "This report has a field this build cannot read.",
      "at": "At {0}: {1}"
    }
  }
};
