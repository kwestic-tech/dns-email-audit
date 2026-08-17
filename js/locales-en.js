/* AUTO-GENERATED — DO NOT EDIT.
 * Source: locales/en.json
 * Regenerate with: npm run build:fallback
 *
 * English is inlined here so the app works when index.html is opened directly
 * from disk (file://), where fetching locales/*.json is blocked by the browser.
 */
window.__I18N_EN__ = {
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
    "subtitle": "· free · no signup · no data leaves your browser",
    "langTitle": "Language"
  },
  "btn": {
    "howItWorks": "📖 How it works",
    "exportCsv": "⬇ Export CSV",
    "exportHtml": "⬇ Export Report",
    "runAudit": "🔎 Run Audit",
    "auditRunning": "Auditing…",
    "uploadFile": "📄 Upload .txt file",
    "loadExamples": "Load examples",
    "clearResults": "🗑 Clear results",
    "learnMore": "Learn more →"
  },
  "input": {
    "heading": "Enter domains to audit",
    "desc": "One domain per line, or upload a .txt file. Up to 200 domains at once.",
    "placeholder": "example.com\nmycompany.org\nanother-domain.net"
  },
  "opt": {
    "dkim": "Check DKIM selectors",
    "www": "Detect website hosting",
    "wildcard": "Detect wildcard TXT bugs",
    "footer": "DNS via Cloudflare DoH · No data stored"
  },
  "help": {
    "title": "How it works:",
    "body": "Runs entirely in your browser via the <a href=\"https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/\" target=\"_blank\" rel=\"noopener\">Cloudflare DNS-over-HTTPS API</a> — no data leaves your machine. Checks: NS (DNS provider), MX (email provider), SPF, DKIM (10 common selectors), DMARC, BIMI, MTA-STS, TLS-RPT, CAA, DNSSEC, and SPF lookup depth. To self-host, clone the repository and drop it on GitHub Pages, Netlify, or Cloudflare Pages — no build step required."
  },
  "netbanner": {
    "title": "⚠️ Network access blocked — DNS queries cannot reach the internet from here",
    "body": "This app uses the <code>cloudflare-dns.com</code> DNS-over-HTTPS API, which is blocked when the page is running inside a sandboxed iframe (e.g. an AI assistant's built-in preview panel). To use the auditor, serve the folder over HTTP or host it on any free static site:<br><br>• <strong>Quickest:</strong> Drag the project folder onto <a href=\"https://app.netlify.com/drop\" target=\"_blank\" rel=\"noopener\">app.netlify.com/drop</a> → live URL in ~60 seconds.<br>• <strong>Own domain:</strong> Deploy to <a href=\"https://pages.cloudflare.com\" target=\"_blank\" rel=\"noopener\">Cloudflare Pages</a> or <a href=\"https://pages.github.com\" target=\"_blank\" rel=\"noopener\">GitHub Pages</a> for free.<br>• <strong>Locally:</strong> Run <code>npx serve</code> (or <code>python3 -m http.server</code>) inside the project folder."
  },
  "progress": {
    "heading": "Querying DNS records…",
    "querying": "Querying {0}…",
    "error": "Error on {0}: {1}"
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
    "hosting": "Hosting"
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
    "noDnssec": "No DNSSEC"
  },
  "empty": {
    "text": "No domains match your filter."
  },
  "footer": {
    "text": "DNS-over-HTTPS via <a href=\"https://cloudflare-dns.com\" target=\"_blank\" rel=\"noopener\">Cloudflare</a> &bull; All queries run in your browser &bull; No data stored or transmitted &bull; Free to use &amp; self-host"
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
    "wildcardTitle": "⚠ Wildcard TXT Bug",
    "wildcardText": "A wildcard TXT record is returning data for ALL subdomains. This breaks DMARC and DKIM. Log into your DNS provider and delete the * TXT record.",
    "status": "Status",
    "none": "None",
    "na": "N/A",
    "dash": "—"
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
    "wildcardBug": "⚠ Wildcard Bug"
  },
  "badge": {
    "notRegistered": "Not registered / NXDOMAIN",
    "noEmail": "✗ No Email",
    "noDkim": "✗ None"
  },
  "provider": {
    "unknown": "Unknown",
    "custom": "Custom",
    "customUnknown": "Custom/Unknown",
    "selfHosted": "Self-hosted",
    "none": "None",
    "noWebPresence": "No web presence",
    "cnameLoop": "⚠ CNAME Loop",
    "cloudflareProxied": "Cloudflare (proxied)",
    "porkbunForwarding": "Porkbun Forwarding"
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
    "permerror": "🔴 Permerror"
  },
  "dmarc": {
    "missing": "✗ Missing",
    "reject": "✓ reject",
    "quarantine": "✓ quarantine",
    "none": "⚠ none (monitor)",
    "set": "✓ Set",
    "invalid": "⚠ Invalid p=",
    "pctSuffix": "({0}%)",
    "permerror": "🔴 Multiple records"
  },
  "dkim": {
    "noteWildcard": "Wildcard TXT bug may be interfering",
    "noteNotFound": "No common selectors found"
  },
  "adv": {
    "configured": "✓ Configured",
    "notConfigured": "Not configured",
    "tip": {
      "bimiOn": "Record: {0}",
      "bimiOff": "Not configured — display your logo in Gmail & Apple Mail",
      "mtaStsOn": "Configured — TLS forced on inbound delivery",
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
    "csvExported": "CSV exported",
    "htmlExported": "HTML report exported",
    "htmlExportFailed": "Could not build the standalone report — serve the app over HTTP and try again.",
    "fileLoaded": "Loaded {0}",
    "examplesLoaded": "Examples loaded — click Run Audit",
    "auditDone": {
      "one": "✅ Audit complete — {0} domain analyzed",
      "other": "✅ Audit complete — {0} domains analyzed"
    },
    "langChanged": "Language changed",
    "langFailed": "Could not load that language — staying on English."
  },
  "csv": {
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
      "Suggestions"
    ],
    "yes": "Yes",
    "no": "No",
    "yesAt": "Yes ({0})"
  },
  "report": {
    "title": "DNS & Email Security Audit Report",
    "generated": "Generated {0} · {1} domains",
    "note": "Static report generated by the DNS & Email Security Auditor. No data was transmitted or stored."
  },
  "issue": {
    "wildcard-txt": {
      "msg": "Wildcard TXT (* TXT) found — breaks DMARC and DKIM lookups for all subdomains. Delete immediately.",
      "what": "A wildcard TXT record (<code>* IN TXT \"...\"</code>) makes your DNS server return data for <em>any</em> subdomain query — even ones you haven't explicitly defined. DKIM validators look up selectors like <code>google._domainkey.yourdomain.com</code> and DMARC validators look up <code>_dmarc.yourdomain.com</code>. Instead of getting \"no record found,\" they get the wildcard result, which breaks authentication for every subdomain.",
      "fix": "Log in to your DNS provider and delete any TXT record whose hostname is <code>*</code> (asterisk). There is almost never a legitimate reason to have a wildcard TXT record.",
      "fixCode": "; Delete this record from your DNS zone:\n*    IN TXT    \"whatever value is here\""
    },
    "dns-loop": {
      "msg": "www CNAME points back to root — DNS loop, website unreachable.",
      "what": "Your <code>www</code> CNAME record points back to the root domain (e.g. <code>www CNAME yourdomain.com</code>), which then tries to resolve <code>www</code> again — creating an infinite loop. Visitors attempting to load your website receive a DNS error and can't reach it.",
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
      "msg": "Multiple SPF records found — SPF fails permanently (permerror) for all mail from this domain.",
      "what": "RFC 7208 §4.5 allows exactly one <code>v=spf1</code> TXT record per domain. When a receiver finds two, it returns <code>permerror</code> and stops — it does not merge them, and it does not pick the stricter one. The practical effect is worse than having no SPF at all: your record looks correct in the DNS panel, but every message from your domain fails SPF authentication. This usually happens when a second mail service is onboarded and adds its own record instead of editing the existing one.",
      "fix": "Merge the records into one. Take every <code>include:</code>, <code>ip4:</code> and <code>ip6:</code> mechanism from all records, put them in a single <code>v=spf1</code> record, and delete the others. Watch the 10-lookup limit while merging — combining records is a common way to exceed it.",
      "fixCode": "; Before — two records, SPF fails for everything:\n@    TXT    \"v=spf1 include:_spf.google.com -all\"\n@    TXT    \"v=spf1 include:sendgrid.net -all\"\n\n; After — one record with both senders:\n@    TXT    \"v=spf1 include:_spf.google.com include:sendgrid.net -all\""
    },
    "dmarc-multiple-records": {
      "msg": "Multiple DMARC records found at _dmarc — DMARC is not applied at all, the domain can be spoofed.",
      "what": "RFC 7489 §6.6.3 requires exactly one DMARC record. Receivers discard anything without a <code>v=DMARC1</code> tag, and if more than one remains, policy discovery terminates and DMARC is not applied to the message. Your policy — however strict — is ignored entirely, so the domain is spoofable while appearing to be protected. You will also stop receiving aggregate reports, which removes the signal that would have told you something was wrong.",
      "fix": "Delete all but one TXT record at <code>_dmarc</code>. If the duplicates specify different report addresses, keep one record and list both addresses in a single <code>rua=</code> tag, separated by a comma.",
      "fixCode": "; Before — two records at _dmarc, DMARC ignored:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n_dmarc    TXT    \"v=DMARC1; p=none; rua=mailto:reports@vendor.example;\"\n\n; After — one record, both report destinations:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com,mailto:reports@vendor.example;\""
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
      "fixCode": "; Step 1 — quarantine (sends failing mail to spam):\n_dmarc    TXT    \"v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@yourdomain.com;\"\n\n; Step 2 — reject (blocks failing mail entirely):\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-quarantine": {
      "msg": "DMARC p=quarantine sends spoofed mail to spam but still delivers it. p=reject is the end state.",
      "what": "Your DMARC policy is <code>p=quarantine</code>, which is genuine enforcement — mail that fails authentication gets routed to the spam folder rather than the inbox. But it is still <em>delivered</em>. A convincing phishing message impersonating your domain remains one click away in a folder people do check, and some receivers apply quarantine inconsistently. <code>p=reject</code> instructs receiving servers to refuse the message outright, so it never reaches the recipient at all.",
      "fix": "Review your DMARC aggregate reports (<code>rua=</code>) over a few weeks and confirm every legitimate sending source is passing SPF or DKIM alignment. Once no genuine mail is failing, change the policy to <code>p=reject</code>. If you're cautious, ramp with <code>pct=</code> — apply reject to a percentage of failing mail first, then raise it to 100.",
      "fixCode": "; Current policy — failing mail goes to spam:\n_dmarc    TXT    \"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com;\"\n\n; Optional ramp — reject 25% of failing mail, quarantine the rest:\n_dmarc    TXT    \"v=DMARC1; p=reject; pct=25; rua=mailto:dmarc@yourdomain.com;\"\n\n; End state — reject all failing mail:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\""
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
      "msg": "DMARC pct={0} — your policy applies to only {0}% of failing mail; the other {1}% is delivered normally.",
      "what": "The <code>pct=</code> tag throttles how much failing mail your policy applies to. At <code>pct={0}</code>, receivers apply your policy to {0}% of messages that fail authentication and fall back to the next weaker action for the remaining {1}% — so a spoofed message has roughly a {1} in 100 chance of landing in the inbox untouched. <code>pct=</code> is a rollout tool for safely ramping enforcement, not a resting state.",
      "fix": "Check your DMARC aggregate reports to confirm no legitimate senders are failing, then remove <code>pct=</code> entirely (it defaults to 100) or set it to 100.",
      "fixCode": "; Remove pct= — defaults to 100:\n_dmarc    TXT    \"v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com;\"\n\n; Or state it explicitly:\n_dmarc    TXT    \"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@yourdomain.com;\""
    },
    "dmarc-bad-pct": {
      "msg": "DMARC pct= value is not a valid number between 0 and 100 — receivers may ignore it or your whole record.",
      "what": "The <code>pct=</code> tag must be an integer from 0 to 100. Yours isn't, which means receiving mail servers may ignore the tag, or reject the entire DMARC record as malformed and treat your domain as having no policy at all. A record that looks correct in your DNS panel but doesn't parse gives you the illusion of protection without the substance.",
      "fix": "Correct the value to an integer between 0 and 100, or remove the tag — it defaults to 100, which is what you want in almost every case.",
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
    }
  },
  "suggestion": {
    "bimiEligible": "BIMI-eligible: DMARC is enforced and DKIM is configured. Add a default._bimi TXT record with your SVG logo URL to display your brand logo in Gmail & Apple Mail.",
    "bimiPrereq": "BIMI (logo in inbox): requires DMARC at p=quarantine or p=reject + DKIM. Get those in place first, then add BIMI.",
    "mta-sts": "MTA-STS not configured. Publishing a _mta-sts TXT record and hosting a policy file forces TLS on inbound mail delivery, preventing downgrade attacks.",
    "tls-rpt": "TLS-RPT (_smtp._tls TXT) not configured. This companion to MTA-STS sends you reports when TLS negotiation fails — easy to add, zero downside.",
    "caa": "No CAA records — any certificate authority can issue SSL certs for this domain. Add CAA records naming only your preferred CA (e.g. Let's Encrypt, DigiCert).",
    "dnssec": "DNSSEC not detected. Signing your DNS records prevents cache poisoning and MX hijacking. Cloudflare and most modern DNS providers enable this with one click."
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
    }
  },
  "score": {
    "label": "Security score",
    "outOf": "{0} / {1}",
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
      "pct": "Enforcement rate (pct=)",
      "rua": "Aggregate reports (rua=)",
      "alignment": "Strict alignment",
      "ruf": "Forensic reports (ruf=)"
    }
  }
};
