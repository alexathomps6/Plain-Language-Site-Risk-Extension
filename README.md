# Plain-Language Site Risk Extension

A browser extension that condenses a dozen technical security signals into a single plain-language warning — shown at the moment it actually matters (when you're about to type a password or payment info), not as a badge nobody reads.

## The problem

Existing site-safety tools (Norton Safe Web, "This Website Safe to Access?", Safeonweb, and others) already exist and do a reasonable job of scoring a site. But they mostly fail the average or lazy-techie user in three ways:

1. **They output a number or letter grade** ("Score: 42", "Moderate risk"), which is exactly the kind of abstraction people tune out. Nobody knows what "58/100" means for their actual safety.
2. **They score the page, not the moment.** A badge on every page load trains people to ignore it. The real risk moment is when you're about to *type something sensitive* into that page.
3. **HTTP vs. HTTPS is a weak signal on its own.** Most phishing sites use HTTPS today (free certificates are trivial to get), so a tool that leans heavily on the lock icon is checking the wrong thing.

There's a fourth failure mode that matters even more: **reputation tools only look at the domain, not the page.** A brand-new phishing kit on a clean-looking domain passes every WHOIS and blocklist check for the first few hours of its life — which is exactly the window it operates in. To catch that, you have to look at what the page is actually *showing* the user and where it's actually *sending* their data.

## The idea

Three differentiators from what's already out there:

- **Plain language over scores.** Instead of "Score: 42," say "This site can read anything you type here, including your password" or "This site was registered 3 days ago and is not the real PayPal."
- **Context-aware, action-triggered.** The popup fires when the user focuses a password or payment field on a flagged site — especially one they just arrived at via an SMS link, email link, or QR code — not on every page load.
- **Look at the page, not just the domain.** Inspect the rendered HTML the user is actually looking at and the network traffic the page generates, then let an LLM reconcile *what the page claims to be* against *what it's actually doing*.

## What it checks

### Tier 1 — Domain and transport signals (cheap, local/cached)

Beyond HTTP/HTTPS, the extension combines:

- **Domain age** (WHOIS/RDAP) — a domain registered days ago pretending to be a bank is a strong red flag
- **Blocklist reputation** (Google Safe Browsing / PhishTank) — has this domain already been reported for phishing or malware
- **Homograph / typosquat distance** — how close the domain is to a well-known brand (`paypa1.com`, `rnicrosoft.com`)
- **TLD risk** — some TLDs (`.zip`, `.top`, `.tk`, `.click`) have far higher abuse rates than `.com`/`.org`/`.gov`
- **Certificate age and issuer** — a cert issued yesterday is less reassuring than one with a long history
- **Referrer context** — did the user arrive via a typed URL/bookmark, or via a link from an SMS, email, or QR code moments ago

### Tier 2 — Rendered page inspection (what the user is actually looking at)

The content script reads the live DOM at the moment a sensitive field is focused. This catches brand-new kits that no blocklist has seen yet:

- **Brand claim extraction** — page title, `<h1>`, favicon, logo `<img>` sources and `alt` text, visible brand names in copy. A page that presents itself as "Chase" while sitting on `secure-acct-verify.top` is a direct contradiction.
- **Form destination mismatch** — does `<form action>` (or a `formaction` override on the submit button) post to a different origin than the page? Credentials leaving to a third party is one of the single strongest phishing signals available.
- **Field inventory vs. plausibility** — a "login" page asking for password *and* full card number *and* CVV *and* date of birth *and* SSN is not a login page. Detected via `type`, `name`, `autocomplete` tokens (`cc-number`, `cc-csc`), and label text.
- **Overlay and iframe trickery** — cross-origin iframes layered over the login area, fake address-bar or padlock images rendered into the page, high-`z-index` transparent capture layers, off-screen or `opacity: 0` inputs shadowing the visible ones.
- **Keystroke capture detection** — listeners bound to `keyup`/`input` on password fields that fire network calls, `paste` handlers on card fields, or fields whose value is mirrored into a hidden input.
- **Obfuscation and evasion** — heavily packed or base64-blob inline scripts, `eval`/`Function()` construction, form actions injected at runtime rather than present in markup, anti-devtools or right-click blocking.
- **Structural clone similarity** — DOM skeleton and stylesheet fingerprint compared against known brand login pages; a pixel-perfect clone of a bank login on an unrelated domain is meaningful even before anything else fires.
- **Copy quality and pressure language** — urgency, deadlines, account-suspension threats, translated-sounding phrasing. Weak on its own, useful as LLM input.

### Tier 3 — Network traffic inspection (where the data actually goes)

Using the extension's observational `webRequest` access, the extension watches request *metadata* generated by the page — never bodies:

- **Submission endpoint origin** — the actual host the credential POST is destined for, including raw-IP hosts, mismatched TLDs, and known exfil/paste services
- **Redirect chain reconstruction** — the full hop path from the SMS/QR/email link to the final page: link shorteners, open redirects on legitimate domains, and cloaking redirects that serve different content to different visitors
- **Third-party script and beacon origins** — which hosts the page pulls executable code from, and whether they resemble legitimate CDNs or one-off hosts registered alongside the domain
- **Exfil-shaped traffic** — small `fetch`/XHR/`sendBeacon` calls fired while the user is still typing, before any submit event, especially to an origin other than the page's own
- **WebSocket and long-poll channels** — live channels opened on a login page, which real-time credential-relay kits use to forward input to an operator instantly
- **Per-connection TLS details** — issuer, age, and whether subresource origins share the page's certificate lineage

### Tier 4 — LLM adjudication (turning signals into a sentence)

The deterministic tiers produce *evidence*. An LLM turns that evidence into the product's actual output: one plain sentence explaining why. It runs on the backend, only when Tiers 1–3 produce something worth escalating.

**Input (sanitized, structural only):** DOM skeleton, visible text, extracted brand claims, form action origins, field inventory, script origins, request-origin list, redirect chain, and the Tier 1 domain facts. No input values, no typed characters, no cookies, no tokens — stripped and redacted client-side before the request leaves the browser.

**The two questions it answers:**

1. *What is this page presenting itself as?* — brand identification from rendered content, which is fuzzy pattern-matching that rules handle badly and an LLM handles well.
2. *Does the page's behavior contradict that claim?* — "it says Chase, it posts credentials to an origin in a different country, the domain is 4 days old, and it opened a WebSocket while you were typing."

**Output (constrained JSON schema):**

```json
{
  "claimed_brand": "Chase",
  "brand_confidence": 0.91,
  "verdict": "dangerous",
  "contradictions": [
    "credential form posts to an unrelated third-party origin",
    "domain registered 4 days ago",
    "live WebSocket opened before form submission"
  ],
  "plain_language_message": "This page is pretending to be Chase, but anything you type here gets sent to someone else's server as you type it.",
  "evidence_refs": ["form_action_mismatch", "domain_age", "websocket_on_login"]
}
```

**Guardrails:**

- **Deterministic signals win.** The LLM can escalate and can explain, but it cannot downgrade a hard signal — a Safe Browsing hit stays dangerous regardless of what the model says.
- **Gated invocation.** The LLM is not called on every page load. Tier 1–3 must produce a trigger first, which keeps cost, latency, and data exposure down.
- **Schema-constrained output only.** Free-form model prose never reaches the user; the `plain_language_message` field is validated for length and rendered into a fixed card.
- **Every claim cites evidence.** `evidence_refs` must map to signals that actually fired, so the warning can't be a hallucination dressed as a finding.
- **Structural cache.** Results are keyed on a hash of the page's structural fingerprint, so re-visiting or re-focusing doesn't re-invoke the model.
- **On-device option.** A small local model can handle brand extraction and message generation for privacy-sensitive deployments, with the hosted model reserved for ambiguous cases.

See `IMPLEMENTATION.md` for how each of these is checked and how they combine into the plain-language message.

## Tech stack

- **Browser extension** (Manifest V3)
  - *Content script* — watches for password/payment field focus, reads page context (URL, referrer, certificate info), and extracts the sanitized DOM/brand/form/field summary
  - *Background service worker* — observational `chrome.webRequest` listeners for redirect chains, request origins, and beacon/WebSocket activity; holds the per-tab evidence buffer
- **Backend API** (Node/Express or Python/Flask) — proxies WHOIS, Safe Browsing, and homograph-distance checks, runs the LLM adjudication step, and caches results (keeps API keys off the client)
- **LLM layer** — hosted model with JSON-schema-constrained output for brand identification, contradiction reasoning, and plain-language message generation; optional on-device small model for the privacy-sensitive path
- **Popup UI** — plain-language warning card, not a score

## Quick start

1. Load the unpacked extension in Chrome/Edge developer mode.
2. Deploy the backend (or run locally) with API keys for Google Safe Browsing, a WHOIS/RDAP provider, and your LLM provider.
3. Visit a flagged test site and focus a password field to see the popup.

## Demo script

1. Visit a normal, long-established site (e.g. your bank's real login page) and focus the password field — no popup, or a quiet "looks fine" confirmation.
2. Visit a freshly registered look-alike domain (register a throwaway test domain or use a known phishing sample from PhishTank's test set) and focus the password field — plain-language warning appears explaining *why* in one sentence.
3. Simulate the context-aware case: open the flagged site via a link (not a direct visit) to show the referrer-context risk bump in the warning text.
4. **Show the page-inspection catch:** serve a local clone of a real brand login page from a domain with no blocklist or WHOIS red flags, with its form posting to a different origin. Tier 1 says nothing; Tier 2 and 3 catch it, and the warning names the brand it's imitating and where the data is actually going.
5. **Show the traffic catch:** on that same page, wire a keystroke handler that beacons out on every keypress. Start typing into the password field and show the warning updating to "this page is sending what you type as you type it."

## Privacy notes

Inspecting page content and network traffic is a meaningful expansion of what the extension sees, so the boundaries are drawn explicitly:

- **Never leaves the browser:** form values, typed characters, clipboard contents, cookies, `localStorage`, auth tokens, or full page HTML.
- **What is sent for Tier 2/3 analysis:** a structural summary only — DOM skeleton with text nodes truncated, visible headings and brand strings, form action origins, field types and `autocomplete` tokens, script/request origins, and the redirect chain. Input `value` attributes are stripped and URL query strings are dropped or hashed before anything leaves the client.
- **Traffic inspection is metadata-only:** origins, methods, timing, and resource types. Request and response bodies are never read or transmitted.
- **Tier 2/3 run only on escalation,** not on every page. Sites the user visits routinely and that have cleared the checks are cached client-side and never re-analyzed server-side.
- **LLM input is redacted before transmission** and is not retained or used for training; retention should be zero-day or the shortest the provider supports.
- **Local-first is the goal:** every Tier 2 check is a deterministic DOM inspection that runs entirely in the browser. Only the adjudication step needs a backend, and an on-device model removes even that.

## Status / scope

This is a hackathon proof of concept. See `IMPLEMENTATION.md` for known limitations. In particular:

- Tier 2 visual/clone detection is implemented as DOM-structure comparison, not screenshot perceptual hashing — the latter is more robust but too heavy for a one-day build.
- Tier 3 traffic inspection is observational only. MV3 removed blocking `webRequest` for extensions, so the extension warns rather than intercepts; actual blocking would require `declarativeNetRequest` rules.
- LLM latency is the main UX risk. The gating and caching described above exist to keep the common path entirely local; an LLM round trip on every password focus would not be shippable.
- Adversarial evasion against DOM inspection (rendering login forms entirely in canvas, shadow DOM obfuscation) is a known gap.
