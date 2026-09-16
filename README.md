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
- **Context-aware, action-triggered.** The popup fires when the user focuses a password or payment field on a flagged site — especially one they just arrived at by following a link rather than typing the address — not on every page load. (A browser extension can see that the user arrived from another page; it cannot see that the link came from SMS, email, or a QR code. See the limitations note below.)
- **Look at the page, not just the domain.** Inspect the rendered HTML the user is actually looking at and the network traffic the page generates, then reconcile *what the page claims to be* against *what it's actually doing*.

## What it checks

### Tier 1 — Domain and transport signals (cheap, local/cached)

Beyond HTTP/HTTPS, the extension combines:

- **Domain age** (RDAP) — a domain registered days ago pretending to be a bank is a strong red flag. RDAP is an open protocol, not a vendor API, so this needs no key and no backend
- **Blocklist reputation** — has this domain already been reported for phishing or malware. Uses a keyless CC0 community feed, bundled as a snapshot and refreshed in the background
- **Homograph / typosquat distance** — how close the domain is to a well-known brand (`paypa1.com`, `rnicrosoft.com`)
- **TLD risk** — some TLDs (`.zip`, `.top`, `.tk`, `.click`) have far higher abuse rates than `.com`/`.org`/`.gov`
- **Referrer context** — did the user arrive via a link from another site, or by typing the URL / using a bookmark

**Why there is no certificate check.** An earlier version of this list promised certificate age and issuer. Chrome exposes no way for an extension to read one: Firefox has `webRequest.getSecurityInfo()`, but the Chrome equivalent is still only a [proposal](https://github.com/w3c/webextensions/issues/882). The one working route is `chrome.debugger` with `Network.getCertificate`, which pins a *"… started debugging this browser"* infobar to every tab — not a reasonable ask from a tool whose entire pitch is being trustworthy. It is left out rather than faked.

### Tier 2 — Rendered page inspection (what the user is actually looking at)

The content script reads the live DOM at the moment a sensitive field is focused. This catches brand-new kits that no blocklist has seen yet. The first two are built today; the rest are roadmap (see Status / scope):

- **Brand claim extraction** — page title, `<h1>`, favicon, logo `<img>` sources and `alt` text, visible brand names in copy. A page that presents itself as "Chase" while sitting on `secure-acct-verify.top` is a direct contradiction. *(Built, against a known-brand list.)*
- **Form destination mismatch** — does `<form action>` (or a `formaction` override on the submit button) post to a different origin than the page? Credentials leaving to a third party is one of the single strongest phishing signals available. *(Built.)*
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
- **Subresource origin lineage** — whether the hosts a page pulls code from look related to the page itself or were stood up alongside it (certificate issuer and age are deliberately excluded here for the reason given under Tier 1)

### Tier 4 — Message generation (deterministic, on the critical path)

The tiers above produce *evidence*. Tier 4 turns evidence into the product's actual output: one plain sentence. This runs locally, in single-digit milliseconds, with no network call.

Messages come from a priority-ordered template set — roughly twenty slot-filled sentences covering the realistic signal combinations, with the most severe contradiction leading:

| Triggering evidence | Rendered message |
|---|---|
| Form posts to a different origin | "Anything you type here goes to someone other than {claimed_brand}." |
| Beacon fires on keystroke | "This page is sending what you type as you type it, before you ever hit submit." |
| Young domain + brand mismatch | "This site was registered {age} ago and is not the real {claimed_brand}." |
| Blocklist hit | "This page has already been reported for stealing passwords." |
| Overlay over credential field | "The box you're typing into isn't part of this page — something is layered over it." |

Rules for this layer:

- **Same evidence always produces the same message.** Verdicts are reproducible and explainable after the fact, which matters when a user asks "why did it warn me?"
- **Every message names the signals that fired,** viewable in the popup's detail expander.
- **It works with the network off.** No dependency can prevent a warning from rendering.

See `IMPLEMENTATION.md` for how each of these is checked and how they combine into the plain-language message.

## The LLM question

Worth answering deliberately, because an LLM is the obvious thing to reach for here and it's the wrong tool for the main job.

**Detection is not an LLM problem.** Every signal that actually catches phishing — form posts cross-origin, domain registered days ago, beacon fires on keypress, cert issued yesterday — is a deterministic check. Rules are faster, free, auditable, work offline, and cannot make things up. In a security tool a false "looks fine" is catastrophic, and a false alarm on a real bank login trains the user to dismiss the popup, which is precisely the failure mode this project exists to fix.

**Latency rules it out of the hot path.** The trigger is password-field focus; there's roughly 300ms before the user starts typing. A model round trip is 1–3 seconds. A warning that arrives after the password is already typed has failed, no matter how well written it is.

So the LLM sits in two places, neither of them blocking.

### Build time — generating the rules

The clearest win, and it costs nothing at runtime:

- Generate brand fingerprints for the top few hundred phished services (title patterns, logo/favicon hashes, characteristic DOM structures)
- Mine phishing corpora for recurring copy patterns and urgency phrasing, and distill them into matchable rules
- Draft and stress-test the Tier 4 message templates for tone and reading level

All of this is reviewed by a human before it ships. Zero latency, zero per-user cost, zero privacy exposure, no runtime hallucination risk.

### Runtime — asynchronous enrichment (optional)

When Tiers 1–3 fire, the deterministic warning renders immediately from a template. *In parallel*, if the evidence is ambiguous or no template matches well, a backend call may run. If it returns, it upgrades the card text in place; if it's slow, errors, or is disabled entirely, the user already has a correct warning.

Its narrow job is the one thing rules genuinely handle badly: **"what brand is this page impersonating?"** — fuzzy identification from rendered content that doesn't match any known fingerprint.

**Input (sanitized, structural only):** DOM skeleton, visible text, extracted brand claims, form action origins, field inventory, script origins, request-origin list, redirect chain, and the Tier 1 domain facts. No input values, no typed characters, no cookies, no tokens — stripped and redacted client-side before the request leaves the browser.

**Output (constrained JSON schema):**

```json
{
  "claimed_brand": "Chase",
  "brand_confidence": 0.91,
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

- **It can only escalate, never downgrade.** The model cannot clear a site. A blocklist or form-mismatch hit stays dangerous regardless of what it returns.
- **Never blocking.** The UI never waits on it. A timeout is a no-op, not a degraded experience.
- **Schema-constrained output only.** Free-form prose never reaches the user; `plain_language_message` is length-validated and rendered into the same fixed card.
- **Every claim cites evidence.** `evidence_refs` must map to signals that actually fired, so a warning can't be a hallucination dressed up as a finding.
- **Structural cache.** Results are keyed on a hash of the page's structural fingerprint, so revisiting or re-focusing never re-invokes the model.
- **Fully removable.** With the enrichment path disabled the extension still detects and still explains — it just falls back to template phrasing.

## Tech stack

- **Browser extension** (Manifest V3)
  - *Content script* — watches for password/payment field focus, reads page context (URL, referrer, transport), runs the local checks, and renders the warning card
  - *Background service worker* — owns the three lookups a content script cannot do itself: `chrome.history` for first-visit, the cross-origin RDAP fetch for domain age, and the bundled blocklist. *(Roadmap: observational `chrome.webRequest` listeners for redirect chains, request origins and beacon/WebSocket activity, holding a per-tab evidence buffer.)*
- **No backend.** Every check ships in the extension. Domain age goes straight to RDAP, an open protocol with no key and no account; blocklist reputation comes from a bundled CC0 feed snapshot that refreshes itself in the background. A server is only needed if the optional enrichment call below is switched on
- **Detection and messaging** — deterministic rules and slot-filled templates, running entirely in the content script; no network dependency for a warning to render
- **LLM (off the critical path)** — used at build time to generate brand fingerprints, copy-pattern rules, and message templates; optionally at runtime as a non-blocking enrichment call for brand identification, with JSON-schema-constrained output. The extension is fully functional with it disabled.
- **Popup UI** — plain-language warning card, not a score

## Quick start

1. Load the unpacked extension in Chrome/Edge developer mode.
2. Visit a flagged test site and focus a password field to see the popup.

There is no step 3. No API keys, no server, no build step — every check runs
from the loaded extension. `./tests/run.sh` exercises the whole signal set in
headless Chrome/Edge without touching the network.

## Demo script

Scripted pages live in `demo-pages/`; see `DEMO.md` for the full walkthrough.

1. **Nothing to say about a good site.** Visit a normal, long-established site and focus the password field — a quiet "looks fine" toast that dismisses itself. (`demo-pages/1-safe-bank.html`)
2. **The look-alike.** A domain two characters off a known brand, registered days ago — one sentence naming the brand and the age. (`demo-pages/2-phishing-typosquat.html`)
3. **Known-bad fires without waiting.** A blocklisted domain warns on page load, before any interaction, because some attacks never need the user to type anything. (`demo-pages/3-known-bad-blocklist.html`)
4. **Real domain age, live.** Focus a password field on any real site and watch the service worker log an actual RDAP registration date. Then turn the network off and do it again — the warning still renders, because every lookup fails open.
5. **The page-inspection catch — the one reputation tools miss.** Every Tier 1 signal comes back clean: HTTPS, a plain `.com`, registered eleven years ago, no blocklist hit, not a first visit. The page still gets flagged, because it presents itself as Chase while posting credentials to an unrelated origin. The warning names both. (`demo-pages/6-form-action-mismatch.html`)
6. *(Roadmap — Tier 3.)* **The traffic catch:** wire a keystroke handler that beacons out on every keypress, and show the warning updating to "this page is sending what you type as you type it." This needs the `webRequest` evidence buffer, which is not built yet.

## Privacy notes

Inspecting page content and network traffic is a meaningful expansion of what the extension sees, so the boundaries are drawn explicitly:

- **Never leaves the browser:** form values, typed characters, clipboard contents, cookies, `localStorage`, auth tokens, or full page HTML.
- **What is sent for Tier 2/3 analysis:** a structural summary only — DOM skeleton with text nodes truncated, visible headings and brand strings, form action origins, field types and `autocomplete` tokens, script/request origins, and the redirect chain. Input `value` attributes are stripped and URL query strings are dropped or hashed before anything leaves the client.
- **Traffic inspection is metadata-only:** origins, methods, timing, and resource types. Request and response bodies are never read or transmitted.
- **Tier 2/3 run only on escalation,** not on every page. Sites the user visits routinely and that have cleared the checks are cached client-side and never re-analyzed server-side.
- **The enrichment call is optional and redacted.** It is the only path that sends structural page data off-device, it is never required for a warning to appear, and it can be switched off entirely. Input is redacted before transmission and should not be retained or used for training.
- **The one thing that does leave the device today is a domain name.** The RDAP age lookup sends the registrable domain (`example.com`, never the full URL, path, or query) to `rdap.org`, which redirects to the registry for that TLD. Those operators can therefore observe that *someone* asked about a domain. Nothing identifies the user, no page content is included, and answers are cached for 24 hours — including "no data" — so a domain is asked about at most once a day. This is a real disclosure and is called out rather than buried: it is the price of a genuine domain-age signal without running a backend.
- **The blocklist never phones home for a verdict.** Lookups are matched against a list held locally, so checking a domain tells nobody anything. The feed is fetched wholesale on a timer, independent of what the user is browsing.
- **The `history` permission stays local.** First-visit checks are `chrome.history.search()` calls inside the extension. Nothing derived from browsing history is transmitted anywhere.
- **Local-first is the goal:** detection, scoring, and message generation all run entirely in the browser, with no backend at all. Turn the network off and the extension still warns.

## Status / scope

This is a hackathon proof of concept. Everything marked **built** below runs
for real, with no API key and no server, and is covered by `./tests/run.sh`.
Everything marked *roadmap* is described here as design intent and has no code
behind it yet.

| Signal | Status |
|---|---|
| HTTPS vs HTTP | **built** — local |
| TLD risk | **built** — local |
| Homograph / typosquat distance | **built** — local |
| First visit to this domain | **built** — `chrome.history`, on-device |
| Referrer context | **built** — `document.referrer`, same-browser navigation only |
| Domain age | **built** — live RDAP, cached 24h, fails open |
| Blocklist reputation | **built** — bundled CC0 feed, refreshed on a 12h alarm |
| Brand claim extraction | **built** — title/headings/logo alt, against a known-brand list |
| Form destination mismatch | **built** — local DOM read |
| Tier 4 message templates | **built** — priority-ordered, slot-filled, deterministic |
| Field inventory, overlay/iframe trickery, keystroke capture, obfuscation, clone similarity | *roadmap* |
| All of Tier 3 (traffic inspection) | *roadmap* |
| LLM enrichment call | *roadmap* — the extension is designed to work fully without it |

Known limitations:

- Brand claim extraction matches against a small known-brand list, not arbitrary brands. Widening that is exactly the job the optional enrichment call is meant to do.
- Domain age depends on the registry: some TLDs publish no RDAP service and some registrars redact the creation date. Both resolve to "no data" rather than a guess, so a missing answer never produces a warning on its own.
- The bundled blocklist is a point-in-time community snapshot, not Safe Browsing. It catches known-reported domains and will miss a kit in its first hours — which is the gap Tier 2 exists to cover.
- Tier 2 visual/clone detection, when built, will be DOM-structure comparison rather than screenshot perceptual hashing — the latter is more robust but too heavy for a one-day build.
- Tier 3 traffic inspection is observational only. MV3 removed blocking `webRequest` for extensions, so the extension warns rather than intercepts; actual blocking would require `declarativeNetRequest` rules.
- LLM enrichment is deliberately non-blocking and therefore demo-safe, but that also means its value is hard to show on stage — the deterministic path usually answers first. The honest framing is that it broadens brand coverage beyond the fingerprint list, not that it catches things rules can't.
- Adversarial evasion against DOM inspection (rendering login forms entirely in canvas, shadow DOM obfuscation) is a known gap.
