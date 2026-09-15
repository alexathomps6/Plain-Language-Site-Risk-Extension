# Plain-Language Site Risk Extension

A browser extension that condenses a dozen technical security signals into
plain-language warnings — triggered at the right moment for each signal's
severity, not as a badge nobody reads.

A working demo build (`site-risk-demo.zip`) implements this end to end; see
`DEMO.md` inside it for how to load and run it.

## The problem

Existing site-safety tools (Norton Safe Web, "This Website Safe to Access?",
Safeonweb, and others) already exist and do a reasonable job of scoring a
site. But they mostly fail the average or lazy-techie user in three ways:

1. **They output a number or letter grade** ("Score: 42", "Moderate risk"),
   which is exactly the kind of abstraction people tune out. Nobody knows
   what "58/100" means for their actual safety.
2. **They show a badge on every page load.** That trains people to ignore
   it — the same alert-fatigue problem every "always-on" security warning
   runs into.
3. **HTTP vs. HTTPS is a weak signal on its own.** Most phishing sites use
   HTTPS today (free certificates are trivial to get), so a tool that leans
   heavily on the lock icon is checking the wrong thing.

## The idea

Three differentiators from what's already out there:

- **Plain language over scores.** Instead of "Score: 42," say "This site can
  read anything you type here, including your password" or "This site was
  registered 3 days ago and is not the real PayPal."
- **Tiered trigger, not one-size-fits-all.** Not every signal deserves the
  same timing:
  - **Confirmed threats fire immediately, on page load.** A phishing/malware
    blocklist hit isn't a "maybe," and some attacks (drive-by downloads,
    malicious redirects, background scripts) don't need the user to click
    or type anything at all — waiting for an action would mean the warning
    arrives too late, or never.
  - **Everything else waits for a risky action** — focusing a password or
    payment field. Domain age, TLD, and typosquat distance are
    probabilistic signals, not certainties, and warning about a "maybe" on
    every page load is exactly how people learn to ignore security
    warnings.
- **Context-aware, including your own browsing history.** The warning
  weighs whether you've been to this exact domain before and whether you
  arrived via an external link (SMS, email, QR code) versus a bookmark or
  typed URL — the same domain is a different risk depending on how and
  when you got there.

## What it checks

Beyond HTTP/HTTPS, the extension combines:

- **Domain age** (WHOIS/RDAP) — a domain registered days ago pretending to
  be a bank is a strong red flag
- **Blocklist reputation** (Google Safe Browsing / PhishTank) — has this
  domain already been reported for phishing or malware
- **Homograph / typosquat distance** — how close the domain is to a
  well-known brand (`paypa1.com`, `rnicrosoft.com`)
- **TLD risk** — some TLDs (`.zip`, `.top`, `.tk`, `.click`) have far higher
  abuse rates than `.com`/`.org`/`.gov`
- **Certificate age and issuer** — a cert issued yesterday is less
  reassuring than one with a long history
- **Referrer context** — did the user arrive via a typed URL/bookmark, or
  via a link from an SMS, email, or QR code moments ago
- **First visit to this domain** — checked against the browser's own
  history (via the `history` permission), so a domain you've never seen
  before combined with an external referrer is flagged even when nothing
  else about it looks wrong

This last signal is the notable one: it needs no backend at all, and the
demo shows a genuinely unknown, unflagged-everywhere-else domain still
getting a meaningful warning purely from first-visit + referrer context.

See `IMPLEMENTATION.md` for how each of these is checked, how they're
prioritized into one message, and which are real vs. mocked in the demo
build.

## Tech stack

- **Browser extension** (Manifest V3)
  - **Content script** — watches for password/payment field focus, reads
    page context (URL, referrer, HTTPS state)
  - **Background service worker** — owns the `history` permission and
    answers "have I visited this domain before?" via
    `chrome.history.search()`, since content scripts can't call
    `chrome.history` directly
- **Backend API** (Node/Express or Python/Flask) — proxies WHOIS, Safe
  Browsing, and homograph-distance checks (keeps API keys off the client
  and allows caching); the demo build mocks this locally so it runs with
  no server and no API keys
- **Injected banner UI** — plain-language warning card with an expandable
  "why am I seeing this" detail list, not a score

## Quick start

1. Unzip `site-risk-demo.zip` and load the `extension/` folder as an
   unpacked extension in Chrome/Edge developer mode (see `DEMO.md`).
2. Try it on any real site — HTTPS, TLD, typosquat, referrer, and
   first-visit checks all run for real, no setup required.
3. To go beyond the demo, deploy a backend with API keys for Google Safe
   Browsing and a WHOIS/RDAP provider, and swap the mocked lookups in
   `content.js` for real network calls (see `IMPLEMENTATION.md`).

## Demo script

1. Visit a normal, long-established site you've been to before and focus
   the password field — a quiet "looks fine" toast, no interruption.
2. Visit a known-bad test domain (or the bundled blocklist demo page) —
   the warning appears **immediately on page load**, before any
   interaction, because a confirmed threat doesn't wait for a click.
3. Visit a freshly registered look-alike domain and focus the password
   field — plain-language warning explaining *why* in one sentence,
   expandable for the underlying signals.
4. Visit a domain that isn't flagged by any lookup at all, but that you've
   never visited before and arrived at via a link — still gets a warning,
   built entirely from first-visit + referrer context.

The bundled demo build implements all four of these as ready-to-run pages;
see `DEMO.md` for exact steps.

## Privacy notes

- Only the current page's domain and HTTPS state are sent to the backend
  for lookups — never page content, form values, or anything the user
  types.
- The `history` permission is a real, meaningful privacy ask, not a
  cosmetic one — the first-visit check runs entirely on-device
  (`chrome.history.search()` in the background worker) and never sends
  browsing history anywhere. Say this explicitly when pitching it.
- Consider caching lookups client-side (safe/known domains) so repeat
  visits to sites the user trusts don't require a network round trip.

## Status / scope

This is a hackathon proof of concept. See `IMPLEMENTATION.md` for known
limitations — in particular, content/behavior signals (logo mismatch, form
destination mismatch) are valuable but out of scope for a one-day build.
