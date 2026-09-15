# Plain-Language Site Risk Extension

A browser extension that condenses a dozen technical security signals into a
single plain-language warning — shown at the moment it actually matters (when
you're about to type a password or payment info), not as a badge nobody reads.

## The problem

Existing site-safety tools (Norton Safe Web, "This Website Safe to Access?",
Safeonweb, and others) already exist and do a reasonable job of scoring a
site. But they mostly fail the average or lazy-techie user in two ways:

1. **They output a number or letter grade** ("Score: 42", "Moderate risk"),
   which is exactly the kind of abstraction people tune out. Nobody knows
   what "58/100" means for their actual safety.
2. **They score the page, not the moment.** A badge on every page load
   trains people to ignore it. The real risk moment is when you're about to
   *type something sensitive* into that page.
3. **HTTP vs. HTTPS is a weak signal on its own.** Most phishing sites use
   HTTPS today (free certificates are trivial to get), so a tool that leans
   heavily on the lock icon is checking the wrong thing.

## The idea

Two differentiators from what's already out there:

- **Plain language over scores.** Instead of "Score: 42," say "This site can
  read anything you type here, including your password" or "This site was
  registered 3 days ago and is not the real PayPal."
- **Context-aware, action-triggered.** The popup fires when the user focuses
  a password or payment field on a flagged site — especially one they just
  arrived at via an SMS link, email link, or QR code — not on every page
  load.

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

See `IMPLEMENTATION.md` for how each of these is checked and how they combine
into the plain-language message.

## Tech stack

- **Browser extension** (Manifest V3) — content script watches for
  password/payment field focus and reads page context (URL, referrer,
  certificate info)
- **Backend API** (Node/Express or Python/Flask) — proxies WHOIS, Safe
  Browsing, and homograph-distance checks (keeps API keys off the client
  and allows caching)
- **Popup UI** — plain-language warning card, not a score

## Quick start

1. Load the unpacked extension in Chrome/Edge developer mode.
2. Deploy the backend (or run locally) with API keys for Google Safe
   Browsing and a WHOIS/RDAP provider.
3. Visit a flagged test site and focus a password field to see the popup.

## Demo script

1. Visit a normal, long-established site (e.g. your bank's real login page)
   and focus the password field — no popup, or a quiet "looks fine"
   confirmation.
2. Visit a freshly registered look-alike domain (register a throwaway test
   domain or use a known phishing sample from PhishTank's test set) and
   focus the password field — plain-language warning appears explaining
   *why* in one sentence.
3. Simulate the context-aware case: open the flagged site via a link (not a
   direct visit) to show the referrer-context risk bump in the warning
   text.

## Privacy notes

- Only the current page's domain and cert metadata are sent to the backend
  for lookups — never page content, form values, or anything the user
  types.
- Consider caching lookups client-side (safe/known domains) so repeat
  visits to sites the user trusts don't require a network round trip.

## Status / scope

This is a hackathon proof of concept. See `IMPLEMENTATION.md` for known
limitations — in particular, content/behavior signals (logo mismatch, form
destination mismatch) are valuable but out of scope for a one-day build.
