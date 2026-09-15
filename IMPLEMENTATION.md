# Implementation plan

A working build of everything below ships in `site-risk-demo.zip` — this
document is both the build log for that demo and the spec for extending it
with a real backend. Where code differs from the shipped demo, it's noted.

## Architecture

```
Content script (per page)
      |
      +--> on page load ---------------> Tier 1: known-bad check
      |                                        |
      |                                        v
      |                                  Blocklist hit?
      |                                        |
      |                                       yes --> banner shown immediately
      |
      +--> on password/payment focus --> Tier 2: heuristic checks
                                                |
                                                v
                                    Signals combiner (rule-based, no ML)
                                                |
                                                v
                                    Plain-language message --> banner

Background service worker (owns the `history` permission)
      ^
      | "have I visited this hostname before?"
      |
Content script -----------------------------------+

Backend API (not in the demo build — see mocked-vs-real table below)
      |
      +--> WHOIS/RDAP lookup ------> domain age
      +--> Google Safe Browsing ---> known-bad reputation
```

Two trigger tiers, not one:

- **Tier 1 — immediate, on page load.** Only the blocklist/reputation
  check runs here. A confirmed phishing/malware hit isn't a "maybe," and
  some attacks (drive-by downloads, malicious redirects, background
  scripts) don't require the user to click or type anything — waiting for
  an action would mean this warning arrives too late or never.
- **Tier 2 — on password/payment field focus.** Everything else (domain
  age, typosquat, TLD, referrer context, first-visit history) is
  probabilistic, not certain. Firing these on every page load is exactly
  how people learn to ignore security warnings, so they wait for the
  moment the risk actually materializes: handing the site sensitive data.

Three components, not two:

- **Content script** — runs both tiers, reads page context (URL, referrer,
  HTTPS state), and never reads or transmits what the user types.
- **Background service worker** — the *only* place that can call
  `chrome.history.search()`; content scripts can't call `chrome.history`
  directly, so the content script asks via `chrome.runtime.sendMessage`
  and the worker answers.
- **Backend** (production only — mocked in the demo) — does the lookups
  that need a server (WHOIS, Safe Browsing) and keeps API keys off the
  client.

## Build order

### 1. Extension skeleton that detects field focus

- Manifest V3 extension with a content script injected on all pages.
- Listen for `focus` events on `input[type="password"]` and payment-like
  fields (`autocomplete="cc-number"`, etc.).
- Success criterion: focusing a password field on any site logs the
  hostname to the extension's console.

```js
// content.js
document.addEventListener('focusin', (e) => {
  const el = e.target;
  const isSensitive = el.tagName === 'INPUT' &&
    (el.type === 'password' || el.autocomplete?.includes('cc-'));
  if (isSensitive) {
    console.log('sensitive field focused on', location.hostname);
  }
});
```

### 2. Background worker + history permission for first-visit checks

This is worth building early — it's a fully real, backend-free signal, and
getting the message-passing plumbing right first makes everything after it
easier to slot in.

- Add `"permissions": ["history"]` and a `background.service_worker` entry
  to `manifest.json`.
- The background worker listens for a message, searches history for the
  hostname, and reports whether this is (effectively) the first visit:

```js
// background.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'CHECK_FIRST_VISIT') return false;
  chrome.history.search({ text: message.hostname, startTime: 0, maxResults: 200 }, (results) => {
    const matching = results.filter(item => {
      try { return new URL(item.url).hostname === message.hostname; } catch { return false; }
    });
    const totalVisits = matching.reduce((sum, item) => sum + (item.visitCount || 0), 0);
    // The page load that triggered this lookup is usually already recorded,
    // so a domain never seen before shows up with exactly one visit (this one).
    sendResponse({ isFirstVisit: totalVisits <= 1, totalVisits });
  });
  return true; // keep the message channel open for the async callback
});
```

- The content script asks for this once per page load and awaits it before
  wiring up either check tier:

```js
// content.js
function getFirstVisitSignal(hostname) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type: 'CHECK_FIRST_VISIT', hostname }, (response) => {
      if (chrome.runtime.lastError || !response) { resolve(null); return; } // fail open
      resolve(response.isFirstVisit);
    });
  });
}
```

**Privacy note worth stating explicitly in a pitch:** this never leaves the
device. The lookup is local `chrome.history.search()`, not a network call —
say this plainly, since `history` is a real permission ask that deserves a
real answer about where the data goes (nowhere).

### 3. Backend endpoint for a single domain check (production only)

The demo build mocks this step entirely with a local lookup table in
`content.js` (see the mocked-vs-real table below) so it runs with no
server and no API keys. For a production version:

- One endpoint, `POST /check-domain`, taking `{ hostname }`.
- Start with just the Google Safe Browsing lookup (free API, well
  documented) — this alone catches a large share of known phishing domains
  and is the highest-value check for the least effort.

```js
app.post('/check-domain', async (req, res) => {
  const { hostname } = req.body;
  const safeBrowsingHit = await checkSafeBrowsing(hostname);
  res.json({ hostname, safeBrowsingHit });
});
```

### 4. Add WHOIS domain age (production only)

- Use a WHOIS/RDAP API (many free tiers available) to get the domain's
  creation date.
- A domain younger than ~30 days is a strong signal on its own; combine
  with any brand-like content in the hostname for a bigger signal boost.

```js
async function getDomainAgeDays(hostname) {
  const data = await rdapLookup(hostname); // returns creation date
  const ageMs = Date.now() - new Date(data.creationDate).getTime();
  return Math.floor(ageMs / (1000 * 60 * 60 * 24));
}
```

### 5. Add homograph/typosquat distance (real in the demo)

- Maintain a small list of commonly spoofed brands (paypal, chase, amazon,
  microsoft, apple, your local bank names for the demo).
- Compute Levenshtein distance, but **compare against hyphen/underscore
  segments as well as the whole label**, not just the whole label alone —
  `paypa1-secure-login.tk` only matches "paypal" if you check the `paypa1`
  segment on its own; comparing the full concatenated string
  (`paypa1securelogin`) against `paypal` misses it completely. This was a
  real bug caught while testing the demo build.

```js
function findTyposquat(hostname) {
  const core = coreName(hostname); // strip TLD, strip "www."
  const wholeToken = core.replace(/[^a-z0-9]/g, '');
  const segments = core.split(/[^a-z0-9]+/).filter(seg => seg.length >= 4);
  const candidates = [wholeToken, ...segments];
  let best = null;
  for (const brand of KNOWN_BRANDS) {
    for (const candidate of candidates) {
      if (candidate === brand) continue; // it's the brand's own name, not a typosquat
      const distance = levenshtein(candidate, brand);
      if (distance > 0 && distance <= 2 && (!best || distance < best.distance)) {
        best = { brand, distance };
      }
    }
  }
  return best;
}
```

### 6. Add TLD risk and referrer context (real in the demo)

- Static table of higher-risk TLDs (`.zip`, `.top`, `.tk`, `.click`,
  `.xyz`) — no external call needed, just a lookup.
- Referrer context: `document.referrer` tells you if the browser itself
  navigated here from another page. It does **not** reliably capture
  "arrived via SMS/email/QR," since that context usually comes from the OS
  or messaging app opening a new tab, not a same-browser navigation — see
  known limitations below.

### 7. Combine into a plain-language message

Skip a numeric score entirely — go straight from signals to a sentence.
This is the full priority order used in the demo build, highest severity
first:

```js
function buildMessage(s) {
  if (s.safeBrowsingHit === true) {
    return { level: 'danger', text: 'This site has been reported for phishing or malware. Do not enter any information here.' };
  }
  if (s.typosquat && s.domainAgeDays !== null && s.domainAgeDays < 30) {
    return { level: 'danger', text: `This site was registered ${s.domainAgeDays} days ago and looks like ${s.typosquat.brand}, but is not their real site.` };
  }
  if (s.typosquat) {
    return { level: 'danger', text: `This domain closely resembles ${s.typosquat.brand} but is not their official site.` };
  }
  if (s.domainAgeDays !== null && s.domainAgeDays < 30 && s.arrivedViaLink) {
    return { level: 'warning', text: 'You just arrived here from a link, and this site is brand new. Verify it\u2019s really who it claims to be before entering anything.' };
  }
  // No backend domain-age data available (a real, un-mocked site) — but the
  // free, on-device first-visit signal plus referrer context is still real
  // and still meaningful on its own.
  if (s.firstVisit === true && s.arrivedViaLink && s.domainAgeDays === null) {
    return { level: 'warning', text: 'You\u2019ve never been to this site before, and you just arrived here from a link. Make sure it\u2019s really who it claims to be before entering anything.' };
  }
  if (s.tldRisky) {
    return { level: 'warning', text: 'This domain ending is commonly used for scam and throwaway sites. Double-check this is really who it claims to be.' };
  }
  if (!s.isHttps) {
    return { level: 'warning', text: 'This page is not encrypted. Anything you type here, including your password, can potentially be read by others on the network.' };
  }
  return null; // no banner — nothing flagged
}
```

Note the ordering logic: typosquat + known-young domain outranks typosquat
alone, which outranks the first-visit-only case, because each step down has
progressively weaker certainty. The first-visit tier only fires when
`domainAgeDays` is `null` — i.e. only for domains the mocked/real backend
has no data on at all — so it never overrides a stronger, backend-informed
signal when one exists.

### 8. Split the trigger by tier

```js
async function initialize() {
  const baseCtx = getContext(); // hostname, isHttps, arrivedViaLink, mocked domainAge/safeBrowsingHit
  const firstVisit = await getFirstVisitSignal(baseCtx.hostname);
  const ctx = { ...baseCtx, firstVisit };

  // Tier 1: fires unconditionally, before any interaction
  if (ctx.safeBrowsingHit === true) {
    injectBanner({ level: 'danger', text: '...' });
    return;
  }

  // Tier 2: fires only when the user focuses a sensitive field
  document.addEventListener('focusin', (e) => {
    if (!isSensitiveField(e.target)) return;
    const signals = computeSignals(ctx); // adds typosquat + tldRisky
    injectBanner(buildMessage(signals));
  });
}
```

### 9. Banner UI

- Small, non-blocking card injected in the page (not a full browser alert,
  which people dismiss reflexively).
- One sentence of plain language, plus a "why am I seeing this" expandable
  detail list for anyone who wants the underlying signals.
- A clear dismiss option — the goal is to inform, not lock people out,
  especially since false positives are possible.
- When nothing is flagged, show a brief, auto-dismissing "looks fine" toast
  rather than nothing at all — this keeps the check visibly active without
  becoming a persistent, ignorable badge.

## What's mocked vs. real in the shipped demo

| Signal | Trigger | Status | Real version |
|---|---|---|---|
| Phishing blocklist hit | Immediate, on page load | Mocked (local lookup table) | Step 3 — Google Safe Browsing |
| HTTPS vs HTTP | On password/payment focus | Real | — |
| Risky TLD | On password/payment focus | Real | — |
| Typosquat / homograph distance | On password/payment focus | Real | — |
| Referrer / "arrived via link" | On password/payment focus | Real for same-browser navigation | See limitation below for SMS/email/QR |
| First visit to this domain | On password/payment focus | Real (`chrome.history`) | — |
| Domain age | On password/payment focus | Mocked (local lookup table) | Step 4 — WHOIS/RDAP |

## Known limitations (be upfront about these to judges)

- **Content/behavior signals are out of scope for a one-day build.** Logo
  mismatch detection and form-destination-mismatch checks need DOM/image
  analysis that's a meaningfully bigger lift than the metadata checks
  above. Form-action-mismatch (does the form submit to a different domain
  than the page itself) is the single best next addition — it's a real DOM
  read, needs no new permissions, and catches phishing pages even when the
  domain itself looks clean.
- **`document.referrer` doesn't capture "arrived via SMS/QR code."** It
  only sees same-browser navigations. Detecting "opened from a messaging
  app" needs OS-level or app-level context a content script doesn't have.
  For the hackathon, this is best simulated in the demo rather than fully
  implemented.
- **False positives on legitimately new domains or first visits.** A
  brand-new startup's real site will trigger the domain-age signal, and
  everyone's first visit to any new legitimate service will trigger the
  first-visit signal. The plain-language message should invite scrutiny,
  not declare certainty — and is exactly why these stay on the
  action-triggered tier instead of blocking the page outright.
- **WHOIS/RDAP data isn't always complete or fast** — some registrars
  redact creation dates or rate-limit lookups; add a timeout and fail open
  (don't block the page if the lookup is slow). The demo's
  `getFirstVisitSignal` already follows this pattern for history lookups —
  a failed or errored lookup resolves to `null`, not a false positive.

## Stretch goals if time allows

- Form-action-mismatch check (see limitations above) — highest value,
  needs no new permissions.
- Client-side caching of previously checked, trusted domains to avoid
  repeat lookups and speed up the demo.
- LLM-generated message phrasing instead of the static rule table, for more
  natural, specific explanations.
- A small allowlist the user can add to ("always trust my bank's real
  domain") to cut down repeat warnings.
