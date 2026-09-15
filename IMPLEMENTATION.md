# Implementation plan

## Architecture

```
Content script (per page)
      |
      | on password/payment field focus
      v
Extension background service worker
      |
      | domain + cert metadata + referrer info (no page content)
      v
Backend API
      |
      +--> WHOIS/RDAP lookup ------> domain age
      +--> Google Safe Browsing ---> known-bad reputation
      +--> Homograph distance -----> typosquat check against brand list
      +--> TLD risk table ---------> static lookup, no external call
      |
      v
Risk combiner (simple weighted rules, no ML needed)
      |
      v
Plain-language message ---> popup shown in the page
```

Two tiers, same pattern as the phone screener project:

- **Extension (client)** — a content script watches for focus events on
  password/payment fields, and reads context available in the browser
  (current URL, referrer, TLS certificate info via the page's security
  state). It never reads or transmits what the user types.
- **Backend** — does the lookups that need a server (WHOIS, Safe Browsing,
  homograph distance against a brand list) and combines them into one
  plain-language message. Keeping this server-side avoids exposing API
  keys in the extension bundle and lets you cache results per domain.

## Build order

### 1. Extension skeleton that detects field focus

- Manifest V3 extension with a content script injected on all pages.
- Listen for `focus` events on `input[type="password"]` and payment-like
  fields (`autocomplete="cc-number"`, etc.).
- On focus, send the current `location.hostname`, `document.referrer`, and
  whether the page is HTTPS to the background service worker.
- Success criterion: focusing a password field on any site logs the
  hostname to the extension's console.

```js
// content-script.js
document.addEventListener('focusin', (e) => {
  const el = e.target;
  const isSensitive = el.tagName === 'INPUT' &&
    (el.type === 'password' || el.autocomplete?.includes('cc-'));
  if (isSensitive) {
    chrome.runtime.sendMessage({
      type: 'FIELD_FOCUS',
      hostname: location.hostname,
      referrer: document.referrer,
      isHttps: location.protocol === 'https:',
    });
  }
});
```

### 2. Backend endpoint for a single domain check

- One endpoint, `POST /check-domain`, taking `{ hostname, referrer, isHttps }`.
- Start with just the Google Safe Browsing lookup (free API, well
  documented) — this alone catches a large share of known phishing domains
  and is the highest-value check for the least effort.
- Return a structured result, not a message yet:

```js
app.post('/check-domain', async (req, res) => {
  const { hostname } = req.body;
  const safeBrowsingHit = await checkSafeBrowsing(hostname);
  res.json({ hostname, safeBrowsingHit });
});
```

### 3. Add WHOIS domain age

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

### 4. Add homograph/typosquat distance

- Maintain a small list of commonly spoofed brands (paypal, chase, amazon,
  microsoft, apple, your local bank names for the demo).
- Compute Levenshtein distance between the hostname's second-level domain
  and each brand name; also check for common confusable substitutions (0
  for o, 1 for l, rn for m).
- A distance of 1-2 characters from a known brand, on a domain that is
  *not* that brand's real domain, is a strong red flag.

```js
const KNOWN_BRANDS = ['paypal', 'chase', 'amazon', 'microsoft', 'apple'];

function typosquatScore(hostnameCore) {
  return KNOWN_BRANDS
    .map(brand => ({ brand, distance: levenshtein(hostnameCore, brand) }))
    .filter(r => r.distance > 0 && r.distance <= 2)
    .sort((a, b) => a.distance - b.distance)[0];
}
```

### 5. Add TLD risk and referrer context

- Static table of higher-risk TLDs (`.zip`, `.top`, `.tk`, `.click`, `.xyz`)
  — no external call needed, just a lookup.
- Referrer context: if `document.referrer` is empty or comes from an SMS
  app / email client webview, treat as "arrived via link" and increase risk
  weight. (Exact detection depends on platform; for the hackathon demo,
  simulate this by opening the test link from a messaging app.)

### 6. Combine into a plain-language message

Skip a numeric score entirely — go straight from signals to a sentence.
A simple rule table covers most cases without needing an LLM call, though
an LLM call can make the phrasing more natural if time allows:

```js
function buildMessage(signals) {
  if (signals.safeBrowsingHit) {
    return "This site has been reported for phishing or malware. Do not enter any information.";
  }
  if (signals.typosquat && signals.domainAgeDays < 30) {
    return `This site was registered ${signals.domainAgeDays} days ago and looks like ${signals.typosquat.brand}, but is not their real site.`;
  }
  if (signals.domainAgeDays < 30 && signals.arrivedViaLink) {
    return "You just arrived here from a link, and this site is brand new. Verify it's really who it claims to be before entering anything.";
  }
  if (!signals.isHttps) {
    return "This page is not encrypted. Anything you type here, including your password, can be read by others on the network.";
  }
  return null; // no popup — nothing flagged
}
```

### 7. Popup UI

- Small, non-blocking card injected near the focused field (not a full
  browser alert, which people dismiss reflexively).
- One sentence of plain language, plus a "why" expandable detail for
  anyone who wants the technical signals underneath.
- A clear "continue anyway" option — the goal is to inform, not lock people
  out, especially since false positives are possible.

## Known limitations (be upfront about these to judges)

- **Content/behavior signals are out of scope for a one-day build.** Logo
  mismatch detection and form-destination-mismatch checks need DOM/image
  analysis that's a meaningfully bigger lift than the metadata checks above.
  Mention this as "next layer" rather than pretending it's covered.
- **Referrer context is only partially available to a browser extension.**
  `document.referrer` doesn't reliably capture "arrived via SMS" — that
  context usually comes from the OS or messaging app, not the browser.  For
  the hackathon, this is best simulated in the demo rather than fully
  implemented.
- **False positives on legitimately new domains.** A brand-new startup's
  real site will trigger the domain-age signal. The plain-language message
  should invite scrutiny, not declare certainty.
- **WHOIS/RDAP data isn't always complete or fast** — some registrars
  redact creation dates or rate-limit lookups; add a timeout and fail open
  (don't block the page if the lookup is slow).

## Stretch goals if time allows

- Client-side caching of previously checked, trusted domains to avoid
  repeat lookups and speed up the demo.
- LLM-generated message phrasing instead of the static rule table, for more
  natural, specific explanations.
- A small allowlist the user can add to ("always trust my bank's real
  domain") to cut down repeat warnings.
