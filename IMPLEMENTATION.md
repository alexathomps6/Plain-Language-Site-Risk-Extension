# Implementation plan

The source for everything below is tracked in `extension/`, with scripted
scenarios in `demo-pages/` and a test suite in `tests/`. This document is the
build log.

Nothing here is mocked. There is no backend and there are no API keys: the two
lookups that would normally need a server — domain age and blocklist
reputation — are done with an open protocol and a bundled feed instead. See
steps 3 and 4.

## Architecture

```
Page probe (MAIN world, document_start)
      |
      +--> wraps fetch / XHR / sendBeacon / WebSocket / addEventListener
      |         |
      |         v
      |    facts only, over postMessage  (no thresholds, no values, host only)
      |
      v
Content script (isolated world, per page)
      |
      +--> on page load ---------------> Tier 1: known-bad check
      |                                        |
      |                                        v
      |                                  Blocklist hit?
      |                                        |
      |                                       yes --> banner shown immediately
      |
      +--> on password/payment focus --> Tier 1 heuristics + Tier 2 page inspection
      |                                        |
      +--> on probe report -------------> Tier 3 criteria applied here
                                                |
                                                v
                                    Signals combiner (rule-based, no ML)
                                                |
                                                v
                                    Plain-language message --> banner

Background service worker  <-- chrome.runtime.sendMessage --  Content script
      |
      +--> chrome.history.search() ----> first visit?   (on-device, no network)
      +--> rdap.org -> registry --------> domain age    (open protocol, no key)
      +--> bundled CC0 feed snapshot ---> blocklist     (refreshed on a 12h alarm)
      +--> chrome.webRequest listeners -> per-tab evidence buffer
                                          (redirect chain, raw IPs, exfil
                                           services, script origins, sockets;
                                           hostnames only, memory only)

Every one of these fails open: timeout, offline or no-data resolves to null,
never to a verdict.
```

Two trigger tiers, not one:

- **Tier 1 — immediate, on page load.** Only the blocklist/reputation
  check runs here. A confirmed phishing/malware hit isn't a "maybe," and
  some attacks (drive-by downloads, malicious redirects, background
  scripts) don't require the user to click or type anything — waiting for
  an action would mean this warning arrives too late or never.
- **On password/payment field focus.** Everything else (domain age,
  typosquat, TLD, referrer context, first-visit history, and all of the
  Tier 2 page inspection) is probabilistic, not certain. Firing these on
  every page load is exactly how people learn to ignore security warnings,
  so they wait for the moment the risk actually materializes: handing the
  site sensitive data.
- **On keystroke.** Tier 3's in-page half reports nothing until a secret is
  actually being typed. A page that never receives a keystroke in a
  credential field produces no traffic evidence at all.

Three components, not four:

- **Page probe** — a `world: "MAIN"` content script at `document_start`. The
  only vantage point from which traffic can be correlated with typing. It is a
  sensor: it reports facts and applies no thresholds, because it runs in the
  page's own world where hostile script can read and forge what it sends.
- **Content script** — runs the domain heuristics and the rendered-page
  inspection, applies the Tier 3 in-page criteria to what the probe reports,
  and never reads or transmits what the user types.
- **Background service worker** — owns every lookup the content script
  cannot do itself. `chrome.history` is unavailable to content scripts, a
  cross-origin RDAP fetch from page context is subject to CORS at each
  redirect hop, and `chrome.webRequest` is worker-only. The content script
  asks via `chrome.runtime.sendMessage` and the worker answers.
- **No backend.** This used to be a further component. It isn't needed: see
  steps 3 and 4 for how the two "server-only" lookups were replaced with a
  keyless protocol and a bundled feed.

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

### 3. Blocklist reputation without an API key

Google Safe Browsing is the obvious choice and it is the wrong one here: it
requires a key, which requires a server to keep the key off the client, which
means the extension stops working the moment the server does.

Instead the extension ships a snapshot of a keyless CC0 community feed at
`extension/data/blocklist-snapshot.json`, and refreshes it from the source on
a 12-hour `chrome.alarms` job. Two properties matter:

- **A fresh install with no network still has real data.** The snapshot is in
  the bundle, so the blocklist is never empty.
- **Checking a domain tells nobody anything.** The list is matched locally.
  The feed is fetched wholesale on a timer, unrelated to what is being browsed
  — unlike a per-lookup reputation API, which learns every domain you visit.

Matching walks up parent domains but only counts exact membership at each
step, so a listed `evil.example.com` still flags its own subdomains while a
listed `someone.github.io` never implicates `github.io` as a whole:

```js
const parts = host.split('.');
for (let i = 0; i + 2 <= parts.length; i++) {
  if (set.has(parts.slice(i).join('.'))) return { blocklistHit: true };
}
```

A refresh that returns an empty or unparseable list is discarded rather than
written — stale real data beats no data.

### 4. Domain age via RDAP, also without an API key

RDAP is the IETF replacement for WHOIS, and it is an open protocol rather than
a vendor product: no key, no account, no quota to sign up for. `rdap.org`
bootstraps to whichever registry is authoritative for the TLD with a 302.

```js
const response = await fetch(`https://rdap.org/domain/${domain}`, {
  signal: controller.signal,                    // 2.5s AbortController
  headers: { accept: 'application/rdap+json' },
});
const data = await response.json();
const registration = (data.events || []).find((e) => e.eventAction === 'registration');
```

Three things this has to get right:

- **It belongs in the service worker, not the content script.** A page-context
  fetch is subject to CORS at every hop. Some registries do send
  `Access-Control-Allow-Origin: *` — Verisign, for `.com`/`.net`, does — but
  RFC 7480 only *recommends* it, so relying on that would mean the signal
  works for some TLDs and silently not others. A worker holding matching
  `host_permissions` is not subject to CORS at all. This is why
  `manifest.json` lists registry hosts alongside `rdap.org`.
- **It must fail open.** Timeout, offline, a TLD with no RDAP service, or a
  registrar that redacts the creation date all resolve to `null` — never to a
  guess, and never to a warning on their own.
- **It must be cached, including the failures.** Results are stored in
  `chrome.storage.local` for 24 hours, keyed by registrable domain. Caching
  `null` too is what stops an unsupported TLD being re-queried on every single
  password focus.

Note the registrable-domain step: RDAP is queried for `bbc.co.uk`, not the
unregistrable `co.uk`, so the worker keeps a small multi-part suffix list. The
production answer is the full Public Suffix List.

### 5. Add homograph/typosquat distance

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

### 6. Add TLD risk and referrer context

- Static table of higher-risk TLDs (`.zip`, `.top`, `.tk`, `.click`,
  `.xyz`) — no external call needed, just a lookup.
- Referrer context: `document.referrer` tells you if the browser itself
  navigated here from another page. It does **not** reliably capture
  "arrived via SMS/email/QR," since that context usually comes from the OS
  or messaging app opening a new tab, not a same-browser navigation — see
  known limitations below.

### 7. Page-level checks: brand claim and form destination

These are the first two signals that look at the page rather than the domain,
and they are what catches a kit on a clean-looking domain that no blocklist
has seen yet. Both are local DOM reads needing no permission and no network.

**Brand claim** — what does this page present itself as? Title, headings,
`og:site_name` and logo `alt` text, matched against the known-brand list.
Deliberately narrow: fuzzy identification of arbitrary brands is the job of
the optional enrichment call, not of a rule.

**Form destination mismatch** — does the form holding this field submit
somewhere else? Read the *attribute*, not the `form.action` property: the
property resolves a missing action to the document URL, which would hide the
difference between "no action" and "posts to itself".

```js
const candidates = [form.getAttribute('action')];
form.querySelectorAll('[formaction]').forEach((el) => candidates.push(el.getAttribute('formaction')));
for (const raw of candidates) {
  const resolved = new URL(raw, location.href);          // guarded by try/catch
  if (!/^https?:$/.test(resolved.protocol)) continue;    // skip javascript:, data:, mailto:
  if (resolved.origin !== location.origin) return { destination: resolved.hostname };
}
```

Together these produce the strongest message the extension can render on a
domain with nothing else wrong with it: *"Anything you type here goes to
someone other than Chase."* That is the scenario in
`demo-pages/6-form-action-mismatch.html`, where every Tier 1 check passes.

### 8. Tier 4: the message template set

Skip a numeric score entirely — go straight from signals to a sentence. Not a
chain of `if` statements returning string literals, but a priority-ordered
array of templates, each a pure function of the signals:

```js
{
  id: 'young_domain_brand_mismatch',
  level: 'danger',
  when: (s) => s.typosquat && s.domainAgeDays !== null && s.domainAgeDays < NEW_DOMAIN_DAYS,
  template: 'This site was registered {age} and is not the real {brand}.',
  slots: (s) => ({ age: humanizeAge(s.domainAgeDays), brand: brandLabel(s.typosquat.brand) }),
  evidence: ['typosquat_distance', 'domain_age'],
  why: (s) => [ /* the expandable detail list */ ],
}
```

The structure is what makes the README's guarantees true rather than
aspirational: the same evidence always selects the same template and fills the
same slots, so a verdict is reproducible and explainable after the fact, and
every template declares `evidence` refs so a message can always name the
signals behind it.

Ordering runs highest-certainty first — blocklist hit, then form mismatch,
then typosquat-plus-young-domain, then typosquat alone, down to the weak
single signals. The first-visit-only template fires solely when
`domainAgeDays` is `null`, so it never speaks over a stronger age-informed
signal.

### 9. Split the trigger by tier, and let the banner escalate

Signals do not all arrive at once. TLD and typosquat are synchronous; history
and RDAP are not. A one-shot "show the first verdict and stop" latch would
mean a real RDAP answer arriving a few hundred milliseconds later is computed
and then thrown away.

So the verdict is re-evaluated whenever new evidence lands, and the banner may
upgrade in place — but never downgrade:

```js
function render(result) {
  const level = result ? result.level : 'none';
  if (LEVEL_RANK[level] < LEVEL_RANK[state.shownLevel]) return; // never downgrade
  if (result && result.id === state.shownId) return;            // already showing this
  injectBanner(result);
}
```

The no-downgrade rule matters: a card that has said "dangerous" must not
soften because a slower, weaker signal resolved afterwards. Tier 1 still fires
without waiting for a focus; everything else waits for the sensitive field.

One subtlety worth recording, because it was a real bug: the lookups are gated
on having a hostname worth looking up, not on `location.protocol`. Gating on
protocol meant a page that was not `http(s)` never fired RDAP at all, which
silently disabled escalation everywhere it was most worth testing.
### 10. Banner UI

- Small, non-blocking card injected in the page (not a full browser alert,
  which people dismiss reflexively).
- One sentence of plain language, plus a "why am I seeing this" expandable
  detail list for anyone who wants the underlying signals.
- A clear dismiss option — the goal is to inform, not lock people out,
  especially since false positives are possible.
- When nothing is flagged, show a brief, auto-dismissing "looks fine" toast
  rather than nothing at all — this keeps the check visibly active without
  becoming a persistent, ignorable badge.

### 11. Tier 2: real rendered-page inspection against stated criteria

`extension/page-inspection.js`. Nine checks, each a measurement against a named
constant in a single `CRITERIA` object at the top of the file, so a reviewer
can read the criterion and find the number without reading the algorithm.
[`CRITERIA.md`](CRITERIA.md) documents every threshold and the false positive
it exists to avoid.

The checks: insecure form action, field inventory plausibility, overlay over a
credential field, shadow capture inputs, fake browser chrome, third-party
credential frames, script obfuscation, anti-inspection, and pressure language.

Three decisions worth recording:

- **The overlay check scans every visible credential field, not just the
  focused one.** First cut checked only the focused element and would never
  have fired. In the realistic attack the focused field *is* the attacker's
  transparent input; the evidence is that the visible field underneath it is
  covered. Checking only the focused element looks at the wrong end of the
  attack.
- **Value mirroring was designed and then dropped.** Comparing a hidden
  input's value against the visible field's would detect mirror-capture
  directly, and would mean the extension reads what the user types — the one
  thing it promises not to do. The structural shadow-input check covers the
  same attack without ever touching a value.
- **Entropy alone is a bad obfuscation signal.** The first threshold was 4.6
  bits/char. Measured against this repository's own source, ordinary commented
  JavaScript runs 4.86–5.16, so it fired on everything and contributed nothing.
  It is now 5.2 *and* gated on average line length ≥ 500, because packed
  payloads are one enormous line and human source is not. There is a test
  asserting this project's own code does not trip the check.

Every check is wrapped in try/catch by `inspectPage()`: a broken check returns
null rather than a verdict.

### 12. Tier 3: real traffic inspection, in two halves

Neither half can see what the other can, so both exist.

**`extension/page-probe.js`** runs in the page's own JavaScript world
(`world: "MAIN"`, `document_start`) and wraps `fetch`, `XMLHttpRequest`,
`sendBeacon`, `WebSocket`, `addEventListener` and `setAttribute`. This is the
only place traffic can be correlated with typing: `chrome.webRequest` sees that
a request went to a host, not that it left 40ms after a keystroke in a password
field and before any submit.

`world: "MAIN"` rather than injecting a `<script>` tag through
`web_accessible_resources`: no CSP problems, and it genuinely runs at
`document_start`.

**`extension/background.js`** holds observational `chrome.webRequest` listeners
and a per-tab evidence buffer for redirect chains, raw-IP endpoints, known
exfil services, script origins and WebSockets.

The two design points that matter:

- **The probe is a sensor, not a judge.** It reports facts; `content.js`
  applies `CRITERIA.network`. The probe runs where hostile script can read and
  forge its `postMessage` traffic, so keeping the thresholds on the other side
  of that boundary means a page cannot reach them. And because the banner never
  downgrades, a forged message can only raise a warning, never clear one.
- **The probe is gated on typing.** It emits no traffic metadata at all until a
  keystroke lands in a sensitive field (or a WebSocket opens on a page that has
  one). That is what lets it sit on `<all_urls>` without being a general
  traffic recorder. On an ordinary page nobody types a password into, it is
  silent.

The worker's asymmetry is stated in the source and in the README: the listener
*sees* full URLs because the browser hands them over, and *stores* only
hostnames. The one place a path is examined at all is the known-exfil-service
match, where `discord.com` and `discord.com/api/webhooks/…` are genuinely
different facts — and even there only the host is retained.

## What runs for real
Nothing is mocked. Every signal below runs from the loaded extension with no
API key and no server, and is covered by `./tests/run.sh`. The thresholds
behind the Tier 2 and Tier 3 rows are documented, with their false-positive
reasoning, in [`CRITERIA.md`](CRITERIA.md).

| Signal | Trigger | How it works |
|---|---|---|
| Phishing blocklist hit | Immediate, on page load | Bundled CC0 feed snapshot, refreshed on a 12h alarm; matched locally |
| HTTPS vs HTTP | On password/payment focus | `location.protocol` |
| Risky TLD | On password/payment focus | Static set, no network |
| Typosquat / homograph distance | On password/payment focus | Levenshtein against a brand list, whole label and per segment |
| Brand claim | On password/payment focus | Title, headings, `og:site_name`, logo `alt` |
| Form destination mismatch | On password/payment focus | `action` / `formaction` attribute resolved against `location.origin` |
| Form action rewritten at runtime | Whenever it happens | `setAttribute` wrapper in the page probe |
| Insecure (HTTP) form action | On password/payment focus | Resolved `action` protocol, on an HTTPS page only |
| Field inventory plausibility | On password/payment focus | `type` / `autocomplete` / label text, seven categories |
| Overlay over a credential field | On password/payment focus | `elementsFromPoint` hit test, 3 of 5 sample points |
| Fake browser chrome | On password/payment focus | Top-of-viewport position + rendered URL + padlock |
| Shadow capture input | On password/payment focus | Computed style and geometry, never values |
| Third-party credential frame | On password/payment focus | Iframe/form overlap fraction, provider allowlist |
| Script obfuscation / anti-inspection | On password/payment focus | Packer signature, or two independent indicators |
| Pressure language | On password/payment focus | Lexicon match in the form's block; supporting only |
| Exfil-shaped traffic while typing | On keystroke | `fetch`/XHR/beacon/WebSocket wrappers, 2s correlation window |
| Known exfil services, raw IPs, redirect chains, script origins | Continuous | `chrome.webRequest` evidence buffer, per tab, host-only |
| Referrer / "arrived via link" | On password/payment focus | `document.referrer`; same-browser navigation only |
| First visit to this domain | On password/payment focus | `chrome.history.search()` in the worker, on-device |
| Domain age | On password/payment focus, async | Live RDAP via `rdap.org`, cached 24h, 2.5s timeout, fails open |

The demo pages in `demo-pages/` declare their own identity and lookup results
through `<meta name="demo-...">` tags, so a scenario is reproducible without
registering real look-alike domains. Those tags live in the pages, not in the
extension: `content.js` contains no fabricated data, so every value it acts on
is either really measured or openly declared by the page under inspection.

## Known limitations (be upfront about these to judges)

- **There is no certificate check, deliberately.** Chrome gives extensions no
  way to read a TLS certificate. Firefox has `webRequest.getSecurityInfo()`;
  the Chrome equivalent is still only a
  [proposal](https://github.com/w3c/webextensions/issues/882). The one working
  route is `chrome.debugger` with `Network.getCertificate`, which pins a
  *"… started debugging this browser"* infobar to every tab — an unreasonable
  ask for a tool selling trustworthiness. The claim was removed from the README
  rather than faked.
- **`document.referrer` doesn't capture "arrived via SMS/QR code."** It only
  sees same-browser navigations. Detecting "opened from a messaging app" needs
  OS-level context a content script doesn't have. The extension claims only
  what it can see: that the user followed a link rather than typing the address.
- **Brand claim extraction only knows the brands on its list.** A page
  impersonating a brand outside `KNOWN_BRANDS` produces the brandless variant
  of the message ("goes to someone other than this site"), which is weaker but
  still correct. Widening this is precisely the job of the optional enrichment
  call, and precisely why it is optional.
- **False positives on legitimately new domains or first visits.** A brand-new
  startup's real site will trigger the domain-age signal, and everyone's first
  visit to any new legitimate service will trigger the first-visit signal. The
  message invites scrutiny rather than declaring certainty — and this is
  exactly why these stay on the action-triggered tier instead of blocking the
  page outright.
- **RDAP isn't universal.** Some TLDs publish no RDAP service and some
  registrars redact the creation date; `.tk` in particular, a TLD the risk
  table already flags, is unlikely to answer. All of these resolve to "no
  data", which produces no warning on its own — the risky-TLD signal still
  fires independently.
- **The blocklist is a community snapshot, not Safe Browsing.** It catches
  domains that have already been reported and will miss a kit in its first
  hours. That gap is the entire argument for the page-level checks.
- **Tier 3 needs `webRequest` and `<all_urls>`, which is a real escalation of
  what the extension can see.** It is the price of a redirect chain or a
  credential POST to a raw IP. The mitigation is in the code, not the prose:
  only hostnames are stored, the buffer is in memory, it resets on every
  top-level navigation, and it is deleted when the tab closes.
- **`world: "MAIN"` content scripts need Chrome/Edge 111+.** On anything older
  the Tier 3 in-page half is silent and only the `webRequest` half runs. The
  extension degrades rather than breaks.
- **A WebSocket opened at `document_start` is missed by the probe,** because
  `content.js` has not registered its message listener yet. The `webRequest`
  listener is the backstop for exactly that case, which is why both halves
  check for it.
- **The overlay hit test only measures a field inside the viewport.** A
  credential field scrolled off-screen returns no measurement rather than a
  clean result — deliberate "no evidence", not "no problem".
- **The obfuscation check reads inline `<script>` content only.** A kit that
  loads its payload from an external `src` is judged on origin (Tier 3) rather
  than content.
- **Adversarial evasion against DOM inspection is a known gap.** A login form
  rendered entirely in canvas, or buried in closed shadow DOM, defeats the
  Tier 2 geometry checks. Tier 3 still sees where the data goes.

## Stretch goals if time allows

- Structural clone similarity: DOM skeleton and stylesheet fingerprints
  compared against known brand login pages.
- The full Public Suffix List in place of the small multi-part suffix set, so
  registrable-domain extraction is correct for every ccTLD.
- A user allowlist ("always trust my bank's real domain") to cut repeat
  warnings.
- The optional enrichment call, for brand identification beyond the fingerprint
  list.
