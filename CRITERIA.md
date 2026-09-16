# Detection criteria

Every Tier 2 and Tier 3 check in this extension is a measurement against a
stated threshold. This file is the contract: what fires each check, the exact
number it is measured against, why that number and not a stricter one, and
what a false positive would look like.

Nothing here is a heuristic score or a model output. Each threshold is a named
constant in source, so a reviewer can read the criterion, find the constant,
and read the test that pins it:

| Tier | Owner | Constants |
|---|---|---|
| Tier 2 — rendered page | `extension/page-inspection.js` | `CRITERIA` |
| Tier 3 — in-page traffic | `extension/page-inspection.js` | `CRITERIA.network` (applied by `content.js`) |
| Tier 3 — `webRequest` | `extension/background.js` | `NETWORK_CRITERIA`, `EXFIL_SERVICES`, `URL_SHORTENERS`, `KNOWN_CDNS`, `CODE_AND_DATA_TYPES` |

Three rules apply to all of them:

- **Fail open.** A check that cannot measure returns `null`, never a verdict.
  "No evidence" and "no problem" are different answers, and the code never
  confuses them.
- **Never downgrade.** Evidence can escalate a banner in place. Nothing can
  clear one.
- **Never read a value.** Sensitivity is determined structurally — `type`,
  `autocomplete` tokens, name/id/label text, geometry, computed style,
  stacking order. Never from what the user typed.

---

## Tier 2 — rendered page inspection

Runs when a sensitive field is focused, against the live DOM.

### C1 · Credential form posts over plain HTTP
`checkInsecureFormAction` · **danger**

| | |
|---|---|
| **Fires when** | The page is `https:` and the form's resolved `action` is `http:` |
| **Threshold** | Exact protocol comparison; no tolerance |
| **False positive** | None realistic. There is no legitimate reason to downgrade a credential POST |

The padlock the user is trusting covers the page, not the submission. Only
checked on an HTTPS page, because on an HTTP page the transport warning
already fired and this would be redundant noise.

### C2 · Field inventory vs. plausibility
`checkFieldInventory` · **danger** (branded) / **warning** (unbranded)

| | |
|---|---|
| **Fires when** | A password field plus **≥ 2** other high-value categories in the same form, *or* government ID + payment card together regardless of password |
| **Threshold** | `fieldInventory.minOtherCategoriesWithPassword: 2` |
| **Categories** | `password`, `payment_card`, `government_id`, `date_of_birth`, `security_answer`, `bank_account`, `pin` |
| **False positive** | Two is the threshold, not one, specifically because combined "create an account and pay" flows legitimately pair a password with card details. Flagging those would put a danger banner on real checkouts |

Detection is by `type`, `autocomplete` token (`cc-number`, `cc-csc`), and the
text around the field: `name`, `id`, `placeholder`, `aria-label`, the
associated `<label>`, and any wrapping label.

### C3 · Something layered over a credential field
`checkCredentialOverlay` · **danger**

| | |
|---|---|
| **Fires when** | ≥ 3 of 5 sample points across a visible credential field's box hit-test to the same foreign element, and that element is either a cross-origin iframe or visually absent |
| **Threshold** | `overlay.samplePoints` (centre + four inset corners), `overlay.minCoveredPoints: 3`, `overlay.maxOpacity: 0.1` |
| **False positive** | Three of five, not one, so a rounded border or a focus ring clipping a corner does not count. A *visible* element over a field is a rendering bug, not an attack, so opacity is required to be under 0.1 |

Two details matter here:

- It scans **every visible credential field on the page**, not just the focused
  one. In the realistic version of this attack the focused field *is* the
  attacker's transparent input; the evidence is that the visible field
  underneath is covered. Checking only the focused element looks at the wrong
  end of the attack and finds nothing.
- `elementsFromPoint` skips `pointer-events: none` elements, and that is
  correct: a layer that cannot receive a click cannot capture input either.
  There is a test asserting this does not fire.

A field scrolled outside the viewport yields **no measurement**, not a clean
result.

### C4 · Shadow capture input
`checkShadowCaptureInput` · **danger**

| | |
|---|---|
| **Fires when** | The same form holds another password / `cc-number` / `cc-csc` field, or a `hidden` input named like a credential, that is visually hidden — while the field the user is filling is visible |
| **Threshold** | `shadowInput.maxOpacity: 0.05`, `maxCollapsedPx: 1`, `offscreenPx: -500` |
| **False positive** | Requires the *visible* counterpart to exist. A form of entirely hidden fields (a template, a disabled section) does not fire |

−500px is far enough off-canvas that no layout reaches it by accident.

### C5 · Fake browser chrome
`checkFakeBrowserChrome` · **danger**

| | |
|---|---|
| **Fires when** | An element in the top quarter of the viewport renders a `https://host` string as text *and* carries a padlock glyph, `alt`, or class |
| **Threshold** | `fakeBrowserChrome.topViewportFraction: 0.25`, `maxContainerTextLength: 300` |
| **False positive** | All three conditions are required. A URL printed in body copy has no padlock; a padlock icon in a header renders no URL. The 300-character cap excludes prose that merely contains a link |

This is the Browser-in-the-Browser attack: a picture of an address bar drawn
into the page to sell an origin the page does not have.

### C6 · Third-party credential frame
`checkThirdPartyCredentialFrame` · **warning**

| | |
|---|---|
| **Fires when** | A cross-origin iframe overlaps ≥ 50% of the credential form's area and its host is not a recognised provider |
| **Threshold** | `thirdPartyCredentialFrame.minOverlapFraction: 0.5` |
| **Allowlist** | Stripe, Braintree, PayPal, Adyen, Checkout.com, Square, Klarna, Affirm, Google/reCAPTCHA, hCaptcha, Okta, Auth0, Microsoft, Apple |
| **False positive** | Hosted payment and SSO widgets do exactly this, legitimately and constantly. Hence the allowlist, and hence warning rather than danger even for hosts outside it |

Allowlist matching is on the registrable domain, so `js.stripe.com` and
`checkout.stripe.com` both resolve to `stripe.com`.

### C7 · Obfuscated inline script
`checkObfuscatedScript` · **warning**

| | |
|---|---|
| **Fires when** | An inline script ≥ 800 chars carries the classic packer signature `eval(function(p,a,c,k,e`, **or** ≥ 2 independent indicators agree |
| **Indicators** | builds code from strings at runtime · escape-sequence density ≥ 5% · a ≥ 512-char base64-shaped blob · ≥ 20 `_0x…` hex-mangled identifiers · machine-generated high entropy |
| **Threshold** | `obfuscatedScript.minIndicators: 2`, `minEntropyBitsPerChar: 5.2`, `minAvgLineLength: 500`, `minEscapeDensity: 0.05`, `minBase64BlobLength: 512`, `minHexIdentifiers: 20` |
| **False positive** | Minified vendor bundles are common and innocent, which is why one indicator is never enough |

**On the entropy threshold specifically.** A first pass used 4.6 bits/char as
the entropy criterion. Measured against this project's own source, ordinary,
commented, human-formatted JavaScript runs **4.86–5.16 bits/char** — so that
threshold fired on every file of normal code and contributed nothing. Raw
entropy does not discriminate JavaScript. It is now 5.2 *and* requires an
average line length ≥ 500, because packed payloads are emitted as one enormous
line and human source is not. `tests/signals.html` case 17 asserts that this
repository's own code does not trip the check, so the regression cannot come
back silently.

### C8 · Anti-inspection
`checkAntiInspection` · supporting evidence only

| | |
|---|---|
| **Fires when** | `oncontextmenu` on `<body>`, an F12 / Ctrl+Shift+I key trap, a `contextmenu` handler calling `preventDefault`, a `setInterval` debugger trap, or a devtools-detection identifier |
| **False positive** | Some legitimate sites disable right-click. This never selects a message; it only ever appears in the "why" list |

### C9 · Pressure and urgency language
`checkPressureLanguage` · supporting evidence only

| | |
|---|---|
| **Fires when** | ≥ 2 distinct phrases from the lexicon appear in the block containing the credential form |
| **Threshold** | `pressureLanguage.minDistinctMatches: 2`, `maxTextLength: 4000` |
| **False positive** | Genuine account-recovery and fraud-alert pages sound exactly like this. Deliberately incapable of producing a verdict on its own |

Scoped to the form's containing block rather than the whole document, so a
promotional banner elsewhere on a large page does not colour the reading of
the login area.

---

## Tier 3 — in-page traffic (the probe)

`page-probe.js` runs in the page's own JavaScript world at `document_start`
and wraps `fetch`, `XMLHttpRequest`, `navigator.sendBeacon`, `WebSocket`,
`addEventListener`, and `setAttribute`.

**It is a sensor, not a judge.** It reports facts; `content.js` applies the
thresholds. That split is deliberate: the probe runs where hostile script can
read and forge its messages, so keeping judgment on the other side of the
`postMessage` boundary means a page cannot reach the criteria. And because the
banner never downgrades, a forged message can only raise a warning, never
clear one.

**Gating.** The probe emits no traffic metadata at all unless a keystroke has
landed in a password or card field, or a WebSocket opens on a page that has
one. This is what lets it sit on `<all_urls>` without becoming a general
traffic recorder.

**Payload.** Hostname, request kind, method, a cross-origin boolean, and a
millisecond delta. Never a path, query, body, or value.

### N1 · Exfil-shaped traffic while typing
**danger**

| | |
|---|---|
| **Fires when** | A cross-origin `fetch` / XHR / beacon / WebSocket leaves within 2000ms of a keystroke in a sensitive field, with no submit having occurred |
| **Threshold** | `network.exfilWhileTyping.maxMsSinceKeystroke: 2000` |
| **False positive** | Same-origin traffic is excluded outright — a page talking to itself is a page working. Post-submit traffic is excluded, because that is just a form being submitted |

Two seconds is wide enough to survive a debounced handler and narrow enough
that unrelated periodic traffic does not land inside the window.

This is the half `chrome.webRequest` genuinely cannot do. `webRequest` sees
that a request went to a host; it cannot see that the request fired 40ms after
a keystroke in a password field and before any submit. That correlation is the
entire difference between "this page talks to an analytics host" and "this
page is relaying your password as you type it".

### N2 · WebSocket on a credential page
**warning**

| | |
|---|---|
| **Fires when** | A cross-origin WebSocket opens on a page holding a credential field |
| **Threshold** | `network.websocketOnCredentialPage.requiresCrossOrigin: true` |
| **False positive** | Same-origin live channels (chat, notifications) are excluded |

### N3 · Keystroke listener on a sensitive field
supporting evidence only

Reported when `addEventListener` binds `keydown` / `keyup` / `keypress` /
`input` / `paste` / `compositionupdate` to a password or card field. On its own
this is not actionable — password strength meters do it for entirely good
reasons. It matters as corroboration for traffic firing on the same keystrokes.

### N4 · Form action rewritten at runtime
**danger**

Reported when `setAttribute('action' | 'formaction', …)` points a form at a
different host after load. The static markup check in `content.js` catches a
destination present in the HTML; this catches the evasion of shipping a
clean-looking form and redirecting it from script once the page is live.

---

## Tier 3 — `webRequest` (the service worker)

Observational only. MV3 removed blocking `webRequest`, so the extension warns
rather than intercepts.

**The asymmetry worth stating:** the listener *sees* full URLs, because the
browser hands them over, but only ever *stores* a hostname. Paths and queries
exist for the duration of one synchronous callback and are then dropped. The
buffer is in memory, is reset on every top-level navigation, and is deleted
when the tab closes.

### W1 · Known exfil and paste services
**danger**

| | |
|---|---|
| **Fires when** | Any request URL matches an entry in `EXFIL_SERVICES` |
| **Matched on** | The **full URL**, because `discord.com` and `discord.com/api/webhooks/…` are genuinely different facts |
| **Retained** | Host only |
| **Services** | Telegram bot API, Discord webhooks, Pastebin API, webhook.site, RequestBin, Pipedream, Beeceptor, ngrok / Cloudflare / localtunnel / serveo tunnels, Formspree / FormSubmit / Getform / StaticForms |
| **False positive** | Path-scoped patterns. `discord.com/api/v10/users/@me` does not match; `discord.com/api/webhooks/…` does. Both cases are tested |

These are what a kit reaches for when it needs somewhere to put stolen data
without standing up a server.

### W2 · Raw-IP endpoint
**danger**

| | |
|---|---|
| **Fires when** | A request to a bare IPv4 or bracketed IPv6 host |
| **Restricted to** | `CODE_AND_DATA_TYPES` — `script`, `xmlhttprequest`, `websocket`, `sub_frame`, `object` |
| **False positive** | A logo served from an IP is a badly configured site. A script or XHR endpoint on one is a different claim entirely, and conflating them would put a danger banner on ordinary intranet pages |

### W3 · Suspicious redirect chain
**warning**

| | |
|---|---|
| **Fires when** | ≥ 2 main-frame hops crossing ≥ 2 distinct registrable domains, **or** any hop originating at a known link shortener |
| **Threshold** | `redirectChain.minHops: 2`, `minDistinctSites: 2` |
| **False positive** | A hop count alone means little — CDNs, locale routers and SSO flows all redirect, usually within one site. Crossing multiple *different sites* is the part that characterises a shortener-into-open-redirect chain |

A redirect rewrites where the page came from, so `pageHost` follows it;
otherwise every later same-site comparison is made against the wrong origin.
There is a test for that.

### W4 · Unrelated script origin
**warning**

| | |
|---|---|
| **Fires when** | A `script` request to a registrable domain other than the page's own, not in `KNOWN_CDNS` |
| **False positive** | A bare same-origin rule would flag every site using jsDelivr, Google Fonts, Sentry, or a tag manager. The allowlist covers ordinary infrastructure; what remains is a one-off host stood up alongside the phishing domain |

### W5 · Cross-origin WebSocket
**warning** — the `webRequest` backstop for N2, catching channels opened at
`document_start` before the content script's message listener is live.

### Buffer limits

`NETWORK_CRITERIA.limits`: 50 hosts per kind, 20 redirect hops, 100 tabs
(oldest buffer evicted first). Evidence here is qualitative — the first 50
distinct hosts of a kind are as diagnostic as the first 5000 — and a tab whose
buffer was evicted reports no network evidence, which fails open.

---

## Testing

`./tests/run.sh` runs both suites in headless Chrome/Edge with no network.

Every criterion above has a positive case, and every criterion with a
plausible false positive has a negative case asserting it stays quiet:

| Negative case | Asserts |
|---|---|
| `pointer-events: none` layer | C3 does not fire on a layer that cannot capture input |
| Password + card signup form | C2 does not fire on a legitimate signup-and-pay flow |
| This project's own source | C7 does not fire on readable, commented JavaScript |
| Stripe / Microsoft iframe hosts | C6's allowlist resolves them |
| Non-HTTPS page | C1 declines to fire |
| Same-origin beacon while typing | N1 does not fire on a page talking to itself |
| `discord.com/api/v10/users/@me` | W1 does not match a non-webhook path |
| Image served from an IP | W2 does not fire for non-code resources |
| jsDelivr and same-site scripts | W4 does not fire on ordinary infrastructure |
| One redirect hop | W3 is under threshold |
| Unknown tab id | Returns `null`, not a clean verdict |
