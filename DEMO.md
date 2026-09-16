# Running the demo

This is a real, working Chrome/Edge extension (Manifest V3). Three of its
checks — HTTPS, risky TLD, and typosquat/homograph distance — run for real
against any site you visit. Two checks that need a backend in production
(domain age, phishing-blocklist reputation) are mocked locally here via a
small lookup table, so the whole thing runs with no API keys and no server.
See `extension/content.js` for exactly which parts are real vs. mocked, and
`README.md` / `IMPLEMENTATION.md` for the production version of the mocked
checks.

## 1. Load the extension

1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `extension/` folder.
4. Find the extension in the list, click **Details**, and turn on
   **Allow access to file URLs**. This is required because the demo pages
   are local HTML files (`file://...`), not real hosted domains.

This version requests the **history** permission, used to check whether
this is the first time your browser has visited a given domain (see step 4
below). Chrome grants permissions listed in the manifest automatically for
an unpacked/developer-mode install — there's no separate prompt to click
through, but it's worth calling out in a demo since it's a real, meaningful
permission ask, not a cosmetic one.

## 2. Try it on a real site (no mocking involved)

Visit any real HTTPS site with a login form and click into the password
field. You should see a quiet "Checked this site — looks fine" toast in the
top-right corner that disappears on its own after a few seconds — this is
the one case that auto-dismisses, since nothing was actually flagged. Try
an HTTP-only site if you can find one — you'll get a plain-language warning
instead, and that one stays on screen until you click somewhere else on the
page (or hit "Dismiss"); it will not disappear on its own.

## 3. Run the five scripted demo scenarios

Open each file in `demo-pages/` directly in the browser
(`File > Open File...`, or drag it into a tab). Two scenarios trigger the
moment the page loads; three only trigger when you click into the password
field — see below for why.

| Page | Simulates | Trigger | Expected result |
|---|---|---|---|
| `1-safe-bank.html` | An old, legitimate bank domain, repeat visitor | On password focus | Quiet "looks fine" toast |
| `2-phishing-typosquat.html` | `paypa1-secure-login.tk`, 2 days old, arrived via link | On password focus | Red warning: registered 2 days ago, looks like PayPal but isn't |
| `3-known-bad-blocklist.html` | A domain already on a phishing blocklist | **Immediately on page load** | Red warning: reported for phishing/malware, no interaction needed |
| `4-unencrypted-http.html` | An old, familiar site that's just plain HTTP | On password focus | Amber warning: connection isn't encrypted |
| `5-first-visit-via-link.html` | A real-feeling site with **no mocked backend data at all** — clean HTTPS, no typosquat, no risky TLD | On password focus | Amber warning: first visit to this domain, arrived via a link |

Click **"Why am I seeing this?"** on any warning to expand the underlying
signals — this is the "condensed but not hidden" detail the plain-language
design is going for.

## 4. First-visit history check

Page 5 is the interesting one: none of its signals come from the mocked
backend lookup table — that hostname isn't in it at all. Every check it
trips (or clears) is either free (HTTPS, TLD, typosquat) or comes from the
`history` permission via `chrome.history.search()` in `background.js`,
which content scripts can't call directly. On the bundled demo page this is
overridden with a `<meta name="demo-first-visit">` tag for a repeatable
demo, but on any real site, focus a password field and the extension will
genuinely ask your browser's own history whether you've been there before.

## Why two different triggers

A confirmed blocklist hit is a near-certain, high-severity signal, and some
attacks (drive-by downloads, malicious redirects, background scripts) don't
require the user to click or type anything — so that check runs immediately
on page load, before any interaction.

The other signals (new domain, risky TLD, typosquat) are probabilistic, not
certain — plenty of legitimate new sites would trip them. Warning on every
page load for a "maybe" is exactly how people learn to ignore security
banners. So those stay tied to the moment the risk actually materializes:
handing the site a password or payment details.

See `runImmediateCheck()` and `runFocusCheck()` in `content.js` for exactly
where this split happens in the code.

## How the demo pages simulate a real site

Since a hackathon demo can't register real look-alike domains, each demo
page declares its pretend identity with meta tags:

```html
<meta name="demo-hostname" content="paypa1-secure-login.tk">
<meta name="demo-https" content="true">
<meta name="demo-arrived-via-link" content="true">
```

`content.js` only reads these tags — a real website has no reason to
include them, so this has zero effect on genuine sites. The typosquat, TLD,
and HTTPS checks all still run for real against whatever hostname is
declared (or the page's real hostname, if there's no demo tag at all).

## What's mocked vs. real, at a glance

| Signal | Trigger | Status | Where the real version lives |
|---|---|---|---|
| Phishing blocklist hit | Immediate, on page load | Mocked | Would call Google Safe Browsing — see `IMPLEMENTATION.md` step 2 |
| HTTPS vs HTTP | On password/payment focus | Real | `content.js` — reads `location.protocol` |
| Risky TLD | On password/payment focus | Real | `content.js` — static list, no network needed |
| Typosquat / homograph distance | On password/payment focus | Real | `content.js` — Levenshtein against a brand list |
| Referrer / "arrived via link" | On password/payment focus | Real (for normal browsing) | `content.js` — `document.referrer` |
| First visit to this domain | On password/payment focus | Real (for normal browsing) | `background.js` — `chrome.history.search()`, since content scripts can't call `chrome.history` directly |
| Domain age | On password/payment focus | Mocked | Would call WHOIS/RDAP — see `IMPLEMENTATION.md` step 3 |

Demo page 5 is the one that shows this off best: it clears every real check
(HTTPS, TLD, typosquat) and isn't in the mocked backend table at all, so
the only reason it gets flagged is a genuinely real signal combo — first
visit plus an external referrer — with no backend involved whatsoever.
