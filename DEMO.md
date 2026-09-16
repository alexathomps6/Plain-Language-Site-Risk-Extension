# Running the demo

This is a real, working Chrome/Edge extension (Manifest V3). Every check it
makes runs for real, against any site you visit, with **no API keys, no
backend, and no build step**. The two lookups that normally need a server —
domain age and blocklist reputation — are done with an open protocol and a
bundled feed instead; see `IMPLEMENTATION.md` steps 3 and 4.

## 1. Load the extension

1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on **Developer mode** (top right).
3. Click **Load unpacked** and select the `extension/` folder.
4. Click **Details** and turn on **Allow access to file URLs**, so the
   `file://` demo pages are covered.

Permissions worth being able to explain, because they are real asks:

| Permission | Why |
|---|---|
| `history` | First-visit check, via `chrome.history.search()`. Never leaves the device. |
| `storage` | Caches RDAP answers for 24h and holds the blocklist. |
| `alarms` | Refreshes the blocklist every 12 hours. |
| `host_permissions` for RDAP hosts | Domain-age lookups. Scoped to `rdap.org` and the registry servers it redirects to — not `<all_urls>`. |

Chrome grants manifest permissions automatically for an unpacked install, so
there is no prompt to click through — worth calling out in a demo rather than
glossing over.

## 2. Try it on a real site

Visit any real HTTPS site with a login form and click into the password field.
You should get a quiet "Checked this site — looks fine" toast that dismisses
itself after a few seconds. That is the only case that auto-dismisses; a real
warning stays until you click away or hit **Dismiss**.

Two things worth doing here, because they are the parts that are easy to
assume are faked:

- **Watch a real RDAP lookup.** Open the service worker console from
  `chrome://extensions` → **Details** → **service worker**, then focus a
  password field. The extension resolves the registrable domain, queries
  `rdap.org`, and reads the real registration date. Focus again and it is
  served from cache.
- **Turn the network off and repeat.** Every lookup fails open, so domain age
  degrades to "no data" and the local checks still produce a verdict. Nothing
  hangs and nothing throws. This is the property the whole design is built
  around: a warning must be able to render with the network off.

## 3. Run the six scripted scenarios

Open each file in `demo-pages/` directly in the browser (`File > Open File…`,
or drag it into a tab).

| Page | Simulates | Trigger | Expected result |
|---|---|---|---|
| `1-safe-bank.html` | An old, legitimate bank domain, repeat visitor | On password focus | Quiet "looks fine" toast |
| `2-phishing-typosquat.html` | `paypa1-secure-login.tk`, 2 days old, arrived via link | On password focus | Red: registered 2 days ago, is not the real PayPal |
| `3-known-bad-blocklist.html` | A domain already on a phishing blocklist | **Immediately on page load** | Red: already reported for stealing passwords, no interaction needed |
| `4-unencrypted-http.html` | An old, familiar site that's just plain HTTP | On password focus | Amber: connection isn't encrypted |
| `5-first-visit-via-link.html` | Clean HTTPS, no typosquat, no risky TLD, and **no declared lookup data at all** | On password focus | Amber: first visit to this domain, arrived via a link |
| `6-form-action-mismatch.html` | **Every domain signal clean** — HTTPS, `.com`, 11 years old, no blocklist hit, repeat visit | On password focus | Red: "Anything you type here goes to someone other than Chase" |

Click **"Why am I seeing this?"** on any warning to expand the signals
underneath — the "condensed but not hidden" detail the plain-language design
is going for.

**Page 6 is the one to spend time on.** It is the scenario reputation tools
structurally cannot catch: there is nothing wrong with the domain. It gets
flagged because the page claims to be Chase while posting credentials to an
unrelated origin, and the warning names both the brand and the destination.
Page 5 is the runner-up: it trips no check that has any data behind it, and is
flagged purely on first-visit plus referrer.

## 4. Why two different triggers

A confirmed blocklist hit is near-certain and high-severity, and some attacks
(drive-by downloads, malicious redirects, background scripts) don't require
the user to click or type anything — so that check runs immediately on page
load, before any interaction.

The other signals are probabilistic; plenty of legitimate new sites trip them.
Warning on every page load for a "maybe" is exactly how people learn to ignore
security banners, so those stay tied to the moment the risk materializes:
handing the site a password or payment details.

See `runImmediateCheck` / the `focusin` handler in `content.js` for where the
split happens.

## 5. Banners escalate, and never downgrade

Signals don't arrive together: TLD and typosquat are synchronous, history and
RDAP are not. If a slower signal raises the severity, the card upgrades in
place. It is never allowed to soften — a card that has said "dangerous" stays
dangerous even if a weaker signal resolves afterwards.

To see it: throttle the network in DevTools, focus a password field on a
domain that resembles a brand, and watch the generic typosquat warning become
the age-qualified one once RDAP lands.

## 6. How the demo pages simulate a real site

A hackathon demo can't register real look-alike domains, so each page declares
its pretend identity and lookup results with meta tags:

```html
<meta name="demo-hostname" content="paypa1-secure-login.tk">
<meta name="demo-https" content="true">
<meta name="demo-domain-age-days" content="2">
<meta name="demo-blocklist-hit" content="false">
<meta name="demo-arrived-via-link" content="true">
```

The important detail: **this fakery lives in the demo pages, not in the
extension.** `content.js` contains no lookup table and no fabricated data, so
every value it acts on is either really measured or openly declared by the
page under inspection. A real website has no reason to include these tags, so
they have zero effect on genuine sites, and any signal a page does *not*
declare gets a real answer — page 5 declares no age or blocklist data at all.

## 7. Run the tests

```
./tests/run.sh
```

Runs in headless Chrome/Edge with no npm, no node, and no network. Two suites:
`tests/signals.html` drives `content.js` in stubbed DOMs and asserts on the
banner actually rendered — template selection, escalation, no-downgrade, and
fail-open behaviour — plus the pure helpers in `background.js`.
`tests/demo-pages.html` replays every page above and checks it still produces
the result documented in the table.
