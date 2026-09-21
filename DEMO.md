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
| `webRequest` | Tier 3. Observational only — MV3 has no blocking form. Feeds a per-tab, in-memory evidence buffer for redirect chains, raw-IP endpoints, known exfil services, script origins and WebSockets. |
| `host_permissions: <all_urls>` | Required by `webRequest`, and by the RDAP lookup. This is the biggest ask in the list and worth stating plainly rather than skipping. |

**Be ready for the `<all_urls>` question.** It is a genuine escalation: the
listener can see the URL of every request every page makes. What the code does
with that is narrow and checkable — it stores **hostnames only**. Paths and
query strings exist for the duration of one synchronous callback and are
dropped. The one place a path is examined at all is the known-exfil-service
match, where `discord.com` and `discord.com/api/webhooks/…` are genuinely
different facts, and even there only the host is kept. The buffer is in memory,
resets on every top-level navigation, and is deleted when the tab closes.

The in-page probe has the same discipline from the other direction: it runs on
every page but reports **nothing at all** until a keystroke lands in a password
or card field. On an ordinary page nobody types a password into, it is silent.
See `CRITERIA.md` for the full criteria and `extension/page-probe.js` for the
gate.

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

## 3. Run the eight scripted scenarios

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
| `7-overlay-capture.html` | Clean domain **and** clean markup — the form posts to itself. A transparent password input is layered over the real one | On password focus | Red: "The box you're typing into isn't part of this page" |
| `8-keystroke-exfil.html` | Clean domain, clean markup, clean form action. Nothing is wrong until you type | **On keystroke** | "Looks fine" at focus, then red: "This page is sending what you type as you type it" |

Click **"Why am I seeing this?"** on any warning to expand the signals
underneath — the "condensed but not hidden" detail the plain-language design
is going for.

**Pages 6, 7 and 8 are the ones to spend time on**, because each one removes a
signal the previous one still had:

- **Page 6** — nothing is wrong with the domain. It gets flagged because the
  page claims to be Chase while posting credentials to an unrelated origin,
  and the warning names both the brand and the destination. This is the
  scenario reputation tools structurally cannot catch.
- **Page 7** — the destination is clean too; the form posts to itself. The only
  evidence is geometric. The extension hit-tests the password field's own box
  with `elementsFromPoint` and finds a transparent `<input>` covering it, so
  the click lands on the attacker's field while the user watches the real one.
  Expand the why-list and the urgency copy shows up as supporting evidence —
  never as the verdict, because genuine fraud-alert pages sound the same.
- **Page 8** — everything is clean and stays clean, right up until the moment
  the page acts. Focus the password field and you get the "looks fine" toast,
  because at that instant that is the honest answer. Type one character and the
  card escalates to red. The banner escalating over a clean toast is the
  demo moment: nothing about this page was observable until it did something.

  This is also the case that justifies the in-page probe existing at all.
  `chrome.webRequest` can see that a request went to
  `relay.credential-collector.invalid`; it cannot see that it left 3ms after a
  keystroke in a password field, with no form submitted. That correlation is
  the whole difference between "talks to an analytics host" and "relaying your
  password as you type it", and it only exists inside the page.

  The page deliberately does **not** send what you type — it posts a fixed
  placeholder string to a host that does not resolve. The behaviour is real;
  the payload is not.

Page 5 is the quiet runner-up: it trips no check that has any data behind it,
and is flagged purely on first-visit plus referrer.

## 4. Why three different triggers

A confirmed blocklist hit is near-certain and high-severity, and some attacks
(drive-by downloads, malicious redirects, background scripts) don't require
the user to click or type anything — so that check runs immediately on page
load, before any interaction.

The domain heuristics and the rendered-page inspection are probabilistic;
plenty of legitimate new sites trip them. Warning on every page load for a
"maybe" is exactly how people learn to ignore security banners, so those stay
tied to the moment the risk materializes: handing the site a password or
payment details.

Traffic evidence waits one step longer still, until a key is actually pressed
in a sensitive field. Page 8 is that trigger in isolation — clean at focus,
dangerous one character later.

See `runImmediateCheck`, the `focusin` handler, and `handleProbeEvent` in
`content.js` for where the three splits happen.

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

The meta tags only ever stand in for the three lookups that need an identity
the demo can't own: hostname, domain age, and blocklist status. **Everything
Tier 2 and Tier 3 report is measured against the page in front of them.** Pages
6, 7 and 8 declare a completely clean identity and are flagged anyway, on
evidence the extension found itself:

| Page | What is declared | What is actually measured |
|---|---|---|
| 6 | Clean domain | The `action` attribute really does point at another origin |
| 7 | Clean domain | `elementsFromPoint` really does return a transparent input covering the password field |
| 8 | Clean domain | `navigator.sendBeacon` really is called on every `input` event, and the wrapper really does time it against the last keystroke |

Delete the meta tags from page 7 or 8 and the warning still fires. Delete them
from page 2 and it doesn't — which is the honest line between the two halves of
this demo, and worth drawing out loud rather than hoping nobody asks.

## 7. Run the tests

```
./tests/run.sh
```

Runs in headless Chrome/Edge with no npm, no node, and no network. Two suites:
`tests/signals.html` drives `content.js` in stubbed DOMs and asserts on the
banner actually rendered — template selection, escalation, no-downgrade, and
fail-open behaviour — plus the Tier 2 criteria checked directly against built
DOMs, the Tier 3 evidence buffer, and the pure helpers in `background.js`.
`tests/demo-pages.html` replays every page above and checks it still produces
the result documented in the table.

Two assertions worth pointing at specifically:

- **The obfuscation check is tested against this project's own source.** The
  first threshold was raised because measurement showed ordinary commented
  JavaScript runs 4.86–5.16 bits/char of Shannon entropy — above the original
  4.6 cutoff, so it fired on everything. The test pins the current threshold
  against real readable code so that regression cannot come back quietly.
- **Every check has a negative case.** The criteria are only worth stating if
  the "should not fire" half is enforced too; `CRITERIA.md` closes with a table
  listing each one.
