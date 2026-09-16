// Plain-Language Site Risk Checker — demo build
//
// Real, working checks (no network, no API keys):
//   - HTTPS vs HTTP
//   - Risky TLD lookup
//   - Homograph / typosquat distance against a small known-brand list
//   - First-time-visiting-this-domain (via chrome.history, in the background worker)
//
// Mocked-for-demo checks (would call a backend in production — see
// IMPLEMENTATION.md for the real WHOIS / Safe Browsing versions):
//   - Domain age
//   - Known-phishing reputation hit
//
// The mocked signals, and the first-visit signal, are only ever overridden
// for the bundled demo pages, via <meta name="demo-..."> tags those pages
// include. A normal real website has no such tags, so it gets the real
// checks above plus a real chrome.history-backed first-visit check —
// nothing is faked for a genuine site.

(function () {
  const KNOWN_BRANDS = ['paypal', 'chase', 'amazon', 'microsoft', 'apple', 'bankofamerica', 'wellsfargo'];
  const RISKY_TLDS = new Set(['zip', 'top', 'tk', 'click', 'xyz', 'gq', 'work', 'link']);

  // Simulated backend lookup table, keyed by the hostname a demo page
  // declares via <meta name="demo-hostname">. In production this data
  // would come from WHOIS/RDAP + Google Safe Browsing (see IMPLEMENTATION.md).
  const MOCK_DB = {
    'secure-firstnational-bank.com': { domainAgeDays: 9125, safeBrowsingHit: false },
    'paypa1-secure-login.tk': { domainAgeDays: 2, safeBrowsingHit: false },
    'totally-legit-crypto-giveaway.xyz': { domainAgeDays: 5, safeBrowsingHit: true },
    'old-community-forum.net': { domainAgeDays: 6200, safeBrowsingHit: false },
  };

  let resultShown = false; // only one banner per page load, whichever check finds something first

  function levenshtein(a, b) {
    const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
    for (let i = 0; i <= a.length; i++) dp[i][0] = i;
    for (let j = 0; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
    return dp[a.length][b.length];
  }

  function coreName(hostname) {
    // strip TLD and common subdomains for a fairer brand comparison
    const parts = hostname.split('.');
    const withoutTld = parts.length > 1 ? parts.slice(0, -1).join('.') : hostname;
    return withoutTld.replace(/^www\./, '').toLowerCase();
  }

  function findTyposquat(hostname) {
    const core = coreName(hostname);
    // Compare both the whole label (catches "rnicrosoft.com") and each
    // hyphen/underscore-separated segment (catches "paypa1-secure-login.tk")
    // against the brand list — a single concatenated comparison misses the
    // hyphenated case entirely.
    const wholeToken = core.replace(/[^a-z0-9]/g, '');
    const segments = core.split(/[^a-z0-9]+/).filter((seg) => seg.length >= 4);
    const candidates = [wholeToken, ...segments];

    let best = null;
    for (const brand of KNOWN_BRANDS) {
      for (const candidate of candidates) {
        if (candidate === brand) continue; // exact match = it's the brand's own segment, not a typosquat
        const distance = levenshtein(candidate, brand);
        if (distance > 0 && distance <= 2 && (best === null || distance < best.distance)) {
          best = { brand, distance };
        }
      }
    }
    return best;
  }

  function getTld(hostname) {
    const parts = hostname.split('.');
    return parts[parts.length - 1].toLowerCase();
  }

  function getContext() {
    const demoHostnameMeta = document.querySelector('meta[name="demo-hostname"]');
    const demoHttpsMeta = document.querySelector('meta[name="demo-https"]');
    const demoArrivedViaLinkMeta = document.querySelector('meta[name="demo-arrived-via-link"]');

    const hostname = demoHostnameMeta ? demoHostnameMeta.content : location.hostname;
    const isHttps = demoHttpsMeta ? demoHttpsMeta.content === 'true' : location.protocol === 'https:';
    const arrivedViaLink = demoArrivedViaLinkMeta
      ? demoArrivedViaLinkMeta.content === 'true'
      : Boolean(document.referrer) && (() => {
          try { return new URL(document.referrer).hostname !== location.hostname; }
          catch (_) { return false; }
        })();

    const mocked = MOCK_DB[hostname] || null;

    return {
      hostname,
      isHttps,
      arrivedViaLink,
      domainAgeDays: mocked ? mocked.domainAgeDays : null,
      safeBrowsingHit: mocked ? mocked.safeBrowsingHit : null,
    };
  }

  // First-visit is the one signal that needs an async lookup (chrome.history
  // lives in the background worker, not the content script), so it's kept
  // separate from the rest of getContext() and resolved once before either
  // check tier runs. Demo pages can still override it for a scripted result;
  // a real page gets a real answer from the user's actual browsing history.
  function getFirstVisitSignal(hostname) {
    const demoMeta = document.querySelector('meta[name="demo-first-visit"]');
    if (demoMeta) {
      return Promise.resolve(demoMeta.content === 'true');
    }
    if (location.protocol !== 'http:' && location.protocol !== 'https:') {
      return Promise.resolve(null); // e.g. a local file with no demo override — nothing meaningful to check
    }
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({ type: 'CHECK_FIRST_VISIT', hostname }, (response) => {
        if (chrome.runtime.lastError || !response) {
          resolve(null); // fail open — don't block the page or throw if the lookup fails
          return;
        }
        resolve(response.isFirstVisit);
      });
    });
  }

  function computeSignals(ctx) {
    return {
      ...ctx,
      typosquat: findTyposquat(ctx.hostname),
      tldRisky: RISKY_TLDS.has(getTld(ctx.hostname)),
    };
  }

  function buildMessage(s) {
    if (s.safeBrowsingHit === true) {
      return {
        level: 'danger',
        text: 'This site has been reported for phishing or malware. Do not enter any information here.',
        why: ['Flagged on a known-phishing blocklist'],
      };
    }
    if (s.typosquat && s.domainAgeDays !== null && s.domainAgeDays < 30) {
      return {
        level: 'danger',
        text: `This site was registered ${s.domainAgeDays} day${s.domainAgeDays === 1 ? '' : 's'} ago and looks like ${capitalize(s.typosquat.brand)}, but is not their real site.`,
        why: withFirstVisitNote(s, [
          `Domain name is ${s.typosquat.distance} character${s.typosquat.distance === 1 ? '' : 's'} off from "${s.typosquat.brand}"`,
          `Domain is only ${s.domainAgeDays} days old`,
        ]),
      };
    }
    if (s.typosquat) {
      return {
        level: 'danger',
        text: `This domain closely resembles ${capitalize(s.typosquat.brand)} but is not their official site.`,
        why: withFirstVisitNote(s, [`Domain name is ${s.typosquat.distance} character${s.typosquat.distance === 1 ? '' : 's'} off from "${s.typosquat.brand}"`]),
      };
    }
    if (s.domainAgeDays !== null && s.domainAgeDays < 30 && s.arrivedViaLink) {
      return {
        level: 'warning',
        text: 'You just arrived here from a link, and this site is brand new. Verify it\u2019s really who it claims to be before entering anything.',
        why: withFirstVisitNote(s, [`Domain is only ${s.domainAgeDays} days old`, 'Arrived via an external link, not a bookmark or direct visit']),
      };
    }
    // No mocked domain-age data available (a real site, since that check needs
    // a backend) — but the history-backed first-visit signal is real and free,
    // and combined with an external link it's still a meaningful, honest signal.
    if (s.firstVisit === true && s.arrivedViaLink && s.domainAgeDays === null) {
      return {
        level: 'warning',
        text: 'You\u2019ve never been to this site before, and you just arrived here from a link. Make sure it\u2019s really who it claims to be before entering anything.',
        why: ['First time this browser has visited this domain', 'Arrived via an external link, not a bookmark or direct visit'],
      };
    }
    if (s.tldRisky) {
      return {
        level: 'warning',
        text: 'This domain ending is commonly used for scam and throwaway sites. Double-check this is really who it claims to be.',
        why: withFirstVisitNote(s, [`".${getTld(s.hostname)}" domains have a higher rate of reported abuse`]),
      };
    }
    if (!s.isHttps) {
      return {
        level: 'warning',
        text: 'This page is not encrypted. Anything you type here, including your password, can potentially be read by others on the network.',
        why: withFirstVisitNote(s, ['Connection is HTTP, not HTTPS']),
      };
    }
    return null;
  }

  function withFirstVisitNote(s, reasons) {
    if (s.firstVisit === true) {
      return [...reasons, 'First time this browser has visited this domain'];
    }
    return reasons;
  }

  function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
  }

  function injectBanner(result) {
    document.querySelectorAll('.plsr-banner, .plsr-toast').forEach((el) => el.remove());

    if (!result) {
      // The site looks fine — a brief, self-dismissing confirmation is enough.
      // This is the one case that does NOT wait for the user to click away.
      const toast = document.createElement('div');
      toast.className = 'plsr-toast';
      toast.textContent = 'Checked this site \u2014 looks fine.';
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 3500);
      return;
    }

    const banner = document.createElement('div');
    banner.className = `plsr-banner plsr-${result.level}`;

    const message = document.createElement('div');
    message.className = 'plsr-message';
    message.textContent = result.text;
    banner.appendChild(message);

    const row = document.createElement('div');
    row.className = 'plsr-row';

    const whyToggle = document.createElement('button');
    whyToggle.className = 'plsr-link-btn';
    whyToggle.textContent = 'Why am I seeing this?';
    row.appendChild(whyToggle);

    const dismiss = document.createElement('button');
    dismiss.className = 'plsr-link-btn';
    dismiss.textContent = 'Dismiss';
    row.appendChild(dismiss);

    banner.appendChild(row);

    const whyList = document.createElement('ul');
    whyList.className = 'plsr-why-list';
    whyList.style.display = 'none';
    result.why.forEach((reason) => {
      const li = document.createElement('li');
      li.textContent = reason;
      whyList.appendChild(li);
    });
    banner.appendChild(whyList);

    whyToggle.onclick = () => {
      whyList.style.display = whyList.style.display === 'none' ? 'block' : 'none';
    };

    document.body.appendChild(banner);

    // A flagged site stays up until the user actively clicks away from it —
    // it does not time out on its own. Only the "looks fine" toast above
    // auto-dismisses; a real warning shouldn't disappear just because a few
    // seconds passed.
    function handleOutsideClick(e) {
      if (banner.contains(e.target)) return; // clicks inside the banner (Why/Dismiss) are handled separately
      dismissBanner();
    }
    function dismissBanner() {
      banner.remove();
      document.removeEventListener('click', handleOutsideClick, true);
    }
    dismiss.onclick = dismissBanner;

    // Deferred so the same click that focused the field (which is what
    // triggered this banner) doesn't immediately count as a "click off" and
    // dismiss the banner the instant it appears.
    setTimeout(() => {
      document.addEventListener('click', handleOutsideClick, true);
    }, 0);
  }

  function isSensitiveField(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.type === 'password') return true;
    const autocomplete = (el.autocomplete || '').toLowerCase();
    return autocomplete.includes('cc-number') || autocomplete.includes('cc-') || el.type === 'tel' && autocomplete.includes('cc');
  }

  // --- Tier 1: known-bad, shown immediately on page load ---
  //
  // A confirmed phishing/malware blocklist hit isn't a "maybe" the way a
  // new domain or a typosquat is — and some attacks (drive-by downloads,
  // malicious redirects, background scripts) don't need the user to click
  // or type anything at all. Waiting for a field focus would mean the
  // warning arrives too late, or never, for exactly the highest-severity
  // case. So this one check runs unconditionally as soon as the page is
  // ready, before any user interaction.
  function runImmediateCheck(ctx) {
    if (ctx.safeBrowsingHit === true) {
      injectBanner({
        level: 'danger',
        text: 'This site has been reported for phishing or malware. Consider leaving this page.',
        why: [
          'Flagged on a known-phishing blocklist',
          'Shown immediately \u2014 confirmed threats aren\u2019t worth waiting on, since some attacks don\u2019t require you to click or type anything',
        ],
      });
      resultShown = true;
    }
  }

  // --- Tier 2: heuristic-only signals, shown when the user takes a risky action ---
  //
  // A brand-new domain, an unusual TLD, or a name that resembles a known
  // brand are all probabilistic signals, not certainties — plenty of new,
  // legitimate sites would trip these. Showing a banner for every one of
  // them on every page load is exactly how people learn to ignore security
  // warnings. The real danger from these signals is specific: handing the
  // site your password or payment details. So this tier waits for that
  // moment instead of firing on load.
  function runFocusCheck(target, ctx) {
    if (!isSensitiveField(target)) return;
    if (resultShown) return; // Tier 1 already showed the strongest possible warning
    resultShown = true;
    const signals = computeSignals(ctx);
    const message = buildMessage(signals);
    injectBanner(message);
  }

  async function initialize() {
    const baseCtx = getContext();
    const firstVisit = await getFirstVisitSignal(baseCtx.hostname);
    const ctx = { ...baseCtx, firstVisit };

    runImmediateCheck(ctx);
    document.addEventListener('focusin', (e) => runFocusCheck(e.target, ctx));
  }

  initialize();
})();
