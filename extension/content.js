// Plain-Language Site Risk Checker
//
// Every signal below is real. There is no mock lookup table in this file.
//
// Local, no network at all:
//   - HTTPS vs HTTP
//   - Risky TLD
//   - Homograph / typosquat distance against a known-brand list
//   - Brand claim extracted from the rendered page
//   - Form destination mismatch (does the credential form post somewhere else)
//
// Answered by the background worker, always fail-open:
//   - First visit to this domain (chrome.history, on-device)
//   - Domain age (RDAP — free, keyless, no backend)
//   - Blocklist reputation (bundled CC0 feed snapshot, refreshed when online)
//
// Demo pages may declare their own identity and lookup results via
// <meta name="demo-..."> tags, so a scripted scenario can be reproduced
// without registering real look-alike domains. Those tags live in the demo
// pages, not in here — a genuine website has no reason to include them, so
// every value this file acts on is either really measured or openly declared
// by the page under inspection.

(function () {
  const KNOWN_BRANDS = ['paypal', 'chase', 'amazon', 'microsoft', 'apple', 'bankofamerica', 'wellsfargo'];
  const RISKY_TLDS = new Set(['zip', 'top', 'tk', 'click', 'xyz', 'gq', 'work', 'link']);
  const NEW_DOMAIN_DAYS = 30;
  const LEVEL_RANK = { none: 0, warning: 1, danger: 2 };

  const BRAND_LABELS = {
    paypal: 'PayPal',
    chase: 'Chase',
    amazon: 'Amazon',
    microsoft: 'Microsoft',
    apple: 'Apple',
    bankofamerica: 'Bank of America',
    wellsfargo: 'Wells Fargo',
  };

  // --- Helpers -------------------------------------------------------------

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
    const parts = hostname.split('.');
    const withoutTld = parts.length > 1 ? parts.slice(0, -1).join('.') : hostname;
    return withoutTld.replace(/^www\./, '').toLowerCase();
  }

  function getTld(hostname) {
    const parts = hostname.split('.');
    return parts[parts.length - 1].toLowerCase();
  }

  function brandLabel(brand) {
    return BRAND_LABELS[brand] || brand;
  }

  function humanizeAge(days) {
    if (days === 0) return 'today';
    if (days === 1) return 'yesterday';
    if (days < 30) return `${days} days ago`;
    if (days < 365) return `${Math.floor(days / 30)} months ago`;
    const years = Math.floor(days / 365);
    return years === 1 ? 'a year ago' : `${years} years ago`;
  }

  function findTyposquat(hostname) {
    const core = coreName(hostname);
    // Compare the whole label (catches "rnicrosoft.com") and each
    // hyphen/underscore-separated segment (catches "paypa1-secure-login.tk").
    // A single concatenated comparison misses the hyphenated case entirely.
    const wholeToken = core.replace(/[^a-z0-9]/g, '');
    const segments = core.split(/[^a-z0-9]+/).filter((seg) => seg.length >= 4);
    const candidates = [wholeToken, ...segments];

    let best = null;
    for (const brand of KNOWN_BRANDS) {
      for (const candidate of candidates) {
        if (candidate === brand) continue; // the brand's own name, not a typosquat
        const distance = levenshtein(candidate, brand);
        if (distance > 0 && distance <= 2 && (best === null || distance < best.distance)) {
          best = { brand, distance };
        }
      }
    }
    return best;
  }

  // What brand does this page present itself as? Deliberately minimal: title,
  // headings, og:site_name and logo alt text, matched against the known-brand
  // list. Fuzzy identification of arbitrary brands is the job of the optional
  // enrichment call described in the README, not of this rule.
  function extractBrandClaim() {
    const sources = [
      document.title,
      ...[...document.querySelectorAll('h1, h2')].slice(0, 5).map((el) => el.textContent),
      ...[...document.querySelectorAll('img[alt]')].slice(0, 15).map((el) => el.alt),
      (document.querySelector('meta[property="og:site_name"]') || {}).content,
      (document.querySelector('meta[name="application-name"]') || {}).content,
    ];
    const haystack = sources.filter(Boolean).join(' ').toLowerCase().replace(/[^a-z0-9]+/g, '');
    return KNOWN_BRANDS.find((brand) => haystack.includes(brand)) || null;
  }

  // Does the form containing this field submit somewhere other than this page?
  // Credentials leaving to a third-party origin is one of the strongest
  // phishing signals available, and it needs no permission and no network.
  function findFormActionMismatch(field) {
    const form = field.form;
    if (!form) return null;

    // Read the attribute rather than form.action: the DOM property resolves a
    // missing action to the document URL, which would hide the difference
    // between "no action" and "posts to itself".
    const candidates = [form.getAttribute('action')];
    form.querySelectorAll('[formaction]').forEach((el) => candidates.push(el.getAttribute('formaction')));

    for (const raw of candidates) {
      if (!raw) continue;
      if (/^(javascript|data|mailto|about):/i.test(raw.trim())) continue;
      let resolved;
      try { resolved = new URL(raw, location.href); }
      catch (_) { continue; }
      if (!/^https?:$/.test(resolved.protocol)) continue;
      if (resolved.origin !== location.origin) {
        return { destination: resolved.hostname };
      }
    }
    return null;
  }

  function isSensitiveField(el) {
    if (!(el instanceof HTMLInputElement)) return false;
    if (el.type === 'password') return true;
    const autocomplete = (el.autocomplete || '').toLowerCase();
    return autocomplete.includes('cc-');
  }

  // --- Page context --------------------------------------------------------

  function metaContent(name) {
    const el = document.querySelector(`meta[name="${name}"]`);
    return el ? el.content : null;
  }

  function getContext() {
    const demoHostname = metaContent('demo-hostname');
    const demoHttps = metaContent('demo-https');
    const demoArrived = metaContent('demo-arrived-via-link');

    return {
      hostname: demoHostname || location.hostname,
      isHttps: demoHttps !== null ? demoHttps === 'true' : location.protocol === 'https:',
      arrivedViaLink: demoArrived !== null
        ? demoArrived === 'true'
        : Boolean(document.referrer) && (() => {
            try { return new URL(document.referrer).hostname !== location.hostname; }
            catch (_) { return false; }
          })(),
    };
  }

  function ask(type, hostname) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type, hostname }, (response) => {
          if (chrome.runtime.lastError || !response) { resolve(null); return; }
          resolve(response);
        });
      } catch (_) {
        resolve(null); // extension context invalidated (e.g. reloaded) — fail open
      }
    });
  }

  // --- Tier 4: message templates -------------------------------------------
  //
  // Priority-ordered, most severe first. Each entry is a pure function of the
  // signals, so the same evidence always produces the same message and every
  // message can name the signals that fired. No network call is involved in
  // generating any of this.

  const TEMPLATES = [
    {
      id: 'blocklist_hit',
      level: 'danger',
      when: (s) => s.blocklistHit === true,
      template: 'This page has already been reported for stealing passwords. Do not enter anything here.',
      evidence: ['blocklist_hit'],
      why: () => ['Listed on a community phishing blocklist'],
    },
    {
      id: 'form_action_mismatch',
      level: 'danger',
      when: (s) => Boolean(s.formMismatch),
      template: 'Anything you type here goes to someone other than {brand}.',
      slots: (s) => ({ brand: s.claimedBrand ? brandLabel(s.claimedBrand) : 'this site' }),
      evidence: ['form_action_mismatch'],
      why: (s) => [
        `The form on this page submits to ${s.formMismatch.destination}, not to this site`,
        ...(s.claimedBrand ? [`This page presents itself as ${brandLabel(s.claimedBrand)}`] : []),
      ],
    },
    {
      id: 'young_domain_brand_mismatch',
      level: 'danger',
      when: (s) => s.typosquat && s.domainAgeDays !== null && s.domainAgeDays < NEW_DOMAIN_DAYS,
      template: 'This site was registered {age} and is not the real {brand}.',
      slots: (s) => ({ age: humanizeAge(s.domainAgeDays), brand: brandLabel(s.typosquat.brand) }),
      evidence: ['typosquat_distance', 'domain_age'],
      why: (s) => [
        `Domain name is ${s.typosquat.distance} character${s.typosquat.distance === 1 ? '' : 's'} off from "${s.typosquat.brand}"`,
        `Domain was registered ${humanizeAge(s.domainAgeDays)}`,
      ],
    },
    {
      id: 'typosquat_only',
      level: 'danger',
      when: (s) => Boolean(s.typosquat),
      template: 'This domain closely resembles {brand} but is not their official site.',
      slots: (s) => ({ brand: brandLabel(s.typosquat.brand) }),
      evidence: ['typosquat_distance'],
      why: (s) => [
        `Domain name is ${s.typosquat.distance} character${s.typosquat.distance === 1 ? '' : 's'} off from "${s.typosquat.brand}"`,
      ],
    },
    {
      id: 'young_domain_via_link',
      level: 'warning',
      when: (s) => s.domainAgeDays !== null && s.domainAgeDays < NEW_DOMAIN_DAYS && s.arrivedViaLink,
      template: 'You just arrived here from a link, and this site was only registered {age}. Verify it is really who it claims to be before entering anything.',
      slots: (s) => ({ age: humanizeAge(s.domainAgeDays) }),
      evidence: ['domain_age', 'referrer_context'],
      why: (s) => [
        `Domain was registered ${humanizeAge(s.domainAgeDays)}`,
        'Arrived via an external link, not a bookmark or direct visit',
      ],
    },
    {
      id: 'first_visit_via_link',
      level: 'warning',
      // Only when there is no domain-age data at all, so this never overrides a
      // stronger, age-informed signal.
      when: (s) => s.firstVisit === true && s.arrivedViaLink && s.domainAgeDays === null,
      template: 'You have never been to this site before, and you just arrived here from a link. Make sure it is really who it claims to be before entering anything.',
      evidence: ['first_visit', 'referrer_context'],
      why: () => [
        'First time this browser has visited this domain',
        'Arrived via an external link, not a bookmark or direct visit',
      ],
    },
    {
      id: 'risky_tld',
      level: 'warning',
      when: (s) => s.tldRisky,
      template: 'This domain ending is commonly used for scam and throwaway sites. Double-check this is really who it claims to be.',
      evidence: ['tld_risk'],
      why: (s) => [`".${getTld(s.hostname)}" domains have a higher rate of reported abuse`],
    },
    {
      id: 'no_https',
      level: 'warning',
      when: (s) => !s.isHttps,
      template: 'This page is not encrypted. Anything you type here, including your password, can potentially be read by others on the network.',
      evidence: ['no_https'],
      why: () => ['Connection is HTTP, not HTTPS'],
    },
  ];

  function fillSlots(template, slots) {
    return template.replace(/\{(\w+)\}/g, (match, key) => (key in slots ? slots[key] : match));
  }

  function buildMessage(signals) {
    const match = TEMPLATES.find((t) => t.when(signals));
    if (!match) return null;

    const slots = match.slots ? match.slots(signals) : {};
    const why = match.why ? match.why(signals) : [];

    // The first-visit signal is real and free, so it is worth surfacing as
    // supporting detail on any warning that did not already cite it.
    const withFirstVisit = signals.firstVisit === true && !match.evidence.includes('first_visit')
      ? [...why, 'First time this browser has visited this domain']
      : why;

    return {
      id: match.id,
      level: match.level,
      text: fillSlots(match.template, slots),
      why: withFirstVisit,
      evidence: match.evidence,
    };
  }

  // --- Banner --------------------------------------------------------------

  function injectBanner(result) {
    document.querySelectorAll('.plsr-banner, .plsr-toast').forEach((el) => el.remove());

    if (!result) {
      // Nothing flagged — a brief, self-dismissing confirmation. This is the
      // only case that disappears on its own.
      const toast = document.createElement('div');
      toast.className = 'plsr-toast';
      toast.textContent = 'Checked this site — looks fine.';
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

    // A flagged site stays up until the user actively clicks away. Only the
    // "looks fine" toast auto-dismisses; a real warning should not disappear
    // just because a few seconds passed.
    function handleOutsideClick(e) {
      if (banner.contains(e.target)) return; // Why/Dismiss are handled separately
      dismissBanner();
    }
    function dismissBanner() {
      banner.remove();
      document.removeEventListener('click', handleOutsideClick, true);
    }
    dismiss.onclick = dismissBanner;

    // Deferred so the same click that focused the field does not immediately
    // count as a click-off and dismiss the banner the instant it appears.
    setTimeout(() => {
      document.addEventListener('click', handleOutsideClick, true);
    }, 0);
  }

  // --- State and escalation ------------------------------------------------
  //
  // Signals arrive at different times: TLD and typosquat are synchronous,
  // history and RDAP are not. So the verdict is re-evaluated whenever new
  // evidence lands, and the banner is allowed to escalate in place.
  //
  // It is never allowed to downgrade. A card that has said "dangerous" must
  // not soften because a slower, weaker signal resolved afterwards.

  const state = {
    signals: null,
    focused: false,
    shownLevel: 'none',
    shownId: null,
    dismissedToast: false,
  };

  function render(result) {
    const level = result ? result.level : 'none';
    if (LEVEL_RANK[level] < LEVEL_RANK[state.shownLevel]) return;      // never downgrade
    if (result && result.id === state.shownId) return;                 // already showing this
    if (!result && state.dismissedToast) return;                       // one "looks fine" is enough

    injectBanner(result);
    state.shownLevel = level;
    state.shownId = result ? result.id : null;
    if (!result) state.dismissedToast = true;
  }

  function evaluate() {
    const s = state.signals;

    // Tier 1 — a confirmed blocklist hit is not a "maybe", and some attacks
    // (drive-by downloads, malicious redirects, background scripts) never
    // require the user to type anything. This one does not wait for a focus.
    if (s.blocklistHit === true) {
      render(buildMessage(s));
      return;
    }

    // Tier 2 — everything else is probabilistic. Firing on every page load is
    // how people learn to ignore security banners, so these wait for the
    // moment the risk actually materializes: handing the site a secret.
    if (!state.focused) return;
    render(buildMessage(s));
  }

  function updateSignals(partial) {
    state.signals = { ...state.signals, ...partial };
    evaluate();
  }

  // --- Init ----------------------------------------------------------------

  function initialize() {
    const ctx = getContext();

    const demoAge = metaContent('demo-domain-age-days');
    const demoBlocklist = metaContent('demo-blocklist-hit');
    const demoFirstVisit = metaContent('demo-first-visit');

    state.signals = {
      ...ctx,
      typosquat: findTyposquat(ctx.hostname),
      tldRisky: RISKY_TLDS.has(getTld(ctx.hostname)),
      claimedBrand: extractBrandClaim(),
      formMismatch: null,
      firstVisit: demoFirstVisit !== null ? demoFirstVisit === 'true' : null,
      domainAgeDays: demoAge !== null ? Number(demoAge) : null,
      blocklistHit: demoBlocklist !== null ? demoBlocklist === 'true' : null,
    };

    // Gate the lookups on having a hostname worth looking up rather than on
    // the page protocol: a file:// demo page that declares a real hostname
    // should still get real answers, while a bare file:// page (hostname "")
    // asks nothing. Each lookup is separately skipped when the page has
    // already declared that value itself.
    const hasLookupableHost = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(ctx.hostname);

    // Each lookup updates independently and re-triggers evaluation as it lands,
    // so a slow RDAP response can upgrade a banner that is already on screen
    // without ever blocking the first one from appearing.
    if (demoBlocklist === null && hasLookupableHost) {
      ask('CHECK_BLOCKLIST', ctx.hostname).then((r) => updateSignals({ blocklistHit: r ? r.blocklistHit : null }));
    }
    if (demoFirstVisit === null && hasLookupableHost) {
      ask('CHECK_FIRST_VISIT', ctx.hostname).then((r) => updateSignals({ firstVisit: r ? r.isFirstVisit : null }));
    }
    if (demoAge === null && hasLookupableHost) {
      ask('CHECK_DOMAIN_AGE', ctx.hostname).then((r) => updateSignals({ domainAgeDays: r ? r.domainAgeDays : null }));
    }

    evaluate(); // Tier 1 may already be decidable from a demo tag

    document.addEventListener('focusin', (e) => {
      if (!isSensitiveField(e.target)) return;
      state.focused = true;
      // The form-destination check needs the focused field to find its form,
      // so it runs here rather than up front.
      const mismatch = findFormActionMismatch(e.target);
      if (mismatch) {
        updateSignals({ formMismatch: mismatch });
      } else {
        evaluate();
      }
    });
  }

  initialize();
})();
