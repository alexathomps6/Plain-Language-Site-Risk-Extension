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
// Tier 2, rendered page inspection (page-inspection.js, local DOM reads):
//   - Credential overlay, measured by hit-testing the field's own box
//   - Hidden shadow copies of a sensitive field
//   - Field inventory against plausibility
//   - Fake browser chrome rendered into the page
//   - Form posting over plain HTTP from an HTTPS page
//   - Third-party iframe over the credential area
//   - Obfuscated inline script, anti-inspection code, pressure language
//
// Tier 3, network traffic inspection (metadata only, never bodies):
//   - page-probe.js, in the page's own world: traffic correlated with
//     keystrokes in a sensitive field, live channels, runtime rewriting of a
//     form's destination
//   - background.js, via webRequest: redirect chains, raw-IP endpoints,
//     unrelated script origins, known credential-relay services
//
// Answered by the background worker, always fail-open:
//   - First visit to this domain (chrome.history, on-device)
//   - Domain age (RDAP, free, keyless, no backend)
//   - Blocklist reputation (bundled CC0 feed snapshot, refreshed when online)
//
// Demo pages may declare their own identity and Tier 1 lookup results via
// <meta name="demo-..."> tags, so a scripted scenario can be reproduced
// without registering real look-alike domains. Those tags live in the demo
// pages, not in here, and they cover Tier 1 only — every Tier 2 and Tier 3
// finding is measured from the page as it actually renders and behaves. A
// genuine website has no reason to include those tags, so every value this
// file acts on is either really measured or openly declared by the page under
// inspection.

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

  function humanList(items) {
    if (items.length <= 1) return items[0] || '';
    return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
  }

  const TRAFFIC_LABELS = {
    fetch: 'background request',
    xhr: 'background request',
    beacon: 'beacon',
    websocket: 'live connection',
  };

  // page-inspection.js is a content script loaded ahead of this one, so it has
  // already populated this global. The fallback keeps the extension working
  // (minus Tier 2) if that file ever fails to load, rather than throwing and
  // taking every other signal down with it.
  const INSPECTION = globalThis.PLSR_PAGE_INSPECTION || {
    CRITERIA: { network: { exfilWhileTyping: { maxMsSinceKeystroke: 2000, kinds: [] } } },
    inspectPage: () => ({}),
  };

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
        resolve(null); // extension context invalidated (e.g. reloaded), fail open
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
      // Tier 3, the strongest thing this extension can observe: data leaving
      // the page on the same keystrokes the user is making, with no form
      // submission anywhere in sight.
      id: 'exfil_while_typing',
      level: 'danger',
      when: (s) => Boolean(s.probe.exfilWhileTyping),
      template: 'This page is sending what you type as you type it, before you ever hit submit.',
      evidence: ['exfil_while_typing'],
      why: (s) => [
        `A ${TRAFFIC_LABELS[s.probe.exfilWhileTyping.kind] || 'request'} was sent to ` +
        `${s.probe.exfilWhileTyping.host} ${s.probe.exfilWhileTyping.msSinceKeystroke}ms after you typed in this field`,
        'No form had been submitted at that point, so this was not a normal sign-in',
      ],
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
      // The static check above reads the markup. This one catches the evasion
      // of shipping clean markup and repointing the form from script once the
      // page is live.
      id: 'action_mutated_at_runtime',
      level: 'danger',
      when: (s) => Boolean(s.probe.actionMutation),
      template: 'This page quietly changed where your details get sent after it finished loading.',
      evidence: ['action_mutated_at_runtime'],
      why: (s) => [
        `Script on this page rewrote the form's ${s.probe.actionMutation.attribute} to point at ${s.probe.actionMutation.host}`,
        'The destination in the page source was not the destination that would have been used',
      ],
    },
    {
      id: 'insecure_form_action',
      level: 'danger',
      when: (s) => Boolean(s.page && s.page.insecureFormAction),
      template: 'The padlock on this page does not cover your password — this form sends it unencrypted.',
      evidence: ['insecure_form_action'],
      why: (s) => [
        `The page is HTTPS, but the form submits over plain HTTP to ${s.page.insecureFormAction.destination}`,
        'Anyone on the same network can read what is submitted',
      ],
    },
    {
      id: 'credential_overlay_iframe',
      level: 'danger',
      when: (s) => Boolean(s.page && s.page.overlay && s.page.overlay.kind === 'iframe'),
      template: "The box you're typing into isn't part of this page — it belongs to {host}.",
      slots: (s) => ({ host: s.page.overlay.host || 'another site' }),
      evidence: ['credential_overlay'],
      why: (s) => [
        `A window from ${s.page.overlay.host || 'another site'} is layered over this field`,
        `It covers ${s.page.overlay.coveredPoints} of ${s.page.overlay.sampled} points tested across the field`,
      ],
    },
    {
      id: 'credential_overlay_invisible',
      level: 'danger',
      when: (s) => Boolean(s.page && s.page.overlay && s.page.overlay.kind === 'invisible'),
      template: "The box you're typing into isn't part of this page — something is layered over it.",
      evidence: ['credential_overlay'],
      why: (s) => [
        `An invisible <${s.page.overlay.tag}> element sits on top of this field`,
        `It covers ${s.page.overlay.coveredPoints} of ${s.page.overlay.sampled} points tested across the field`,
      ],
    },
    {
      id: 'shadow_capture_input',
      level: 'danger',
      when: (s) => Boolean(s.page && s.page.shadowInput),
      template: 'There is a second, hidden copy of this field on the page, collecting the same thing you type.',
      evidence: ['shadow_capture_input'],
      why: (s) => [
        `A hidden field ("${s.page.shadowInput.name}") duplicates the one you can see`,
        'Legitimate sign-in forms do not keep an invisible copy of your password',
      ],
    },
    {
      id: 'fake_browser_chrome',
      level: 'danger',
      when: (s) => Boolean(s.page && s.page.fakeBrowserChrome && s.page.fakeBrowserChrome.spoofed),
      template: 'The address bar at the top of this page is a picture drawn by the page, not your real one.',
      evidence: ['fake_browser_chrome'],
      why: (s) => [
        `The page draws "${s.page.fakeBrowserChrome.shownHost}" with a padlock, as if it were the browser's address bar`,
        `You are actually on ${s.page.fakeBrowserChrome.actualHost}`,
      ],
    },
    {
      id: 'exfil_service_endpoint',
      level: 'danger',
      when: (s) => Boolean(s.network && s.network.exfilServices.length),
      template: 'This page is wired to send data to {service}, which is commonly used to collect stolen logins.',
      slots: (s) => ({ service: s.network.exfilServices[0].label }),
      evidence: ['exfil_service_endpoint'],
      why: (s) => [
        `The page contacted ${s.network.exfilServices[0].host}, a known credential drop-off service`,
        'A real sign-in page sends your details to its own servers',
      ],
    },
    {
      id: 'raw_ip_endpoint',
      level: 'danger',
      when: (s) => Boolean(s.network && s.network.rawIpHosts.length),
      template: 'This sign-in page is talking to a bare IP address instead of a named site.',
      slots: (s) => ({ host: s.network.rawIpHosts[0] }),
      evidence: ['raw_ip_endpoint'],
      why: (s) => [
        `Code or data on this page goes to ${s.network.rawIpHosts[0]}, which has no domain name behind it`,
        'Established services put their infrastructure behind named domains',
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
      id: 'field_inventory_branded',
      level: 'danger',
      when: (s) => Boolean(s.page && s.page.fieldInventory) && Boolean(s.claimedBrand),
      template: '{brand} does not ask for {extras} to sign in. This page does.',
      slots: (s) => ({
        brand: brandLabel(s.claimedBrand),
        extras: humanList(s.page.fieldInventory.extras),
      }),
      evidence: ['field_inventory_implausible', 'brand_claim'],
      why: (s) => [
        `This one form asks for ${humanList(s.page.fieldInventory.extras)} alongside your password`,
        `This page presents itself as ${brandLabel(s.claimedBrand)}`,
      ],
    },
    {
      id: 'field_inventory_unbranded',
      level: 'warning',
      when: (s) => Boolean(s.page && s.page.fieldInventory),
      template: 'A sign-in page has no reason to ask for {extras} as well as your password.',
      slots: (s) => ({ extras: humanList(s.page.fieldInventory.extras) }),
      evidence: ['field_inventory_implausible'],
      why: (s) => [
        `This one form asks for ${humanList(s.page.fieldInventory.extras)} alongside your password`,
        'Collecting several unrelated kinds of sensitive data in one form is a harvesting pattern',
      ],
    },
    {
      id: 'third_party_credential_frame',
      level: 'warning',
      when: (s) => Boolean(s.page && s.page.thirdPartyFrame),
      template: 'The sign-in box on this page is served by {host}, which is not part of this site.',
      slots: (s) => ({ host: s.page.thirdPartyFrame.host }),
      evidence: ['third_party_credential_frame'],
      why: (s) => [
        `The credential area is covered by a frame from ${s.page.thirdPartyFrame.host}`,
        'That host is not a recognised payment or sign-in provider',
      ],
    },
    {
      id: 'websocket_on_credential_page',
      level: 'warning',
      when: (s) => s.probe.websocketHosts.length > 0 || Boolean(s.network && s.network.websocketHosts.length),
      template: 'This page opened a live connection to {host} while asking you to sign in.',
      slots: (s) => ({ host: s.probe.websocketHosts[0] || s.network.websocketHosts[0] }),
      evidence: ['websocket_on_credential_page'],
      why: (s) => [
        `A live channel to ${s.probe.websocketHosts[0] || s.network.websocketHosts[0]} is open on this page`,
        'Relay kits use live channels to forward what you type to an operator immediately',
      ],
    },
    {
      id: 'suspicious_redirect_chain',
      level: 'warning',
      when: (s) => Boolean(s.network && s.network.redirectChain),
      template: 'You were bounced through {hops} other sites to reach this page.',
      slots: (s) => ({ hops: s.network.redirectChain.hops }),
      evidence: ['redirect_chain'],
      why: (s) => [
        s.network.redirectChain.shortener
          ? `The trail started at the link shortener ${s.network.redirectChain.shortener}`
          : `The trail crossed ${s.network.redirectChain.sites.length} different sites: ${s.network.redirectChain.sites.join(' \u2192 ')}`,
        'Chained redirects are used to hide where a link really leads',
      ],
    },
    {
      id: 'obfuscated_script',
      level: 'warning',
      when: (s) => Boolean(s.page && s.page.obfuscatedScript),
      template: 'The code running on this page is deliberately scrambled, which a real sign-in page has no reason to do.',
      evidence: ['obfuscated_script'],
      why: (s) => [
        `An inline script on this page ${humanList(s.page.obfuscatedScript.indicators)}`,
        'Phishing kits scramble their code to slow down anyone inspecting them',
      ],
    },
    {
      id: 'unrelated_script_origin',
      level: 'warning',
      when: (s) => Boolean(s.network && s.network.unrelatedScriptHosts.length),
      template: 'This sign-in page runs code from {host}, which has nothing to do with this site.',
      slots: (s) => ({ host: s.network.unrelatedScriptHosts[0] }),
      evidence: ['unrelated_script_origin'],
      why: (s) => [
        `Executable code was loaded from ${s.network.unrelatedScriptHosts[0]}`,
        'That host is neither this site nor a recognised content delivery network',
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

  // Signals too weak to select a message on their own, but worth showing in
  // the expandable detail once something else has fired. Each is appended only
  // if the chosen template did not already cite it.
  //
  // Keystroke listeners and urgency phrasing live here rather than in
  // TEMPLATES on purpose: a password strength meter binds to every keystroke,
  // and plenty of legitimate account-recovery pages sound urgent. As
  // corroboration they are useful; as a verdict they would be a false alarm
  // generator, and a false alarm on a real bank login is the exact failure
  // this project exists to avoid.
  const SUPPORTING = [
    {
      evidence: 'first_visit',
      when: (s) => s.firstVisit === true,
      text: () => 'First time this browser has visited this domain',
    },
    {
      evidence: 'keystroke_listener',
      when: (s) => s.probe.keystrokeListeners.length > 0,
      text: (s) => `Script on this page is listening to every "${s.probe.keystrokeListeners[0]}" event in this field`,
    },
    {
      evidence: 'pressure_language',
      when: (s) => Boolean(s.page && s.page.pressureLanguage),
      text: (s) => `Page uses urgency or account-suspension language (${s.page.pressureLanguage.matches} distinct phrases)`,
    },
    {
      evidence: 'anti_inspection',
      when: (s) => Boolean(s.page && s.page.antiInspection),
      text: (s) => `Page tries to prevent inspection: ${s.page.antiInspection.technique}`,
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

    const supporting = SUPPORTING
      .filter((sup) => !match.evidence.includes(sup.evidence) && sup.when(signals))
      .map((sup) => sup.text(signals));

    return {
      id: match.id,
      level: match.level,
      text: fillSlots(match.template, slots),
      why: [...why, ...supporting],
      evidence: match.evidence,
    };
  }

  // --- Banner --------------------------------------------------------------
  //
  // A card is created once and updated in place for every later escalation.
  // The previous version removed and rebuilt the whole element on every call,
  // which replayed the entrance animation each time, visually indistinguishable
  // from the warning vanishing and a new one appearing, even though nothing
  // was actually auto-dismissing. Confirmed with real timing: a typosquat
  // warning appeared at 86ms and was torn down and replaced at 591ms once
  // domain age landed, well under a second and well before a person could
  // read the first line. Same content, same card, updated text: the fix.

  let mountedBanner = null;
  let outsideClickHandler = null;

  const ICONS = {
    danger: '<path d="M12 3.5 2.5 20h19L12 3.5Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9.5v4.2M12 16.8v.2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    warning: '<path d="M12 3.5 2.5 20h19L12 3.5Z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/><path d="M12 9.5v4.2M12 16.8v.2" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    ok: '<path d="M5 12.5l4.5 4.5L19 7.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
  };

  function svgIcon(kind) {
    return `<svg class="plsr-icon" viewBox="0 0 24 24" width="15" height="15" aria-hidden="true">${ICONS[kind]}</svg>`;
  }

  function dismissBanner() {
    if (mountedBanner) {
      mountedBanner.remove();
      mountedBanner = null;
    }
    if (outsideClickHandler) {
      document.removeEventListener('click', outsideClickHandler, true);
      outsideClickHandler = null;
    }
  }

  function fillWhyList(whyList, reasons) {
    whyList.innerHTML = '';
    reasons.forEach((reason) => {
      const li = document.createElement('li');
      li.textContent = reason;
      whyList.appendChild(li);
    });
  }

  function buildBannerDom(result) {
    const banner = document.createElement('div');
    banner.className = `plsr-banner plsr-${result.level}`;
    banner.innerHTML = `
      <div class="plsr-accent"></div>
      <div class="plsr-kicker">${svgIcon(result.level)}<span>Heads Up</span></div>
      <div class="plsr-message"></div>
      <div class="plsr-row">
        <button type="button" class="plsr-link-btn plsr-why-toggle">Why am I seeing this?</button>
        <button type="button" class="plsr-link-btn plsr-dismiss">Dismiss</button>
      </div>
      <ul class="plsr-why-list" style="display:none"></ul>
    `;
    banner.querySelector('.plsr-message').textContent = result.text;
    fillWhyList(banner.querySelector('.plsr-why-list'), result.why);

    const whyList = banner.querySelector('.plsr-why-list');
    banner.querySelector('.plsr-why-toggle').onclick = () => {
      whyList.style.display = whyList.style.display === 'none' ? 'block' : 'none';
    };
    banner.querySelector('.plsr-dismiss').onclick = dismissBanner;
    return banner;
  }

  function updateBannerInPlace(banner, result) {
    banner.className = `plsr-banner plsr-${result.level} plsr-pulse`;
    banner.querySelector('.plsr-kicker').innerHTML = `${svgIcon(result.level)}<span>Heads Up</span>`;
    banner.querySelector('.plsr-message').textContent = result.text;
    const whyList = banner.querySelector('.plsr-why-list');
    const wasOpen = whyList.style.display !== 'none';
    fillWhyList(whyList, result.why);
    whyList.style.display = wasOpen ? 'block' : 'none';
    // Signals "this just changed" with a brief ring rather than replaying the
    // full entrance animation. The card never actually left the screen.
    banner.addEventListener('animationend', () => banner.classList.remove('plsr-pulse'), { once: true });
  }

  function injectBanner(result) {
    document.querySelectorAll('.plsr-toast').forEach((el) => el.remove());

    if (!result) {
      // Nothing flagged, a brief, self-dismissing confirmation. This is the
      // only case that disappears on its own.
      const toast = document.createElement('div');
      toast.className = 'plsr-toast';
      toast.innerHTML = `<div class="plsr-kicker">${svgIcon('ok')}<span>Heads Up</span></div><div class="plsr-toast-message">Checked this site, looks fine.</div>`;
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 3500);
      return;
    }

    if (mountedBanner) {
      updateBannerInPlace(mountedBanner, result);
      return;
    }

    mountedBanner = buildBannerDom(result);
    document.body.appendChild(mountedBanner);

    // A flagged site stays up until the user actively clicks away. Only the
    // "looks fine" toast auto-dismisses; a real warning should not disappear
    // just because a few seconds passed.
    //
    // Re-clicking the very field the warning is about (to reposition the
    // cursor before typing, which is completely normal) does not count as
    // "clicking away" -- it is the opposite, continued engagement with the
    // exact thing the warning is warning about. Confirmed as a real bug: a
    // second click on the same password field was dismissing the banner
    // essentially every time, since that field sits outside the banner's own
    // DOM subtree just like any other "outside" element.
    outsideClickHandler = (e) => {
      if (mountedBanner && mountedBanner.contains(e.target)) return; // Why/Dismiss handled separately
      if (isSensitiveField(e.target)) return; // re-focusing the field itself is not clicking away
      dismissBanner();
    };

    // Deferred so the same click that focused the field does not immediately
    // count as a click-off and dismiss the banner the instant it appears.
    setTimeout(() => {
      if (outsideClickHandler) document.addEventListener('click', outsideClickHandler, true);
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

    // Tier 1: a confirmed blocklist hit is not a "maybe", and some attacks
    // (drive-by downloads, malicious redirects, background scripts) never
    // require the user to type anything. This one does not wait for a focus.
    if (s.blocklistHit === true) {
      render(buildMessage(s));
      return;
    }

    // Tier 2: everything else is probabilistic. Firing on every page load is
    // how people learn to ignore security banners, so these wait for the
    // moment the risk actually materializes: handing the site a secret.
    if (!state.focused) return;
    render(buildMessage(s));
  }

  function updateSignals(partial) {
    state.signals = { ...state.signals, ...partial };
    evaluate();
  }

  // --- Tier 3: evidence from the in-page probe -----------------------------
  //
  // page-probe.js reports facts; the thresholds are applied here. That split
  // is deliberate — the probe runs in the page's own world, where hostile
  // script can read and forge what it sends. Keeping judgment on this side
  // means a page cannot reach the criteria, and because render() never
  // downgrades, a forged message can only raise a warning, never clear one.

  function handleProbeEvent(data) {
    const probe = state.signals.probe;
    const criteria = INSPECTION.CRITERIA.network;

    if (data.kind === 'traffic') {
      const t = data.detail;
      if (!t || !t.crossOrigin) return; // a page talking to itself is a page working

      const rule = criteria.exfilWhileTyping;
      const duringTyping = t.msSinceKeystroke !== null &&
        t.msSinceKeystroke <= rule.maxMsSinceKeystroke &&
        !t.afterSubmit;

      if (!probe.exfilWhileTyping && duringTyping && rule.kinds.includes(t.kind)) {
        updateSignals({
          probe: {
            ...probe,
            exfilWhileTyping: { host: t.host, kind: t.kind, msSinceKeystroke: t.msSinceKeystroke },
          },
        });
        return;
      }
      if (t.kind === 'websocket' && !probe.websocketHosts.includes(t.host)) {
        updateSignals({ probe: { ...probe, websocketHosts: [...probe.websocketHosts, t.host] } });
      }
      return;
    }

    if (data.kind === 'keystroke_listener') {
      const event = data.detail && data.detail.event;
      if (event && !probe.keystrokeListeners.includes(event)) {
        updateSignals({ probe: { ...probe, keystrokeListeners: [...probe.keystrokeListeners, event] } });
      }
      return;
    }

    if (data.kind === 'action_mutated' && !probe.actionMutation && data.detail) {
      updateSignals({ probe: { ...probe, actionMutation: data.detail } });
    }
  }

  function listenToProbe() {
    window.addEventListener('message', (event) => {
      if (event.source !== window) return;
      const data = event.data;
      if (!data || data.__plsr !== 'plsr-probe' || !data.kind) return;
      try { handleProbeEvent(data); } catch (_) { /* a malformed report is not a verdict */ }
    });
  }

  function askNetworkEvidence() {
    ask('CHECK_NETWORK_EVIDENCE', state.signals.hostname).then((response) => {
      // No worker, no permission, or no buffer for this tab all land here.
      // "No evidence" is not "no problem", so the signal simply stays null.
      if (!response || !response.networkEvidence) return;
      updateSignals({ network: response.networkEvidence });
    });
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
      // Tier 2 findings, filled in at focus: the checks need to know which
      // field the user is actually about to type into.
      page: null,
      // Tier 3, in-page half. Always an object so no template has to guard it.
      probe: { exfilWhileTyping: null, websocketHosts: [], keystrokeListeners: [], actionMutation: null },
      // Tier 3, webRequest half. Null until the worker answers, and null
      // forever if the permission was declined — which is a missing signal,
      // not a clean verdict.
      network: null,
      firstVisit: demoFirstVisit !== null ? demoFirstVisit === 'true' : null,
      domainAgeDays: demoAge !== null ? Number(demoAge) : null,
      blocklistHit: demoBlocklist !== null ? demoBlocklist === 'true' : null,
    };

    listenToProbe();

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
      // The Tier 2 checks and the form-destination check all need the focused
      // field — which form it belongs to, where it sits on screen, what is
      // stacked above it — so they run here rather than up front.
      updateSignals({
        formMismatch: findFormActionMismatch(e.target),
        page: INSPECTION.inspectPage(e.target),
      });

      // Tier 3's webRequest buffer is asked for now and once more shortly
      // after: scripts and channels a page opens in response to the user
      // reaching the login form have not necessarily loaded yet at focus time.
      askNetworkEvidence();
      setTimeout(askNetworkEvidence, 1200);
    });
  }

  initialize();
})();
