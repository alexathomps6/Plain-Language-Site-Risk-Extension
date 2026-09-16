// Tier 2 — rendered page inspection.
//
// Reads the live DOM the user is actually looking at, at the moment a
// sensitive field is focused. This is the tier that catches a kit on a clean
// domain: a phishing page that was stood up an hour ago passes every RDAP and
// blocklist check, but it still has to render a credential form and it still
// has to send the credentials somewhere.
//
// Every check below is a measurement against a stated threshold, not a vibe.
// The thresholds live in CRITERIA so they are inspectable, testable, and
// documented in CRITERIA.md rather than buried as magic numbers. Each check
// returns either null (did not fire) or an evidence object naming what was
// measured, so the banner can always explain itself.
//
// Nothing here reads a field's value. Sensitivity is determined from
// structure — type, autocomplete tokens, name/id/label text, geometry,
// computed style, stacking order — never from what the user typed.
//
// This file is a content script in the extension's isolated world, loaded
// before content.js, so content.js can read the global it exports.

(function () {
  const CRITERIA = {
    // An overlay has to actually cover the field to capture what goes into
    // it. Five sample points are taken across the field's box; three of them
    // resolving to the same foreign element is coverage, one is a rounded
    // border or a focus ring clipping a corner.
    overlay: {
      samplePoints: [[0.5, 0.5], [0.25, 0.25], [0.75, 0.25], [0.25, 0.75], [0.75, 0.75]],
      minCoveredPoints: 3,
      // Below this, the covering element is invisible to the user, which is
      // the entire point of a capture layer. A visible element sitting over a
      // field is a rendering bug, not an attack.
      maxOpacity: 0.1,
    },

    // A cross-origin iframe holding the credential area is normal for hosted
    // payment and SSO widgets and abnormal for everything else, so it fires
    // only for origins outside this list, and only as a warning.
    thirdPartyCredentialFrame: {
      minOverlapFraction: 0.5,
      knownProviders: [
        'stripe.com', 'stripe.network', 'braintreegateway.com', 'paypal.com', 'paypalobjects.com',
        'adyen.com', 'checkout.com', 'squareup.com', 'squarecdn.com', 'klarna.com', 'affirm.com',
        'google.com', 'gstatic.com', 'accounts.google.com', 'recaptcha.net', 'hcaptcha.com',
        'okta.com', 'oktacdn.com', 'auth0.com', 'microsoftonline.com', 'live.com', 'apple.com',
      ],
    },

    // A second, non-visible copy of a sensitive field in the same form is the
    // classic mirror-capture pattern: the user fills the visible one, script
    // copies into the hidden one, the hidden one is what gets submitted.
    shadowInput: {
      maxOpacity: 0.05,
      maxCollapsedPx: 1,
      // Far enough off-canvas that no layout does it by accident.
      offscreenPx: -500,
    },

    // No sign-in form needs a password plus two unrelated categories of
    // high-value personal data. Two is the threshold rather than one because
    // combined "create account and pay" flows legitimately pair a password
    // with card details, and flagging those would be a false positive on a
    // real checkout.
    fieldInventory: {
      minOtherCategoriesWithPassword: 2,
    },

    // A fake address bar has to be at the top of the page to be believable,
    // has to render a URL as text, and has to carry a padlock to sell it.
    // All three together; a URL printed in body copy is not an attack.
    fakeBrowserChrome: {
      topViewportFraction: 0.25,
      maxContainerTextLength: 300,
    },

    // Obfuscation is judged on several independent measurements so that one
    // minified bundle does not trip it. A classic packer signature is
    // conclusive on its own; otherwise two indicators must agree.
    obfuscatedScript: {
      minLength: 800,
      // Measured against this project's own source: ordinary, commented,
      // human-formatted JavaScript runs 4.86-5.16 bits/char, so an entropy
      // threshold alone fires on every file of normal code. Entropy is only
      // meaningful here alongside line density -- packed payloads are emitted
      // as one enormous line, human source is not.
      minEntropyBitsPerChar: 5.2,
      minEntropyLength: 1500,
      minAvgLineLength: 500,
      minEscapeDensity: 0.05,
      minBase64BlobLength: 512,
      // The default output of the common `javascript-obfuscator` toolchain.
      // Nothing written by a person names twenty variables `_0x4f2a1b`.
      minHexIdentifiers: 20,
      minIndicators: 2,
    },

    // Weak on its own by design: urgency phrasing is evidence that supports a
    // verdict, never a verdict by itself. It only ever reaches the "why" list.
    pressureLanguage: {
      minDistinctMatches: 2,
      maxTextLength: 4000,
    },

    // Tier 3, in-page half. Applied by content.js to what page-probe.js
    // reports. The probe measures; these decide.
    network: {
      // A request that leaves within this window of a keystroke in a password
      // or card field, with no submit having happened, is not a form
      // submission — it is the field's contents being relayed as they are
      // typed. Two seconds is wide enough to survive a debounce and narrow
      // enough that unrelated periodic traffic does not land inside it.
      exfilWhileTyping: {
        maxMsSinceKeystroke: 2000,
        kinds: ['fetch', 'xhr', 'beacon', 'websocket'],
      },
      // A live channel opened on a page holding a credential field, to
      // somewhere other than the page's own site. Real-time relay kits use
      // this to forward input to an operator while the victim is still typing.
      websocketOnCredentialPage: {
        requiresCrossOrigin: true,
      },
    },
  };

  const PRESSURE_LEXICON = [
    /\baccount (?:has been |will be )?(?:suspend|lock|disabl|restrict|clos)/i,
    /\bunusual (?:sign[- ]?in|activity|login)\b/i,
    /\bverify (?:your )?(?:identity|account|information) (?:now|immediately|within)\b/i,
    /\bwithin \d+ (?:hours?|minutes?|days?)\b/i,
    /\b(?:immediate|urgent|final) (?:action|notice|warning|reminder)\b/i,
    /\bfailure to (?:verify|confirm|respond|act)\b/i,
    /\bavoid (?:permanent )?(?:suspension|closure|termination)\b/i,
    /\byour access will be (?:revoked|removed|terminated)\b/i,
    /\bconfirm your details to (?:continue|restore|reactivate)\b/i,
  ];

  const ANTI_INSPECTION_PATTERNS = [
    /\bkeyCode\s*===?\s*123\b/,              // F12
    /\b(?:which|keyCode)\s*===?\s*73\b[\s\S]{0,80}\bshiftKey\b/, // Ctrl+Shift+I
    /addEventListener\(\s*['"]contextmenu['"][\s\S]{0,120}preventDefault/,
    /setInterval\([^)]{0,40}debugger/,
    /\bdevtools?(?:Open|Detect)/i,
  ];

  const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk',
    'com.au', 'net.au', 'org.au', 'edu.au',
    'co.nz', 'co.za', 'co.jp', 'co.kr', 'co.in',
    'com.br', 'com.mx', 'com.ar', 'com.tr', 'com.cn', 'com.tw', 'com.hk', 'com.sg',
  ]);

  function registrableDomain(hostname) {
    const parts = String(hostname || '').toLowerCase().replace(/\.$/, '').split('.');
    if (parts.length <= 2) return parts.join('.');
    const lastTwo = parts.slice(-2).join('.');
    return MULTI_PART_SUFFIXES.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
  }

  function sameSite(hostA, hostB) {
    const a = registrableDomain(hostA);
    const b = registrableDomain(hostB);
    return Boolean(a) && a === b;
  }

  // --- Field classification ------------------------------------------------
  //
  // Structural only. `type`, autocomplete tokens, and the words around the
  // field; never the value.

  const FIELD_CATEGORIES = [
    {
      id: 'password',
      label: 'a password',
      test: (f) => f.type === 'password' || /(?:current|new)-password/.test(f.autocomplete),
    },
    {
      id: 'payment_card',
      label: 'card details',
      test: (f) => /cc-(?:number|csc|exp)/.test(f.autocomplete) ||
        /card.?number|cardnum|ccnum|\bcvv\b|\bcvc\b|\bcsc\b|security.?code/.test(f.hay),
    },
    {
      id: 'government_id',
      label: 'a Social Security or national ID number',
      test: (f) => /\bssn\b|social.?security|national.?id|\btax.?id\b|passport.?number/.test(f.hay),
    },
    {
      id: 'date_of_birth',
      label: 'a date of birth',
      test: (f) => /date.?of.?birth|\bdob\b|birth.?date|birthday/.test(f.hay),
    },
    {
      id: 'security_answer',
      label: 'a security question answer',
      test: (f) => /mother'?s?.?maiden|maiden.?name|security.?(?:question|answer)|first.?pet/.test(f.hay),
    },
    {
      id: 'bank_account',
      label: 'bank account numbers',
      test: (f) => /routing.?number|account.?number|\biban\b|sort.?code/.test(f.hay),
    },
    {
      id: 'pin',
      label: 'a PIN',
      test: (f) => /\bpin\b|atm.?pin|passcode/.test(f.hay),
    },
  ];

  function fieldHaystack(input) {
    const bits = [input.name, input.id, input.placeholder, input.getAttribute('aria-label')];
    if (input.id) {
      const label = input.ownerDocument.querySelector(`label[for="${CSS.escape(input.id)}"]`);
      if (label) bits.push(label.textContent);
    }
    const wrapping = input.closest('label');
    if (wrapping) bits.push(wrapping.textContent);
    return bits.filter(Boolean).join(' ').toLowerCase();
  }

  function describeField(input) {
    return {
      el: input,
      type: (input.type || '').toLowerCase(),
      autocomplete: (input.autocomplete || '').toLowerCase(),
      hay: fieldHaystack(input),
    };
  }

  function categorize(input) {
    const described = describeField(input);
    return FIELD_CATEGORIES.filter((c) => c.test(described)).map((c) => c.id);
  }

  // --- Visibility and geometry --------------------------------------------

  function isVisuallyHidden(el) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') return true;
    if (Number(cs.opacity) <= CRITERIA.shadowInput.maxOpacity) return true;
    const rect = el.getBoundingClientRect();
    if (rect.width <= CRITERIA.shadowInput.maxCollapsedPx ||
        rect.height <= CRITERIA.shadowInput.maxCollapsedPx) return true;
    if (rect.right < CRITERIA.shadowInput.offscreenPx ||
        rect.bottom < CRITERIA.shadowInput.offscreenPx) return true;
    return false;
  }

  function overlapFraction(outer, inner) {
    const x = Math.max(0, Math.min(outer.right, inner.right) - Math.max(outer.left, inner.left));
    const y = Math.max(0, Math.min(outer.bottom, inner.bottom) - Math.max(outer.top, inner.top));
    const area = inner.width * inner.height;
    return area > 0 ? (x * y) / area : 0;
  }

  function iframeHost(el) {
    try { return new URL(el.getAttribute('src') || '', location.href).hostname; }
    catch (_) { return null; }
  }

  function isCrossOriginIframe(el) {
    if (!el || el.tagName !== 'IFRAME') return false;
    const host = iframeHost(el);
    return Boolean(host) && host !== location.hostname;
  }

  function isInvisibleCover(el) {
    const cs = getComputedStyle(el);
    if (Number(cs.opacity) < CRITERIA.overlay.maxOpacity) return true;
    const bg = cs.backgroundColor || '';
    const rgba = /rgba?\(([^)]+)\)/.exec(bg);
    const alpha = rgba ? Number(rgba[1].split(',')[3] ?? 1) : 1;
    const transparentBackground = bg === 'transparent' || alpha < CRITERIA.overlay.maxOpacity;
    const hasNoContent = !(el.textContent || '').trim() && !el.querySelector('img, svg, input, button');
    return transparentBackground && hasNoContent;
  }

  // --- Checks --------------------------------------------------------------

  // C1. A credential form that posts over plain HTTP from an HTTPS page. The
  // padlock the user is trusting covers the page, not the submission.
  function checkInsecureFormAction(field) {
    const form = field.form;
    if (!form || location.protocol !== 'https:') return null;
    const raw = form.getAttribute('action');
    if (!raw) return null;
    let resolved;
    try { resolved = new URL(raw, location.href); }
    catch (_) { return null; }
    if (resolved.protocol !== 'http:') return null;
    return { destination: resolved.hostname };
  }

  // C2. Field inventory against plausibility. A sign-in form asking for a
  // password plus two unrelated categories of high-value data is not a
  // sign-in form.
  function checkFieldInventory(field) {
    const form = field.form;
    if (!form) return null;
    const found = new Map();
    form.querySelectorAll('input, select').forEach((input) => {
      categorize(input).forEach((id) => {
        if (!found.has(id)) found.set(id, FIELD_CATEGORIES.find((c) => c.id === id).label);
      });
    });
    const ids = [...found.keys()];
    const others = ids.filter((id) => id !== 'password');

    const passwordPlusTwo = ids.includes('password') &&
      others.length >= CRITERIA.fieldInventory.minOtherCategoriesWithPassword;
    // Government ID next to payment details is a harvesting form whether or
    // not it also takes a password.
    const idPlusPayment = ids.includes('government_id') && ids.includes('payment_card');

    if (!passwordPlusTwo && !idPlusPayment) return null;
    return { categories: ids, extras: others.map((id) => found.get(id)) };
  }

  // C3. Something is layered over a credential field. Measured by hit-testing
  // the field's own box: if the topmost element at most of those points is
  // not the field, the user is not typing where they think they are.
  //
  // This scans *every* visible credential field on the page, not only the one
  // that received focus, because in the realistic version of this attack the
  // focused field IS the attacker's: a transparent input is layered over the
  // real one, the click lands on the transparent input, and the evidence is
  // that the visible field underneath is covered. Checking only the focused
  // element would look at the wrong end of the attack and find nothing.
  function sensitiveFieldsIn(root) {
    return [...root.querySelectorAll('input[type="password"], input[autocomplete*="cc-"]')];
  }

  function coverageOf(target) {
    const rect = target.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;

    const viewportHeight = document.documentElement.clientHeight;
    const viewportWidth = document.documentElement.clientWidth;
    const counts = new Map();
    let sampled = 0;

    for (const [fx, fy] of CRITERIA.overlay.samplePoints) {
      const x = rect.left + rect.width * fx;
      const y = rect.top + rect.height * fy;
      if (x < 0 || y < 0 || x > viewportWidth || y > viewportHeight) continue;
      sampled += 1;
      const stack = document.elementsFromPoint(x, y);
      if (!stack || !stack.length) continue;
      const top = stack[0];
      if (top === target || target.contains(top) || top.contains(target)) continue;
      if (top.closest && top.closest('.plsr-banner, .plsr-toast')) continue; // our own card
      counts.set(top, (counts.get(top) || 0) + 1);
    }
    if (!sampled) return null; // field is off-screen: no measurement, no claim

    for (const [el, count] of counts) {
      if (count < CRITERIA.overlay.minCoveredPoints) continue;
      if (isCrossOriginIframe(el)) {
        return { kind: 'iframe', host: iframeHost(el), coveredPoints: count, sampled };
      }
      if (isInvisibleCover(el)) {
        return { kind: 'invisible', tag: el.tagName.toLowerCase(), coveredPoints: count, sampled };
      }
    }
    return null;
  }

  function checkCredentialOverlay(field) {
    const candidates = [field, ...sensitiveFieldsIn(document).filter((el) => el !== field)];
    for (const candidate of candidates) {
      // A field the user cannot see being covered tells us nothing; a field
      // they can see being covered is the whole finding.
      if (candidate !== field && isVisuallyHidden(candidate)) continue;
      const found = coverageOf(candidate);
      if (found) return found;
    }
    return null;
  }

  // C4. A hidden duplicate of a sensitive field in the same form, alongside
  // the visible one the user fills in.
  function checkShadowCaptureInput(field) {
    const form = field.form;
    if (!form) return null;

    for (const input of form.querySelectorAll('input')) {
      if (input === field) continue;
      const described = describeField(input);
      const sensitive = described.type === 'password' ||
        /cc-(?:number|csc)/.test(described.autocomplete) ||
        (described.type === 'hidden' && /pass|pwd|card|cvv|cvc|token/.test(described.hay));
      if (!sensitive) continue;
      if (described.type !== 'hidden' && !isVisuallyHidden(input)) continue;
      // Only meaningful if it shadows a field the user can actually see.
      if (isVisuallyHidden(field)) continue;
      return { name: input.name || input.id || `hidden ${described.type} field` };
    }
    return null;
  }

  // C5. A picture of a browser address bar rendered into the page, which is
  // how a Browser-in-the-Browser popup sells a fake origin.
  function checkFakeBrowserChrome() {
    const limit = document.documentElement.clientHeight * CRITERIA.fakeBrowserChrome.topViewportFraction;
    const candidates = [...document.querySelectorAll('div, header, section, span, p')].slice(0, 500);

    for (const el of candidates) {
      const rect = el.getBoundingClientRect();
      if (!rect.height || rect.top > limit) continue;
      const text = (el.textContent || '').trim();
      if (!text || text.length > CRITERIA.fakeBrowserChrome.maxContainerTextLength) continue;
      const url = /https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/i.exec(text);
      if (!url) continue;
      const hasLock = /[\u{1F512}\u{1F513}\u{1F510}]/u.test(text) || Boolean(el.querySelector(
        'img[alt*="lock" i], img[src*="lock" i], [class*="lock" i], [class*="padlock" i], [aria-label*="lock" i]'
      ));
      if (!hasLock) continue;
      return { shownHost: url[1], actualHost: location.hostname, spoofed: !sameSite(url[1], location.hostname) };
    }
    return null;
  }

  // C6. A cross-origin iframe sitting over the credential area. Hosted
  // payment and SSO widgets do exactly this legitimately, so recognized
  // providers are excluded and the rest is a warning, not a verdict.
  function checkThirdPartyCredentialFrame(field) {
    const form = field.form;
    if (!form) return null;
    const formRect = form.getBoundingClientRect();
    if (!formRect.width || !formRect.height) return null;

    for (const frame of document.querySelectorAll('iframe')) {
      if (!isCrossOriginIframe(frame)) continue;
      const host = iframeHost(frame);
      if (CRITERIA.thirdPartyCredentialFrame.knownProviders.some((p) => sameSite(host, p))) continue;
      const frameRect = frame.getBoundingClientRect();
      if (overlapFraction(frameRect, formRect) < CRITERIA.thirdPartyCredentialFrame.minOverlapFraction) continue;
      return { host };
    }
    return null;
  }

  function shannonEntropy(text) {
    const freq = new Map();
    for (const ch of text) freq.set(ch, (freq.get(ch) || 0) + 1);
    let bits = 0;
    for (const count of freq.values()) {
      const p = count / text.length;
      bits -= p * Math.log2(p);
    }
    return bits;
  }

  // C7. Deliberately scrambled inline script. Minified bundles are common and
  // innocent, so a single indicator is never enough: either a known packer
  // signature, or two independent measurements agreeing.
  function checkObfuscatedScript() {
    for (const script of document.querySelectorAll('script:not([src])')) {
      const code = script.textContent || '';
      if (code.length < CRITERIA.obfuscatedScript.minLength) continue;

      if (/eval\(function\(p,a,c,k,e/.test(code)) {
        return { indicators: ['known packer signature'], length: code.length };
      }

      const indicators = [];
      if (/\b(?:eval|new Function|Function)\s*\(\s*(?:['"`]|atob|[a-zA-Z_$][\w$]*\s*\()/.test(code)) {
        indicators.push('builds code from strings at runtime');
      }
      const escapes = (code.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}/gi) || []).length;
      if ((escapes * 4) / code.length >= CRITERIA.obfuscatedScript.minEscapeDensity) {
        indicators.push('text encoded as escape sequences');
      }
      if (new RegExp(`[A-Za-z0-9+/=]{${CRITERIA.obfuscatedScript.minBase64BlobLength},}`).test(code)) {
        indicators.push('large encoded blob');
      }
      if ((code.match(/\b_0x[0-9a-f]{4,}\b/g) || []).length >= CRITERIA.obfuscatedScript.minHexIdentifiers) {
        indicators.push('hex-mangled identifier names');
      }
      const avgLineLength = code.length / (code.split('\n').length || 1);
      if (code.length >= CRITERIA.obfuscatedScript.minEntropyLength &&
          avgLineLength >= CRITERIA.obfuscatedScript.minAvgLineLength &&
          shannonEntropy(code) >= CRITERIA.obfuscatedScript.minEntropyBitsPerChar) {
        indicators.push('machine-generated high-entropy content');
      }
      if (indicators.length >= CRITERIA.obfuscatedScript.minIndicators) {
        return { indicators, length: code.length };
      }
    }
    return null;
  }

  // C8. The page actively resists being looked at.
  function checkAntiInspection() {
    if (document.body && document.body.getAttribute('oncontextmenu')) {
      return { technique: 'right-click disabled' };
    }
    for (const script of document.querySelectorAll('script:not([src])')) {
      const code = script.textContent || '';
      if (ANTI_INSPECTION_PATTERNS.some((re) => re.test(code))) {
        return { technique: 'developer tools blocked' };
      }
    }
    return null;
  }

  // C9. Urgency and threat phrasing. Supporting evidence only — it never
  // selects a message on its own.
  function checkPressureLanguage(field) {
    // Scoped to the block the credential form sits in rather than the whole
    // document, so a banner elsewhere on a large page does not colour the
    // reading of the login area.
    const form = field.form;
    const scope = (form && (form.closest('section, main, article, div') || form)) || document.body;
    if (!scope) return null;
    const text = (scope.innerText || scope.textContent || '').slice(0, CRITERIA.pressureLanguage.maxTextLength);
    const matches = PRESSURE_LEXICON.filter((re) => re.test(text)).length;
    if (matches < CRITERIA.pressureLanguage.minDistinctMatches) return null;
    return { matches };
  }

  function inspectPage(field) {
    const run = (fn) => { try { return fn(); } catch (_) { return null; } }; // a broken check is not a verdict
    return {
      insecureFormAction: run(() => checkInsecureFormAction(field)),
      fieldInventory: run(() => checkFieldInventory(field)),
      overlay: run(() => checkCredentialOverlay(field)),
      shadowInput: run(() => checkShadowCaptureInput(field)),
      fakeBrowserChrome: run(() => checkFakeBrowserChrome()),
      thirdPartyFrame: run(() => checkThirdPartyCredentialFrame(field)),
      obfuscatedScript: run(() => checkObfuscatedScript()),
      antiInspection: run(() => checkAntiInspection()),
      pressureLanguage: run(() => checkPressureLanguage(field)),
    };
  }

  globalThis.PLSR_PAGE_INSPECTION = {
    CRITERIA,
    inspectPage,
    registrableDomain,
    sameSite,
    // Exported for the test suite, which asserts each criterion independently.
    checks: {
      checkInsecureFormAction,
      checkFieldInventory,
      checkCredentialOverlay,
      checkShadowCaptureInput,
      checkFakeBrowserChrome,
      checkThirdPartyCredentialFrame,
      checkObfuscatedScript,
      checkAntiInspection,
      checkPressureLanguage,
      shannonEntropy,
    },
  };
})();
