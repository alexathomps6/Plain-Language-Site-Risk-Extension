// Tier 3 (in-page half) — traffic probe.
//
// Runs in the page's own JavaScript world at document_start, which is the
// only place the two things that matter here are observable:
//
//   1. Traffic correlated with typing. chrome.webRequest sees that a request
//      went to a host; it cannot see that the request fired 40ms after a
//      keystroke in a password field and before any submit. That correlation
//      is the difference between "this page talks to an analytics host" and
//      "this page is relaying your password as you type it", and it only
//      exists inside the page.
//   2. Listener registration and runtime attribute mutation, which leave no
//      network trace at all.
//
// This file is a sensor, not a judge. It reports facts; content.js applies the
// thresholds in PLSR_PAGE_INSPECTION.CRITERIA.network. Keeping the judgment on
// the other side of the postMessage boundary means a hostile page cannot reach
// the criteria, and it keeps every threshold in one reviewable place.
//
// PRIVACY: only a hostname, a method, and a timing delta ever leave this file.
// Never a URL path, never a query string, never a request body, never a field
// value, never a keystroke. The page already knows every hostname it contacts,
// so nothing is disclosed to the page that it did not itself originate.
//
// TRUST: messages go over window.postMessage, so page script can read and
// forge them. Reading them discloses nothing. Forging them can only *raise* a
// warning, never clear one — content.js never downgrades a verdict, and a page
// gains nothing by making itself look more dangerous than it is.

(function () {
  const CHANNEL = 'plsr-probe';
  const KEYSTROKE_EVENTS = new Set(['keydown', 'keyup', 'keypress', 'input', 'paste', 'compositionupdate']);

  let lastKeystrokeAt = 0;
  let submittedAt = 0;
  const reportedListeners = new Set();

  function post(kind, detail) {
    try {
      window.postMessage({ __plsr: CHANNEL, kind, detail }, '*');
    } catch (_) {
      // A page that has broken postMessage gets no probe evidence. Fail open.
    }
  }

  function isSensitiveField(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    if ((el.type || '').toLowerCase() === 'password') return true;
    return String(el.autocomplete || '').toLowerCase().includes('cc-');
  }

  // Hostname only. This is the single function that decides what a URL is
  // allowed to become before it is reported.
  function hostOf(url) {
    try {
      const resolved = new URL(String(url), location.href);
      if (!/^(?:https?|wss?):$/.test(resolved.protocol)) return null;
      return resolved.hostname || null;
    } catch (_) {
      return null;
    }
  }

  function trafficDetail(kind, url, method) {
    const host = hostOf(url);
    if (!host) return null;
    return {
      host,
      kind,
      method: method ? String(method).toUpperCase() : null,
      crossOrigin: host !== location.hostname,
      msSinceKeystroke: lastKeystrokeAt ? Date.now() - lastKeystrokeAt : null,
      afterSubmit: Boolean(submittedAt),
    };
  }

  // Gate. This is the reason the probe can sit on <all_urls> without becoming
  // a general-purpose traffic recorder: on an ordinary page nobody types a
  // password into, it reports nothing at all. Traffic is only worth describing
  // once the user has actually put a secret into a field, or a live channel
  // opens on a page that is asking for one.
  let sensitiveFieldCheckedAt = 0;
  let sensitiveFieldPresent = false;

  function hasSensitiveField() {
    const now = Date.now();
    if (now - sensitiveFieldCheckedAt < 1000) return sensitiveFieldPresent;
    sensitiveFieldCheckedAt = now;
    try {
      sensitiveFieldPresent = Boolean(
        document.querySelector('input[type="password"], input[autocomplete*="cc-"]')
      );
    } catch (_) {
      sensitiveFieldPresent = false;
    }
    return sensitiveFieldPresent;
  }

  function shouldReport(kind) {
    if (lastKeystrokeAt) return true;                        // a secret is being typed right now
    if (kind === 'websocket') return hasSensitiveField();     // a live channel on a credential page
    return false;
  }

  function reportTraffic(kind, url, method) {
    if (!shouldReport(kind)) return;
    const detail = trafficDetail(kind, url, method);
    if (detail) post('traffic', detail);
  }

  // --- Typing and submit context ------------------------------------------
  //
  // Capture phase on the document, so a page that stops propagation on its own
  // fields cannot blind the correlation.

  document.addEventListener('keydown', (e) => {
    if (isSensitiveField(e.target)) lastKeystrokeAt = Date.now();
  }, true);
  document.addEventListener('input', (e) => {
    if (isSensitiveField(e.target)) lastKeystrokeAt = Date.now();
  }, true);
  document.addEventListener('submit', () => { submittedAt = Date.now(); }, true);

  // --- fetch ---------------------------------------------------------------

  const nativeFetch = window.fetch;
  if (typeof nativeFetch === 'function') {
    window.fetch = function (input, init) {
      try {
        const url = (input && typeof input === 'object' && 'url' in input) ? input.url : input;
        const method = (init && init.method) || (input && input.method) || 'GET';
        reportTraffic('fetch', url, method);
      } catch (_) { /* never let instrumentation break the page */ }
      return nativeFetch.apply(this, arguments);
    };
  }

  // --- XMLHttpRequest ------------------------------------------------------

  const nativeOpen = XMLHttpRequest.prototype.open;
  const nativeSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    try { this.__plsrRequest = { method, url }; } catch (_) {}
    return nativeOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    try {
      // Reported at send rather than open: open() is bookkeeping, send() is
      // the moment data actually leaves.
      const req = this.__plsrRequest;
      if (req) reportTraffic('xhr', req.url, req.method);
    } catch (_) {}
    return nativeSend.apply(this, arguments);
  };

  // --- sendBeacon ----------------------------------------------------------

  if (navigator.sendBeacon) {
    const nativeBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url) {
      try { reportTraffic('beacon', url, 'POST'); } catch (_) {}
      return nativeBeacon.apply(navigator, arguments);
    };
  }

  // --- WebSocket -----------------------------------------------------------
  //
  // A Proxy rather than a subclass, so statics (OPEN, CLOSED) and prototype
  // identity survive intact and nothing downstream can tell the difference.

  if (window.WebSocket) {
    window.WebSocket = new Proxy(window.WebSocket, {
      construct(target, args) {
        try { reportTraffic('websocket', args[0], 'WS'); } catch (_) {}
        return Reflect.construct(target, args);
      },
    });
  }

  // --- Keystroke listeners on sensitive fields -----------------------------
  //
  // On its own this is not actionable: password strength meters bind to
  // `input` for entirely good reasons. It matters as corroboration for traffic
  // that fires on the same keystrokes.

  const nativeAddEventListener = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function (type, listener, options) {
    try {
      if (KEYSTROKE_EVENTS.has(type) && isSensitiveField(this)) {
        const key = `${type}:${this.name || this.id || 'unnamed'}`;
        if (!reportedListeners.has(key)) {
          reportedListeners.add(key);
          post('keystroke_listener', { event: type, field: this.name || this.id || null });
        }
      }
    } catch (_) {}
    return nativeAddEventListener.apply(this, arguments);
  };

  // --- Form destination rewritten at runtime -------------------------------
  //
  // A destination present in the markup is caught by the static check in
  // content.js. This catches the evasion: ship a clean-looking form, then
  // point it somewhere else from script once the page is live.

  const nativeSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    try {
      const attr = String(name).toLowerCase();
      if (attr === 'action' || attr === 'formaction') {
        const host = hostOf(value);
        if (host && host !== location.hostname) {
          post('action_mutated', { host, attribute: attr });
        }
      }
    } catch (_) {}
    return nativeSetAttribute.apply(this, arguments);
  };

  post('ready', { host: location.hostname });
})();
