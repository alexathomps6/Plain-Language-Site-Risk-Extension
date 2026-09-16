// Background service worker.
//
// Owns the lookups a content script cannot do itself:
//
//   CHECK_FIRST_VISIT       — chrome.history is unavailable to content scripts
//   CHECK_DOMAIN_AGE        — cross-origin RDAP fetch (see note on CORS below)
//   CHECK_BLOCKLIST         — reads the bundled feed snapshot
//   CHECK_NETWORK_EVIDENCE  — Tier 3: the per-tab webRequest evidence buffer
//
// Every handler fails open. A lookup that times out, errors, or has no data
// resolves to null, never to a false "safe" or a false "dangerous". The
// README's rule is that a warning must be able to render with the network
// off, so nothing here is ever on the critical path for a verdict.

const RDAP_TIMEOUT_MS = 2500;
const RDAP_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // domain age does not meaningfully change day to day
const BLOCKLIST_REFRESH_HOURS = 12;
const BLOCKLIST_STORAGE_KEY = 'blocklist';
const BLOCKLIST_SNAPSHOT_PATH = 'data/blocklist-snapshot.json';
const BLOCKLIST_DEFAULT_SOURCE = 'https://phishunt.io/feed.txt';

// Multi-part public suffixes, needed so RDAP is queried for "bbc.co.uk" rather
// than the unregistrable "co.uk". This is a deliberately small subset — the
// production answer is the full Public Suffix List, which is far more than a
// demo build needs.
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

// --- First visit -----------------------------------------------------------

function handleFirstVisit(hostname, sendResponse) {
  chrome.history.search({ text: hostname, startTime: 0, maxResults: 200 }, (results) => {
    const matching = results.filter((item) => {
      try { return new URL(item.url).hostname === hostname; }
      catch (_) { return false; }
    });
    const totalVisits = matching.reduce((sum, item) => sum + (item.visitCount || 0), 0);

    // The page load that triggered this lookup is usually already recorded in
    // history by the time the query runs, so a domain the user has never
    // visited shows up with exactly one visit (this one). More than one means
    // they have genuinely been here before.
    sendResponse({ isFirstVisit: totalVisits <= 1, totalVisits });
  });
}

// --- Domain age via RDAP ---------------------------------------------------
//
// RDAP is an open protocol, not a vendor API: no key, no account, no backend.
// rdap.org bootstraps to the authoritative registry with a 302, which is why
// manifest.json lists the registry hosts alongside rdap.org itself.
//
// This belongs in the worker rather than the content script. A page-context
// fetch is subject to CORS at every hop, and while some registries do send
// "Access-Control-Allow-Origin: *" (Verisign, for .com/.net, does), that is a
// per-registry courtesy rather than a guarantee — RFC 7480 only recommends it.
// A service worker holding matching host_permissions is not subject to CORS at
// all, so the lookup works uniformly across registries instead of succeeding
// only for the TLDs whose operator happens to be permissive.

async function fetchDomainAgeDays(domain) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RDAP_TIMEOUT_MS);
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: controller.signal,
      headers: { accept: 'application/rdap+json' },
    });
    if (!response.ok) return null; // 404 = no record for this TLD; 5xx = registry trouble
    const data = await response.json();
    const registration = (data.events || []).find((e) => e.eventAction === 'registration');
    if (!registration || !registration.eventDate) return null; // some registrars redact this
    const registered = new Date(registration.eventDate).getTime();
    if (!Number.isFinite(registered)) return null;
    return Math.max(0, Math.floor((Date.now() - registered) / 86400000));
  } catch (_) {
    return null; // timeout, offline, DNS failure, unparseable body — all fail open
  } finally {
    clearTimeout(timer);
  }
}

async function handleDomainAge(hostname) {
  const domain = registrableDomain(hostname);
  if (!domain || !domain.includes('.')) return { domainAgeDays: null };

  const cacheKey = `rdap:${domain}`;
  const cached = (await chrome.storage.local.get(cacheKey))[cacheKey];
  if (cached && Date.now() - cached.at < RDAP_CACHE_TTL_MS) {
    return { domainAgeDays: cached.domainAgeDays, cached: true };
  }

  const domainAgeDays = await fetchDomainAgeDays(domain);
  // Null results are cached too, so an unsupported TLD is not re-queried on
  // every password focus.
  await chrome.storage.local.set({ [cacheKey]: { domainAgeDays, at: Date.now() } });
  return { domainAgeDays, cached: false };
}

// --- Blocklist -------------------------------------------------------------

function parseFeed(text) {
  return [...new Set(
    text.split('\n')
      .map((line) => line.trim().replace(/^https?:\/\//, '').replace(/[/:?#].*$/, '').toLowerCase())
      .filter((d) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))
  )];
}

async function loadBlocklist() {
  const stored = (await chrome.storage.local.get(BLOCKLIST_STORAGE_KEY))[BLOCKLIST_STORAGE_KEY];
  if (stored && Array.isArray(stored.domains) && stored.domains.length) {
    return stored.domains;
  }
  // First run, or storage cleared: fall back to the snapshot shipped in the
  // bundle. This is what lets a fresh install with no network still hold real
  // blocklist data instead of an empty set.
  const response = await fetch(chrome.runtime.getURL(BLOCKLIST_SNAPSHOT_PATH));
  const snapshot = await response.json();
  await chrome.storage.local.set({
    [BLOCKLIST_STORAGE_KEY]: {
      domains: snapshot.domains,
      source: snapshot.source || BLOCKLIST_DEFAULT_SOURCE,
      at: Date.now(),
    },
  });
  return snapshot.domains;
}

async function handleBlocklist(hostname) {
  let domains;
  try {
    domains = await loadBlocklist();
  } catch (_) {
    return { blocklistHit: null }; // unknown, which is not the same as clean
  }
  const set = new Set(domains);
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');

  // Match the exact host, then walk up parent domains, stopping at two labels.
  // Only exact set membership counts at each step, so a listed
  // "evil.example.com" still flags its own subdomains, while a listed
  // "someone.github.io" never implicates github.io as a whole.
  const parts = host.split('.');
  for (let i = 0; i + 2 <= parts.length; i++) {
    const candidate = parts.slice(i).join('.');
    if (set.has(candidate)) return { blocklistHit: true, matched: candidate };
  }
  return { blocklistHit: false };
}

async function refreshBlocklist() {
  const stored = (await chrome.storage.local.get(BLOCKLIST_STORAGE_KEY))[BLOCKLIST_STORAGE_KEY];
  const source = (stored && stored.source) || BLOCKLIST_DEFAULT_SOURCE;
  try {
    const response = await fetch(source, { cache: 'no-cache' });
    if (!response.ok) return;
    const domains = parseFeed(await response.text());
    if (!domains.length) return; // never replace a good list with an empty one
    await chrome.storage.local.set({
      [BLOCKLIST_STORAGE_KEY]: { domains, source, at: Date.now() },
    });
  } catch (_) {
    // Offline, or the feed is down: keep whatever is already in storage.
    // Stale real data beats no data.
  }
}

// --- Tier 3: network traffic inspection ------------------------------------
//
// Observational only. MV3 removed blocking webRequest, so nothing here can
// stop a request; it watches metadata and hands the content script evidence.
// Request and response bodies are never read.
//
// One deliberate asymmetry worth stating: the listener sees full URLs, because
// the browser hands them over, but only ever *stores* a hostname. The path and
// query of every request the user's browser makes are visible for the duration
// of one synchronous callback and then dropped. The only place a path is even
// examined is the exfil-service match below, where "discord.com" and
// "discord.com/api/webhooks/..." are genuinely different facts — and even
// there, only the host is retained.

const NETWORK_CRITERIA = {
  // A hop count on its own means little: CDNs, locale routers and SSO flows
  // all redirect. Crossing two or more *different sites* on the way is the
  // part that characterises a shortener-into-open-redirect chain.
  redirectChain: { minHops: 2, minDistinctSites: 2 },
  // Caps, so a long-lived tab on a heavy site cannot grow the buffer without
  // bound. Evidence is qualitative — the first 50 distinct hosts of a kind are
  // as diagnostic as the first 5000.
  limits: { maxHostsPerKind: 50, maxRedirectHops: 20, maxTabs: 100 },
};

const RAW_IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

const URL_SHORTENERS = new Set([
  'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'buff.ly', 'is.gd', 'cutt.ly',
  'rebrand.ly', 'shorturl.at', 'rb.gy', 't.ly', 'lnkd.in', 'bit.do', 's.id', 'qrco.de',
]);

// Services a phishing kit reaches for when it needs somewhere to put stolen
// data without standing up a server. Matched against the full URL because the
// distinction between a site and its webhook endpoint is the whole point.
const EXFIL_SERVICES = [
  { pattern: /^https?:\/\/api\.telegram\.org\/bot/i, label: 'Telegram' },
  { pattern: /^https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\//i, label: 'a Discord webhook' },
  { pattern: /^https?:\/\/(?:www\.)?pastebin\.com\/api\//i, label: 'Pastebin' },
  { pattern: /^https?:\/\/(?:[a-z0-9-]+\.)?webhook\.site\//i, label: 'webhook.site' },
  { pattern: /^https?:\/\/(?:[a-z0-9-]+\.)?requestbin\.(?:com|net)\//i, label: 'RequestBin' },
  { pattern: /^https?:\/\/(?:[a-z0-9-]+\.)?(?:m\.)?pipedream\.net\//i, label: 'Pipedream' },
  { pattern: /^https?:\/\/(?:[a-z0-9-]+\.)?beeceptor\.com\//i, label: 'Beeceptor' },
  { pattern: /^https?:\/\/(?:[a-z0-9-]+\.)?(?:ngrok\.io|ngrok-free\.app|trycloudflare\.com|loca\.lt|serveo\.net)\//i, label: 'a temporary tunnel host' },
  { pattern: /^https?:\/\/(?:www\.)?(?:formspree\.io|formsubmit\.co|getform\.io|staticforms\.xyz)\//i, label: 'a form-relay service' },
];

// Script origins that are ordinary infrastructure rather than a one-off host
// registered alongside the phishing domain.
const KNOWN_CDNS = new Set([
  'googleapis.com', 'gstatic.com', 'google.com', 'googletagmanager.com', 'google-analytics.com',
  'cloudflare.com', 'cloudflareinsights.com', 'jsdelivr.net', 'unpkg.com', 'jquery.com',
  'bootstrapcdn.com', 'fontawesome.com', 'akamaihd.net', 'akamaized.net', 'cloudfront.net',
  'azureedge.net', 'azurefd.net', 'facebook.net', 'hotjar.com', 'segment.com', 'segment.io',
  'newrelic.com', 'nr-data.net', 'sentry.io', 'typekit.net', 'stripe.com', 'stripe.network',
  'paypal.com', 'paypalobjects.com', 'recaptcha.net', 'hcaptcha.com', 'onetrust.com',
  'cookielaw.org', 'adyen.com', 'braintreegateway.com', 'okta.com', 'oktacdn.com', 'auth0.com',
  'microsoftonline.com', 'msauth.net', 'msftauth.net', 'apple.com', 'squarecdn.com',
]);

// tabId -> evidence buffer. Reset on every top-level navigation, so evidence
// always describes the page currently on screen.
const tabEvidence = new Map();

function blankEvidence(pageHost) {
  return {
    pageHost: pageHost || null,
    startedAt: Date.now(),
    redirects: [],
    rawIpHosts: new Set(),
    exfilServices: new Map(), // host -> label
    scriptHosts: new Set(),
    websocketHosts: new Set(),
  };
}

function addCapped(set, value) {
  if (set.size < NETWORK_CRITERIA.limits.maxHostsPerKind) set.add(value);
}

function evidenceFor(tabId) {
  return tabId >= 0 ? tabEvidence.get(tabId) : null;
}

function resetTab(tabId, pageHost) {
  if (tabEvidence.size >= NETWORK_CRITERIA.limits.maxTabs && !tabEvidence.has(tabId)) {
    // Evict the oldest buffer rather than growing forever. A tab whose buffer
    // is gone simply reports no network evidence, which fails open.
    const oldest = [...tabEvidence.entries()].sort((a, b) => a[1].startedAt - b[1].startedAt)[0];
    if (oldest) tabEvidence.delete(oldest[0]);
  }
  tabEvidence.set(tabId, blankEvidence(pageHost));
}

function hostOfUrl(url) {
  try { return new URL(url).hostname; }
  catch (_) { return null; }
}

function isRawIpHost(host) {
  return RAW_IPV4.test(host) || host.startsWith('[');
}

// A raw IP only means something for resources that carry code or data. A
// logo served from an IP address is a badly configured site; a script or an
// XHR endpoint on one is a different claim entirely, and conflating them
// would put a danger-level banner on ordinary intranet pages.
const CODE_AND_DATA_TYPES = new Set(['script', 'xmlhttprequest', 'websocket', 'sub_frame', 'object']);

function recordRequest(details) {
  const { tabId, url, type } = details;

  if (type === 'main_frame') {
    resetTab(tabId, hostOfUrl(url));
    return;
  }
  const evidence = evidenceFor(tabId);
  if (!evidence) return;

  const host = hostOfUrl(url);
  if (!host) return;

  if (CODE_AND_DATA_TYPES.has(type) && isRawIpHost(host)) addCapped(evidence.rawIpHosts, host);

  const service = EXFIL_SERVICES.find((s) => s.pattern.test(url));
  if (service && evidence.exfilServices.size < NETWORK_CRITERIA.limits.maxHostsPerKind) {
    evidence.exfilServices.set(host, service.label);
  }

  if (type === 'script' && evidence.pageHost &&
      registrableDomain(host) !== registrableDomain(evidence.pageHost) &&
      !KNOWN_CDNS.has(registrableDomain(host))) {
    addCapped(evidence.scriptHosts, host);
  }

  if (type === 'websocket' && evidence.pageHost &&
      registrableDomain(host) !== registrableDomain(evidence.pageHost)) {
    addCapped(evidence.websocketHosts, host);
  }
}

function recordRedirect(details) {
  if (details.type !== 'main_frame') return;
  const evidence = evidenceFor(details.tabId);
  if (!evidence) return;
  if (evidence.redirects.length >= NETWORK_CRITERIA.limits.maxRedirectHops) return;
  const from = hostOfUrl(details.url);
  const to = hostOfUrl(details.redirectUrl);
  if (from && to) evidence.redirects.push({ from, to });
  // A redirect rewrites where the page came from, so the page host has to
  // follow it or every later same-site comparison is made against the wrong
  // origin.
  if (to) evidence.pageHost = to;
}

// Evaluate the buffer against the criteria above. Returns plain, structured
// facts; the content script turns them into a sentence.
function summarizeNetworkEvidence(tabId) {
  const evidence = evidenceFor(tabId);
  if (!evidence) return { networkEvidence: null }; // no buffer, no claim

  const sites = new Set();
  evidence.redirects.forEach(({ from, to }) => {
    sites.add(registrableDomain(from));
    sites.add(registrableDomain(to));
  });
  const viaShortener = evidence.redirects.find(({ from }) => URL_SHORTENERS.has(registrableDomain(from)));
  const suspiciousChain =
    (evidence.redirects.length >= NETWORK_CRITERIA.redirectChain.minHops &&
     sites.size >= NETWORK_CRITERIA.redirectChain.minDistinctSites) ||
    Boolean(viaShortener);

  return {
    networkEvidence: {
      redirectChain: suspiciousChain
        ? {
            hops: evidence.redirects.length,
            sites: [...sites],
            shortener: viaShortener ? registrableDomain(viaShortener.from) : null,
          }
        : null,
      rawIpHosts: [...evidence.rawIpHosts],
      exfilServices: [...evidence.exfilServices].map(([host, label]) => ({ host, label })),
      unrelatedScriptHosts: [...evidence.scriptHosts],
      websocketHosts: [...evidence.websocketHosts],
    },
  };
}

// webRequest is unavailable if the permission was declined; the extension
// still works, it just has no Tier 3 network evidence.
if (chrome.webRequest) {
  chrome.webRequest.onBeforeRequest.addListener(recordRequest, { urls: ['<all_urls>'] });
  chrome.webRequest.onBeforeRedirect.addListener(recordRedirect, { urls: ['<all_urls>'] });
}
if (chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => tabEvidence.delete(tabId));
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('refresh-blocklist', { periodInMinutes: BLOCKLIST_REFRESH_HOURS * 60 });
  loadBlocklist().catch(() => {});
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'refresh-blocklist') refreshBlocklist();
});

// --- Message routing -------------------------------------------------------

const ASYNC_HANDLERS = {
  CHECK_DOMAIN_AGE: (msg) => handleDomainAge(msg.hostname),
  CHECK_BLOCKLIST: (msg) => handleBlocklist(msg.hostname),
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_FIRST_VISIT') {
    handleFirstVisit(message.hostname, sendResponse);
    return true; // keep the channel open for the async history callback
  }

  // Synchronous: the buffer is already in memory, and the tab is taken from
  // the sender rather than the message, so a page cannot ask about a tab that
  // is not its own.
  if (message.type === 'CHECK_NETWORK_EVIDENCE') {
    const tabId = sender && sender.tab ? sender.tab.id : -1;
    sendResponse(summarizeNetworkEvidence(tabId));
    return false;
  }

  const handler = ASYNC_HANDLERS[message.type];
  if (!handler) return false;

  handler(message)
    .then(sendResponse)
    .catch(() => sendResponse(null)); // fail open; the content script treats null as "no data"
  return true;
});
