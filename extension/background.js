// Background service worker.
//
// Owns the three lookups a content script cannot do itself:
//
//   CHECK_FIRST_VISIT — chrome.history is unavailable to content scripts
//   CHECK_DOMAIN_AGE  — cross-origin RDAP fetch (see note on CORS below)
//   CHECK_BLOCKLIST   — reads the bundled feed snapshot
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

  const handler = ASYNC_HANDLERS[message.type];
  if (!handler) return false;

  handler(message)
    .then(sendResponse)
    .catch(() => sendResponse(null)); // fail open; the content script treats null as "no data"
  return true;
});
