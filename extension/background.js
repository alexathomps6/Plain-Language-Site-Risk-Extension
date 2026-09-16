// Content scripts can't call chrome.history directly — only extension pages
// and the background service worker can. So the content script asks this
// background worker "have I been to this hostname before?" via a message,
// and this file does the actual chrome.history.search() lookup.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'CHECK_FIRST_VISIT') return false;

  const hostname = message.hostname;
  chrome.history.search({ text: hostname, startTime: 0, maxResults: 200 }, (results) => {
    const matching = results.filter((item) => {
      try { return new URL(item.url).hostname === hostname; }
      catch (_) { return false; }
    });
    const totalVisits = matching.reduce((sum, item) => sum + (item.visitCount || 0), 0);

    // The page load that triggered this lookup is usually already recorded
    // in history by the time this query runs, so a domain the user has
    // never visited before will show up with exactly one visit (this one).
    // More than one recorded visit means they've genuinely been here before.
    const isFirstVisit = totalVisits <= 1;
    sendResponse({ isFirstVisit, totalVisits });
  });

  return true; // keep the message channel open for the async history.search callback
});
