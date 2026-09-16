#!/usr/bin/env bash
# Runs the test suite in headless Edge/Chrome. No npm, no node, no network.
#
#   ./tests/run.sh
#
# tests/signals.html    drives content.js in stubbed DOMs and asserts on the
#                       banner it renders: template selection, escalation,
#                       fail-open behaviour, Tier 2/3 inspection criteria, and
#                       background.js pure helpers.
# tests/demo-pages.html loads every real demo-pages/*.html and asserts each
#                       still produces the result DEMO.md documents.
set -u
cd "$(dirname "$0")/.."
ROOT=$(pwd)
WORK="${TMPDIR:-/tmp}/plsr-testrun"
mkdir -p "$WORK"  # kept out of the repo: a browser profile inside a synced folder (OneDrive) makes headless startup hang

BROWSER=""
for candidate in \
  "/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" \
  "/c/Program Files/Google/Chrome/Application/chrome.exe" \
  "$(command -v google-chrome || true)" \
  "$(command -v chromium || true)"; do
  [ -n "$candidate" ] && [ -x "$candidate" ] && BROWSER="$candidate" && break
done
if [ -z "$BROWSER" ]; then echo "No Chrome/Edge found." >&2; exit 2; fi

topath() { command -v cygpath >/dev/null 2>&1 && cygpath -m "$1" || echo "$1"; }

run_suite() {
  local suite="$1"; shift
  local out
  { printf '<!DOCTYPE html><html><body>\n<script>%s</script>\n' "$*"
    sed '1,/<body>/d' "$ROOT/tests/$suite"
  } > "$WORK/run.html"
  out=$(timeout 90 "$BROWSER" --headless=new --disable-gpu --no-sandbox --no-first-run \
        --user-data-dir="$(topath "$WORK/profile")" --virtual-time-budget=8000 \
        --dump-dom "file:///$(topath "$WORK/run.html")" 2>/dev/null \
        | sed -n '/<pre id="out">/,/<\/pre>/p' | sed 's|<[^>]*>||g')
  echo "$out"
  echo "$out" | grep -q 'ALL_PASSED'
}

CONTENT=$(base64 -w0 extension/content.js)
BACKGROUND=$(base64 -w0 extension/background.js)
INSPECTION=$(base64 -w0 extension/page-inspection.js)
PROBE=$(base64 -w0 extension/page-probe.js)
# Injected in the same order the manifest loads them: probe first (it wraps
# fetch/XHR/beacon/WebSocket and must be in place before the page can call
# them), then the Tier 2 criteria module, then content.js.
SCRIPTS="window.__PROBE_B64=\"$PROBE\";window.__INSPECTION_B64=\"$INSPECTION\";window.__CONTENT_B64=\"$CONTENT\";"

{ printf '['; first=1
  for f in demo-pages/*.html; do
    [ $first -eq 1 ] || printf ','; first=0
    printf '{"name":"%s","b64":"%s"}' "$(basename "$f")" "$(base64 -w0 "$f")"
  done; printf ']'
} > "$WORK/pages.json"
PAGES=$(base64 -w0 "$WORK/pages.json")

status=0
echo "=== signals ==="
run_suite signals.html "${SCRIPTS}window.__BACKGROUND_B64=\"$BACKGROUND\";" || status=1
echo
echo "=== demo pages ==="
run_suite demo-pages.html "${SCRIPTS}window.__PAGES_B64=\"$PAGES\";" || status=1

echo
[ $status -eq 0 ] && echo "ALL SUITES PASSED" || echo "SUITE FAILURES"
exit $status
