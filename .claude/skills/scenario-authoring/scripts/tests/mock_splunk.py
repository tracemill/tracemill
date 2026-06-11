#!/usr/bin/env python3
"""mock_splunk.py — stateful HTTP mock for the scenario-authoring bats tests.

Started by the bats helper `start_mock_splunk` (helpers.bash). Reads its
configuration from $MOCK_SPLUNK_CONFIG and appends one JSON line per
incoming request to $MOCK_SPLUNK_LOG. Used by the Splunk-facing tests
(e.g. extract-spl-groupby.sh's REST parser cross-check).

Why a custom mock when fetch_dataset.bats just uses python3 -m http.server?
Because some tests exercise stateful, per-call response sequences (e.g. a
first POST returns 409 and a second returns 200), which the stock
module-form server cannot do. This file is small enough to keep inline
next to the bats suite that owns it.

Config schema ($MOCK_SPLUNK_CONFIG, JSON):

    {
      "responses": {
        "<path-pattern>": [<status1>, <status2>, ...],
        ...
      },
      "bodies": {
        "<path-pattern>": <json-body>,
        ...
      }
    }

  - <path-pattern> matches the request path WITHOUT its query string —
    the matcher strips `?...` before comparing, so a pattern of
    "/services/search/parser" matches `/services/search/parser?q=...`.
    Don't put `?q=...` in patterns; they'll never match. Two forms are
    supported:
      • exact path: "/services/saved/searches"
      • prefix glob ending in "/*": "/services/saved/searches/*"
        Matches the literal prefix plus anything after the trailing slash.
    Exact patterns win over glob patterns; among globs, the longest
    pattern wins. Unmatched paths fall back to 201 with no body.
  - The status list is replayed by call index for the matched pattern.
    Calls past the end of the list reuse the last entry (so [201]
    means "always 201" and [409, 200] means "first call 409, subsequent
    calls 200").
  - "bodies" is optional. When set, the value is JSON-serialised and sent
    as the response body with Content-Type: application/json. A single
    body per pattern is sufficient for tests that vary the body across
    invocations by restarting the mock with a fresh config.

Log schema ($MOCK_SPLUNK_LOG, JSONL):

    {"method": "POST", "path": "...", "form": {"name": "...", ...}}

  - One JSON line per request, in arrival order.
  - Form fields decoded from application/x-www-form-urlencoded bodies via
    urllib.parse.parse_qsl (matches what curl sends with --data-urlencode).
"""

from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import urllib.parse


CONFIG_PATH = os.environ["MOCK_SPLUNK_CONFIG"]
LOG_PATH = os.environ["MOCK_SPLUNK_LOG"]

with open(CONFIG_PATH) as fh:
    _CONFIG = json.load(fh)

_RESPONSES: dict[str, list[int]] = _CONFIG.get("responses", {})
_BODIES: dict[str, object] = _CONFIG.get("bodies", {})

# Validate every configured response sequence at load time so a typo in a
# test config (empty list, non-list, non-int) raises a clear error here
# instead of an `IndexError`/`TypeError` at request-handling time. The
# request handler reuses the last entry of each list when calls overflow,
# which would silently raise IndexError on `seq[-1]` for an empty list.
for _key, _seq in _RESPONSES.items():
    if not isinstance(_seq, list) or not _seq:
        sys.stderr.write(
            f"mock_splunk.py: responses[{_key!r}] must be a non-empty list "
            f"of HTTP status codes (got {_seq!r})\n"
        )
        sys.exit(2)
    for _code in _seq:
        if not isinstance(_code, int):
            sys.stderr.write(
                f"mock_splunk.py: responses[{_key!r}] contains non-int "
                f"entry {_code!r} (got type {type(_code).__name__})\n"
            )
            sys.exit(2)

# call_counts is keyed by the matched config pattern (not the request
# path) so /services/saved/searches/Foo and /services/saved/searches/Bar
# both increment the same counter when they share a "/*"-suffixed pattern.
_call_counts: dict[str, int] = {}
_log_lock = threading.Lock()


def _match_pattern_in(path: str, mapping: dict) -> str | None:
    """Return the longest pattern in mapping that matches path, or None.

    Exact matches win over glob matches; among globs, longest wins.
    """
    if path in mapping:
        return path
    best: str | None = None
    for key in mapping:
        if key.endswith("/*"):
            prefix = key[:-1]  # keep trailing slash, drop only the "*"
            if path.startswith(prefix):
                if best is None or len(key) > len(best):
                    best = key
    return best


def _next_status(path: str) -> int:
    pattern = _match_pattern_in(path, _RESPONSES)
    if pattern is None:
        return 201
    seq = _RESPONSES[pattern]
    n = _call_counts.get(pattern, 0)
    _call_counts[pattern] = n + 1
    return int(seq[min(n, len(seq) - 1)])


def _body_for(path: str) -> bytes:
    """Return the configured response body for path as bytes, or b''."""
    pattern = _match_pattern_in(path, _BODIES)
    if pattern is None:
        return b""
    return json.dumps(_BODIES[pattern]).encode("utf-8")


def _log(record: dict) -> None:
    with _log_lock:
        with open(LOG_PATH, "a") as fh:
            fh.write(json.dumps(record) + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    # log_message is the BaseHTTPRequestHandler hook that writes the noisy
    # "127.0.0.1 - - [date] ..." access lines to stderr. Silence them so
    # the bats banner-parsing helper sees only the "Serving ... port N"
    # line we actually need.
    def log_message(self, *args, **kwargs):  # noqa: ARG002
        return

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        # Form decode mirrors what curl sends with --data-urlencode (which
        # is application/x-www-form-urlencoded by default).
        form = dict(urllib.parse.parse_qsl(body, keep_blank_values=True))
        # Strip query string so configured patterns can match by path
        # alone — the parser endpoint takes its q via query string and we
        # don't want every distinct SPL to require its own pattern.
        path_only = self.path.split("?", 1)[0]
        _log({"method": self.command, "path": self.path, "form": form})
        status = _next_status(path_only)
        resp_body = _body_for(path_only)
        self.send_response(status)
        if resp_body:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        if resp_body:
            self.wfile.write(resp_body)

    # Splunk REST install paths only use POST; the script never sends
    # GET/PUT/DELETE today. Wire all four anyway so an accidental method
    # change in the script gets logged rather than producing a 501 that
    # would be hard to diagnose.
    do_POST = _handle
    do_GET = _handle
    do_PUT = _handle
    do_DELETE = _handle


def main() -> int:
    # Port 0 → kernel-assigned ephemeral port. The bats helper greps for
    # "Serving ... port N" so it knows which port to point curl at.
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    print(
        f"Serving HTTP on 127.0.0.1 port {server.server_port}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
