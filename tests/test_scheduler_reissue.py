"""The scheduler's operator-gated actions — the server and the Worker agree.

The MCP signs each request as the operator (NIP-98: the event names the
method, URL and body hash); the Worker verifies the signature against the
request it received. Two actions use this: reading the pending phrase and
re-issuing the request. If the server and the Worker ever disagree on a route
or method, the action fails as ``not_operator`` for the one person it exists
for — so each side's source is checked against the other's here.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = (ROOT / "scheduler-worker" / "src" / "index.ts").read_text()
SERVER = (ROOT / "src" / "excalibur_mcp" / "server.py").read_text()

# route -> the method the server signs and sends
ROUTES = {"/pending": "GET", "/reissue": "POST"}


def _category(capability: str) -> str:
    m = re.search(rf'capability="{capability}",\s*category="(\w+)"', SERVER)
    assert m, f"no ToolIdentity for {capability}"
    return m.group(1)


def test_reissuing_is_the_operators_alone():
    """Unlike check_now, a reissue ACTS: it throws away the pending request
    and DMs the operator again. A patron doing that would be spam."""
    assert _category("scheduler_reissue") == "restricted"


def test_reading_the_phrase_stays_the_operators_alone():
    assert _category("scheduler_pending") == "restricted"


def test_the_server_signs_each_request_it_sends_the_worker():
    for route, method in ROUTES.items():
        assert f"/{route.strip('/')}\"" in SERVER, route
        assert f'sign_request(runtime._get_nsec(), method="{method}", url=url, body=b"")' in SERVER, route


def test_the_worker_checks_method_path_and_body_of_the_signed_request():
    assert 'tag("method") !== req.method' in WORKER
    assert "new URL(String(tag(\"u\"))).pathname !== new URL(req.url).pathname" in WORKER
    assert 'tag("payload") !== (await sha256Hex(body))' in WORKER
