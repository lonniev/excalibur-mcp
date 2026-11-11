""""Check now" must finish: the Worker answers only after the check is done.

Work a Worker leaves in ``waitUntil`` after a fetch has answered is cancelled
about 30 s later, so a check that collected a relay reply in the background
never completed and "Check now" never flipped the scheduler. The check now
runs before the Worker answers, posts nothing, and the server waits for it.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = (ROOT / "scheduler-worker" / "src" / "index.ts").read_text()
SERVER = (ROOT / "src" / "excalibur_mcp" / "server.py").read_text()


def _tick_route() -> str:
    m = re.search(r'if \(url\.pathname === "/tick"\) \{(.*?)\n    \}\n', WORKER, re.S)
    assert m, "no /tick route"
    return m.group(1)


def test_the_tick_route_answers_after_the_check():
    route = _tick_route()
    assert "await tick(env, { fire: false })" in route
    assert "waitUntil" not in route


def test_a_check_posts_nothing():
    assert 'if (!fireDue) return "Approved.' in WORKER
    assert 'if (!fireDue) return "Authorized.' in WORKER


def test_the_server_waits_for_the_answer_and_relays_it():
    body = SERVER.split("async def scheduler_check_now(", 1)[1].split("\n@tool", 1)[0]
    assert "httpx.AsyncClient(timeout=90)" in body
    assert '"message": str(body.get("message")' in body
