"""The scheduler's operator-gated actions — the server and the Worker agree.

The MCP signs, as the operator, a kind-27235 event carrying a sentinel ``u``
tag; the Worker checks that tag literally. Two actions use this shape: reading
the pending phrase and re-issuing the request. If the server and the Worker
ever disagree on a tag, the action fails as ``not_operator`` for the one person
it exists for — so the tags are checked against each other's source here.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = (ROOT / "scheduler-worker" / "src" / "index.ts").read_text()
SERVER = (ROOT / "src" / "excalibur_mcp" / "server.py").read_text()

TAGS = {
    "PENDING_U_TAG": "excalibur_scheduler_pending",
    "REISSUE_U_TAG": "excalibur_scheduler_reissue",
}


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


def test_the_server_signs_the_tags_the_worker_checks():
    for const, tag in TAGS.items():
        assert f'const {const} = "{tag}"' in WORKER, const
        assert f'create_proof(runtime._get_nsec(), "{tag}")' in SERVER, tag


def test_a_proof_for_one_action_is_not_a_proof_for_the_other():
    assert len(set(TAGS.values())) == len(TAGS)
