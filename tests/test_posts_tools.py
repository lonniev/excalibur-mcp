"""Posts CRUD tool-handler tests — validation, idempotency, not-found refunds.

The handlers sit above the SQL layer (``db.posts``) and the billing decorator.
We fake both: ``posts_db`` is patched per test, and ``runtime`` is a stub whose
``rollback_debit`` records refunds. These tests assert the contract's money
rules — a repeated client_req_id or a missing post must never leave the patron
charged.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp.tools import posts as posts_tools

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
PID = "11111111-1111-1111-1111-111111111111"
TOOL = "tool-uuid"


def _runtime() -> SimpleNamespace:
    return SimpleNamespace(rollback_debit=AsyncMock())


# -- validation (raises → decorator refunds + tool_input_invalid) ------------

@pytest.mark.asyncio
async def test_create_rejects_empty_doc():
    with pytest.raises(ValueError):
        await posts_tools.create(
            _runtime(), TOOL, doc={}, text_cache="", publish_at=None,
            recurrence=None, cease_at=None, status="draft", client_req_id="", npub=NPUB,
        )


@pytest.mark.asyncio
async def test_create_rejects_bad_status():
    with pytest.raises(ValueError):
        await posts_tools.create(
            _runtime(), TOOL, doc={"blocks": []}, text_cache="", publish_at=None,
            recurrence=None, cease_at=None, status="sent", client_req_id="", npub=NPUB,
        )


@pytest.mark.asyncio
async def test_create_scheduled_requires_publish_at():
    with pytest.raises(ValueError):
        await posts_tools.create(
            _runtime(), TOOL, doc={"blocks": []}, text_cache="", publish_at=None,
            recurrence=None, cease_at=None, status="scheduled", client_req_id="", npub=NPUB,
        )


@pytest.mark.asyncio
async def test_create_rejects_bad_recurrence_freq():
    with pytest.raises(ValueError):
        await posts_tools.create(
            _runtime(), TOOL, doc={"blocks": []}, text_cache="", publish_at="2026-07-01T00:00:00+00:00",
            recurrence={"freq": "yearly", "interval": 1}, cease_at=None,
            status="scheduled", client_req_id="", npub=NPUB,
        )


@pytest.mark.asyncio
async def test_get_rejects_non_uuid():
    with pytest.raises(ValueError):
        await posts_tools.get(_runtime(), TOOL, post_id="not-a-uuid", npub=NPUB)


@pytest.mark.asyncio
async def test_update_rejects_unknown_patch_key():
    with pytest.raises(ValueError):
        await posts_tools.update(
            _runtime(), TOOL, post_id=PID, patch={"npub": "x"}, text_cache="",
            client_req_id="", npub=NPUB,
        )


# -- create idempotency ------------------------------------------------------

@pytest.mark.asyncio
async def test_create_idempotent_returns_prior_and_refunds():
    rt = _runtime()
    prior = {"post_id": PID, "status": "draft", "created_at": "2026-06-19T00:00:00+00:00"}
    with patch.object(posts_tools.posts_db, "find_by_req_id", AsyncMock(return_value=prior)), \
         patch.object(posts_tools.posts_db, "create_post", AsyncMock()) as create_mock:
        out = await posts_tools.create(
            rt, TOOL, doc={"blocks": []}, text_cache="hi", publish_at=None,
            recurrence=None, cease_at=None, status="draft", client_req_id="req-1", npub=NPUB,
        )
    assert out["post_id"] == PID and out["idempotent"] is True
    rt.rollback_debit.assert_awaited_once_with(TOOL, NPUB)
    create_mock.assert_not_called()  # no second insert


@pytest.mark.asyncio
async def test_create_fresh_inserts_and_does_not_refund():
    rt = _runtime()
    row = {"post_id": PID, "status": "draft", "created_at": "2026-06-19T00:00:00+00:00"}
    with patch.object(posts_tools.posts_db, "find_by_req_id", AsyncMock(return_value=None)), \
         patch.object(posts_tools.posts_db, "create_post", AsyncMock(return_value=row)):
        out = await posts_tools.create(
            rt, TOOL, doc={"blocks": []}, text_cache="hi", publish_at=None,
            recurrence=None, cease_at=None, status="draft", client_req_id="req-1", npub=NPUB,
        )
    assert out == {"post_id": PID, "status": "draft", "created_at": "2026-06-19T00:00:00+00:00"}
    rt.rollback_debit.assert_not_awaited()


# -- update idempotency + not-found ------------------------------------------

@pytest.mark.asyncio
async def test_update_idempotent_repeat_refunds_and_noops():
    rt = _runtime()
    cur = {"status": "scheduled", "updated_at": "2026-06-19T01:00:00+00:00"}
    with patch.object(posts_tools.posts_db, "current_req_id", AsyncMock(return_value="req-9")), \
         patch.object(posts_tools.posts_db, "get_post", AsyncMock(return_value=cur)), \
         patch.object(posts_tools.posts_db, "update_post", AsyncMock()) as upd:
        out = await posts_tools.update(
            rt, TOOL, post_id=PID, patch={"status": "scheduled"}, text_cache="",
            client_req_id="req-9", npub=NPUB,
        )
    assert out["idempotent"] is True and out["status"] == "scheduled"
    rt.rollback_debit.assert_awaited_once_with(TOOL, NPUB)
    upd.assert_not_called()


@pytest.mark.asyncio
async def test_update_not_found_refunds():
    rt = _runtime()
    with patch.object(posts_tools.posts_db, "current_req_id", AsyncMock(return_value=None)), \
         patch.object(posts_tools.posts_db, "update_post", AsyncMock(return_value=None)):
        out = await posts_tools.update(
            rt, TOOL, post_id=PID, patch={"status": "draft"}, text_cache="",
            client_req_id="", npub=NPUB,
        )
    assert out["error_code"] == "post_not_found"
    rt.rollback_debit.assert_awaited_once_with(TOOL, NPUB)


@pytest.mark.asyncio
async def test_soft_delete_not_found_refunds():
    rt = _runtime()
    with patch.object(posts_tools.posts_db, "soft_delete", AsyncMock(return_value=None)):
        out = await posts_tools.delete(rt, TOOL, post_id=PID, hard=False, npub=NPUB)
    assert out["error_code"] == "post_not_found"
    rt.rollback_debit.assert_awaited_once_with(TOOL, NPUB)


@pytest.mark.asyncio
async def test_soft_delete_ok():
    rt = _runtime()
    with patch.object(posts_tools.posts_db, "soft_delete",
                      AsyncMock(return_value={"post_id": PID, "status": "archived"})):
        out = await posts_tools.delete(rt, TOOL, post_id=PID, hard=False, npub=NPUB)
    assert out == {"post_id": PID, "status": "archived"}
    rt.rollback_debit.assert_not_awaited()
