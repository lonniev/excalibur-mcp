"""Snippet CRUD tool-handler tests — validation + owner-scoped contract.

The handlers sit above the SQL layer (``db.snippets``) and the free billing
decorator. We patch ``snippets_db`` per test. Snippets are free, so there is no
refund path to assert — the rules under test are input validation and the
create-vs-update dispatch.
"""

from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp.tools import snippets as snippets_tools

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"
SID = "11111111-1111-1111-1111-111111111111"


# -- validation --------------------------------------------------------------

@pytest.mark.asyncio
async def test_save_rejects_empty_name():
    with pytest.raises(ValueError):
        await snippets_tools.save(NPUB, name="", text="hello")


@pytest.mark.asyncio
async def test_save_rejects_empty_text_on_create():
    with pytest.raises(ValueError):
        await snippets_tools.save(NPUB, name="Footer", text="")


@pytest.mark.asyncio
async def test_save_rejects_overlong_body():
    with pytest.raises(ValueError):
        await snippets_tools.save(NPUB, name="Footer", text="x" * 9000)


@pytest.mark.asyncio
async def test_delete_rejects_bad_uuid():
    with pytest.raises(ValueError):
        await snippets_tools.delete(NPUB, snippet_id="not-a-uuid")


# -- create vs update dispatch ----------------------------------------------

@pytest.mark.asyncio
async def test_save_without_id_creates():
    row = {"id": SID, "name": "Footer", "text": "thanks", "favorite": False}
    with patch.object(snippets_tools.snippets_db, "create_snippet",
                      new=AsyncMock(return_value=row)) as create, \
         patch.object(snippets_tools.snippets_db, "update_snippet",
                      new=AsyncMock()) as update:
        out = await snippets_tools.save(NPUB, name="Footer", text="thanks")
    create.assert_awaited_once()
    update.assert_not_awaited()
    assert out == {"success": True, "snippet": row}


@pytest.mark.asyncio
async def test_save_with_id_updates():
    row = {"id": SID, "name": "Footer", "text": "thanks", "favorite": True}
    with patch.object(snippets_tools.snippets_db, "update_snippet",
                      new=AsyncMock(return_value=row)) as update, \
         patch.object(snippets_tools.snippets_db, "create_snippet",
                      new=AsyncMock()) as create:
        out = await snippets_tools.save(NPUB, snippet_id=SID, favorite=True)
    update.assert_awaited_once()
    create.assert_not_awaited()
    assert out["success"] is True
    assert out["snippet"]["favorite"] is True


@pytest.mark.asyncio
async def test_update_missing_row_is_not_found():
    with patch.object(snippets_tools.snippets_db, "update_snippet",
                      new=AsyncMock(return_value=None)):
        out = await snippets_tools.save(NPUB, snippet_id=SID, favorite=True)
    assert out["success"] is False
    assert out["error_code"] == "snippet_not_found"


@pytest.mark.asyncio
async def test_delete_missing_row_is_not_found():
    with patch.object(snippets_tools.snippets_db, "delete_snippet",
                      new=AsyncMock(return_value=False)):
        out = await snippets_tools.delete(NPUB, snippet_id=SID)
    assert out["success"] is False
    assert out["error_code"] == "snippet_not_found"


@pytest.mark.asyncio
async def test_list_passes_through():
    rows = [{"id": SID, "name": "Footer", "text": "thanks", "favorite": True}]
    with patch.object(snippets_tools.snippets_db, "list_snippets",
                      new=AsyncMock(return_value=rows)):
        out = await snippets_tools.list_(NPUB)
    assert out == {"success": True, "snippets": rows}
