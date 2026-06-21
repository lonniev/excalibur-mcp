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
async def test_list_passes_paged_shape_through():
    paged = {
        "snippets": [{"id": SID, "name": "Footer", "text": "thanks", "favorite": True}],
        "total": 1, "page": 0, "page_size": 25,
    }
    with patch.object(snippets_tools.snippets_db, "list_snippets",
                      new=AsyncMock(return_value=paged)) as lst:
        out = await snippets_tools.list_(NPUB, sort_col="name", sort_dir="asc", page=2)
    lst.assert_awaited_once_with(
        NPUB, sort_col="name", sort_dir="asc", page=2, page_size=25,
        search=None, date_from=None, date_to=None, date_field="created",
    )
    assert out == {"success": True, **paged}


@pytest.mark.asyncio
async def test_list_rejects_invalid_regex_search():
    with pytest.raises(ValueError):
        await snippets_tools.list_(NPUB, search="[unterminated")


@pytest.mark.asyncio
async def test_list_threads_valid_search_and_dates():
    with patch.object(snippets_tools.snippets_db, "list_snippets",
                      new=AsyncMock(return_value={"snippets": [], "total": 0, "page": 0, "page_size": 25})) as lst:
        await snippets_tools.list_(NPUB, search="foo|bar", date_from="2026-01-01", date_field="updated")
    kw = lst.await_args.kwargs
    assert kw["search"] == "foo|bar" and kw["date_from"] == "2026-01-01"
    assert kw["date_field"] == "updated"


# -- doc handling -----------------------------------------------------------

@pytest.mark.asyncio
async def test_save_rejects_non_object_doc():
    with pytest.raises(ValueError):
        await snippets_tools.save(NPUB, name="Footer", text="hi", doc="not-an-object")


@pytest.mark.asyncio
async def test_save_threads_doc_to_create():
    doc = {"blocks": [{"text": "hi", "flags": []}]}
    row = {"id": SID, "name": "Footer", "text": "hi", "favorite": False, "doc": doc}
    with patch.object(snippets_tools.snippets_db, "create_snippet",
                      new=AsyncMock(return_value=row)) as create:
        out = await snippets_tools.save(NPUB, name="Footer", text="hi", doc=doc)
    create.assert_awaited_once_with(NPUB, "Footer", "hi", False, doc=doc)
    assert out["snippet"]["doc"] == doc


# -- get --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_rejects_bad_uuid():
    with pytest.raises(ValueError):
        await snippets_tools.get(NPUB, snippet_id="not-a-uuid")


@pytest.mark.asyncio
async def test_get_missing_row_is_not_found():
    with patch.object(snippets_tools.snippets_db, "get_snippet",
                      new=AsyncMock(return_value=None)):
        out = await snippets_tools.get(NPUB, snippet_id=SID)
    assert out["success"] is False
    assert out["error_code"] == "snippet_not_found"


@pytest.mark.asyncio
async def test_get_returns_row():
    row = {"id": SID, "name": "Footer", "text": "thanks", "favorite": True, "doc": None}
    with patch.object(snippets_tools.snippets_db, "get_snippet",
                      new=AsyncMock(return_value=row)):
        out = await snippets_tools.get(NPUB, snippet_id=SID)
    assert out == {"success": True, "snippet": row}
