"""Pin the projection: a degraded send must be distinguishable in the LIST."""
from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp.db import posts as posts_db

_FELL = {"reason": "resolve_failed:ConnectError", "budget_s": 480}


@pytest.mark.asyncio
async def test_list_projects_fell_back_from_the_sent_snapshot():
    # A sent occurrence carries the RENDERED blocks in `doc`; the row the FE
    # gets must say the post went out on fallback text. Before this the list
    # showed a green "Sent" pill and nothing else, and the only way to notice
    # was to open the post and recognise the wording.
    rows = [{"post_id": "p1", "status": "sent", "title": "", "excerpt": "",
             "publish_at": None, "updated_at": "", "created_at": "", "tweet_url": None,
             "last_sent_at": None, "last_attempt_at": None, "last_attempt_reason": None,
             "last_attempt_detail": None, "template_id": None, "is_recurring": False,
             "has_dynamic": True, "fell_back": [_FELL]}]
    with patch.object(posts_db, "fetchrow", AsyncMock(return_value={"n": 1})), \
         patch.object(posts_db, "fetch", AsyncMock(return_value=rows)):
        out = await posts_db.list_posts("npub1x")
    assert out["posts"][0]["fell_back"] == [_FELL]


@pytest.mark.asyncio
async def test_clean_send_reports_no_fallbacks():
    rows = [{"post_id": "p2", "status": "sent", "title": "", "excerpt": "",
             "publish_at": None, "updated_at": "", "created_at": "", "tweet_url": None,
             "last_sent_at": None, "last_attempt_at": None, "last_attempt_reason": None,
             "last_attempt_detail": None, "template_id": None, "is_recurring": False,
             "has_dynamic": True, "fell_back": []}]
    with patch.object(posts_db, "fetchrow", AsyncMock(return_value={"n": 1})), \
         patch.object(posts_db, "fetch", AsyncMock(return_value=rows)):
        out = await posts_db.list_posts("npub1x")
    assert out["posts"][0]["fell_back"] == []


def test_neon_may_return_jsonb_as_a_raw_string():
    # The Neon HTTP API hands JSONB back parsed OR raw depending on the path;
    # a badge built on a misread is worse than no badge.
    assert posts_db._as_list('[{"reason":"x"}]') == [{"reason": "x"}]
    assert posts_db._as_list([{"reason": "x"}]) == [{"reason": "x"}]
    assert posts_db._as_list(None) == []
    assert posts_db._as_list("not json") == []
    assert posts_db._as_list('{"not":"a list"}') == []
