"""Voice tool-handler tests — validation, bans normalization, owner-scoped save.

The handlers sit above the SQL layer (``db.voices``) and the free billing
decorator. We patch ``voices_db`` per test. Voice is free, so there is no refund
path to assert — the rules under test are input validation, bans normalization,
and the empty-when-unset read contract.
"""

from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp.tools import voices as voices_tools

NPUB = "npub1l94pd4qu4eszrl6ek032ftcnsu3tt9a7xvq2zp7eaxeklp6mrpzssmq8pf"


# -- get --------------------------------------------------------------------

@pytest.mark.asyncio
async def test_get_unset_returns_empty_voice_not_error():
    with patch.object(voices_tools.voices_db, "get_voice",
                      new=AsyncMock(return_value=None)):
        out = await voices_tools.get(NPUB)
    assert out == {"success": True, "voice": {"profile": "", "bans": []}}


@pytest.mark.asyncio
async def test_get_returns_saved_voice():
    row = {"npub": NPUB, "profile": "plain", "bans": [{"text": "x", "on": True}]}
    with patch.object(voices_tools.voices_db, "get_voice",
                      new=AsyncMock(return_value=row)):
        out = await voices_tools.get(NPUB)
    assert out["success"] is True
    assert out["voice"]["profile"] == "plain"
    assert out["voice"]["bans"] == [{"text": "x", "on": True}]


# -- validation -------------------------------------------------------------

@pytest.mark.asyncio
async def test_save_rejects_non_string_profile():
    with pytest.raises(ValueError):
        await voices_tools.save(NPUB, profile=123)


@pytest.mark.asyncio
async def test_save_rejects_overlong_profile():
    with pytest.raises(ValueError):
        await voices_tools.save(NPUB, profile="x" * 5000)


@pytest.mark.asyncio
async def test_save_rejects_non_list_bans():
    with pytest.raises(ValueError):
        await voices_tools.save(NPUB, bans="not-a-list")


@pytest.mark.asyncio
async def test_save_rejects_ban_without_string_text():
    with pytest.raises(ValueError):
        await voices_tools.save(NPUB, bans=[{"text": 5, "on": True}])


# -- bans normalization -----------------------------------------------------

@pytest.mark.asyncio
async def test_save_drops_blank_and_dedupes_bans():
    captured = {}

    async def fake_upsert(npub, profile, bans):
        captured["bans"] = bans
        return {"npub": npub, "profile": profile, "bans": bans}

    with patch.object(voices_tools.voices_db, "upsert_voice", fake_upsert):
        await voices_tools.save(NPUB, profile="p", bans=[
            {"text": " hype ", "on": True},
            {"text": "", "on": True},       # blank → dropped
            {"text": "HYPE", "on": False},  # dup (case-insensitive) → last wins
        ])
    assert captured["bans"] == [{"text": "HYPE", "on": False}]


@pytest.mark.asyncio
async def test_save_defaults_on_to_true():
    captured = {}

    async def fake_upsert(npub, profile, bans):
        captured["bans"] = bans
        return {"npub": npub, "profile": profile, "bans": bans}

    with patch.object(voices_tools.voices_db, "upsert_voice", fake_upsert):
        await voices_tools.save(NPUB, bans=[{"text": "delve"}])
    assert captured["bans"] == [{"text": "delve", "on": True}]


@pytest.mark.asyncio
async def test_save_returns_stored_voice():
    row = {"npub": NPUB, "profile": "plain", "bans": [{"text": "x", "on": True}]}
    with patch.object(voices_tools.voices_db, "upsert_voice",
                      new=AsyncMock(return_value=row)):
        out = await voices_tools.save(NPUB, profile="plain", bans=[{"text": "x", "on": True}])
    assert out["success"] is True
    assert out["voice"]["profile"] == "plain"
    assert out["voice"]["bans"] == [{"text": "x", "on": True}]
