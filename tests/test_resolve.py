"""Tests for the dynamic-block resolver (prompt build, cleaning, length gate)."""

from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp import resolve
from excalibur_mcp.resolve import (
    _build_prompt,
    _build_tools,
    _clean,
    clamp_budget,
    clamp_fetches,
    resolve_block,
)


def test_clean_strips_fences_and_quotes():
    assert _clean('```\n"sunny, 72°F"\n```') == "sunny, 72°F"
    assert _clean("“BTC at $64k”") == "BTC at $64k"
    assert _clean("  plain  ") == "plain"


def test_clamp_budget_bounds():
    assert clamp_budget(2) == 8          # below floor
    assert clamp_budget(999999) == 10000  # above ceiling
    assert clamp_budget(280) == 280
    assert clamp_budget("nope") == 280    # non-numeric → default


def test_prompt_includes_prompt_context_voice_bans_budget():
    system, user = _build_prompt(
        prompt="state the weather now",
        context="Good morning. ⟨HERE⟩ Stay warm.",
        voice="plain and contrarian",
        bans=["delve", "game-changer"],
        char_budget=120,
    )
    assert "plain and contrarian" in system
    assert "delve" in system and "game-changer" in system
    assert "120 characters" in system
    assert "state the weather now" in user
    assert "Stay warm." in user
    assert resolve.INSERT_MARKER in user


def test_prompt_shorten_variant_carries_previous_draft():
    _, user = _build_prompt(
        prompt="p", context="", voice="", bans=[], char_budget=50,
        shorten_from="a draft that was too long",
    )
    assert "too long" in user
    assert "50 characters or fewer" in user


def test_clamp_fetches_bounds():
    assert clamp_fetches(0) == 1          # floor
    assert clamp_fetches(999) == 25       # cap
    assert clamp_fetches(9) == 9
    assert clamp_fetches("nope") == 5     # non-numeric → default


def test_build_tools_blank_domains_enables_unrestricted_fetch():
    tools = _build_tools(None, 5)
    assert {t["name"] for t in tools} == {"web_search", "web_fetch"}
    fetch = next(t for t in tools if t["name"] == "web_fetch")
    assert "allowed_domains" not in fetch  # blank = any URL the prompt references
    assert fetch["max_uses"] == 5


def test_build_tools_with_domains_restricts_fetch():
    tools = _build_tools(["coindesk.com", "kraken.com"], 9)
    fetch = next(t for t in tools if t["name"] == "web_fetch")
    assert fetch["allowed_domains"] == ["coindesk.com", "kraken.com"]
    assert fetch["max_uses"] == 9


@pytest.mark.asyncio
async def test_resolve_block_passes_web_tools_to_the_call():
    call = AsyncMock(return_value="ok")
    with patch.object(resolve, "_call", call):
        await resolve_block(api_key="k", prompt="p", allowed_domains=["a.com"], max_fetches=3)
    tools = call.await_args.args[3]  # _call(api_key, system, user, tools)
    fetch = next(t for t in tools if t["name"] == "web_fetch")
    assert fetch["allowed_domains"] == ["a.com"] and fetch["max_uses"] == 3


@pytest.mark.asyncio
async def test_resolve_block_happy_path():
    with patch.object(resolve, "_call", AsyncMock(return_value="sunny, 72°F · BTC $64k")):
        out = await resolve_block(api_key="k", prompt="weather + btc now", char_budget=280)
    assert out == "sunny, 72°F · BTC $64k"


@pytest.mark.asyncio
async def test_resolve_block_over_budget_triggers_shorten_retry():
    long_text = "x" * 50
    short_text = "y" * 10
    call = AsyncMock(side_effect=[long_text, short_text])
    with patch.object(resolve, "_call", call):
        out = await resolve_block(api_key="k", prompt="p", char_budget=20)
    assert out == short_text
    assert call.await_count == 2  # first draft over budget → one shorten retry


@pytest.mark.asyncio
async def test_resolve_block_hard_caps_when_shorten_still_long():
    long_text = "x" * 50
    still_long = "y" * 40
    with patch.object(resolve, "_call", AsyncMock(side_effect=[long_text, still_long])):
        out = await resolve_block(api_key="k", prompt="p", char_budget=20)
    assert len(out) == 20  # last-resort truncation


@pytest.mark.asyncio
async def test_resolve_block_empty_output_raises():
    with patch.object(resolve, "_call", AsyncMock(return_value="")):
        with pytest.raises(ValueError):
            await resolve_block(api_key="k", prompt="p")


@pytest.mark.asyncio
async def test_resolve_block_empty_prompt_raises():
    with pytest.raises(ValueError):
        await resolve_block(api_key="k", prompt="   ")
