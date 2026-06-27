"""Tests for the dynamic-block resolver (prompt build, cleaning, web tools)."""

from unittest.mock import AsyncMock, patch

import pytest

from excalibur_mcp import resolve
from excalibur_mcp.resolve import (
    _build_prompt,
    _build_tools,
    _clean,
    _extract_answer,
    clamp_fetches,
    resolve_block,
)


def test_clean_strips_fences_and_quotes():
    assert _clean('```\n"sunny, 72°F"\n```') == "sunny, 72°F"
    assert _clean("“BTC at $64k”") == "BTC at $64k"
    assert _clean("  plain  ") == "plain"


def test_prompt_includes_prompt_context_voice_bans_no_char_cap():
    system, user = _build_prompt(
        prompt="state the weather now",
        context="Good morning. ⟨HERE⟩ Stay warm.",
        voice="plain and contrarian",
        bans=["delve", "game-changer"],
    )
    assert "plain and contrarian" in system
    assert "delve" in system and "game-changer" in system
    assert "no fixed character limit" in system  # X is long-form; no 280 cap
    assert "characters or fewer" not in system
    assert "<post>" in system and "</post>" in system  # deliverable goes in the tags
    assert "DOWN-FORMAT" in system and "HTML" in system  # X-unicode-only guard
    assert "state the weather now" in user
    assert "Stay warm." in user
    assert resolve.INSERT_MARKER in user


def test_extract_answer_prefers_post_tag_dropping_narration():
    data = {"content": [
        {"type": "text", "text": "The book is X. I now have enough detail to write the fragment."},
        {"type": "web_fetch_tool_result"},
        {"type": "text", "text": "scratch <post>Final marketing copy.</post> trailing note"},
    ]}
    assert _extract_answer(data) == "Final marketing copy."


def test_extract_answer_trailing_fallback_when_no_tag():
    data = {"content": [
        {"type": "text", "text": "thinking out loud before the tools"},
        {"type": "web_search_tool_result"},
        {"type": "text", "text": "the actual answer"},
    ]}
    assert _extract_answer(data) == "the actual answer"  # narration before the tool dropped


def test_extract_answer_no_tools_keeps_the_text():
    data = {"content": [{"type": "text", "text": "<post>just this</post>"}]}
    assert _extract_answer(data) == "just this"


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
        out = await resolve_block(api_key="k", prompt="weather + btc now")
    assert out == "sunny, 72°F · BTC $64k"


@pytest.mark.asyncio
async def test_resolve_block_returns_long_output_untruncated():
    long_text = "x" * 5000  # well past the old 280 cap — no truncation now
    with patch.object(resolve, "_call", AsyncMock(return_value=long_text)) as call:
        out = await resolve_block(api_key="k", prompt="write a long essay")
    assert out == long_text          # returned whole
    assert call.await_count == 1     # no shorten retry


@pytest.mark.asyncio
async def test_resolve_block_downformats_markup_to_x_text():
    # Even if rich markup slips through, resolve_block returns X-ready plain text.
    raw = "<b>Hi</b> — see [shop](https://e.com/p)"
    with patch.object(resolve, "_call", AsyncMock(return_value=raw)):
        out = await resolve_block(api_key="k", prompt="p")
    assert "<b>" not in out and "</b>" not in out and "](" not in out
    assert "Hi" in out and "https://e.com/p" in out


@pytest.mark.asyncio
async def test_resolve_block_empty_output_raises():
    with patch.object(resolve, "_call", AsyncMock(return_value="")):
        with pytest.raises(ValueError):
            await resolve_block(api_key="k", prompt="p")


@pytest.mark.asyncio
async def test_resolve_block_empty_prompt_raises():
    with pytest.raises(ValueError):
        await resolve_block(api_key="k", prompt="   ")
