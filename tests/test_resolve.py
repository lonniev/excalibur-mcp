"""Tests for the dynamic-block resolver (prompt build, cleaning, web tools)."""

from unittest.mock import patch

import pytest

from excalibur_mcp import resolve
from excalibur_mcp.resolve import (
    _build_prompt,
    _build_tools,
    _clean,
    _extract_answer,
    build_anthropic_request,
    clamp_fetches,
    extract_resolved_text,
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


# --- build_anthropic_request: the half sealed into the durable closure --------

def test_build_anthropic_request_bakes_key_tools_and_body():
    req = build_anthropic_request(
        api_key="k", prompt="p", allowed_domains=["a.com"], max_fetches=3,
    )
    assert req["method"] == "POST"
    assert req["url"].endswith("/v1/messages")
    # the operator key rides only as the x-api-key header (sealed by the wheel)
    assert req["headers"]["x-api-key"] == "k"
    fetch = next(t for t in req["json"]["tools"] if t["name"] == "web_fetch")
    assert fetch["allowed_domains"] == ["a.com"] and fetch["max_uses"] == 3
    assert req["json"]["messages"][0]["content"]  # the user prompt is present
    # fully JSON-serializable (it must survive sealing as a closure)
    import json as _json
    _json.dumps(req)


def test_build_anthropic_request_empty_prompt_raises():
    with pytest.raises(ValueError):
        build_anthropic_request(api_key="k", prompt="   ")


# --- extract_resolved_text: the half that shapes the detached result ----------

def test_extract_resolved_text_happy_path():
    body = {"content": [{"type": "text", "text": "<post>sunny, 72°F · BTC $64k</post>"}]}
    assert extract_resolved_text(body) == "sunny, 72°F · BTC $64k"


def test_extract_resolved_text_returns_long_output_untruncated():
    long_text = "x" * 5000  # well past the old 280 cap — no truncation now
    body = {"content": [{"type": "text", "text": f"<post>{long_text}</post>"}]}
    assert extract_resolved_text(body) == long_text


def test_extract_resolved_text_downformats_markup_to_x_text():
    # Even if rich markup slips through, the result is X-ready plain text.
    body = {"content": [
        {"type": "text", "text": "<post><b>Hi</b> — see [shop](https://e.com/p)</post>"},
    ]}
    out = extract_resolved_text(body)
    assert "<b>" not in out and "</b>" not in out and "](" not in out
    assert "Hi" in out and "https://e.com/p" in out


def test_extract_resolved_text_empty_raises():
    with pytest.raises(ValueError):
        extract_resolved_text({"content": []})


# --- resolve_block: the in-process / scheduler path recomposes both halves ----

@pytest.mark.asyncio
async def test_resolve_block_recomposes_build_and_extract():
    body = {"content": [{"type": "text", "text": "<post>sunny, 72°F · BTC $64k</post>"}]}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return body

    async def fake_post(self, url, **kwargs):
        # the request was built by build_anthropic_request → carries the key
        assert kwargs["headers"]["x-api-key"] == "k"
        return _Resp()

    with patch.object(resolve.httpx.AsyncClient, "post", fake_post):
        out = await resolve_block(api_key="k", prompt="weather + btc now")
    assert out == "sunny, 72°F · BTC $64k"


@pytest.mark.asyncio
async def test_resolve_block_empty_prompt_raises():
    with pytest.raises(ValueError):
        await resolve_block(api_key="k", prompt="   ")
