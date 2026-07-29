"""Tests for the server-side refine helper (prompt + suggestion parsing)."""

from excalibur_mcp.refine import _build_prompt, _parse_suggestions


def test_parse_json_array():
    raw = '["one", "two", "three", "four"]'
    assert _parse_suggestions(raw) == ["one", "two", "three"]  # capped at 3


def test_parse_json_array_in_code_fence():
    raw = "```json\n[\"a\", \"b\"]\n```"
    assert _parse_suggestions(raw) == ["a", "b"]


def test_parse_falls_back_to_lines():
    raw = "1. first option\n2. second option\n- third option"
    assert _parse_suggestions(raw) == ["first option", "second option", "third option"]


def test_parse_empty():
    assert _parse_suggestions("") == []
    assert _parse_suggestions("   ") == []


def test_prompt_includes_voice_and_bans():
    system, user = _build_prompt(
        region="the region", full_text="the full tweet", instruction="make it punchy",
        voice="plain and contrarian", bans=["delve", "game-changer"],
    )
    assert "plain and contrarian" in system
    assert "delve" in system and "game-changer" in system
    assert "JSON array" in system
    assert "the region" in user
    assert "the full tweet" in user
    assert "make it punchy" in user


def test_prompt_default_instruction_when_blank():
    system, user = _build_prompt(
        region="r", full_text="t", instruction="", voice="", bans=[],
    )
    assert "sharper and more human" in user
    # No voice/bans clauses when absent.
    assert "voice profile" not in system.lower()
    assert "hard constraints" not in system.lower()


# -- the route, and what an upstream refusal turns into ----------------------

def test_refine_draws_the_cheaper_reader_tier():
    """Three short rewrites are judgement, not authorship — unlike resolve.py,
    which composes copy the owner publishes under their own name."""
    from tollbooth.llm_route import TIER_READER, model_for

    from excalibur_mcp.refine import _TIER
    assert _TIER == TIER_READER
    assert model_for(_TIER) != model_for("writer")


def test_an_empty_provider_account_is_not_answered_with_try_again():
    """An unfunded account used to read here as a transient 'try again shortly' —
    advice that can never come true, and which told the operator nothing."""
    import httpx

    from excalibur_mcp.server import _llm_situation_from_exception

    req = httpx.Request("POST", "https://openrouter.ai/api/v1/messages")
    resp = httpx.Response(402, json={"error": {"message": "Insufficient credits"}}, request=req)
    exc = httpx.HTTPStatusError("402", request=req, response=resp)

    situation = _llm_situation_from_exception(
        exc, fallback_code="llm_upstream_error", fallback_message="fallback",
    )
    assert situation.error_code == "operator_llm_unfunded"
    assert situation.transient is False
    assert "Insufficient credits" not in situation.message  # raw body stays operator-side


def test_a_transport_failure_still_takes_the_callers_fallback():
    """No response, no status — only an exception string the wheel can't name."""
    from excalibur_mcp.server import _llm_situation_from_exception

    situation = _llm_situation_from_exception(
        TimeoutError("read timeout"),
        fallback_code="llm_upstream_error",
        fallback_message="The refine request failed upstream.",
    )
    assert situation.error_code == "llm_upstream_error"
    assert situation.transient is True
