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
