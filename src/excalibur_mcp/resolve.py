"""Server-side resolution of a *dynamic* post block.

A dynamic block's text IS a runnable prompt ("…the current weather and the
BTC/USD price now"). At post time — or in the editor's Preview dry-run — the
operator's vaulted Anthropic key runs that prompt, with Claude's server-side
``web_search`` tool for live facts, and returns one tweet-ready fragment woven
into the surrounding copy in the author's voice and fitted to a character budget.

Same posture as ``refine.py``: the operator's key stays in the vault and never
leaves the server, and the call is metered as a paid tollbooth fare. This module
is pure resolution — it ``raise``s on transport/HTTP error or empty output so the
caller (the dry-run tool or the scheduler) can refund / fall back.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"
_ENDPOINT = "https://api.anthropic.com/v1/messages"
_TIMEOUT = 90.0
_MAX_TOKENS = 1500

# Claude's server-side web tools (dynamic-filtering variants — supported on
# claude-sonnet-4-6). web_search queries the indexed web (no URL needed);
# web_fetch retrieves a specific URL already present in the conversation (the
# prompt, or a link a prior search/fetch surfaced). Anthropic runs both server
# side and folds the findings into the final answer, so a single request still
# returns finished text. allowed_domains/max_uses are author-controlled per block.
_WEB_SEARCH_TYPE = "web_search_20260209"
_WEB_FETCH_TYPE = "web_fetch_20260209"

# Per-block web-lookup budget. The author may raise it; we cap it so a runaway
# prompt can't fan out indefinitely (each lookup costs the post owner).
_MAX_FETCHES_DEFAULT = 5
_MAX_FETCHES_CAP = 25


def clamp_fetches(value: int) -> int:
    """Clamp an author-requested web-lookup budget into a sane range."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return _MAX_FETCHES_DEFAULT
    return max(1, min(_MAX_FETCHES_CAP, v))


def _build_tools(allowed_domains: list[str] | None, max_fetches: int) -> list[dict[str, Any]]:
    """Web tools for one resolution: search (always) + fetch (always). When the
    author listed domains, web_fetch is restricted to them; otherwise it may
    fetch any URL the prompt references (Anthropic gates fetch to URLs already in
    the conversation). ``max_fetches`` bounds uses of each tool."""
    fetch: dict[str, Any] = {"type": _WEB_FETCH_TYPE, "name": "web_fetch", "max_uses": max_fetches}
    if allowed_domains:
        fetch["allowed_domains"] = allowed_domains
    return [
        {"type": _WEB_SEARCH_TYPE, "name": "web_search", "max_uses": max_fetches},
        fetch,
    ]


# The marker a caller embeds in ``context`` where the fragment belongs. Optional —
# absent it, the model just composes a fragment that reads after the context.
INSERT_MARKER = "⟨HERE⟩"

# Bounds for the character budget so an adversarial value can't ask for a
# 2-char fragment or an unbounded essay.
_BUDGET_MIN = 8
_BUDGET_MAX = 10_000


def clamp_budget(value: int) -> int:
    """Clamp a requested character budget into a sane range."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 280
    return max(_BUDGET_MIN, min(_BUDGET_MAX, v))


def _build_prompt(
    prompt: str, context: str, voice: str, bans: list[str], char_budget: int,
    *, shorten_from: str | None = None,
) -> tuple[str, str]:
    constraints: list[str] = []
    if voice.strip():
        constraints.append(f"Match this voice profile exactly: {voice}.")
    if bans:
        constraints.append(
            f"Hard constraints — never produce any of these constructions: {'; '.join(bans)}."
        )
    system = (
        "You compose ONE fragment of a single tweet being posted to X. Run the "
        "author's instruction — use web search whenever it needs current facts — "
        "then return ONLY the finished fragment text: no preamble, no surrounding "
        "quotes, no markdown, no code fences, no citations or source list. The "
        "fragment must read naturally where it sits in the surrounding tweet and "
        "carry forward its voice. "
        + (" ".join(constraints) + " " if constraints else "")
        + f"Hard limit: at most {char_budget} characters."
    )
    surround = context.strip() or "(the fragment stands on its own)"
    user = (
        f"SURROUNDING TWEET (the fragment goes where you see {INSERT_MARKER}):\n"
        f"{surround}\n\n"
        f"AUTHOR'S INSTRUCTION FOR THE FRAGMENT:\n{prompt.strip()}"
    )
    if shorten_from is not None:
        user += (
            f"\n\nYour previous draft was too long ({len(shorten_from)} chars). "
            f"Rewrite it to {char_budget} characters or fewer, same meaning, same "
            f"voice:\n{shorten_from}"
        )
    return system, user


def _extract_text(data: dict[str, Any]) -> str:
    """Join the model's text blocks (ignoring web-search tool-use blocks)."""
    return "".join(
        b.get("text", "")
        for b in data.get("content", [])
        if b.get("type") == "text"
    ).strip()


def _clean(text: str) -> str:
    """Strip wrappers a model sometimes adds around a bare fragment.

    Removes code fences and a single layer of matching surrounding quotes so an
    echoed-prompt / quoted answer doesn't post with stray punctuation.
    """
    t = (text or "").replace("```", "").strip()
    if len(t) >= 2 and t[0] in "\"'“‘" and t[-1] in "\"'”’":
        t = t[1:-1].strip()
    return t


async def _call(api_key: str, system: str, user: str, tools: list[dict[str, Any]]) -> str:
    """One Anthropic messages call with the given web tools; returns clean text."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(
            _ENDPOINT,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": _MODEL,
                "max_tokens": _MAX_TOKENS,
                "system": system,
                "tools": tools,
                "messages": [{"role": "user", "content": user}],
            },
        )
    resp.raise_for_status()
    return _clean(_extract_text(resp.json()))


async def resolve_block(
    *,
    api_key: str,
    prompt: str,
    context: str = "",
    voice: str = "",
    bans: list[str] | None = None,
    char_budget: int = 280,
    allowed_domains: list[str] | None = None,
    max_fetches: int = _MAX_FETCHES_DEFAULT,
) -> str:
    """Resolve one dynamic block to its final, tweet-ready fragment text.

    ``context`` is the surrounding composed tweet (optionally with
    ``INSERT_MARKER`` where the fragment belongs). The length gate makes one
    bounded "shorten" retry when the first draft overruns ``char_budget``, then
    hard-caps as a last resort. ``allowed_domains`` (author allowlist; empty = any
    URL the prompt references) and ``max_fetches`` (author budget) scope the
    server-side web tools. Raises ``ValueError`` on empty input/output and
    propagates transport/HTTP errors so the caller can refund / fall back.
    """
    bans = bans or []
    budget = clamp_budget(char_budget)
    if not prompt.strip():
        raise ValueError("empty prompt")

    tools = _build_tools(allowed_domains, clamp_fetches(max_fetches))
    system, user = _build_prompt(prompt, context, voice, bans, budget)
    text = await _call(api_key, system, user, tools)

    if text and len(text) > budget:
        # One bounded regenerate to fit the budget before we resort to truncation.
        system2, user2 = _build_prompt(
            prompt, context, voice, bans, budget, shorten_from=text,
        )
        shortened = await _call(api_key, system2, user2, tools)
        if shortened:
            text = shortened

    if not text:
        raise ValueError("no text returned")
    if len(text) > budget:
        text = text[:budget].rstrip()
    return text
