"""Server-side resolution of a *dynamic* post block.

A dynamic block's text IS a runnable prompt ("…the current weather and the
BTC/USD price now"). At post time — or in the editor's Preview dry-run — the
operator's vaulted Anthropic key runs that prompt, with Claude's server-side
``web_search`` + ``web_fetch`` tools for live data, and returns one post-ready
fragment woven into the surrounding copy in the author's voice. The author's
instruction governs length (X is long-form; no character cap), and the finished
fragment is extracted from the model's ``<post>…</post>`` tags so its reasoning
never leaks into the copy.

Same posture as ``refine.py``: the operator's key stays in the vault and never
leaves the server, and the call is metered as a paid tollbooth fare. This module
is pure resolution — it ``raise``s on transport/HTTP error or empty output so the
caller (the dry-run tool or the scheduler) can refund / fall back.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from excalibur_mcp.formatter import to_x_text

logger = logging.getLogger(__name__)

# The model wraps its finished fragment in these tags so its own reasoning /
# between-tool narration ("I now have enough detail to write the fragment…")
# stays OUTSIDE and is discarded — we extract only what's inside.
_FRAGMENT_RE = re.compile(r"<post>(.*?)</post>", re.S | re.I)

_MODEL = "claude-sonnet-4-6"
_ENDPOINT = "https://api.anthropic.com/v1/messages"
_TIMEOUT = 110.0
# Generation ceiling, not a content limit — X supports long-form posts, so the
# author's instruction governs length. Generous enough for long prose while
# bounding latency/cost (and staying under the FE's per-call timeout).
_MAX_TOKENS = 4000

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

def _build_prompt(
    prompt: str, context: str, voice: str, bans: list[str],
) -> tuple[str, str]:
    constraints: list[str] = []
    if voice.strip():
        constraints.append(f"Match this voice profile exactly: {voice}.")
    if bans:
        constraints.append(
            f"Hard constraints — never produce any of these constructions: {'; '.join(bans)}."
        )
    system = (
        "You compose a fragment of a post being published to X. Run the author's "
        "instruction — use web search or web fetch whenever it needs current facts. "
        "You may think, search, and take notes freely while working. "
        "Output the FINISHED fragment wrapped in <post> and </post> tags, with "
        "nothing inside those tags except the fragment itself — no preamble, no "
        "\"here is\" or \"I now have enough detail\", no notes to yourself, no "
        "surrounding quotes, no citations or source list. Anything outside the "
        "tags is discarded, so put all reasoning there. "
        "Format for X, which renders only plain text with Unicode styling: use "
        "plain text, line breaks, and emoji; for emphasis use markdown **bold**, "
        "*italic*, or `monospace` (these become Unicode glyphs). Write URLs bare — "
        "X auto-links them; do not use markdown link syntax. NEVER output HTML, "
        "CSS, JSX/XML, tags of any kind, markdown headings or tables, or fenced "
        "code blocks. If the author asks for rich, structured, or coded formatting "
        "(a web page, a React/JSX component, HTML/CSS, a table, a code block), "
        "DOWN-FORMAT it to the closest plain X rendering — keep the readable "
        "content with simple Unicode emphasis and drop the markup. "
        "The fragment must read naturally where it sits in the surrounding post and "
        "carry forward its voice. Let the author's instruction set the length — X "
        "supports long-form posts, so there is no fixed character limit."
        + (" " + " ".join(constraints) if constraints else "")
    )
    surround = context.strip() or "(the fragment stands on its own)"
    user = (
        f"SURROUNDING POST (the fragment goes where you see {INSERT_MARKER}):\n"
        f"{surround}\n\n"
        f"AUTHOR'S INSTRUCTION FOR THE FRAGMENT:\n{prompt.strip()}"
    )
    return system, user


def _extract_answer(data: dict[str, Any]) -> str:
    """Pull the finished fragment from a tool-using response.

    Prefer the text inside the model's ``<post>…</post>`` tags (the deliverable;
    its reasoning/narration stays outside). If the tags are absent, fall back to
    the text emitted *after* the last tool block — the final answer — so
    between-tool narration doesn't leak in.
    """
    content = data.get("content", [])
    full = "".join(b.get("text", "") for b in content if b.get("type") == "text")
    tagged = _FRAGMENT_RE.findall(full)
    if tagged:
        return _clean(tagged[-1])

    last_tool = -1
    for i, b in enumerate(content):
        if b.get("type") != "text":
            last_tool = i
    trailing = "".join(
        b.get("text", "") for b in content[last_tool + 1:] if b.get("type") == "text"
    )
    return _clean(trailing)


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
    return _extract_answer(resp.json())


async def resolve_block(
    *,
    api_key: str,
    prompt: str,
    context: str = "",
    voice: str = "",
    bans: list[str] | None = None,
    allowed_domains: list[str] | None = None,
    max_fetches: int = _MAX_FETCHES_DEFAULT,
) -> str:
    """Resolve one dynamic block to its final, post-ready fragment text.

    ``context`` is the surrounding composed post (optionally with
    ``INSERT_MARKER`` where the fragment belongs). The author's instruction
    governs length — there is no character cap (X supports long-form posts).
    ``allowed_domains`` (author allowlist; empty = any URL the prompt references)
    and ``max_fetches`` (author budget) scope the server-side web tools. Raises
    ``ValueError`` on empty input/output and propagates transport/HTTP errors so
    the caller can refund / fall back.
    """
    bans = bans or []
    if not prompt.strip():
        raise ValueError("empty prompt")

    tools = _build_tools(allowed_domains, clamp_fetches(max_fetches))
    system, user = _build_prompt(prompt, context, voice, bans)
    text = await _call(api_key, system, user, tools)
    # Down-format to X-ready plain text + Unicode styling, in case the prompt
    # asked for (or the model produced) HTML/CSS/JSX/markdown the platform can't
    # render. The model is also instructed to do this; this is the safety net.
    text = to_x_text(text)
    if not text:
        raise ValueError("no text returned")
    return text
