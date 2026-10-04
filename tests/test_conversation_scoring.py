"""Pure scoring, query composition and weight validation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from excalibur_mcp import conversation_scoring as sc

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


def _tweet(text="hello", *, replies=0, created=NOW, reply_to=None, tid="10", cid="10"):
    return {
        "id": tid, "conversation_id": cid, "text": text,
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "public_metrics": {"reply_count": replies, "like_count": 0},
        **({"in_reply_to_user_id": reply_to} if reply_to else {}),
    }


def _author(followers=1000):
    return {"id": "u1", "username": "someone", "public_metrics": {"followers_count": followers}}


# -- signals in isolation ---------------------------------------------------

def test_need_phrase_alone():
    score, why = sc.score_tweet(_tweet("anyone know how this works"), _author(0), now=NOW)
    assert score == 40 and why == ["need"]


def test_thread_alone():
    score, why = sc.score_tweet(_tweet("plain", replies=3), _author(0), now=NOW)
    assert score == 20 and why == ["thread"]


def test_band_alone_and_edges():
    assert sc.score_tweet(_tweet("plain"), _author(200), now=NOW) == (15, ["reachable"])
    assert sc.score_tweet(_tweet("plain"), _author(20000), now=NOW) == (15, ["reachable"])
    assert sc.score_tweet(_tweet("plain"), _author(199), now=NOW) == (0, [])
    assert sc.score_tweet(_tweet("plain"), _author(20001), now=NOW) == (0, [])


@pytest.mark.parametrize("text", [
    "buy $PUMP now", "join the airdrop", "giveaway inside", "\U0001d401\U0001d402\U0001d403 styled",
])
def test_spam_markers_penalise(text):
    score, why = sc.score_tweet(_tweet(text), _author(0), now=NOW)
    assert score == 0 and why == ["spam"]


def test_reply_penalty_via_in_reply_to_or_conversation_mismatch():
    assert sc.score_tweet(_tweet("x", reply_to="9"), _author(0), now=NOW)[1] == ["reply"]
    assert sc.score_tweet(_tweet("x", tid="11", cid="10"), _author(0), now=NOW)[1] == ["reply"]


def test_penalties_do_not_fade_and_positives_do():
    old = NOW - timedelta(hours=36)
    score, why = sc.score_tweet(_tweet("how do I fix this", created=old), _author(1000), now=NOW)
    # need 40 + band 15 = 55, halved by decay → 27.5 → 28
    assert score == 28 and "aged" in why
    score, _ = sc.score_tweet(_tweet("buy $X", created=old), _author(0), now=NOW)
    assert score == 0


def test_decay_reaches_zero_at_decay_hours():
    old = NOW - timedelta(hours=72)
    score, _ = sc.score_tweet(_tweet("how do I", created=old), _author(1000), now=NOW)
    assert score == 0


def test_clamped_to_0_100_and_overrides_apply():
    score, _ = sc.score_tweet(
        _tweet("how do I", replies=5), _author(1000), weights={"need": 100}, now=NOW,
    )
    assert score == 100
    score, _ = sc.score_tweet(
        _tweet("plain", replies=1), _author(0), weights={"replies_min": 1}, now=NOW,
    )
    assert score == 20


def test_unparseable_date_means_no_decay():
    t = _tweet("how do I")
    t["created_at"] = "not a date"
    assert sc.score_tweet(t, _author(0), now=NOW) == (40, ["need"])


# -- weights ----------------------------------------------------------------

def test_validate_weights_returns_overrides_only():
    assert sc.validate_weights({"need": 10}) == {"need": 10}
    assert sc.validate_weights(None) == {}


@pytest.mark.parametrize("bad", [
    {"unknown": 1}, {"need": 1.5}, {"need": True}, {"need": 101}, {"decay_hours": 0},
    {"followers_min": 500, "followers_max": 100}, "need=1", [1],
])
def test_validate_weights_rejects(bad):
    with pytest.raises(ValueError):
        sc.validate_weights(bad)


def test_effective_weights_layers_in_order():
    merged = sc.effective_weights({"need": 1}, {"need": 2})
    assert merged["need"] == 2 and merged["band"] == sc.DEFAULT_WEIGHTS["band"]


# -- compose ----------------------------------------------------------------

def test_compose_query_wraps_defaults_and_excludes_self():
    assert sc.compose_query("mcp server", "123") == (
        "(mcp server) -is:retweet -has:links -has:cashtags lang:en -from:123"
    )


def test_compose_query_without_defaults_or_own_id():
    assert sc.compose_query(" mcp ", "", safe_defaults=False) == "(mcp)"


def test_compose_query_length_guard():
    with pytest.raises(ValueError):
        sc.compose_query("x" * 600, "1")


def test_is_bold_unicode_needs_a_run():
    assert not sc.is_bold_unicode("one \U0001d401 glyph")
    assert sc.is_bold_unicode("\U0001d401\U0001d402\U0001d403")
