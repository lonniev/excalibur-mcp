"""Tests for the ephemeral-scribe Nostr note builder (issue #276).

``post_nostr_message`` publishes a public kind-1 note authored by a proven
patron npub. Because a Nostr event must be signed by the key it claims to come
from — and eXcalibur never holds a patron nsec — it mints a FRESH ephemeral
"scribe" keypair per call, signs with it, and ``p``-tags the proven author so
the note lands in that author's own mentions (the repudiation channel).
"""

from pynostr.event import Event
from pynostr.key import PrivateKey

from excalibur_mcp.nostr_note import build_note_event, publish_note


def _author():
    key = PrivateKey()
    return key, key.public_key.bech32()


def test_build_note_signs_with_ephemeral_scribe_not_author():
    author, author_npub = _author()
    signed, scribe_pub_hex, scribe_nsec = build_note_event("gm, stack sats", author_npub)

    # Signed by the ephemeral scribe — NOT the author's key.
    assert signed["pubkey"] == scribe_pub_hex
    assert signed["pubkey"] != author.public_key.hex()
    # A real, verifiable kind-1 note.
    assert signed["kind"] == 1
    assert Event.from_dict(signed).verify()
    # The scribe secret is returned (held in process only), never the patron's.
    assert scribe_nsec and scribe_nsec != author.hex()


def test_build_note_ptags_the_author():
    author, author_npub = _author()
    signed, _, _ = build_note_event("hello", author_npub)
    p_tags = [t[1] for t in signed["tags"] if t and t[0] == "p"]
    assert author.public_key.hex() in p_tags


def test_build_note_names_author_in_content_for_followup():
    author, author_npub = _author()
    signed, _, _ = build_note_event("my message", author_npub)
    assert "my message" in signed["content"]
    # The author npub is in the content so a reader can follow up out-of-band.
    assert author_npub in signed["content"]


def test_each_call_mints_a_fresh_scribe_key():
    _, author_npub = _author()
    _, pub_a, nsec_a = build_note_event("a", author_npub)
    _, pub_b, nsec_b = build_note_event("b", author_npub)
    assert pub_a != pub_b
    assert nsec_a != nsec_b


def test_publish_note_succeeds_if_any_relay_accepts(monkeypatch):
    from excalibur_mcp import nostr_note

    def fake_publish_one(url, message):
        return (url.endswith("good"), None if url.endswith("good") else "rejected")

    monkeypatch.setattr(nostr_note, "_publish_one", fake_publish_one)
    _, author_npub = _author()
    result = publish_note("hi", author_npub, relays=["wss://a.good", "wss://b.bad"])

    assert result["success"] is True
    assert result["accepted"] == 1
    assert result["attempted"] == 2
    # Per-relay detail is always present — a one-relay publish never reads clean.
    assert any(r["accepted"] for r in result["relays"])
    assert any(not r["accepted"] for r in result["relays"])
    assert result["author_npub"] == author_npub


def test_publish_note_fails_when_all_relays_reject(monkeypatch):
    from excalibur_mcp import nostr_note

    monkeypatch.setattr(nostr_note, "_publish_one", lambda url, msg: (False, "nope"))
    _, author_npub = _author()
    result = publish_note("hi", author_npub, relays=["wss://a", "wss://b"])

    assert result["success"] is False
    assert result["accepted"] == 0
    assert result["attempted"] == 2


def test_scribe_key_retained_in_process_for_warm_retraction(monkeypatch):
    from excalibur_mcp import nostr_note

    monkeypatch.setattr(nostr_note, "_publish_one", lambda url, msg: (True, None))
    _, author_npub = _author()
    result = publish_note("hi", author_npub, relays=["wss://a"])
    # The ephemeral key stays in warm memory so a best-effort NIP-09 retraction
    # can be signed by the same scribe — never vaulted, gone on cold start.
    assert result["event_id"] in nostr_note._SCRIBE_KEYS
