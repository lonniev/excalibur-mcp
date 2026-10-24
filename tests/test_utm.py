"""Shop-link campaign tags — what a sent post's links carry.

The tagger rewrites only links to the owner's shop hosts, keeps their existing
query and fragment, and leaves alone any link the author already tagged.
"""

from urllib.parse import parse_qs, urlsplit

import pytest

from excalibur_mcp.utm import owner_hosts, tag_links

HOSTS = ["cafe.tollbooth-dpyc.com"]


def _tag(text, source="x"):
    return tag_links(text, hosts=HOSTS, source=source, campaign="tmpl", content="occ")


def _q(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def test_a_shop_link_carries_all_four_tags():
    out = _tag("New roast: https://cafe.tollbooth-dpyc.com/products/mug")
    url = out.split(": ", 1)[1]
    assert url.startswith("https://cafe.tollbooth-dpyc.com/products/mug?")
    assert _q(url) == {"utm_source": "x", "utm_medium": "social",
                       "utm_campaign": "tmpl", "utm_content": "occ"}


def test_an_existing_query_and_fragment_are_kept():
    out = _tag("https://cafe.tollbooth-dpyc.com/products/mug?variant=42#reviews")
    parts = urlsplit(out)
    assert parts.fragment == "reviews"
    q = _q(out)
    assert q["variant"] == "42" and q["utm_content"] == "occ"


def test_a_link_already_tagged_is_left_alone():
    url = "https://cafe.tollbooth-dpyc.com/x?UTM_source=newsletter"
    assert _tag(url) == url


def test_other_hosts_are_left_alone():
    text = "See https://example.com/a and https://shop.cafe.tollbooth-dpyc.com.evil.io/b"
    assert _tag(text) == text


def test_the_host_match_ignores_case_and_a_port():
    out = _tag("https://Cafe.Tollbooth-DPYC.com:443/p")
    assert "utm_campaign=tmpl" in out


def test_trailing_punctuation_stays_outside_the_link():
    out = _tag("Grab one (https://cafe.tollbooth-dpyc.com/p). Or https://cafe.tollbooth-dpyc.com/q!")
    assert "/p?utm_source=x&utm_medium=social&utm_campaign=tmpl&utm_content=occ)." in out
    assert out.endswith("utm_content=occ!")


def test_every_link_and_nothing_else_changes():
    text = ("Line one https://cafe.tollbooth-dpyc.com/a\n"
            "**bold** text\nhttps://cafe.tollbooth-dpyc.com/b")
    out = _tag(text)
    assert out.count("utm_content=occ") == 2
    assert "**bold** text" in out
    # The link order is unchanged, so X's preview card is the same link.
    assert out.index("/a?") < out.index("/b?")


def test_nostr_source():
    assert "utm_source=nostr" in _tag("https://cafe.tollbooth-dpyc.com/p", source="nostr")


def test_no_hosts_means_no_change():
    text = "https://cafe.tollbooth-dpyc.com/p"
    assert tag_links(text, hosts=[], source="x", campaign="c", content="c") == text


@pytest.mark.parametrize("saved,expected", [
    (None, HOSTS),                                         # never chosen → defaults
    ({"on": False, "hosts": ["a.com"]}, []),               # turned off
    ({"on": True, "hosts": []}, HOSTS),                    # on, no hosts → defaults
    ({"on": True, "hosts": ["shop.example.com"]}, ["shop.example.com"]),
    ("garbage", HOSTS),
])
def test_owner_hosts(saved, expected):
    assert owner_hosts(saved, HOSTS) == expected
