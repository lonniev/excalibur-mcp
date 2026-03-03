"""Tests for ExcaliburOperator protocol conformance."""

from tollbooth.actor_types import ToolPathInfo
from tollbooth.operator_protocol import OperatorProtocol

from excalibur_mcp.actor import ExcaliburOperator


def test_isinstance_conformance():
    """ExcaliburOperator satisfies OperatorProtocol at runtime."""
    assert isinstance(ExcaliburOperator(), OperatorProtocol)


def test_dict_does_not_satisfy():
    """A plain dict must not satisfy OperatorProtocol."""
    assert not isinstance({}, OperatorProtocol)


def test_slug():
    """Slug is 'excalibur'."""
    assert ExcaliburOperator().slug == "excalibur"


def test_tool_catalog_completeness():
    """Catalog has exactly 15 entries matching Protocol method names."""
    catalog = ExcaliburOperator.tool_catalog()
    assert len(catalog) == 15

    for entry in catalog:
        assert isinstance(entry, ToolPathInfo)

    expected = {
        "check_balance",
        "account_statement",
        "account_statement_infographic",
        "restore_credits",
        "service_status",
        "purchase_credits",
        "check_payment",
        "certify_credits",
        "register_operator",
        "operator_status",
        "lookup_member",
        "how_to_join",
        "get_tax_rate",
        "about",
        "network_advisory",
    }
    actual = {e.tool_name for e in catalog}
    assert actual == expected


def test_tool_catalog_returns_copy():
    """tool_catalog() returns a fresh list each time."""
    a = ExcaliburOperator.tool_catalog()
    b = ExcaliburOperator.tool_catalog()
    assert a == b
    assert a is not b


async def test_delegation_stub_returns_error():
    """Delegation stubs return success=False with guidance message."""
    op = ExcaliburOperator()
    result = await op.certify_credits(operator_id="npub1test", amount_sats=100)
    assert result["success"] is False
    assert "Authority" in result["error"]


async def test_restore_credits_stub():
    """restore_credits returns not-implemented since server.py lacks it."""
    op = ExcaliburOperator()
    result = await op.restore_credits(npub="npub1test", invoice_id="inv123")
    assert result["success"] is False
    assert "not yet implemented" in result["error"]
