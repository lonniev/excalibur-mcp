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


def test_hot_path_count():
    """5 hot-path tools (check_balance, account_statement, infographic, restore_credits, service_status)."""
    from tollbooth.actor_types import ToolPath

    catalog = ExcaliburOperator.tool_catalog()
    hot = [e for e in catalog if e.path == ToolPath.HOT]
    assert len(hot) == 5
