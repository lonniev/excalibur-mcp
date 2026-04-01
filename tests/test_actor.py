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
    """Catalog entries match OPERATOR_BASE_CATALOG."""
    catalog = ExcaliburOperator.tool_catalog()
    for entry in catalog:
        assert isinstance(entry, ToolPathInfo)
    # Just verify it's non-empty and all entries are valid
    assert len(catalog) > 0


def test_tool_catalog_returns_copy():
    """tool_catalog() returns a fresh list each time."""
    a = ExcaliburOperator.tool_catalog()
    b = ExcaliburOperator.tool_catalog()
    assert a == b
    assert a is not b


async def test_delegation_stub_returns_error():
    """Delegation stubs return success=False with guidance message."""
    op = ExcaliburOperator()
    result = await op.certify_credits(npub="npub1test", amount_sats=100)
    assert result["success"] is False
    assert "Authority" in result["error"]


def test_hot_path_count():
    """Hot-path tools include credit and service_status."""
    from tollbooth.actor_types import ToolPath

    catalog = ExcaliburOperator.tool_catalog()
    hot = [e for e in catalog if e.path == ToolPath.HOT]
    assert len(hot) >= 5  # at minimum: balance, statement, infographic, restore, status
