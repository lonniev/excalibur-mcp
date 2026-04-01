"""Concrete OperatorProtocol implementation for eXcalibur MCP.

Thin delegation layer over existing server.py tool functions.
Hot-path methods delegate to server.py; cold-path methods that
reach the Authority or Oracle return delegation stubs.

purchase_credits and check_payment are also delegation stubs —
the long-term design delegates all Lightning payment processing
to the Tollbooth Authority.
"""

from __future__ import annotations

from typing import Any

from tollbooth.actor_types import ActorRole, ToolPath, ToolPathInfo

_DELEGATION_MSG = (
    "Cold-path delegation not yet implemented. "
    "Connect to the {actor} MCP directly."
)

_CATALOG: list[ToolPathInfo] = [
    # ── Hot-path (local ledger) ──────────────────────────────────
    ToolPathInfo(
        tool_name="check_balance",
        path=ToolPath.HOT,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Return the patron's credit balance.",
    ),
    ToolPathInfo(
        tool_name="account_statement",
        path=ToolPath.HOT,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Return the patron's transaction history.",
    ),
    ToolPathInfo(
        tool_name="account_statement_infographic",
        path=ToolPath.HOT,
        requires_auth=True,
        cost_tier="READ",
        agent_hint="Return a visual summary of the patron's account.",
    ),
    ToolPathInfo(
        tool_name="restore_credits",
        path=ToolPath.HOT,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Restore credits from a previously paid invoice.",
    ),
    ToolPathInfo(
        tool_name="service_status",
        path=ToolPath.HOT,
        requires_auth=False,
        cost_tier="FREE",
        agent_hint="Return the Operator's health and version info.",
    ),
    ToolPathInfo(
        tool_name="get_operator_onboarding_status",
        path=ToolPath.HOT,
        requires_auth=False,
        cost_tier="FREE",
        agent_hint="Report the operator's configuration readiness.",
    ),
    ToolPathInfo(
        tool_name="get_patron_onboarding_status",
        path=ToolPath.HOT,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Report a patron's credential readiness. Use get_operator_onboarding_status instead.",
    ),
    # ── Delegation (BTCPay via Authority) ────────────────────────
    ToolPathInfo(
        tool_name="purchase_credits",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.AUTHORITY,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Create a Lightning invoice for patron credit purchase.",
    ),
    ToolPathInfo(
        tool_name="check_payment",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.AUTHORITY,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Poll a Lightning invoice for settlement status.",
    ),
    # ── Delegation (Authority) ───────────────────────────────────
    ToolPathInfo(
        tool_name="certify_credits",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.AUTHORITY,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Certify a credit purchase via the Authority.",
    ),
    ToolPathInfo(
        tool_name="register_operator",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.AUTHORITY,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Register as an operator via the Authority.",
    ),
    ToolPathInfo(
        tool_name="operator_status",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.AUTHORITY,
        requires_auth=True,
        cost_tier="FREE",
        agent_hint="Get operator registration info from the Authority.",
    ),
    # ── Delegation (Oracle via Authority) ────────────────────────
    ToolPathInfo(
        tool_name="lookup_member",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.ORACLE,
        requires_auth=False,
        cost_tier="FREE",
        agent_hint="Look up a DPYC member via the Oracle.",
    ),
    ToolPathInfo(
        tool_name="how_to_join",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.ORACLE,
        requires_auth=False,
        cost_tier="FREE",
        agent_hint="Get onboarding instructions from the Oracle.",
    ),
    ToolPathInfo(
        tool_name="get_tax_rate",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.ORACLE,
        requires_auth=False,
        cost_tier="FREE",
        agent_hint="Get the current tax rate from the Oracle.",
    ),
    ToolPathInfo(
        tool_name="about",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.ORACLE,
        requires_auth=False,
        cost_tier="FREE",
        agent_hint="Describe the DPYC ecosystem via the Oracle.",
    ),
    ToolPathInfo(
        tool_name="network_advisory",
        path=ToolPath.DELEGATION,
        delegates_to=ActorRole.ORACLE,
        requires_auth=False,
        cost_tier="FREE",
        agent_hint="Get active network advisories from the Oracle.",
    ),
]


class ExcaliburOperator:
    """Concrete OperatorProtocol implementation for eXcalibur MCP.

    Hot-path methods delegate to server.py tool functions.
    Cold-path and delegation methods return stubs.
    """

    @property
    def slug(self) -> str:
        return "excalibur"

    @classmethod
    def tool_catalog(cls) -> list[ToolPathInfo]:
        return list(_CATALOG)

    # ── Hot-path (local ledger) ──────────────────────────────────

    async def check_balance(self, npub: str) -> dict[str, Any]:
        from excalibur_mcp.server import check_balance

        return await check_balance()

    async def account_statement(self, npub: str) -> dict[str, Any]:
        from excalibur_mcp.server import account_statement

        return await account_statement()

    async def account_statement_infographic(
        self, npub: str
    ) -> dict[str, Any]:
        from excalibur_mcp.server import account_statement_infographic

        return await account_statement_infographic()

    async def restore_credits(
        self, npub: str, invoice_id: str
    ) -> dict[str, Any]:
        from excalibur_mcp.server import restore_credits

        return await restore_credits(invoice_id=invoice_id)

    async def service_status(self) -> dict[str, Any]:
        from excalibur_mcp.server import service_status

        return await service_status()

    async def get_operator_onboarding_status(self) -> dict[str, Any]:
        from excalibur_mcp.server import get_operator_onboarding_status

        return await get_operator_onboarding_status()

    async def get_patron_onboarding_status(self, patron_npub: str) -> dict[str, Any]:
        from excalibur_mcp.server import get_patron_onboarding_status

        return await get_patron_onboarding_status(patron_npub=patron_npub)

    # ── Secure Courier (hot-path) ─────────────────────────────────

    async def session_status(self) -> dict[str, Any]:
        from excalibur_mcp.server import session_status

        return await session_status()

    async def request_credential_channel(
        self, service: str, greeting: str, recipient_npub: str | None,
    ) -> dict[str, Any]:
        from excalibur_mcp.server import request_credential_channel

        return await request_credential_channel(service, recipient_npub)

    async def receive_credentials(
        self, sender_npub: str, service: str, credential_card: str,
    ) -> dict[str, Any]:
        from excalibur_mcp.server import receive_credentials

        return await receive_credentials(sender_npub, service)

    async def forget_credentials(
        self, sender_npub: str, service: str,
    ) -> dict[str, Any]:
        from excalibur_mcp.server import forget_credentials

        return await forget_credentials(sender_npub, service)

    # ── Delegation stubs (BTCPay via Authority) ──────────────────
    # DELEGATION_STUB

    async def purchase_credits(
        self, npub: str, amount_sats: int, certificate: str
    ) -> dict[str, Any]:
        """Delegate to server.py — auto-certifies via Authority."""
        from excalibur_mcp.server import purchase_credits

        return await purchase_credits(amount_sats=amount_sats)

    async def check_payment(
        self, npub: str, invoice_id: str
    ) -> dict[str, Any]:
        """Delegate to server.py — polls BTCPay invoice status."""
        from excalibur_mcp.server import check_payment

        return await check_payment(invoice_id=invoice_id)

    # ── Delegation stubs (Authority) ─────────────────────────────
    # DELEGATION_STUB

    async def certify_credits(
        self, operator_id: str, amount_sats: int
    ) -> dict[str, Any]:
        """(delegation, delegates to Authority) Not yet implemented."""
        return {  # DELEGATION_STUB
            "success": False,
            "error": _DELEGATION_MSG.format(actor="Authority"),
        }

    async def register_operator(self, npub: str) -> dict[str, Any]:
        """(delegation, delegates to Authority) Not yet implemented."""
        return {  # DELEGATION_STUB
            "success": False,
            "error": _DELEGATION_MSG.format(actor="Authority"),
        }

    async def operator_status(self) -> dict[str, Any]:
        """(delegation, delegates to Authority) Not yet implemented."""
        return {  # DELEGATION_STUB
            "success": False,
            "error": _DELEGATION_MSG.format(actor="Authority"),
        }

    # ── Delegation stubs (Oracle via Authority) ──────────────────
    # DELEGATION_STUB

    async def lookup_member(self, npub: str) -> dict[str, Any] | str:
        """(delegation, delegates to Oracle) Not yet implemented."""
        return {  # DELEGATION_STUB
            "success": False,
            "error": _DELEGATION_MSG.format(actor="Oracle"),
        }

    async def how_to_join(self) -> str:
        """(delegation, delegates to Oracle) Not yet implemented."""
        return _DELEGATION_MSG.format(actor="Oracle")  # DELEGATION_STUB

    async def get_tax_rate(self) -> dict[str, Any]:
        """(delegation, delegates to Oracle) Not yet implemented."""
        return {  # DELEGATION_STUB
            "success": False,
            "error": _DELEGATION_MSG.format(actor="Oracle"),
        }

    async def about(self) -> str:
        """(delegation, delegates to Oracle) Not yet implemented."""
        return _DELEGATION_MSG.format(actor="Oracle")  # DELEGATION_STUB

    async def network_advisory(self) -> str:
        """(delegation, delegates to Oracle) Not yet implemented."""
        return _DELEGATION_MSG.format(actor="Oracle")  # DELEGATION_STUB
