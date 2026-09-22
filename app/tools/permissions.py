"""Tool Permission Model - Sprint 5.

Least privilege, scoped credentials, authorization middleware simulation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Permission:
    tool: str
    allowed: bool
    reason: str
    requires_approval: bool = False
    scoped_credentials: str | None = None  # e.g., "read-only-token"


class PermissionModel:
    """Evaluates tool invocation against policy (allowlist, roles, approval)."""

    def __init__(self, allowlist: set[str], approval_required: set[str], user_role: str = "user"):
        self.allowlist = allowlist
        self.approval_required = approval_required
        self.user_role = user_role

    def authorize(self, tool: str, arguments: dict[str, Any], approval_token: str | None = None) -> Permission:
        # 1. Allowlist check
        if tool not in self.allowlist:
            if tool in self.approval_required:
                if approval_token != "HUMAN_APPROVED_123":
                    return Permission(tool, False, f"Tool '{tool}' requires human approval", requires_approval=True)
                # Approved - still check role
            else:
                return Permission(tool, False, f"Tool '{tool}' not in allowlist")

        # 2. Role check (admin panel example)
        if tool == "access_admin_panel" and self.user_role != "admin":
            return Permission(tool, False, "Admin role required")

        # 3. Argument validation delegated elsewhere, but basic scoping
        # For demo, scoped credentials: read_file only allowed with read-only token
        scoped = "scoped-token" if tool in {"search", "read_file"} else None

        return Permission(tool, True, "Authorized", requires_approval=False, scoped_credentials=scoped)

    def is_least_privilege(self) -> bool:
        # Secure if allowlist minimal (2 tools) vs vulnerable (8)
        return len(self.allowlist) <= 2
