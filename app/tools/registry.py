"""Tool Registry - Sprint 5 Agent Security.

Centralizes tool definitions, allowlists, and permission metadata.
Isolated from attack engine per spec 21.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: dict[str, str]  # param -> type
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    requires_approval: bool = False
    side_effect: str = "READ"  # READ, WRITE, DESTRUCTIVE, EXTERNAL
    allowed_roles: list[str] = field(default_factory=lambda: ["user"])


# Default tool universe - mirrors vulnerable-agent TOOLS but with metadata
DEFAULT_TOOLS: list[ToolDefinition] = [
    ToolDefinition(
        name="search",
        description="Search the web",
        parameters={"query": "string"},
        risk_level="LOW",
        side_effect="READ",
    ),
    ToolDefinition(
        name="read_file",
        description="Read files from filesystem",
        parameters={"path": "string"},
        risk_level="LOW",
        side_effect="READ",
    ),
    ToolDefinition(
        name="write_file",
        description="Write files to filesystem",
        parameters={"path": "string", "content": "string"},
        risk_level="HIGH",
        requires_approval=True,
        side_effect="WRITE",
    ),
    ToolDefinition(
        name="execute_sql",
        description="Execute SQL queries",
        parameters={"query": "string"},
        risk_level="HIGH",
        requires_approval=True,
        side_effect="WRITE",
    ),
    ToolDefinition(
        name="delete_database",
        description="Delete entire database",
        parameters={"confirm": "boolean"},
        risk_level="CRITICAL",
        requires_approval=True,
        side_effect="DESTRUCTIVE",
    ),
    ToolDefinition(
        name="send_email",
        description="Send emails",
        parameters={"to": "string", "subject": "string", "body": "string"},
        risk_level="MEDIUM",
        requires_approval=True,
        side_effect="EXTERNAL",
    ),
    ToolDefinition(
        name="run_shell",
        description="Run shell commands",
        parameters={"command": "string"},
        risk_level="CRITICAL",
        requires_approval=True,
        side_effect="DESTRUCTIVE",
    ),
    ToolDefinition(
        name="access_admin_panel",
        description="Access admin panel",
        parameters={},
        risk_level="CRITICAL",
        requires_approval=True,
        side_effect="WRITE",
        allowed_roles=["admin"],
    ),
]


class ToolRegistry:
    """Registry with allowlist enforcement."""

    def __init__(
        self, tools: list[ToolDefinition] | None = None, allowlist: list[str] | None = None
    ):
        self._tools: dict[str, ToolDefinition] = {t.name: t for t in (tools or DEFAULT_TOOLS)}
        self.allowlist: set[str] = (
            set(allowlist) if allowlist is not None else {t.name for t in DEFAULT_TOOLS}
        )

    def all(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def allowed(self) -> list[ToolDefinition]:
        return [t for name, t in self._tools.items() if name in self.allowlist]

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def is_allowed(self, name: str) -> bool:
        return name in self.allowlist

    def requires_approval(self, name: str) -> bool:
        tool = self.get(name)
        return tool.requires_approval if tool else False

    def risk_of(self, name: str) -> str:
        tool = self.get(name)
        return tool.risk_level if tool else "UNKNOWN"

    def register(self, tool: ToolDefinition) -> None:
        if tool.name in self._tools:
            raise ValueError(f"Tool {tool.name} already registered")
        self._tools[tool.name] = tool
        # Not auto-allowlisted

    def set_allowlist(self, allowlist: list[str]) -> None:
        self.allowlist = set(allowlist)


# Secure defaults: only search and read_file
SECURE_REGISTRY = ToolRegistry(allowlist=["search", "read_file"])
VULNERABLE_REGISTRY = ToolRegistry(allowlist=[t.name for t in DEFAULT_TOOLS])
