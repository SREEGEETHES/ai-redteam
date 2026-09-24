"""Argument Validation - Sprint 5.

Validates tool arguments for injection, path traversal, etc.
"""

from __future__ import annotations

import re


def validate_path(path: str) -> tuple[bool, str]:
    """Returns (valid, reason). Secure: only /sandbox/* and no .."""
    if ".." in path:
        return False, "Path traversal detected (..)"
    if path.startswith(("/etc", "/root", "/proc")):
        return False, "Sensitive path denied"
    if not path.startswith("/sandbox/"):
        return False, "Only /sandbox/* allowed (sandbox violation)"
    return True, "OK"


def validate_sql(query: str) -> tuple[bool, str]:
    """Basic SQL injection check - downstream should use parameterized, but validator flags raw OR 1=1 etc."""
    lowered = query.lower()
    # Flag classic injection patterns as needing parameterized handling
    patterns = [r"or\s+'1'\s*=\s*'1", r";\s*--", r"union\s+select", r"drop\s+table"]
    for pat in patterns:
        if re.search(pat, lowered):
            return False, f"SQL injection pattern {pat} - requires parameterized query"
    return True, "OK"


def validate_command(command: str) -> tuple[bool, str]:
    """Blocks destructive shell patterns."""
    dangerous = ["rm -rf", "; rm", "&& rm", "| rm", "mkfs", "dd if=", "shutdown"]
    lowered = command.lower()
    for d in dangerous:
        if d in lowered:
            return False, f"Destructive command pattern {d} blocked"
    return True, "OK"


def validate_tool_arguments(tool: str, arguments: dict) -> tuple[bool, str]:
    if tool == "read_file":
        return validate_path(arguments.get("path", ""))
    if tool == "write_file":
        valid, reason = validate_path(arguments.get("path", ""))
        if not valid:
            return valid, reason
        # Also check content for script injection?
        content = arguments.get("content", "")
        if "<script" in content.lower():
            return False, "XSS in write content blocked"
        return True, "OK"
    if tool == "execute_sql":
        return validate_sql(arguments.get("query", ""))
    if tool == "run_shell":
        return validate_command(arguments.get("command", ""))
    if tool == "send_email":
        to = arguments.get("to", "")
        if "@" not in to or "." not in to:
            return False, "Invalid email"
        return True, "OK"
    return True, "OK"
