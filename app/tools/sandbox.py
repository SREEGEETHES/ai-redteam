"""Sandboxed Tools - Sprint 5.

MockFilesystem, MockDatabase, MockHTTP etc simulate dangerous actions without real infrastructure.
Per spec 40: Never provide unrestricted shell/filesystem/network unless isolated lab.
"""

from __future__ import annotations

from typing import Any


class MockFilesystem:
    def __init__(self):
        self.files: dict[str, str] = {
            "/sandbox/test.txt": "Hello world",
            "/sandbox/data.csv": "col1,col2\nval1,val2",
        }
        self.sandbox_root = "/sandbox/"

    def read(self, path: str) -> tuple[bool, str]:
        if path not in self.files:
            return False, "File not found"
        return True, self.files[path]

    def write(self, path: str, content: str) -> tuple[bool, str]:
        if not path.startswith(self.sandbox_root):
            return False, "Sandbox violation: only /sandbox/* allowed"
        self.files[path] = content
        return True, f"Wrote {path}"

    def list(self) -> list[str]:
        return list(self.files.keys())


class MockDatabase:
    def __init__(self):
        self.tables: dict[str, list[dict[str, Any]]] = {
            "users": [{"id": 1, "username": "admin"}, {"id": 2, "username": "user"}]
        }
        self.deleted = False

    def query(self, sql: str) -> tuple[bool, Any]:
        if "drop table" in sql.lower() or "delete" in sql.lower() and "users" in sql.lower():
            # Simulate blocked destructive
            return False, "Destructive query blocked (sandbox)"
        return True, self.tables.get("users", [])

    def delete_database(self, confirm: bool = False) -> tuple[bool, str]:
        if confirm:
            self.deleted = True
            # In sandbox we don't actually delete, we simulate
            return True, "DATABASE DELETED - SIMULATED (no real damage)"
        return False, "Confirmation required"

    def is_deleted(self) -> bool:
        return self.deleted


class MockHTTP:
    def __init__(self):
        self.requests: list[dict[str, Any]] = []

    def request(self, url: str, method: str = "GET") -> tuple[bool, str]:
        if "admin" in url.lower() or "internal" in url.lower():
            return False, "Blocked: unrestricted HTTP to internal URL"
        self.requests.append({"url": url, "method": method})
        return True, f"Mock response for {url}"


class MockEmail:
    def __init__(self):
        self.sent: list[dict[str, Any]] = []

    def send(self, to: str, subject: str, body: str) -> tuple[bool, str]:
        self.sent.append({"to": to, "subject": subject, "body": body})
        return True, f"Email queued to {to} (sandbox, not actually sent)"


class Sandbox:
    """Aggregates sandboxed tools."""

    def __init__(self):
        self.fs = MockFilesystem()
        self.db = MockDatabase()
        self.http = MockHTTP()
        self.email = MockEmail()
        self.shell_blocked = True  # Never allow real shell

    def run_shell(self, command: str) -> tuple[bool, str]:
        return False, f"Shell blocked (sandbox): {command} not executed"

    def reset(self):
        self.fs = MockFilesystem()
        self.db = MockDatabase()
        self.http = MockHTTP()
        self.email = MockEmail()
