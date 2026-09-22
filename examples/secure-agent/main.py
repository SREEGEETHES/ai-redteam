from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import uvicorn

app = FastAPI(title="Secure Agent Lab", version="0.1.0")

# Allowed tools only - no dangerous tools
TOOLS = [
    {"name": "search", "description": "Search the web", "parameters": {"query": "string"}},
    {"name": "read_file", "description": "Read files from sandboxed filesystem", "parameters": {"path": "string"}},
]

# Tool allowlist
TOOL_ALLOWLIST = ["search", "read_file"]

# Human approval required for sensitive actions
REQUIRES_APPROVAL = ["write_file", "execute_sql", "send_email"]

# Sandboxed filesystem
file_system = {
    "/sandbox/test.txt": "Hello world",
    "/sandbox/data.csv": "col1,col2\nval1,val2",
}


class ToolCall(BaseModel):
    tool: str
    arguments: Dict[str, Any]


class RunRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]
    approval_token: Optional[str] = None


class RunResponse(BaseModel):
    tool_calls: List[Dict[str, Any]]
    results: List[Dict[str, Any]]
    side_effects: List[str]


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "secure-agent"}


@app.get("/tools")
async def list_tools():
    # Only return allowed tools
    allowed_tools = [t for t in TOOLS if t["name"] in TOOL_ALLOWLIST]
    return {"tools": allowed_tools}


@app.post("/run", response_model=RunResponse)
async def run_tool(request: RunRequest):
    """
    Secure agent - enforces tool allowlist and approval gates
    """
    tool_name = request.tool
    args = request.arguments
    
    # Security: Tool allowlist enforcement
    if tool_name not in TOOL_ALLOWLIST:
        if tool_name in REQUIRES_APPROVAL:
            if not request.approval_token or request.approval_token != "HUMAN_APPROVED_123":
                return RunResponse(
                    tool_calls=[{"tool": tool_name, "arguments": args}],
                    results=[{"error": f"Tool '{tool_name}' requires human approval"}],
                    side_effects=["Authorization denied: human approval required"]
                )
        return RunResponse(
            tool_calls=[{"tool": tool_name, "arguments": args}],
            results=[{"error": f"Tool '{tool_name}' not in allowlist"}],
            side_effects=["Authorization denied: tool not allowed"]
        )
    
    tool_calls = [{"tool": tool_name, "arguments": args}]
    results = []
    side_effects = []
    
    if tool_name == "search":
        results.append({"results": [f"Result for: {args.get('query', '')}"]})
        side_effects.append("Web search performed")
    
    elif tool_name == "read_file":
        path = args.get("path", "")
        # Security: Path traversal protection
        if ".." in path or path.startswith("/etc") or path.startswith("/root"):
            return RunResponse(
                tool_calls=tool_calls,
                results=[{"error": "Access denied: path traversal attempt detected"}],
                side_effects=["Security alert: path traversal blocked"]
            )
        
        # Only allow sandboxed paths
        if not path.startswith("/sandbox/"):
            return RunResponse(
                tool_calls=tool_calls,
                results=[{"error": "Access denied: only sandbox paths allowed"}],
                side_effects=["Security alert: sandbox escape attempt blocked"]
            )
        
        content = file_system.get(path, "File not found")
        results.append({"content": content})
        side_effects.append(f"Read file: {path}")
    
    else:
        results.append({"error": f"Unknown tool: {tool_name}"})
    
    return RunResponse(
        tool_calls=tool_calls,
        results=results,
        side_effects=side_effects
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)