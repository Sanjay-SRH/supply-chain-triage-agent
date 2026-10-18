"""MCP server: exposes the same graph tools to ANY MCP client (Claude Desktop, Claude Code, IDEs, other agents).

Run:  python -m backend.mcp_server            (stdio transport)
Tenant: set TRIAGE_TENANT (default 'acme'). The tenant is fixed per server process, never chosen by the caller.
"""
from mcp.server.mcpserver import MCPServer

from backend import config
from backend.agent.tools import TOOL_SPECS, Toolbox


def build_server(tenant: str | None = None, toolbox: Toolbox | None = None) -> MCPServer:
    box = toolbox or Toolbox(tenant=tenant or config.DEFAULT_TENANT)
    server = MCPServer("supply-chain-triage")
    for spec in TOOL_SPECS:
        server.add_tool(getattr(box, spec["name"]), name=spec["name"], description=spec["description"])
    return server


if __name__ == "__main__":
    build_server().run()  # stdio
