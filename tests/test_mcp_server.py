import asyncio

from backend.agent.tools import TOOL_NAMES
from backend.mcp_server import build_server


def test_all_tools_are_exposed_over_mcp(box):
    server = build_server(toolbox=box)
    tools = asyncio.run(server.list_tools())
    assert {t.name for t in tools} == TOOL_NAMES
    by = {t.name: t for t in tools}
    assert by["save_decision"].input_schema["properties"]["action"]
    assert by["find_affected_services"].description


def test_mcp_call_returns_graph_answer(box):
    server = build_server(toolbox=box)
    result = asyncio.run(server.call_tool("get_owner", {"service": "web"}))
    assert "Platform" in str(result)
