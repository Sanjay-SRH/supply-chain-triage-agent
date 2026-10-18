"""Starts the MCP server as a subprocess and talks to it like a real MCP client would.

Run: python -m backend.mcp_smoke
"""
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    params = StdioServerParameters(command=sys.executable, args=["-m", "backend.mcp_server"], env={**os.environ})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            tools = (await s.list_tools()).tools
            print(f"Server exposes {len(tools)} tools: {', '.join(t.name for t in tools)}")
            top = json.loads((await s.call_tool("most_exposed_cves", {"limit": 1})).content[0].text)["cves"][0]
            aff = json.loads((await s.call_tool("find_affected_services", {"cve": top["cve"]})).content[0].text)
            print(f"\nTop CVE {top['cve']} reaches {aff['total_services']} services. Example chain:")
            print("  " + " -> ".join(aff["services"][0]["chain"]))
            print("\nMCP server OK.")


if __name__ == "__main__":
    asyncio.run(main())
