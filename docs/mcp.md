# Connecting an MCP client

The server speaks MCP over stdio: `python -m backend.mcp_server`. Run it from the project root so
`backend` is importable, and make sure FalkorDB is running with the graph loaded.

Tenant is fixed per server process via `TRIAGE_TENANT` (default `acme`). Run a second entry with `globex` to compare.

## Claude Desktop

Edit the Claude Desktop config file (Settings > Developer > Edit Config) and add (use absolute paths):

```json
{
  "mcpServers": {
    "supply-chain-triage": {
      "command": "C:\\path\\to\\graph-triage\\.venv\\Scripts\\python.exe",
      "args": ["-m", "backend.mcp_server"],
      "cwd": "C:\\path\\to\\graph-triage",
      "env": { "TRIAGE_TENANT": "acme", "GRAPH_NAME": "triage" }
    }
  }
}
```
Mac/Linux: `"command": "/path/to/graph-triage/.venv/bin/python"`. Restart Claude Desktop, then ask:
"Which services are exposed to <CVE>? Show the dependency chain."

If the client ignores `cwd`, add `"PYTHONPATH": "/path/to/graph-triage"` to `env`, and set `DATA_DIR` only if you moved `data/`.

## Claude Code

```
claude mcp add supply-chain-triage -e TRIAGE_TENANT=acme -- /path/to/.venv/bin/python -m backend.mcp_server
```
Run it from the project folder. If the flags differ in your version, check `claude mcp add --help`.

## Check without any client

`python -m backend.mcp_smoke` launches the server and calls it as a client would.
