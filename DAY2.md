# Day 2 guide: tools, agent loop, MCP server

Goal for today: you type a question in the terminal, the agent picks graph tools on its own, shows the
dependency chain behind its answer, and the same tools work from any MCP client.

## 0. Setup (about 5 minutes)

1. Make sure Day 1 still passes: `python -m backend.verify`
2. Install the new packages: `pip install -r requirements.txt`
   (adds `anthropic` and `mcp>=2.0`; the MCP SDK renamed `FastMCP` to `MCPServer` in 2.x, and this project uses the 2.x name)
3. Put your key in `.env`:
   ```
   ANTHROPIC_API_KEY=sk-ant-...
   ANTHROPIC_MODEL=claude-sonnet-5-5
   ```
   The key comes from console.anthropic.com. A Claude chat subscription does not include API credits.
   If the model name is rejected, set `ANTHROPIC_MODEL` to any current Claude model with tool use.
4. Run the tests: `python -m pytest tests -q`. You want all green (they use a throwaway graph called `triage_test`, never your real `triage` graph).

## 1. What was built

| File | Job |
|------|-----|
| `backend/agent/tools.py` | **Toolbox**: 11 tools, each wrapping one graph query. Single source of truth for the agent AND the MCP server |
| `backend/agent/prompts.py` | The agent's instructions (how to triage, rules) |
| `backend/agent/loop.py` | The loop: Claude chooses a tool, we run it, feed the result back, repeat until it answers |
| `backend/agent/cli.py` | Terminal chat that prints every tool call and which Cypher ran |
| `backend/mcp_server.py` | Exposes the same 11 tools over MCP |
| `backend/demo_picks.py` | Finds CVEs that are good for demos (high exposure, with memory precedent) |
| `backend/mcp_smoke.py` | Starts the MCP server and talks to it like a real client |

### The 11 tools

| Tool | Graph question it answers |
|------|---------------------------|
| `most_exposed_cves` | Which CVEs reach the most services? |
| `find_cves_for_package` | Which CVEs affect `lodash`? |
| `get_cve` | Facts about one CVE |
| `find_affected_services` | Which services are exposed, and through which chain? (multi-hop) |
| `explain_path` | The exact chain for one service (the "Why?") |
| `blast_radius` | Which non-exposed services call an exposed one? |
| `rank_services` | Risk order: `cvss x tier x exposure / (1 + hops) x (1 + PageRank)` |
| `get_owner` | Which team, who is on call |
| `recall_decisions` | Memory read: earlier decisions on this CVE or the same package, this tenant only |
| `save_decision` | Memory write (only when the user states a decision) |
| `draft_ticket` | Drafts a ticket with chain, owner and precedent (nothing is sent anywhere) |

### Design decisions you should be able to defend

- **Tenant is not an LLM argument.** It is fixed when the Toolbox is created, so the model cannot read another tenant's memory even if prompted to.
- **Tools never raise.** Errors come back as `{"error": ...}` so the model can recover and explain instead of crashing.
- **Descriptions come from docstrings**, so tool descriptions and code cannot drift apart. A test checks every schema matches its method signature.
- **The answer comes from tool results, not model memory.** The prompt forbids guessing, and tools return the path that justifies each claim.
- **Every Cypher query is recorded** per tool call (`queries_used`), which Day 3's "Why?" button will display.

## 2. Try it

First find good demo CVEs:
```
python -m backend.demo_picks
```
Then chat (replace the CVE with one from the list):
```
python -m backend.agent.cli "Triage CVE-XXXX-YYYY for me"
python -m backend.agent.cli                       # interactive
```
Things to try, in order:

1. `What are the most exposed vulnerabilities right now?`
2. `Triage <CVE>: who is exposed, what is the riskiest service and why, who owns it, and have we seen this before?`
3. `Draft a ticket for the top service.`
4. `Which services are affected indirectly through calls?`
5. Memory: `We decided to accept the risk on <service> for <CVE> because it is internal-only.` then ask `Have we handled <CVE> before?`
6. Tenants: in interactive mode type `/tenant globex` and repeat the triage. The memory should differ.
7. Guardrail: ask about `CVE-0000-0000`. The agent should say it is not in the graph and not invent anything.

You will see lines like `> find_affected_services({"cve": ...})` and `cypher[affected_services]`: that is the explainability the track asks for.

## 3. Test the MCP server

```
python -m backend.mcp_smoke
```
Then connect a real client, see `docs/mcp.md`.

## 4. Understand it (the judges will ask)

1. Walk through one loop iteration: what is sent to Claude, what comes back, what do we do with a `tool_use` block?
2. Why tools instead of letting the model write Cypher? (Safer, testable, explainable, and each tool is documented.)
3. What does the ranking formula say, and why include PageRank? (Exposure alone ignores how central a service is to the call graph.)
4. How is tenant isolation enforced? (Fixed in the Toolbox; the recall query filters on it.)
5. What happens if a tool fails? (Error returned to the model; `is_error` set.)

## 5. Troubleshooting

| Problem | Fix |
|---------|-----|
| `ANTHROPIC_API_KEY is not set` | Add it to `.env`, restart the terminal |
| 401 / authentication error | Key is wrong or has no credits |
| `model not found` | Change `ANTHROPIC_MODEL` to a model your account can use |
| Agent loops without answering | Raise `MAX_AGENT_STEPS` or read the printed tool results for errors |
| Agent says CVE not in graph | Use ids from `python -m backend.demo_picks` |
| Tests skip with "FalkorDB is not reachable" | Start Docker (`docker compose up -d`) |
| `cannot import MCPServer` | `pip install -U "mcp>=2.0"` |

## 6. End-of-day checklist

- [ ] `python -m pytest tests -q` all green
- [ ] CLI triage of one CVE works and shows the chain
- [ ] Memory write then recall works; `/tenant globex` shows different memory
- [ ] `python -m backend.mcp_smoke` prints `MCP server OK`
- [ ] Connected one real MCP client (Claude Desktop or Claude Code), see `docs/mcp.md`
- [ ] `docs/ai-disclosure.md` updated, committed and pushed

Tomorrow (Day 3): FastAPI streaming, React UI with path highlighting and the Why? button, supersede links, tenant switcher.
