# Supply-Chain Triage Agent (Graph Hacks, FalkorDB)

An agent that answers: **"A new CVE was published. Which of our services are really exposed, through which
dependency chain, who owns them, and how did we handle similar issues before?"**

Tracks: **Agents That Act on Connected Data** (main) + **Agent Memory and Coordination** (decision memory, tenants).

> Status: Day 3 (streaming API, web UI, memory upgrades). Deployment, demo and submission next.

## Data

| Layer | Source | Real or synthetic |
|-------|--------|-------------------|
| Packages, versions, dependency edges | npm registry (public) | Real |
| Vulnerabilities (CVE/GHSA) and affected version ranges | OSV (api.osv.dev, public) | Real |
| Teams, services, ownership, service calls, which versions each service uses, past decisions | `backend/ingest/synth.py`, `load.py` (fixed random seed) | **Synthetic** |

No private or restricted data is used.

## Graph data model

```
(Version)-[:OF]->(Package)
(Version)-[:DEPENDS_ON]->(Version)
(CVE)-[:AFFECTS]->(Version)
(Service)-[:USES]->(Version)
(Service)-[:OWNED_BY]->(Team)
(Service)-[:CALLS]->(Service)
(Decision)-[:ABOUT]->(CVE)
(Decision)-[:APPLIES_TO]->(Service)
```

| Node | Properties |
|------|-----------|
| Package | name, ecosystem |
| Version | id (`name@version`), name, version |
| CVE | id, osv_id, severity, cvss, summary, published |
| Service | name, tier (1-3), exposure (public/internal) |
| Team | name, oncall |
| Decision | id, action, reasoning, tenant, created_at |

`cvss` is a representative score derived from the OSV severity label (LOW 3.1, MODERATE 5.5, HIGH 7.5, CRITICAL 9.5).

## Agent and tools

`backend/agent/tools.py` defines 11 tools, each wrapping one graph query. The same tools power the Claude
agent (`backend/agent/loop.py`, CLI: `python -m backend.agent.cli`) and an MCP server (`python -m backend.mcp_server`,
see [docs/mcp.md](docs/mcp.md)). Every answer carries the dependency chain that justifies it, and every Cypher query
run is recorded per tool call.

Risk score: `cvss x tier_weight(1:3, 2:2, 3:1) x exposure_weight(public:2, internal:1) / (1 + hops) x (1 + normalised PageRank on CALLS)`.

Memory: decisions are graph nodes (`Decision -[:ABOUT]-> CVE`, `-[:APPLIES_TO]-> Service`) scoped by tenant; recall
follows `CVE -> Version -> Package <- Version <- CVE <- Decision`. The tenant is fixed per agent/server instance, never an LLM argument.

## Web UI

React + Cytoscape. Chat with live tool-call steps, an exposure graph with the selected dependency chain highlighted,
a risk-ranked table, a memory tab (decision history with supersede links), a tenant switcher, and a **Why?** drawer that
shows the Cypher and raw result behind every step. The API (`backend/api.py`) streams agent events as Server-Sent Events.
Without an LLM key it runs a clearly badged scripted flow over the same tools.

```bash
cd frontend && npm install && npm run build && cd ..
uvicorn backend.api:app --port 8000     # http://localhost:8000
```

## Memory and coordination (Track 2)

- Decisions are graph nodes, per tenant; recall traverses `CVE -> Version -> Package <- Version <- CVE <- Decision`.
- A newer decision for the same tenant + CVE + service links `(:Decision)-[:SUPERSEDES]->(:Decision)`; recall ignores superseded ones.
- Tenant isolation is enforced server-side (allow-list, fixed per request) and in every memory query.
- Concurrency: `python -m backend.loadtest` runs parallel reads and writes and checks for lost writes and tenant leaks.
  _(paste your own run's output here)_

## Core queries

All in [`backend/graph/queries.py`](backend/graph/queries.py), each documented inline:
affected services + exposure chain, explain path, upstream callers (blast radius), owner lookup,
decision recall (memory read), decision save (memory write), most-exposed CVEs, PageRank over `CALLS`.

## Setup

See [DAY1.md](DAY1.md) (data) and [DAY2.md](DAY2.md) (agent and MCP) for the step-by-step.

```bash
docker compose up -d
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
python -m backend.ingest.run_all
python -m backend.verify
python -m backend.agent.cli "Triage the most exposed CVE"   # needs ANTHROPIC_API_KEY in .env
```

## Tests

```bash
python -m pytest tests -q
```

## AI disclosure

See [docs/ai-disclosure.md](docs/ai-disclosure.md).
