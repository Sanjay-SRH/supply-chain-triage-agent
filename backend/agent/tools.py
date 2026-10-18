"""The agent's tools. Each tool wraps one graph query (see backend/graph/queries.py) and returns
plain JSON-serialisable data, always including the dependency path that justifies the answer.

The same Toolbox is used by the Claude agent loop (loop.py) and by the MCP server (mcp_server.py),
so there is exactly one implementation of every capability.

Tenant isolation: the tenant is fixed when the Toolbox is created (never chosen by the LLM), so the
model cannot read or write another tenant's decisions.
"""
import uuid

from backend.graph import queries as q
from backend.graph.client import get_graph

ALLOWED_ACTIONS = ["patched", "upgrade_planned", "accepted_risk", "mitigated_waf", "false_positive"]
TIER_WEIGHT = {1: 3, 2: 2, 3: 1}
EXPOSURE_WEIGHT = {"public": 2, "internal": 1}
MAX_ROWS = 25  # keep tool output small so the LLM context stays cheap


def priority(cvss: float, tier: int, exposure: str) -> str:
    if cvss >= 9 or (cvss >= 7 and tier == 1 and exposure == "public"):
        return "P1"
    if cvss >= 7 or (tier == 1 and exposure == "public"):
        return "P2"
    return "P3"


class Toolbox:
    def __init__(self, graph=None, tenant: str = "acme"):
        self.g = graph if graph is not None else get_graph()
        self.tenant = tenant
        self.queries_used: list[dict] = []  # trace of every Cypher run (powers the UI "Why?" button)

    # ---------- internals ----------
    def _q(self, name: str, query: str, write: bool = False, **params):
        self.queries_used.append({"name": name, "cypher": query.strip(), "params": params})
        return (q.write_rows if write else q.rows)(self.g, query, **params)

    def _resolve_cve(self, cve: str):
        rows = self._q("get_cve", q.GET_CVE, cve=cve.strip())
        return rows[0] if rows and rows[0]["id"] else None

    def _service_exists(self, service: str) -> bool:
        return bool(self._q("service_exists", "MATCH (s:Service {name:$s}) RETURN s.name AS n", s=service))

    def call(self, name: str, args: dict) -> dict:
        """Dispatch a tool call by name. Never raises: errors come back as {"error": ...} so the model can recover."""
        if name not in TOOL_NAMES:
            return {"error": f"Unknown tool '{name}'. Available: {', '.join(sorted(TOOL_NAMES))}"}
        try:
            return getattr(self, name)(**(args or {}))
        except TypeError as e:
            return {"error": f"Bad arguments for {name}: {e}"}
        except Exception as e:  # database or logic failure
            return {"error": f"{name} failed: {e}"}

    # ---------- discovery ----------
    def find_cves_for_package(self, package: str) -> dict:
        """List vulnerabilities that affect any version of an npm package (use when the user names a package, not a CVE id)."""
        rows = self._q("cves_for_package", q.CVES_FOR_PACKAGE, package=package.strip(), limit=10)
        if not rows:
            return {"package": package, "cves": [], "note": "No known vulnerabilities for this package in the graph."}
        return {"package": package, "cves": rows}

    def most_exposed_cves(self, limit: int = 5) -> dict:
        """The CVEs that reach the most of our services right now. Use when asked 'what should I worry about?'"""
        limit = max(1, min(int(limit), 15))
        return {"cves": self._q("most_exposed_cves", q.MOST_EXPOSED_CVES, limit=limit)}

    def get_cve(self, cve: str) -> dict:
        """Basic facts about one CVE: severity, score, summary, affected packages."""
        c = self._resolve_cve(cve)
        return c if c else {"error": f"CVE '{cve}' is not in the graph. Try find_cves_for_package."}

    # ---------- core graph reasoning ----------
    def find_affected_services(self, cve: str) -> dict:
        """Which of our services are exposed to this CVE, with the shortest dependency chain for each (multi-hop traversal)."""
        c = self._resolve_cve(cve)
        if not c:
            return {"error": f"CVE '{cve}' is not in the graph. Try find_cves_for_package."}
        rows = self._q("affected_services", q.AFFECTED_SERVICES, cve=c["id"])
        return {"cve": c["id"], "severity": c["severity"], "cvss": c["cvss"], "summary": c["summary"],
                "total_services": len(rows), "services": rows[:MAX_ROWS]}

    def explain_path(self, service: str, cve: str) -> dict:
        """Why is this service exposed? Returns the exact chain: service -> package version -> ... -> vulnerable version -> CVE."""
        c = self._resolve_cve(cve)
        if not c:
            return {"error": f"CVE '{cve}' is not in the graph."}
        rows = self._q("explain_path", q.EXPLAIN_PATH, service=service.strip(), cve=c["id"])
        if not rows:
            return {"service": service, "cve": c["id"], "exposed": False,
                    "note": "No dependency path from this service to the CVE (check the service name)."}
        chain = rows[0]["chain"]
        return {"service": service, "cve": c["id"], "exposed": True, "hops": rows[0]["hops"], "chain": chain,
                "vulnerable_version": chain[-2], "pulled_in_by": chain[1] if len(chain) > 3 else None}

    def blast_radius(self, cve: str) -> dict:
        """Services that are not directly exposed but CALL an exposed service (up to 3 hops), so may be affected at runtime."""
        c = self._resolve_cve(cve)
        if not c:
            return {"error": f"CVE '{cve}' is not in the graph."}
        rows = self._q("upstream_callers", q.UPSTREAM_CALLERS, cve=c["id"])
        return {"cve": c["id"], "total": len(rows), "upstream_callers": rows[:MAX_ROWS]}

    def rank_services(self, cve: str, limit: int = 10) -> dict:
        """Rank exposed services by risk. score = cvss x tier weight x exposure weight / (1 + hops) x (1 + normalised PageRank)."""
        c = self._resolve_cve(cve)
        if not c:
            return {"error": f"CVE '{cve}' is not in the graph."}
        rows = self._q("affected_services", q.AFFECTED_SERVICES, cve=c["id"])
        pagerank, note = {}, None
        try:
            pr = self._q("service_pagerank", q.SERVICE_PAGERANK, limit=1000)
            top = max((r["score"] for r in pr), default=0) or 1
            pagerank = {r["service"]: r["score"] / top for r in pr}
        except Exception:
            note = "PageRank unavailable; ranked without centrality."
        ranked = []
        for r in rows:
            tw, ew = TIER_WEIGHT.get(r["tier"], 1), EXPOSURE_WEIGHT.get(r["exposure"], 1)
            pr_norm = pagerank.get(r["service"], 0.0)
            score = c["cvss"] * tw * ew / (1 + r["hops"]) * (1 + pr_norm)
            ranked.append({"service": r["service"], "score": round(score, 2), "tier": r["tier"],
                           "exposure": r["exposure"], "hops": r["hops"], "centrality": round(pr_norm, 2),
                           "priority": priority(c["cvss"], r["tier"], r["exposure"]), "chain": r["chain"]})
        ranked.sort(key=lambda x: (-x["score"], x["service"]))
        out = {"cve": c["id"], "cvss": c["cvss"], "formula": "cvss * tier_weight(1:3,2:2,3:1) * exposure_weight(public:2,internal:1) / (1 + hops) * (1 + pagerank_norm)",
               "total_services": len(ranked), "ranked": ranked[:max(1, min(int(limit), MAX_ROWS))]}
        if note:
            out["note"] = note
        return out

    def get_owner(self, service: str) -> dict:
        """Which team owns a service and who is on call."""
        rows = self._q("owner", q.OWNER, service=service.strip())
        return {"service": service, **rows[0]} if rows else {"error": f"No owner found for service '{service}'."}

    # ---------- memory ----------
    def recall_decisions(self, cve: str) -> dict:
        """Memory: earlier decisions on this CVE or on other CVEs in the same package. Scoped to the current tenant."""
        c = self._resolve_cve(cve)
        if not c:
            return {"error": f"CVE '{cve}' is not in the graph."}
        rows = self._q("recall_decisions", q.RECALL_DECISIONS, cve=c["id"], tenant=self.tenant)
        return {"cve": c["id"], "tenant": self.tenant, "precedents": rows,
                "note": None if rows else "No earlier decisions on this package for this tenant."}

    def save_decision(self, cve: str, service: str, action: str, reasoning: str) -> dict:
        """Memory: record a decision. Only call when the user explicitly states a decision. If one already exists for the same CVE and service, the new one supersedes it (history is kept). action: patched | upgrade_planned | accepted_risk | mitigated_waf | false_positive."""
        if action not in ALLOWED_ACTIONS:
            return {"error": f"action must be one of {ALLOWED_ACTIONS}"}
        if not reasoning.strip():
            return {"error": "reasoning is required so future recalls are useful"}
        c = self._resolve_cve(cve)
        if not c:
            return {"error": f"CVE '{cve}' is not in the graph."}
        if not self._service_exists(service):
            return {"error": f"Service '{service}' does not exist."}
        old = self._q("find_active_decision", q.FIND_ACTIVE_DECISION, tenant=self.tenant, cve=c["id"], service=service)
        did = f"d-{uuid.uuid4().hex[:8]}"
        rows = self._q("save_decision", q.SAVE_DECISION, write=True, cve=c["id"], service=service, id=did,
                       action=action, reasoning=reasoning.strip(), tenant=self.tenant)
        out = {"saved": bool(rows), "decision_id": did, "cve": c["id"], "service": service,
               "action": action, "tenant": self.tenant}
        if rows and old:  # a newer decision replaces the old one; keep it in the graph as history
            self._q("supersede_decision", q.SUPERSEDE_DECISION, write=True, new=did, old=old[0]["id"])
            out["supersedes"] = old[0]["id"]
            out["previous_action"] = old[0]["action"]
        return out

    def list_decisions(self, limit: int = 50) -> list[dict]:
        """Not an agent tool: used by the web UI to show this tenant's decision history."""
        return self._q("list_decisions", q.LIST_DECISIONS, tenant=self.tenant, limit=int(limit))

    # ---------- output ----------
    def draft_ticket(self, service: str, cve: str, reasoning: str = "") -> dict:
        """Draft (not send) a remediation ticket for a service/CVE pair, with chain, owner and precedent. No side effects."""
        c = self._resolve_cve(cve)
        if not c:
            return {"error": f"CVE '{cve}' is not in the graph."}
        path = self.explain_path(service, c["id"])
        if not path.get("exposed"):
            return {"error": f"{service} is not exposed to {c['id']}, so no ticket is needed."}
        svc = self._q("service_facts", "MATCH (s:Service {name:$s}) RETURN s.tier AS tier, s.exposure AS exposure", s=service)[0]
        owner = self.get_owner(service)
        precedents = self.recall_decisions(c["id"]).get("precedents", [])
        prio = priority(c["cvss"], svc["tier"], svc["exposure"])
        lines = [
            f"**CVE:** {c['id']} ({c['severity']}, CVSS ~{c['cvss']})", f"**Summary:** {c['summary']}",
            f"**Service:** {service} (tier {svc['tier']}, {svc['exposure']})",
            f"**Why it is exposed:** {' -> '.join(path['chain'])}",
            f"**Vulnerable version:** {path['vulnerable_version']}",
            f"**Owner:** {owner.get('team', 'unknown')} ({owner.get('oncall', 'n/a')})",
            "**Suggested action:** upgrade the vulnerable version to a fixed release; if it is pulled in transitively, upgrade the direct dependency that brings it in.",
        ]
        if reasoning:
            lines.append(f"**Triage reasoning:** {reasoning}")
        if precedents:
            p = precedents[0]
            lines.append(f"**Precedent:** {p['past_cve']} on {p['service']} was handled as '{p['action']}': {p['reasoning']}")
        return {"title": f"[{prio}] {c['id']} in {service}", "priority": prio,
                "assignee": owner.get("oncall"), "body": "\n".join(lines)}


# ---- tool definitions: one source of truth for the Claude agent AND the MCP server ----
def _obj(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required}


_S = {"type": "string"}
TOOL_SPECS = [
    {"name": "most_exposed_cves", "input_schema": _obj({"limit": {"type": "integer", "description": "How many (1-15), default 5"}}, [])},
    {"name": "find_cves_for_package", "input_schema": _obj({"package": {**_S, "description": "npm package name, e.g. lodash"}}, ["package"])},
    {"name": "get_cve", "input_schema": _obj({"cve": {**_S, "description": "CVE or GHSA id"}}, ["cve"])},
    {"name": "find_affected_services", "input_schema": _obj({"cve": {**_S, "description": "CVE or GHSA id"}}, ["cve"])},
    {"name": "explain_path", "input_schema": _obj({"service": _S, "cve": _S}, ["service", "cve"])},
    {"name": "blast_radius", "input_schema": _obj({"cve": _S}, ["cve"])},
    {"name": "rank_services", "input_schema": _obj({"cve": _S, "limit": {"type": "integer"}}, ["cve"])},
    {"name": "get_owner", "input_schema": _obj({"service": _S}, ["service"])},
    {"name": "recall_decisions", "input_schema": _obj({"cve": _S}, ["cve"])},
    {"name": "save_decision", "input_schema": _obj({"cve": _S, "service": _S, "action": {"type": "string", "enum": ALLOWED_ACTIONS},
                                                     "reasoning": _S}, ["cve", "service", "action", "reasoning"])},
    {"name": "draft_ticket", "input_schema": _obj({"service": _S, "cve": _S, "reasoning": _S}, ["service", "cve"])},
]
for _spec in TOOL_SPECS:  # descriptions come from the method docstrings, so they can never drift apart
    _spec["description"] = getattr(Toolbox, _spec["name"]).__doc__.strip()
TOOL_NAMES = {s["name"] for s in TOOL_SPECS}
