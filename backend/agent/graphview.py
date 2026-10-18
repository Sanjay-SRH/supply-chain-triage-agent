"""Turns tool results into a small graph the UI can draw (nodes, edges, highlightable chains).

It is built purely from the chains the tools already returned, so what you SEE is exactly what the agent
REASONED over. Edge directions match the real graph model:
  Service -USES-> Version -DEPENDS_ON-> Version ... ;  CVE -AFFECTS-> (vulnerable) Version
"""


def _chains(tool: str, out: dict) -> list[tuple[list[str], dict]]:
    """Extract (chain, extra node info for the service) pairs from a tool result."""
    if "error" in out:
        return []
    if tool == "find_affected_services":
        return [(s["chain"], {"tier": s["tier"], "exposure": s["exposure"]}) for s in out.get("services", [])]
    if tool == "rank_services":
        return [(r["chain"], {"tier": r["tier"], "exposure": r["exposure"], "score": r["score"],
                              "priority": r["priority"]}) for r in out.get("ranked", [])]
    if tool == "explain_path" and out.get("exposed"):
        return [(out["chain"], {})]
    return []


def subgraph_from_output(tool: str, out: dict) -> dict | None:
    pairs = [(c, info) for c, info in _chains(tool, out) if len(c) >= 3]
    if not pairs:
        return None
    cve = pairs[0][0][-1]
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}
    chains: dict[str, list[str]] = {}

    def node(nid, kind, **attrs):
        n = nodes.setdefault(nid, {"id": nid, "kind": kind, "label": nid})
        n.update({k: v for k, v in attrs.items() if v is not None})

    def edge(src, dst, etype):
        edges.setdefault(f"{src}>{dst}", {"id": f"{src}>{dst}", "source": src, "target": dst, "type": etype})

    for chain, info in pairs:
        last = len(chain) - 1
        for i, nid in enumerate(chain):
            if i == 0:
                node(nid, "service", **info)
            elif i == last:
                node(nid, "cve")
            else:
                node(nid, "version", vulnerable=(i == last - 1) or None)
        for i in range(last):
            a, b = chain[i], chain[i + 1]
            if i == 0:
                edge(a, b, "USES")
            elif i == last - 1:
                edge(b, a, "AFFECTS")  # arrow points CVE -> vulnerable version
            else:
                edge(a, b, "DEPENDS_ON")
        chains[chain[0]] = chain
    return {"cve": cve, "nodes": list(nodes.values()), "edges": list(edges.values()), "chains": chains}
