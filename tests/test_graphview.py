from backend.agent.graphview import subgraph_from_output

AFF = {"cve": "CVE-X", "services": [
    {"service": "web", "tier": 1, "exposure": "public", "hops": 3, "chain": ["web", "app@1", "lib@1", "CVE-X"]},
    {"service": "batch", "tier": 3, "exposure": "internal", "hops": 2, "chain": ["batch", "lib@1", "CVE-X"]},
]}


def test_nodes_edges_and_directions():
    g = subgraph_from_output("find_affected_services", AFF)
    assert g["cve"] == "CVE-X"
    kinds = {n["id"]: n["kind"] for n in g["nodes"]}
    assert kinds == {"web": "service", "batch": "service", "app@1": "version", "lib@1": "version", "CVE-X": "cve"}
    edges = {(e["source"], e["target"], e["type"]) for e in g["edges"]}
    assert edges == {("web", "app@1", "USES"), ("app@1", "lib@1", "DEPENDS_ON"),
                     ("CVE-X", "lib@1", "AFFECTS"), ("batch", "lib@1", "USES")}
    assert next(n for n in g["nodes"] if n["id"] == "lib@1")["vulnerable"] is True
    assert g["chains"]["batch"] == ["batch", "lib@1", "CVE-X"]


def test_shared_nodes_are_not_duplicated():
    g = subgraph_from_output("find_affected_services", AFF)
    assert len(g["nodes"]) == len({n["id"] for n in g["nodes"]}) == 5


def test_rank_adds_score_and_priority():
    ranked = {"ranked": [{**AFF["services"][0], "score": 9.1, "priority": "P1"}]}
    g = subgraph_from_output("rank_services", ranked)
    web = next(n for n in g["nodes"] if n["id"] == "web")
    assert web["score"] == 9.1 and web["priority"] == "P1"


def test_explain_path_and_non_graph_results():
    g = subgraph_from_output("explain_path", {"exposed": True, "chain": ["web", "app@1", "lib@1", "CVE-X"], "cve": "CVE-X"})
    assert len(g["nodes"]) == 4
    assert subgraph_from_output("get_owner", {"team": "x"}) is None
    assert subgraph_from_output("find_affected_services", {"error": "nope"}) is None
    assert subgraph_from_output("explain_path", {"exposed": False}) is None
