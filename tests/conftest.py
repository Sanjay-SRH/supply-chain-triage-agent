"""A tiny hand-built graph with known answers, loaded into a throwaway graph named triage_test.

web (tier1, public) -> app@1 -> lib@1 <- CVE-T-1 (CRITICAL)      : exposed in 3 hops
batch (tier3, internal) -> lib@1                                  : exposed in 2 hops
gateway -CALLS-> web -CALLS-> batch                               : gateway is not exposed but calls an exposed service;
                                                                    web is exposed AND calls batch (must not count as a 'caller')
safe -> other@1                                                   : not exposed
Past decision (tenant acme) on CVE-T-0, which affects lib@0 (same package `lib`).
"""
import pytest

from backend.graph.client import get_db
from backend.graph.schema import create_indexes

GRAPH = "triage_test"


@pytest.fixture(scope="session")
def test_graph():
    try:
        db = get_db()
        db.select_graph("probe").query("RETURN 1")
    except Exception:
        pytest.skip("FalkorDB is not reachable (start Docker or set FALKORDB_EMBEDDED_PATH)")
    try:
        db.select_graph(GRAPH).delete()
    except Exception:
        pass
    g = db.select_graph(GRAPH)
    create_indexes(g)
    g.query("""
    CREATE (lib:Package {name:'lib'}), (app:Package {name:'app'}), (oth:Package {name:'other'}),
      (lib0:Version {id:'lib@0', name:'lib', version:'0'}), (lib1:Version {id:'lib@1', name:'lib', version:'1'}),
      (app1:Version {id:'app@1', name:'app', version:'1'}), (oth1:Version {id:'other@1', name:'other', version:'1'}),
      (lib0)-[:OF]->(lib), (lib1)-[:OF]->(lib), (app1)-[:OF]->(app), (oth1)-[:OF]->(oth),
      (app1)-[:DEPENDS_ON]->(lib1),
      (c1:CVE {id:'CVE-T-1', severity:'CRITICAL', cvss:9.5, summary:'test critical', published:'2024-01-01'}),
      (c0:CVE {id:'CVE-T-0', severity:'HIGH', cvss:7.5, summary:'older lib bug', published:'2023-01-01'}),
      (c1)-[:AFFECTS]->(lib1), (c0)-[:AFFECTS]->(lib0),
      (t1:Team {name:'Platform', oncall:'@platform-oncall'}), (t2:Team {name:'Data', oncall:'@data-oncall'}),
      (web:Service {name:'web', tier:1, exposure:'public'}), (batch:Service {name:'batch', tier:3, exposure:'internal'}),
      (gw:Service {name:'gateway', tier:1, exposure:'public'}), (safe:Service {name:'safe', tier:2, exposure:'internal'}),
      (web)-[:USES]->(app1), (batch)-[:USES]->(lib1), (safe)-[:USES]->(oth1),
      (web)-[:OWNED_BY]->(t1), (batch)-[:OWNED_BY]->(t2), (gw)-[:OWNED_BY]->(t1), (safe)-[:OWNED_BY]->(t2),
      (gw)-[:CALLS]->(web), (web)-[:CALLS]->(batch),
      (d:Decision {id:'d-old', action:'patched', reasoning:'upgraded lib', tenant:'acme', created_at:1700000000000}),
      (d)-[:ABOUT]->(c0), (d)-[:APPLIES_TO]->(batch)
    """)
    yield g
    try:
        db.select_graph(GRAPH).delete()
    except Exception:
        pass


@pytest.fixture
def box(test_graph):
    from backend.agent.tools import Toolbox
    return Toolbox(graph=test_graph, tenant="acme")
