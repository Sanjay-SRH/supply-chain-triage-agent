"""STEP 4 - Load everything into FalkorDB (wipes and rebuilds the graph each run).

Run: python -m backend.ingest.load
"""
import json
import random
import time

from backend.config import DATA_DIR, GRAPH_NAME, SEED
from backend.graph.client import get_db
from backend.graph.schema import create_indexes

BATCH = 500

# (action, reasoning) pairs used to seed realistic past decisions (the agent's memory)
DECISION_TEMPLATES = [
    ("patched", "Upgraded the dependency to the fixed release and redeployed."),
    ("upgrade_planned", "Fix needs a major version bump; scheduled for the next sprint."),
    ("accepted_risk", "Service is internal-only and the vulnerable code path is not reachable."),
    ("mitigated_waf", "Blocked the exploit pattern at the gateway while the upgrade is prepared."),
    ("false_positive", "We do not call the affected function; confirmed by code search."),
]


def batches(rows, n=BATCH):
    for i in range(0, len(rows), n):
        yield rows[i:i + n]


def run(g, query, rows):
    for chunk in batches(rows):
        g.query(query, {"rows": chunk})


def seed_decisions(g, rng, count=14):
    """Create past Decision nodes for real exposed (service, CVE) pairs so memory has something to recall."""
    res = g.query(
        "MATCH (s:Service)-[:USES]->(:Version)-[:DEPENDS_ON*0..8]->(:Version)<-[:AFFECTS]-(c:CVE) "
        "RETURN DISTINCT s.name, c.id LIMIT 3000"
    )
    pairs = sorted((r[0], r[1]) for r in res.result_set)
    if not pairs:
        return 0
    chosen = rng.sample(pairs, k=min(count, len(pairs)))
    now_ms = int(time.time() * 1000)
    rows = []
    for i, (svc, cve) in enumerate(chosen):
        action, why = rng.choice(DECISION_TEMPLATES)
        rows.append({
            "id": f"d{i + 1:03d}", "service": svc, "cve": cve, "action": action, "reasoning": why,
            "tenant": "acme" if i < 11 else "globex",
            "created_at": now_ms - rng.randint(1, 90) * 86_400_000,
        })
    run(g, """UNWIND $rows AS r
              MATCH (s:Service {name:r.service}), (c:CVE {id:r.cve})
              CREATE (d:Decision {id:r.id, action:r.action, reasoning:r.reasoning,
                                  tenant:r.tenant, created_at:r.created_at})
              CREATE (d)-[:ABOUT]->(c), (d)-[:APPLIES_TO]->(s)""", rows)
    return len(rows)


def main():
    deps = json.loads((DATA_DIR / "graph_deps.json").read_text())
    vulns = json.loads((DATA_DIR / "vulns.json").read_text())
    company = json.loads((DATA_DIR / "company.json").read_text())

    db = get_db()
    try:
        db.select_graph(GRAPH_NAME).delete()
    except Exception:
        pass  # graph did not exist yet
    g = db.select_graph(GRAPH_NAME)
    create_indexes(g)

    print("Loading nodes...")
    run(g, "UNWIND $rows AS r CREATE (:Package {name:r.name, ecosystem:'npm'})",
        [{"name": n} for n in deps["packages"]])
    run(g, "UNWIND $rows AS r CREATE (:Version {id:r.id, name:r.name, version:r.version})", deps["versions"])
    run(g, "UNWIND $rows AS r CREATE (:CVE {id:r.id, osv_id:r.osv_id, severity:r.severity, cvss:r.cvss, "
           "summary:r.summary, published:r.published})", vulns["cves"])
    run(g, "UNWIND $rows AS r CREATE (:Team {name:r.name, oncall:r.oncall})", company["teams"])
    run(g, "UNWIND $rows AS r CREATE (:Service {name:r.name, tier:r.tier, exposure:r.exposure})", company["services"])

    print("Loading relationships...")
    run(g, "UNWIND $rows AS r MATCH (v:Version {id:r.id}), (p:Package {name:r.name}) CREATE (v)-[:OF]->(p)",
        deps["versions"])
    run(g, "UNWIND $rows AS r MATCH (a:Version {id:r[0]}), (b:Version {id:r[1]}) CREATE (a)-[:DEPENDS_ON]->(b)",
        deps["edges"])
    run(g, "UNWIND $rows AS r MATCH (c:CVE {id:r[0]}), (v:Version {id:r[1]}) CREATE (c)-[:AFFECTS]->(v)",
        vulns["affects"])
    run(g, "UNWIND $rows AS r MATCH (s:Service {name:r[0]}), (v:Version {id:r[1]}) CREATE (s)-[:USES]->(v)",
        company["uses"])
    run(g, "UNWIND $rows AS r MATCH (s:Service {name:r[0]}), (t:Team {name:r[1]}) CREATE (s)-[:OWNED_BY]->(t)",
        company["owned_by"])
    run(g, "UNWIND $rows AS r MATCH (a:Service {name:r[0]}), (b:Service {name:r[1]}) CREATE (a)-[:CALLS]->(b)",
        company["calls"])

    n = seed_decisions(g, random.Random(SEED))
    print(f"Seeded {n} past decisions.")
    print("Done. Run: python -m backend.verify")


if __name__ == "__main__":
    main()
