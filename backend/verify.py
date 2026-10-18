"""Day-1 check: is the graph loaded, and do the core queries return sensible answers?

Run: python -m backend.verify
"""
import sys

from backend.graph import queries as q
from backend.graph.client import get_graph


def main() -> int:
    g = get_graph()
    ok = True

    def check(label, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
        ok &= bool(cond)

    print("== Graph size ==")
    nodes = {r["label"]: r["n"] for r in q.rows(g, q.COUNT_NODES)}
    rels = {r["type"]: r["n"] for r in q.rows(g, q.COUNT_RELS)}
    print("  nodes:", nodes)
    print("  rels: ", rels)
    check("has Version, CVE, Service nodes", all(nodes.get(k, 0) > 0 for k in ("Version", "CVE", "Service")))
    check("has DEPENDS_ON, AFFECTS, USES edges", all(rels.get(k, 0) > 0 for k in ("DEPENDS_ON", "AFFECTS", "USES")))

    print("\n== Most exposed CVEs ==")
    top = q.rows(g, q.MOST_EXPOSED_CVES, limit=5)
    for r in top:
        print(f"  {r['cve']:<22} {r['severity']:<9} {r['services']} services")
    check("at least one CVE reaches a service", bool(top))
    if not top:
        return 1
    cve = top[0]["cve"]

    print(f"\n== find affected services for {cve} ==")
    aff = q.rows(g, q.AFFECTED_SERVICES, cve=cve)
    for r in aff[:5]:
        print(f"  {r['service']:<22} tier {r['tier']} {r['exposure']:<8} {r['hops']} hops: {' -> '.join(r['chain'])}")
    check("affected-services query returns paths", bool(aff))
    check("every path starts at a service and ends at the CVE",
          all(r["chain"][0] == r["service"] and r["chain"][-1] == cve for r in aff))
    check("service count matches the exposure ranking", len(aff) == top[0]["services"])

    svc = aff[0]["service"]
    print(f"\n== explain {svc} / {cve} ==")
    ex = q.rows(g, q.EXPLAIN_PATH, service=svc, cve=cve)
    print("  ", " -> ".join(ex[0]["chain"]) if ex else "(none)")
    check("explain returns a chain", bool(ex))

    print(f"\n== upstream callers of exposed services ==")
    callers = q.rows(g, q.UPSTREAM_CALLERS, cve=cve)
    print("  ", [c["service"] for c in callers][:8])
    check("blast-radius query runs", callers is not None)

    print(f"\n== owner of {svc} ==")
    own = q.rows(g, q.OWNER, service=svc)
    print("  ", own)
    check("service has an owner", bool(own))

    print("\n== memory: seeded decisions ==")
    dec = q.rows(g, "MATCH (d:Decision) RETURN d.tenant AS tenant, count(d) AS n")
    print("  ", dec)
    check("past decisions exist", bool(dec))
    for r in top:  # look for any CVE that has a recallable precedent
        rec = q.rows(g, q.RECALL_DECISIONS, cve=r["cve"], tenant="acme")
        if rec:
            print(f"  recall for {r['cve']}: {rec[0]['action']} on {rec[0]['service']} ({rec[0]['past_cve']})")
            break
    else:
        print("  (no top CVE shares a package with a past decision; fine, recall is tested again on Day 2)")

    print("\n== PageRank over CALLS ==")
    try:
        pr = q.rows(g, q.SERVICE_PAGERANK, limit=5)
        for r in pr:
            print(f"  {r['service']:<22} {r['score']:.4f}")
        check("PageRank returns scores", bool(pr))
    except Exception as e:
        print("  PageRank call failed:", e)
        print("  -> check docs.falkordb.com/algorithms for this version's syntax (fallback: degree counts)")
        ok = False

    print("\nALL CHECKS PASSED" if ok else "\nSOME CHECKS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
