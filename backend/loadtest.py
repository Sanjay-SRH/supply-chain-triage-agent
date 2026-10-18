"""Concurrency check for the memory layer (Track 2): many parallel reads AND writes, then verify integrity.

  python -m backend.loadtest                      # 50 workers, 600 operations (80% reads / 20% writes)
  python -m backend.loadtest --workers 100 --ops 2000

It writes temporary decisions (ids start with "lt-") and deletes them at the end. It checks that
  1. no write was lost (graph count == number of successful writes), and
  2. each tenant sees only its own writes (isolation under concurrency).
Paste the printed summary into your README (numbers depend on your machine, so run it yourself).
"""
import argparse
import random
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

from backend.graph import queries as q
from backend.graph.client import get_graph

TENANTS = ["acme", "globex"]
WRITE = """
MATCH (c:CVE {id:$cve}), (s:Service {name:$service})
CREATE (d:Decision {id:$id, action:'patched', reasoning:'load test', tenant:$tenant, created_at:timestamp()})
CREATE (d)-[:ABOUT]->(c), (d)-[:APPLIES_TO]->(s)
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--ops", type=int, default=600)
    ap.add_argument("--write-ratio", type=float, default=0.2)
    args = ap.parse_args()

    g = get_graph()
    top = q.rows(g, q.MOST_EXPOSED_CVES, limit=1)
    if not top:
        raise SystemExit("Graph is empty. Run the Day 1 pipeline first.")
    cve = top[0]["cve"]
    services = [r["service"] for r in q.rows(g, q.AFFECTED_SERVICES, cve=cve)]
    q.write_rows(g, "MATCH (d:Decision) WHERE d.id STARTS WITH 'lt-' DETACH DELETE d")  # clean leftovers

    rng = random.Random(7)
    plan = [("w" if rng.random() < args.write_ratio else "r", i) for i in range(args.ops)]
    expected = {t: 0 for t in TENANTS}
    latencies: dict[str, list[float]] = {"r": [], "w": []}
    errors = []

    def op(item):
        kind, i = item
        t0 = time.perf_counter()
        try:
            if kind == "w":
                tenant = TENANTS[i % len(TENANTS)]
                g.query(WRITE, {"cve": cve, "service": services[i % len(services)], "id": f"lt-{i}", "tenant": tenant})
                return kind, time.perf_counter() - t0, tenant
            q.rows(g, q.AFFECTED_SERVICES, cve=cve)
            return kind, time.perf_counter() - t0, None
        except Exception as e:
            errors.append(repr(e))
            return None

    start = time.perf_counter()
    with ThreadPoolExecutor(args.workers) as pool:
        results = [r for r in pool.map(op, plan) if r]
    wall = time.perf_counter() - start
    for kind, dt, tenant in results:
        latencies[kind].append(dt)
        if tenant:
            expected[tenant] += 1

    got = {r["tenant"]: r["n"] for r in q.rows(
        g, "MATCH (d:Decision) WHERE d.id STARTS WITH 'lt-' RETURN d.tenant AS tenant, count(d) AS n")}
    q.write_rows(g, "MATCH (d:Decision) WHERE d.id STARTS WITH 'lt-' DETACH DELETE d")

    def pct(xs, p):
        return sorted(xs)[int(len(xs) * p) - 1] * 1000 if xs else 0.0

    print(f"{len(results)}/{args.ops} operations succeeded with {args.workers} concurrent workers in {wall:.2f}s "
          f"({len(results) / wall:.0f} ops/s)")
    for k, name in (("r", "reads (multi-hop exposure query)"), ("w", "writes (decision + 2 edges)")):
        xs = latencies[k]
        if xs:
            print(f"  {name}: n={len(xs)} p50={statistics.median(xs) * 1000:.1f}ms p95={pct(xs, 0.95):.1f}ms")
    lost = {t: expected[t] - got.get(t, 0) for t in TENANTS}
    print(f"  errors: {len(errors)}")
    print(f"  writes confirmed per tenant: {expected}  found in graph: { {t: got.get(t, 0) for t in TENANTS} }")
    ok = not errors and all(v == 0 for v in lost.values())
    print("INTEGRITY OK: no lost writes, tenants isolated." if ok else f"INTEGRITY FAILED: lost={lost} errors={errors[:3]}")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
