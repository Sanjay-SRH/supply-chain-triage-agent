"""The Cypher queries the whole product depends on. Each one becomes an agent tool on Day 2.

Reading a path:  (Service)-[:USES]->(Version)-[:DEPENDS_ON*0..8]->(Version)<-[:AFFECTS]-(CVE)
  = "the service uses a version, which (directly or through up to 8 levels of dependencies)
     depends on a version that the CVE affects."  *0 means the service's own version may be the vulnerable one.
"""

# 1. Which services are exposed to a CVE, and through which chain? (shortest chain per service;
#    ties are broken alphabetically so the same question always gives the same answer)
AFFECTED_SERVICES = """
MATCH p = (s:Service)-[:USES]->(:Version)-[:DEPENDS_ON*0..8]->(:Version)<-[:AFFECTS]-(c:CVE {id:$cve})
WITH s, [n IN nodes(p) | coalesce(n.id, n.name)] AS chain, length(p) AS hops,
     reduce(k = '', n IN nodes(p) | k + coalesce(n.id, n.name) + '>') AS sortkey
ORDER BY hops, sortkey
WITH s, collect(chain)[0] AS best
RETURN s.name AS service, s.tier AS tier, s.exposure AS exposure, size(best) - 1 AS hops, best AS chain
ORDER BY tier, hops, service
"""

# 2. Explain ONE service/CVE pair: the shortest dependency chain (this is the "Why?" answer)
EXPLAIN_PATH = """
MATCH p = (s:Service {name:$service})-[:USES]->(:Version)-[:DEPENDS_ON*0..8]->(:Version)<-[:AFFECTS]-(c:CVE {id:$cve})
WITH [n IN nodes(p) | coalesce(n.id, n.name)] AS chain, length(p) AS hops,
     reduce(k = '', n IN nodes(p) | k + coalesce(n.id, n.name) + '>') AS sortkey
ORDER BY hops, sortkey LIMIT 1
RETURN chain, hops
"""

# 3. Blast radius: services that are NOT themselves exposed but call (within 3 hops) a service that is
UPSTREAM_CALLERS = """
MATCH (c:CVE {id:$cve})-[:AFFECTS]->(:Version)<-[:DEPENDS_ON*0..8]-(:Version)<-[:USES]-(s:Service)
WITH collect(DISTINCT s) AS exposed
UNWIND exposed AS s
MATCH (caller:Service)-[:CALLS*1..3]->(s)
WHERE NOT caller IN exposed
RETURN DISTINCT caller.name AS service, caller.tier AS tier, caller.exposure AS exposure
ORDER BY tier, service
"""

# 4. Who should be told?
OWNER = """
MATCH (s:Service {name:$service})-[:OWNED_BY]->(t:Team)
RETURN t.name AS team, t.oncall AS oncall
"""

# 5. MEMORY (read): this tenant's CURRENT decisions on this CVE (same_cve = true) or on other CVEs in the same package.
#    Decisions that a newer one SUPERSEDES are ignored.
RECALL_DECISIONS = """
MATCH (:CVE {id:$cve})-[:AFFECTS]->(:Version)-[:OF]->(p:Package)
MATCH (p)<-[:OF]-(:Version)<-[:AFFECTS]-(c2:CVE)<-[:ABOUT]-(d:Decision)-[:APPLIES_TO]->(s:Service)
WHERE d.tenant = $tenant AND NOT (d)<-[:SUPERSEDES]-()
RETURN DISTINCT d.id AS decision, d.action AS action, d.reasoning AS reasoning,
       c2.id AS past_cve, (c2.id = $cve) AS same_cve, s.name AS service, d.created_at AS created_at
ORDER BY same_cve DESC, created_at DESC LIMIT 5
"""

# 6. MEMORY (write)
SAVE_DECISION = """
MATCH (c:CVE {id:$cve}), (s:Service {name:$service})
CREATE (d:Decision {id:$id, action:$action, reasoning:$reasoning, tenant:$tenant, created_at:timestamp()})
CREATE (d)-[:ABOUT]->(c), (d)-[:APPLIES_TO]->(s)
RETURN d.id AS id
"""

# 7. Which CVEs hit the most services? (used to pick demo CVEs and to rank)
MOST_EXPOSED_CVES = """
MATCH (c:CVE)-[:AFFECTS]->(:Version)<-[:DEPENDS_ON*0..8]-(:Version)<-[:USES]-(s:Service)
RETURN c.id AS cve, c.severity AS severity, c.cvss AS cvss, count(DISTINCT s) AS services
ORDER BY services DESC, cvss DESC LIMIT $limit
"""

# 8. Graph algorithm: PageRank over the service call graph = "how central is this service?"
SERVICE_PAGERANK = """
CALL algo.pageRank('Service', 'CALLS') YIELD node, score
RETURN node.name AS service, node.tier AS tier, score
ORDER BY score DESC LIMIT $limit
"""

# 9. Look up one CVE (case-insensitive: GHSA ids contain lowercase letters)
GET_CVE = """
MATCH (c:CVE) WHERE toLower(c.id) = toLower($cve)
OPTIONAL MATCH (c)-[:AFFECTS]->(:Version)-[:OF]->(p:Package)
RETURN c.id AS id, c.severity AS severity, c.cvss AS cvss, c.summary AS summary, c.published AS published,
       collect(DISTINCT p.name) AS packages
"""

# 10. Which CVEs affect a package? (lets a user ask about "lodash" without knowing a CVE id)
CVES_FOR_PACKAGE = """
MATCH (c:CVE)-[:AFFECTS]->(:Version)-[:OF]->(p:Package {name:$package})
RETURN DISTINCT c.id AS cve, c.severity AS severity, c.cvss AS cvss, c.summary AS summary
ORDER BY cvss DESC, cve LIMIT $limit
"""

# 11. MEMORY (update): the current (not yet superseded) decision for the same tenant + CVE + service, if any
FIND_ACTIVE_DECISION = """
MATCH (d:Decision {tenant:$tenant})-[:ABOUT]->(:CVE {id:$cve}), (d)-[:APPLIES_TO]->(:Service {name:$service})
WHERE NOT (d)<-[:SUPERSEDES]-()
RETURN d.id AS id, d.action AS action ORDER BY d.created_at DESC LIMIT 1
"""

# 12. MEMORY (update): link a new decision to the one it replaces
SUPERSEDE_DECISION = """
MATCH (n:Decision {id:$new}), (o:Decision {id:$old})
CREATE (n)-[:SUPERSEDES]->(o)
"""

# 13. All decisions for a tenant, with their supersede links (feeds the UI's decision history)
LIST_DECISIONS = """
MATCH (d:Decision {tenant:$tenant})-[:ABOUT]->(c:CVE), (d)-[:APPLIES_TO]->(s:Service)
OPTIONAL MATCH (newer:Decision)-[:SUPERSEDES]->(d)
OPTIONAL MATCH (d)-[:SUPERSEDES]->(older:Decision)
RETURN d.id AS id, d.action AS action, d.reasoning AS reasoning, d.created_at AS created_at,
       c.id AS cve, s.name AS service, newer.id AS superseded_by, older.id AS supersedes
ORDER BY created_at DESC LIMIT $limit
"""

COUNT_NODES = "MATCH (n) RETURN labels(n)[0] AS label, count(n) AS n ORDER BY n DESC"
COUNT_RELS = "MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS n ORDER BY n DESC"


def rows(g, query: str, **params) -> list[dict]:
    """Run a read-only query and return a list of {column: value} dicts."""
    res = g.ro_query(query, params)
    names = [h[1] for h in res.header]
    return [dict(zip(names, r)) for r in res.result_set]


def write_rows(g, query: str, **params) -> list[dict]:
    """Run a query that changes the graph (CREATE/MERGE/SET) and return its rows."""
    res = g.query(query, params)
    names = [h[1] for h in res.header]
    return [dict(zip(names, r)) for r in res.result_set]
