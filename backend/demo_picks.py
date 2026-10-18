"""Find good demo CVEs: the most exposed ones, and which of them have precedent in each tenant's memory.

Run: python -m backend.demo_picks
"""
from backend.agent.tools import Toolbox

TENANTS = ["acme", "globex"]


def main():
    base = Toolbox()
    top = [c["cve"] for c in base.most_exposed_cves(15)["cves"]]
    print("Most exposed CVEs:")
    for c in base.most_exposed_cves(5)["cves"]:
        print(f"  {c['cve']:<24} {c['severity']:<9} {c['services']} services")
    print("\nCVEs with precedent in memory (best for demoing recall):")
    for t in TENANTS:
        box = Toolbox(tenant=t)
        decided = [r["cve"] for r in box._q("decided", "MATCH (d:Decision {tenant:$t})-[:ABOUT]->(c:CVE) RETURN DISTINCT c.id AS cve", t=t)]
        hits = []
        for cve in dict.fromkeys(top + decided):
            prec = box.recall_decisions(cve).get("precedents", [])
            if prec:
                hits.append((cve, len(prec), prec[0]["action"]))
        print(f"  tenant {t}: " + (", ".join(f"{c} ({n} precedent, e.g. {a})" for c, n, a in hits[:5]) or "none"))
    print("\nTip: ask the same question as 'acme' and then as 'globex' to show isolated memory.")


if __name__ == "__main__":
    main()
