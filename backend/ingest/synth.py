"""STEP 3 - Generate the SYNTHETIC company layer: teams, services, who owns what, which service
calls which, and which exact package versions each service uses.

This is invented data (allowed by the hackathon rules) laid on top of REAL npm/OSV data.
A fixed random seed makes it reproducible: same input, same company.

Output: data/company.json
Run:    python -m backend.ingest.synth
"""
import json
import random

from backend.config import DATA_DIR, SEED

GRAPH_IN = DATA_DIR / "graph_deps.json"
OUT = DATA_DIR / "company.json"

TEAMS = ["Platform", "Payments", "Identity", "Growth", "Data", "Mobile"]

# Ordered roughly from customer-facing (top) to internal (bottom): a service only calls services below it.
SERVICE_NAMES = [
    "gateway", "checkout-web", "mobile-bff", "admin-portal", "partner-api", "docs-site",
    "orders-api", "cart-service", "payments-api", "auth-service", "user-profile", "search-api",
    "recommendation-engine", "notification-hub", "chat-service", "cms-backend", "media-uploader",
    "billing-worker", "fraud-checker", "inventory-sync", "geo-service", "email-sender",
    "webhook-relay", "analytics-collector", "reporting-dashboard", "export-worker", "scheduler",
    "feature-flags", "session-store", "audit-log",
]


def generate(deps: dict, seed: int = SEED) -> dict:
    rng = random.Random(seed)
    teams = [{"name": t, "oncall": f"@{t.lower()}-oncall"} for t in TEAMS]

    # Direct dependency pool: every seed package with its release lines (index 0 = oldest major).
    pool = {pkg: vers for pkg, vers in deps["seed_versions"].items() if vers}
    pkgs = sorted(pool)

    services, uses, owned_by, calls = [], [], [], []
    for i, name in enumerate(SERVICE_NAMES):
        tier = 1 if i in (0, 8, 9) else rng.choices([1, 2, 3], weights=[2, 4, 3])[0]
        exposure = "public" if i < 5 or rng.random() < 0.25 else "internal"
        services.append({"name": name, "tier": tier, "exposure": exposure})

        for pkg in rng.sample(pkgs, k=rng.randint(4, 8)):
            vers = pool[pkg]
            # older release lines are chosen more often, as in real codebases
            weights = [len(vers) - j for j in range(len(vers))]
            uses.append([name, rng.choices(vers, weights=weights)[0]])

        owned_by.append([name, rng.choice(TEAMS)])

        below = SERVICE_NAMES[i + 1:]
        if below:
            for target in rng.sample(below, k=min(len(below), rng.randint(1, 3))):
                calls.append([name, target])

    return {"teams": teams, "services": services, "uses": uses, "owned_by": owned_by, "calls": calls}


def main():
    deps = json.loads(GRAPH_IN.read_text())
    company = generate(deps)
    OUT.write_text(json.dumps(company, indent=1))
    print(f"Wrote {OUT}: {len(company['services'])} services, {len(company['teams'])} teams, "
          f"{len(company['uses'])} USES, {len(company['calls'])} CALLS")


if __name__ == "__main__":
    main()
