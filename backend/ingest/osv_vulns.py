"""STEP 2 - Pull real vulnerabilities from OSV (api.osv.dev, public, no key) for every package
found in step 1, and work out WHICH of our exact versions each vulnerability affects.

OSV gives us version ranges ("introduced 4.0.0, fixed 4.17.21"); we evaluate them against the
versions that are actually in our graph and emit CVE -[:AFFECTS]-> Version edges.

Note on scores: OSV records usually carry a CVSS *vector*, not a number. We use the
severity label (LOW/MODERATE/HIGH/CRITICAL) and map it to a representative CVSS score.

Output: data/vulns.json
Run:    python -m backend.ingest.osv_vulns
"""
import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
from semantic_version import Version

from backend.config import DATA_DIR

API = "https://api.osv.dev/v1/query"
CACHE = DATA_DIR / "osv"
GRAPH_IN = DATA_DIR / "graph_deps.json"
OUT = DATA_DIR / "vulns.json"
SEVERITY_TO_CVSS = {"LOW": 3.1, "MODERATE": 5.5, "MEDIUM": 5.5, "HIGH": 7.5, "CRITICAL": 9.5}


# ---------- fetching ----------
def fetch_package_vulns(client: httpx.Client, pkg: str):
    """All OSV records for one npm package (handles pagination). Cached on disk."""
    path = CACHE / (pkg.replace("/", "__") + ".json")
    if path.exists():
        return json.loads(path.read_text())
    vulns, token = [], None
    while True:
        body = {"package": {"name": pkg, "ecosystem": "npm"}}
        if token:
            body["page_token"] = token
        for attempt in range(4):
            try:
                r = client.post(API, json=body, timeout=30)
                r.raise_for_status()
                break
            except httpx.HTTPError:
                if attempt == 3:
                    print(f"  ! OSV failed for {pkg}")
                    return None
                time.sleep(1.5 * (attempt + 1))
        data = r.json()
        vulns.extend(data.get("vulns", []))
        token = data.get("next_page_token")
        if not token:
            break
    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(vulns))
    return vulns


# ---------- version matching (pure functions, unit-tested) ----------
def _ver(s: str):
    try:
        return Version.coerce(s)
    except ValueError:
        return None


def in_ranges(version: str, ranges: list[dict]) -> bool:
    """Is `version` inside any OSV SEMVER/ECOSYSTEM range? Events are processed in ascending order:
    introduced -> turns 'affected' on, fixed / last_affected -> turn it off."""
    v = _ver(version)
    if v is None:
        return False
    for rng in ranges:
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        events = []
        for ev in rng.get("events", []):
            (kind, val), = ev.items()
            ev_v = Version("0.0.0") if val == "0" else _ver(val)
            if ev_v is not None:
                events.append((ev_v, kind))
        events.sort(key=lambda e: (e[0], e[1] != "introduced"))
        affected = False
        for ev_v, kind in events:
            if kind == "introduced" and v >= ev_v:
                affected = True
            elif kind == "fixed" and v >= ev_v:
                affected = False
            elif kind == "last_affected" and v > ev_v:
                affected = False
        if affected:
            return True
    return False


def affected_versions(vuln: dict, pkg: str, known: list[str]) -> list[str]:
    """Which of our known versions of `pkg` does this OSV record affect?"""
    hit = set()
    for aff in vuln.get("affected", []):
        p = aff.get("package", {})
        if p.get("name") != pkg or p.get("ecosystem") != "npm":
            continue
        explicit = set(aff.get("versions", []))
        for v in known:
            if v in explicit or in_ranges(v, aff.get("ranges", [])):
                hit.add(v)
    return sorted(hit)


def normalise(vuln: dict) -> dict:
    aliases = vuln.get("aliases", [])
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    if cve is None and vuln["id"].startswith("CVE-"):
        cve = vuln["id"]
    sev = ((vuln.get("database_specific") or {}).get("severity") or "").upper()
    summary = vuln.get("summary") or (vuln.get("details") or "").strip().split("\n")[0]
    return {
        "id": cve or vuln["id"],
        "osv_id": vuln["id"],
        "severity": sev or "UNKNOWN",
        "cvss": SEVERITY_TO_CVSS.get(sev, 5.0),
        "summary": summary[:240],
        "published": (vuln.get("published") or "")[:10],
    }


def build(raw_by_pkg: dict, versions_by_pkg: dict):
    """Turn raw OSV records into CVE nodes + AFFECTS edges (only vulns hitting versions we have)."""
    cves, affects = {}, set()
    for pkg, vulns in raw_by_pkg.items():
        for vuln in vulns or []:
            if vuln.get("withdrawn") or vuln["id"].startswith("MAL-"):  # skip withdrawn + malware reports
                continue
            hits = affected_versions(vuln, pkg, versions_by_pkg.get(pkg, []))
            if not hits:
                continue
            rec = normalise(vuln)
            cves.setdefault(rec["id"], rec)
            for v in hits:
                affects.add((rec["id"], f"{pkg}@{v}"))
    return sorted(cves.values(), key=lambda c: c["id"]), sorted(list(a) for a in affects)


def main():
    g = json.loads(GRAPH_IN.read_text())
    versions_by_pkg: dict[str, list[str]] = {}
    for v in g["versions"]:
        versions_by_pkg.setdefault(v["name"], []).append(v["version"])
    pkgs = g["packages"]
    print(f"Querying OSV for {len(pkgs)} packages...")
    with httpx.Client(follow_redirects=True) as client, ThreadPoolExecutor(8) as pool:
        raw = dict(zip(pkgs, pool.map(lambda p: fetch_package_vulns(client, p), pkgs)))
    failed = [p for p, r in raw.items() if r is None]
    if len(failed) == len(pkgs):
        raise SystemExit("OSV is unreachable from this network. Check your internet / proxy and retry.")
    cves, affects = build(raw, versions_by_pkg)
    OUT.write_text(json.dumps({"cves": cves, "affects": affects}, indent=1))
    print(f"Wrote {OUT}: {len(cves)} CVEs, {len(affects)} AFFECTS edges"
          + (f" ({len(failed)} packages failed, rerun to retry)" if failed else ""))


if __name__ == "__main__":
    main()
