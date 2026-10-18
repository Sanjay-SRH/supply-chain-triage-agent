"""Run all four ingestion steps in order. Safe to re-run: network results are cached in data/."""
from backend.ingest import load, npm_deps, osv_vulns, synth

if __name__ == "__main__":
    print("=== 1/4 npm dependency crawl ===");  npm_deps.crawl()
    print("=== 2/4 OSV vulnerabilities ===");   osv_vulns.main()
    print("=== 3/4 synthetic company ===");     synth.main()
    print("=== 4/4 load into FalkorDB ===");    load.main()
