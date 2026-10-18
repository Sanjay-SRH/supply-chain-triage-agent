# Day 1 guide: from empty repo to a verified graph

Goal for today: the graph is loaded with real data and **every core query returns a correct answer**.
Do not start the agent or UI until `python -m backend.verify` says ALL CHECKS PASSED.

## 0. One-time setup (about 10 minutes)

1. Unzip the project and open the folder in your editor. Open a terminal **in the project root**.
2. Start FalkorDB:
   ```
   docker compose up -d
   ```
   Open http://localhost:3000. If the FalkorDB Browser loads, the database is running.
3. Create a Python environment and install packages:
   ```
   python -m venv .venv
   .venv\Scripts\activate        (Windows)       source .venv/bin/activate   (Mac/Linux)
   pip install -r requirements.txt
   ```
4. Copy the settings file: `copy .env.example .env` (Windows) or `cp .env.example .env`.
5. Create your own git history now (the rules want original work and meaningful commits):
   ```
   git init
   git add . && git commit -m "Day 1: project skeleton, data pipeline, core queries"
   git remote add origin <your-empty-github-repo-url>
   git push -u origin main
   ```

## 1. Run the pipeline

```
python -m backend.ingest.run_all
```

This takes roughly 5 to 15 minutes the first time (it calls npm and OSV; results are cached in `data/`).

| Step | Module | What it does |
|------|--------|--------------|
| 1 | `npm_deps` | Crawls npm: 40 popular packages, their last 4 major versions, and their dependency trees (about 900 versions) |
| 2 | `osv_vulns` | Asks OSV for every vulnerability in those packages and works out which exact versions each one affects |
| 3 | `synth` | Invents 30 services, 6 teams, who owns what, who calls whom, and which versions each service uses |
| 4 | `load` | Wipes the graph and loads everything, then adds 14 past decisions |

You can also run any step on its own: `python -m backend.ingest.npm_deps`, `osv_vulns`, `synth`, `load`.

## 2. Verify

```
python -m backend.verify
```

You want `ALL CHECKS PASSED`. It prints the most exposed CVEs and an example exposure chain such as
`gateway -> express@4.17.1 -> body-parser@1.19.0 -> qs@6.7.0 -> CVE-...`.

## 3. Explore it visually (do this, it is how you learn the graph)

Open http://localhost:3000, choose the graph named `triage`, and try:

```cypher
MATCH (c:CVE) RETURN c.id, c.severity LIMIT 10
```
```cypher
MATCH p = (s:Service)-[:USES]->(:Version)-[:DEPENDS_ON*0..8]->(:Version)<-[:AFFECTS]-(c:CVE {id:"PASTE-A-CVE-ID"})
RETURN p
```
The second query draws the exposure chains as a picture. That is your demo visual.

## 4. Understand it (the judges will ask)

Be able to answer these without looking:

1. Why is `DEPENDS_ON*0..8` the key idea? (It follows dependency chains of unknown length; `*0` includes the case where the service's own version is the vulnerable one.)
2. Why is it a graph problem and not a SQL join? (Chains have variable length.)
3. Why do ties in `AFFECTED_SERVICES` sort alphabetically? (So the same question always gives the same chain.)
4. Which data is real and which is synthetic? (See README.)
5. How does decision recall find precedent? (Decision -> CVE -> Version -> Package <- Version <- other CVE.)

## 5. Troubleshooting

| Problem | Fix |
|---------|-----|
| `Connection refused` on port 6379 | `docker compose up -d`, wait a few seconds, check `docker ps` |
| OSV step says unreachable | Check internet or VPN or proxy, then rerun `python -m backend.ingest.osv_vulns` (cache makes reruns cheap) |
| `ModuleNotFoundError: backend` | Run commands from the project root with `python -m ...` |
| Docker will not start (Mac/Linux only) | Use embedded mode: `pip install falkordblite`, then set `FALKORDB_EMBEDDED_PATH=./data/falkor.rdb` in `.env` |
| PageRank check fails | Your FalkorDB version may use different syntax; see docs.falkordb.com/algorithms. The other checks do not depend on it |
| Verify says no CVE reaches a service | Rerun `python -m backend.ingest.synth` then `load`; if still empty, increase seeds or `MAX_VERSIONS` |

## 6. End-of-day checklist

- [ ] `python -m backend.verify` passes
- [ ] You ran the exposure query in FalkorDB Browser and saw the picture
- [ ] You can explain the five questions above
- [ ] Committed and pushed to GitHub
- [ ] `docs/ai-disclosure.md` updated

Tomorrow (Day 2): wrap each query as an agent tool, build the agent loop and the MCP server.
