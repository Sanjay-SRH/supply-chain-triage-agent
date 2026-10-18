# Day 3 guide: streaming API, web UI, memory upgrades

Goal for today: open a browser, click a CVE, watch the agent work step by step, see the exposure paths drawn
as a graph with the riskiest chain highlighted, click **Why?** to see the Cypher behind any step, and watch memory
differ between tenants.

## 0. Setup (about 10 minutes)

1. Day 1 and Day 2 must still pass: `python -m backend.verify` and `python -m pytest tests -q`.
2. Install the new Python packages: `pip install -r requirements.txt` (adds `fastapi`, `uvicorn`).
3. Install the frontend (Node 18+): 
   ```
   cd frontend
   npm install
   ```

## 1. Run it

**Development (two terminals, hot reload):**
```
# terminal 1, project root
uvicorn backend.api:app --reload --port 8000
# terminal 2
cd frontend && npm run dev          # open http://localhost:5173
```
**Single process (what you will deploy):**
```
cd frontend && npm run build && cd ..
uvicorn backend.api:app --port 8000   # open http://localhost:8000
```
With no `ANTHROPIC_API_KEY` the app runs in **scripted mode** (a fixed triage flow, clearly badged "Scripted (no LLM)")
so you can build and test without credits. With a key it uses the Claude agent ("Claude agent" badge).
Set `DEMO_MODE=true` to force scripted mode.

## 2. What was built

| Piece | File | Job |
|-------|------|-----|
| Streaming API | `backend/api.py` | `POST /api/chat` streams every agent step as Server-Sent Events; also `/api/health`, `/api/suggestions`, `/api/decisions` |
| Graph view builder | `backend/agent/graphview.py` | Turns tool results into nodes/edges/chains for the UI, from the same chains the agent used |
| Scripted agent | `backend/agent/scripted.py` | No-LLM fallback with the same event stream |
| Memory updates | `tools.py`, `queries.py` | A new decision on the same tenant + CVE + service **supersedes** the old one (`(:Decision)-[:SUPERSEDES]->(:Decision)`); recall ignores superseded decisions |
| Concurrency test | `backend/loadtest.py` | 50+ parallel reads and writes; checks no lost writes and tenant isolation |
| UI | `frontend/src/` | Chat with live steps, Cytoscape graph with chain highlighting, ranking table, memory tab, Why? drawer, tenant switcher |

### Design decisions you should be able to defend

- **The graph on screen is the agent's reasoning.** The UI draws exactly the chains the tools returned; nothing is re-derived in the browser.
- **Why? is real.** Every tool call ships the Cypher and parameters that ran; the drawer shows them, plus the raw result.
- **SSE over WebSockets.** One-directional streaming of agent steps; simpler, works through proxies, no state to manage.
- **Tenant is validated server-side** against an allow-list and fixed per request. The browser cannot name an arbitrary tenant.
- **Supersede instead of overwrite.** History stays in the graph (audit trail), recall only uses current decisions.
- **Model output is rendered as React elements, never HTML**, so a prompt-injected answer cannot inject markup. A test checks it.
- **Rate limit** (default 30 chat requests per 10 minutes per client) protects your API credits once deployed publicly.

## 3. Try it (this is also your demo rehearsal)

1. Click a suggested CVE chip. Watch the steps appear, the graph draw, the top-ranked chain light up.
2. Click another row in the Ranking table, or a service node in the graph: its chain highlights.
3. Click **Why?** on the first step: Cypher, parameters, raw result.
4. Type: `We decided to accept the risk on <service> for <CVE>: it is internal-only.` (needs the Claude agent; scripted mode cannot save decisions). Check the **Memory** tab.
5. Say it again with a different decision for the same service and CVE: the old one shows struck through as superseded.
6. Switch **Tenant** to `globex` and triage the same CVE: different precedent.
7. Run the concurrency check and keep the output for your README:
   ```
   python -m backend.loadtest
   python -m backend.loadtest --workers 100 --ops 2000
   ```

## 4. Tests

```
python -m pytest tests -q            # backend: tools, API, graph view, MCP
cd frontend
npm test                             # pure logic: SSE parser, reducer, graph merge, headless Cytoscape
npm run test:ui                      # renders the app in jsdom: mocked API, and a run with the REAL Cytoscape library
npm run test:e2e                     # needs `uvicorn backend.api:app --port 8000` running; real UI -> real API -> FalkorDB
```

## 5. What I could not verify for you

I had no browser, so **nobody has looked at the UI with eyes yet**. The logic, rendering and the layout
computation are tested, but please check by eye and tell me what looks wrong:
- Is the graph readable with 16+ services? (zoom with the mouse wheel, drag to pan)
- Do colours and contrast work in both light and dark mode?
- Does the layout work on a phone-width window?
- Does Claude (real API) pick sensible tools? I could only test the loop with a scripted fake model.

## 6. Troubleshooting

| Problem | Fix |
|---------|-----|
| Blank page (title shows, nothing drawn) | Open DevTools (F12) > Console and read the red error. Since v3b the app shows a red error card instead of a blank page, and a graph failure only affects the graph panel. Also try: stop Vite, `rm -rf node_modules/.vite`, `npm install`, `npm run dev`, then hard refresh (Ctrl+Shift+R) |
| Red card: `destroy is not a function` | An effect returned a value. Fixed in v3c (and guarded by a test). Update to the latest zip |
| UI says "Cannot reach the API" | Start `uvicorn backend.api:app --port 8000`; in dev the Vite proxy forwards `/api` to it |
| Blank graph | Run the Day 1 pipeline; check `python -m backend.verify` |
| Steps arrive all at once at the end | A proxy is buffering SSE; the server sends `X-Accel-Buffering: no` for nginx; check other proxies |
| `429` in the chat | Rate limit; raise `RATE_LIMIT` in `.env` for development |
| Badge says "Scripted" but you set a key | Key is empty in the server's environment, or `DEMO_MODE=true`; restart uvicorn after editing `.env` |
| `npm install` fails on Node 16 | Use Node 18 or newer |

## 7. End-of-day checklist

- [ ] All three test commands green
- [ ] Triage works in the browser, graph highlights, Why? drawer opens
- [ ] Supersede visible in the Memory tab (needs the Claude agent)
- [ ] Tenant switch shows different memory
- [ ] `python -m backend.loadtest` output saved for the README
- [ ] Screenshots saved to `docs/` (you need them for the README and submission)
- [ ] `docs/ai-disclosure.md` updated, committed, pushed

Tomorrow (Day 4): deploy (FalkorDB Cloud + a host), README polish, demo video, submit by about 6 PM IST.
