import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { getDecisions, getHealth, getSuggestions, newSessionId, streamChat } from "./api.js";
import ChatPanel from "./components/ChatPanel.jsx";
import DecisionsPanel from "./components/DecisionsPanel.jsx";
import GraphPanel from "./components/GraphPanel.jsx";
import RankingTable from "./components/RankingTable.jsx";
import WhyDrawer from "./components/WhyDrawer.jsx";
import { initialState, reducer } from "./lib/state.js";

export default function App() {
  const [state, dispatch] = useReducer(reducer, undefined, initialState);
  const [tenants, setTenants] = useState(["acme", "globex"]);
  const [tenant, setTenant] = useState("acme");
  const [tab, setTab] = useState("ranking");
  const [why, setWhy] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [decisions, setDecisions] = useState({ list: [], error: null });
  const [apiError, setApiError] = useState(null);
  const session = useRef(newSessionId());
  const abort = useRef(null);

  const refresh = useCallback(async (t) => {
    try {
      const [s, d] = await Promise.all([getSuggestions(t), getDecisions(t)]);
      setSuggestions(s.cves || []);
      setDecisions({ list: d.decisions || [], error: null });
      setApiError(null);
    } catch (e) {
      setApiError("Cannot reach the API. Is the server running? (uvicorn backend.api:app --port 8000)");
    }
  }, []);

  useEffect(() => {
    getHealth()
      .then((h) => {
        dispatch({ type: "health", mode: h.mode });
        if (h.tenants?.length) setTenants(h.tenants);
      })
      .catch(() => setApiError("Cannot reach the API. Is the server running? (uvicorn backend.api:app --port 8000)"));
  }, []);

  useEffect(() => {
    abort.current?.abort();
    dispatch({ type: "reset" });
    session.current = newSessionId();
    refresh(tenant);
  }, [tenant, refresh]);

  const send = useCallback(
    async (message) => {
      const ctl = new AbortController();
      abort.current = ctl;
      let finished = false;
      dispatch({ type: "user", text: message });
      try {
        await streamChat({
          message, tenant, sessionId: session.current, signal: ctl.signal,
          onEvent: (event) => {
            if (event.type === "final" || event.type === "error") finished = true;
            dispatch({ type: "event", event });
          },
        });
        if (!finished) dispatch({ type: "event", event: { type: "error", message: "The connection closed before the agent finished." } });
      } catch (e) {
        const message = e.name === "AbortError" ? "Stopped." : e.message;
        dispatch({ type: "event", event: { type: "error", message } });
      } finally {
        refresh(tenant); // the agent may have saved a decision
      }
    },
    [tenant, refresh],
  );

  const reset = () => {
    abort.current?.abort();
    dispatch({ type: "reset" });
    session.current = newSessionId();
  };

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <span aria-hidden="true">🕸</span> Supply-chain triage agent
          <span className="muted sub">powered by FalkorDB</span>
        </div>
        <div className="controls">
          <span className={`mode ${state.mode}`} title={state.mode === "scripted" ? "No LLM key configured: a fixed triage flow runs the same graph tools" : "Claude chooses which graph tools to call"}>
            {state.mode === "claude" ? "Claude agent" : state.mode === "scripted" ? "Scripted (no LLM)" : "…"}
          </span>
          <label className="tenant">
            Tenant
            <select value={tenant} onChange={(e) => setTenant(e.target.value)} disabled={state.busy}>
              {tenants.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <button className="secondary" onClick={reset}>New chat</button>
        </div>
      </header>
      {apiError && <div className="banner">{apiError}</div>}
      <main>
        <section className="panel chatcol">
          <ChatPanel messages={state.messages} busy={state.busy} suggestions={suggestions} tenant={tenant}
            onSend={send} onStop={() => abort.current?.abort()} onWhy={setWhy} />
        </section>
        <section className="rightcol">
          <div className="panel graphbox">
            <GraphPanel graph={state.graph} selected={state.selected} onSelect={(s) => dispatch({ type: "select", service: s })} />
          </div>
          <div className="panel lower">
            <div className="tabs" role="tablist">
              <button role="tab" aria-selected={tab === "ranking"} className={tab === "ranking" ? "on" : ""} onClick={() => setTab("ranking")}>
                Ranking{state.table ? ` · ${state.table.cve}` : ""}
              </button>
              <button role="tab" aria-selected={tab === "memory"} className={tab === "memory" ? "on" : ""} onClick={() => setTab("memory")}>
                Memory ({decisions.list.length})
              </button>
            </div>
            {tab === "ranking" ? (
              <RankingTable table={state.table} selected={state.selected} onSelect={(s) => dispatch({ type: "select", service: s })} />
            ) : (
              <div className="scroll"><DecisionsPanel decisions={decisions.list} tenant={tenant} error={decisions.error} /></div>
            )}
          </div>
        </section>
      </main>
      {why && <WhyDrawer step={why} onClose={() => setWhy(null)} />}
    </div>
  );
}
