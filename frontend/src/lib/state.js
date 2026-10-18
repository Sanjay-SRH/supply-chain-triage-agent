// All UI state transitions live here as a pure reducer, so they can be unit-tested without a browser.
import { emptyGraph, mergeGraph } from "./graph.js";

export const initialState = () => ({
  messages: [],
  graph: emptyGraph(),
  table: null, // {cve, rows:[{service,tier,exposure,hops,score?,priority?}]}
  selected: null,
  mode: null,
  busy: false,
});

let counter = 0;
const nextId = () => `m${++counter}`;

function updateLastAgent(state, fn) {
  const messages = state.messages.slice();
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i].role === "agent") {
      messages[i] = fn(messages[i]);
      break;
    }
  }
  return { ...state, messages };
}

function applyToolResult(state, ev) {
  let next = updateLastAgent(state, (m) => {
    const steps = m.steps.slice();
    for (let i = steps.length - 1; i >= 0; i--) {
      if (steps[i].tool === ev.tool && steps[i].status === "running") {
        steps[i] = { ...steps[i], status: ev.error ? "error" : "done", output: ev.output, queries: ev.queries };
        break;
      }
    }
    return { ...m, steps };
  });

  if (ev.graph) {
    const graph = mergeGraph(next.graph, ev.graph);
    next = { ...next, graph, selected: graph.cve !== next.graph.cve ? null : next.selected };
  }
  const out = ev.output || {};
  if (ev.tool === "find_affected_services" && out.services && next.table?.cve !== out.cve) {
    next = { ...next, table: { cve: out.cve, rows: out.services.map((s) => ({ ...s })) } };
  }
  if (ev.tool === "rank_services" && out.ranked) {
    const rows = out.ranked.map((r) => ({ ...r }));
    next = { ...next, table: { cve: out.cve, rows }, selected: next.selected ?? rows[0]?.service ?? null };
  }
  if (ev.tool === "explain_path" && out.exposed) {
    next = { ...next, selected: out.chain[0] };
  }
  return next;
}

export function reducer(state, action) {
  switch (action.type) {
    case "user":
      return {
        ...state,
        busy: true,
        messages: [
          ...state.messages,
          { id: nextId(), role: "user", text: action.text },
          { id: nextId(), role: "agent", notes: [], steps: [], text: "", status: "streaming" },
        ],
      };
    case "select":
      return { ...state, selected: action.service };
    case "health":
      return { ...state, mode: action.mode };
    case "reset":
      return { ...initialState(), mode: state.mode };
    case "event": {
      const ev = action.event;
      switch (ev.type) {
        case "meta":
          return { ...state, mode: ev.mode };
        case "thought":
          return updateLastAgent(state, (m) => ({ ...m, notes: [...m.notes, ev.text] }));
        case "tool_call":
          return updateLastAgent(state, (m) => ({
            ...m,
            steps: [...m.steps, { id: nextId(), tool: ev.tool, input: ev.input, status: "running" }],
          }));
        case "tool_result":
          return applyToolResult(state, ev);
        case "final":
          return { ...updateLastAgent(state, (m) => ({ ...m, text: ev.text, status: "done" })), busy: false };
        case "error":
          return { ...updateLastAgent(state, (m) => ({ ...m, text: ev.message, status: "error" })), busy: false };
        default:
          return state;
      }
    }
    default:
      return state;
  }
}
