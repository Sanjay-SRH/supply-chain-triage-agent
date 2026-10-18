import test from "node:test";
import assert from "node:assert/strict";
import { initialState, reducer } from "./state.js";

const run = (events, start = reducer(initialState(), { type: "user", text: "triage" })) =>
  events.reduce((s, event) => reducer(s, { type: "event", event }), start);

const sub = {
  cve: "CVE-1",
  nodes: [
    { id: "web", kind: "service", label: "web", tier: 1, exposure: "public" },
    { id: "lib@1", kind: "version", label: "lib@1", vulnerable: true },
    { id: "CVE-1", kind: "cve", label: "CVE-1" },
  ],
  edges: [{ id: "web>lib@1", source: "web", target: "lib@1", type: "USES" }, { id: "CVE-1>lib@1", source: "CVE-1", target: "lib@1", type: "AFFECTS" }],
  chains: { web: ["web", "lib@1", "CVE-1"] },
};

test("a user message creates a streaming agent message and sets busy", () => {
  const s = reducer(initialState(), { type: "user", text: "hi" });
  assert.equal(s.busy, true);
  assert.deepEqual(s.messages.map((m) => m.role), ["user", "agent"]);
  assert.equal(s.messages[1].status, "streaming");
});

test("full flow: tool call, result with graph, ranking selects top, final answer", () => {
  const s = run([
    { type: "meta", mode: "scripted", tenant: "acme" },
    { type: "thought", text: "checking" },
    { type: "tool_call", tool: "find_affected_services", input: { cve: "CVE-1" } },
    { type: "tool_result", tool: "find_affected_services", input: {}, queries: [{ name: "q" }], error: false, graph: sub,
      output: { cve: "CVE-1", services: [{ service: "web", tier: 1, exposure: "public", hops: 2, chain: sub.chains.web }] } },
    { type: "tool_call", tool: "rank_services", input: { cve: "CVE-1" } },
    { type: "tool_result", tool: "rank_services", queries: [], error: false, graph: sub,
      output: { cve: "CVE-1", ranked: [{ service: "web", score: 9, priority: "P1", tier: 1, exposure: "public", hops: 2, chain: sub.chains.web }] } },
    { type: "final", text: "web is exposed" },
  ]);
  const agent = s.messages[1];
  assert.equal(s.mode, "scripted");
  assert.equal(agent.notes[0], "checking");
  assert.deepEqual(agent.steps.map((x) => [x.tool, x.status]), [["find_affected_services", "done"], ["rank_services", "done"]]);
  assert.equal(agent.steps[0].queries.length, 1);
  assert.equal(agent.text, "web is exposed");
  assert.equal(agent.status, "done");
  assert.equal(s.busy, false);
  assert.equal(s.graph.cve, "CVE-1");
  assert.equal(s.table.rows[0].priority, "P1");   // ranking replaces the plain affected list
  assert.equal(s.selected, "web");
});

test("errors from a tool mark the step failed", () => {
  const s = run([
    { type: "tool_call", tool: "get_cve", input: { cve: "X" } },
    { type: "tool_result", tool: "get_cve", output: { error: "not in graph" }, queries: [], error: true },
  ]);
  assert.equal(s.messages[1].steps[0].status, "error");
});

test("stream errors finish the message and release busy", () => {
  const s = run([{ type: "error", message: "key rejected" }]);
  assert.equal(s.messages[1].status, "error");
  assert.equal(s.messages[1].text, "key rejected");
  assert.equal(s.busy, false);
});

test("switching to a new CVE clears the selection; reset keeps the mode", () => {
  let s = run([{ type: "meta", mode: "claude" }, { type: "tool_result", tool: "explain_path", queries: [], error: false, graph: sub,
    output: { exposed: true, chain: sub.chains.web, cve: "CVE-1" } }]);
  assert.equal(s.selected, "web");
  s = run([{ type: "tool_result", tool: "explain_path", queries: [], error: false,
    graph: { ...sub, cve: "CVE-2", chains: { web: ["web", "lib@1", "CVE-2"] } }, output: { exposed: false } }], s);
  assert.equal(s.graph.cve, "CVE-2");
  assert.equal(s.selected, null);
  const r = reducer(s, { type: "reset" });
  assert.equal(r.messages.length, 0);
  assert.equal(r.mode, "claude");
});
