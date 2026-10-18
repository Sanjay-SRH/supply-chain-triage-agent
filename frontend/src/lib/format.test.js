import test from "node:test";
import assert from "node:assert/strict";
import { parseBlocks, relativeTime, summarize, summarizeInput, tokenizeInline } from "./format.js";

test("summarize covers each tool and errors", () => {
  assert.equal(summarize("find_affected_services", { total_services: 3 }), "3 service(s) exposed");
  assert.equal(summarize("rank_services", { ranked: [{ service: "web", priority: "P1" }] }), "top risk: web (P1)");
  assert.equal(summarize("recall_decisions", { precedents: [] }), "no precedent");
  assert.equal(summarize("save_decision", { saved: true, supersedes: "d1" }), "saved, supersedes d1");
  assert.equal(summarize("get_owner", { error: "No owner" }), "No owner");
});

test("summarizeInput is short", () => {
  assert.equal(summarizeInput({ service: "web", cve: "CVE-1" }), "web, CVE-1");
  assert.ok(summarizeInput({ reasoning: "x".repeat(100) }).length <= 48);
});

test("tokenizeInline never produces html and handles bold/code", () => {
  const t = tokenizeInline("a **b** `c` <script>alert(1)</script>");
  assert.deepEqual(t.slice(0, 4).map((x) => x.t), ["text", "bold", "text", "code"]);
  assert.ok(t.some((x) => x.t === "text" && x.v.includes("<script>")));  // kept as plain text; React escapes it
});

test("parseBlocks groups bullets and drops leading/duplicate gaps", () => {
  const b = parseBlocks("\nhello\n\n- one\n- two\n\n\nbye");
  assert.deepEqual(b.map((x) => x.type), ["p", "gap", "list", "gap", "p"]);
  assert.deepEqual(b[2].items, ["one", "two"]);
});

test("relativeTime", () => {
  const now = 1_000_000_000_000;
  assert.equal(relativeTime(now - 5 * 60_000, now), "5m ago");
  assert.equal(relativeTime(now - 3 * 3_600_000, now), "3h ago");
  assert.equal(relativeTime(now - 2 * 86_400_000, now), "2d ago");
  assert.equal(relativeTime(null, now), "");
});
