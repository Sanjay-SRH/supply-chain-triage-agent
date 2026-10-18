// Runs the real Cytoscape inside jsdom (with a canvas mock). jsdom cannot DRAW, but this catches crashes in
// initialisation, style parsing, layout and highlighting, which is what used to blank the page.
import "vitest-canvas-mock";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { StrictMode } from "react";
import App from "./App.jsx"; // REAL cytoscape: this file deliberately does NOT mock it

// jsdom has no layout engine: give every element a real size, like a browser would.
beforeAll(() => {
  for (const [p, v] of [["clientWidth", 800], ["clientHeight", 500], ["offsetWidth", 800], ["offsetHeight", 500]])
    Object.defineProperty(HTMLElement.prototype, p, { configurable: true, get: () => v });
  HTMLElement.prototype.getBoundingClientRect = () => ({ x: 0, y: 0, top: 0, left: 0, right: 800, bottom: 500, width: 800, height: 500 });
});
afterEach(cleanup);
const json = (x) => new Response(JSON.stringify(x), { headers: { "content-type": "application/json" } });
const CH = { web: ["web", "app@1", "lib@1", "CVE-T-1"], batch: ["batch", "lib@1", "CVE-T-1"] };
const SUB = { cve: "CVE-T-1",
  nodes: [{ id: "web", kind: "service", label: "web", tier: 1, exposure: "public", score: 9, priority: "P1" },
          { id: "batch", kind: "service", label: "batch", tier: 3, exposure: "internal" },
          { id: "app@1", kind: "version", label: "app@1" }, { id: "lib@1", kind: "version", label: "lib@1", vulnerable: true },
          { id: "CVE-T-1", kind: "cve", label: "CVE-T-1" }],
  edges: [{ id: "web>app@1", source: "web", target: "app@1", type: "USES" }, { id: "app@1>lib@1", source: "app@1", target: "lib@1", type: "DEPENDS_ON" },
          { id: "batch>lib@1", source: "batch", target: "lib@1", type: "USES" }, { id: "CVE-T-1>lib@1", source: "CVE-T-1", target: "lib@1", type: "AFFECTS" }],
  chains: CH };
const rk = [{ service: "web", score: 9, priority: "P1", tier: 1, exposure: "public", hops: 3, chain: CH.web }, { service: "batch", score: 2, priority: "P3", tier: 3, exposure: "internal", hops: 2, chain: CH.batch }];
const FLOW = [{ type: "meta", mode: "scripted" }, { type: "tool_call", tool: "rank_services", input: {} },
  { type: "tool_result", tool: "rank_services", input: {}, queries: [], error: false, graph: SUB, output: { cve: "CVE-T-1", ranked: rk } },
  { type: "final", text: "done" }];
const sse = (ev) => new Response(ev.map((e) => `data: ${JSON.stringify(e)}\n\n`).join(""), { headers: { "content-type": "text/event-stream" } });

describe("REAL cytoscape in the real app", () => {
  it("mounts under StrictMode, draws a graph, highlights, restyles, unmounts cleanly", async () => {
    const errors = []; const origErr = console.error; console.error = (...a) => errors.push(a.join(" "));
    const warns = []; const origWarn = console.warn; console.warn = (...a) => warns.push(a.join(" "));
    globalThis.fetch = vi.fn(async (u) => String(u).includes("health") ? json({ mode: "scripted", tenants: ["acme"] })
      : String(u).includes("suggestions") ? json({ cves: [{ cve: "CVE-T-1", severity: "HIGH", cvss: 7.5, services: 2 }] })
      : String(u).includes("chat") ? sse(FLOW) : json({ decisions: [] }));
    const { unmount } = render(<StrictMode><App /></StrictMode>);
    fireEvent.click(await screen.findByText(/Triage CVE-T-1/));
    await screen.findByText("done");
    await waitFor(() => expect(screen.getByLabelText("Selected exposure chain")).toBeTruthy());
    fireEvent.click(screen.getByText("batch", { selector: "td b" }));
    expect(screen.queryByRole("alert")).toBeNull();
    expect(document.body.textContent).toContain("Supply-chain triage agent"); // app still on screen, not a blank page
    unmount();
    console.error = origErr; console.warn = origWarn;
    // the graph must not have reported a failure, and React must not have logged an uncaught render error
    expect(screen.queryByRole("alert")).toBeNull();
    expect(errors.filter((e) => /Graph|uncaught|crashed|Error:/i.test(e) && !/not wrapped in act/i.test(e))).toEqual([]);
  });
});
