import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { instances } from "./test-utils/fakeCytoscape.js";

vi.mock("cytoscape", async () => import("./test-utils/fakeCytoscape.js"));
import App from "./App.jsx";

const CHAINS = { web: ["web", "app@1", "lib@1", "CVE-T-1"], batch: ["batch", "lib@1", "CVE-T-1"] };
const SUB = {
  cve: "CVE-T-1",
  nodes: [
    { id: "web", kind: "service", label: "web", tier: 1, exposure: "public" },
    { id: "batch", kind: "service", label: "batch", tier: 3, exposure: "internal" },
    { id: "app@1", kind: "version", label: "app@1" },
    { id: "lib@1", kind: "version", label: "lib@1", vulnerable: true },
    { id: "CVE-T-1", kind: "cve", label: "CVE-T-1" },
  ],
  edges: [
    { id: "web>app@1", source: "web", target: "app@1", type: "USES" },
    { id: "app@1>lib@1", source: "app@1", target: "lib@1", type: "DEPENDS_ON" },
    { id: "batch>lib@1", source: "batch", target: "lib@1", type: "USES" },
    { id: "CVE-T-1>lib@1", source: "CVE-T-1", target: "lib@1", type: "AFFECTS" },
  ],
  chains: CHAINS,
};
const Q = [{ name: "affected_services", cypher: "MATCH p = (s:Service)-[:USES]->(v) RETURN s", params: { cve: "CVE-T-1" } }];
const ranked = [
  { service: "web", score: 9.1, priority: "P1", tier: 1, exposure: "public", hops: 3, chain: CHAINS.web },
  { service: "batch", score: 2.4, priority: "P3", tier: 3, exposure: "internal", hops: 2, chain: CHAINS.batch },
];
const FLOW = [
  { type: "meta", mode: "scripted", tenant: "acme" },
  { type: "thought", text: "Checking exposure first." },
  { type: "tool_call", tool: "find_affected_services", input: { cve: "CVE-T-1" } },
  { type: "tool_result", tool: "find_affected_services", input: {}, queries: Q, error: false, graph: SUB,
    output: { cve: "CVE-T-1", total_services: 2, services: ranked.map(({ score, priority, ...r }) => r) } },
  { type: "tool_call", tool: "rank_services", input: { cve: "CVE-T-1" } },
  { type: "tool_result", tool: "rank_services", input: {}, queries: Q, error: false, graph: SUB, output: { cve: "CVE-T-1", ranked } },
  { type: "final", text: "**web** is the riskiest service.\n- web: P1\n- batch: P3" },
];

const json = (x, status = 200) => new Response(JSON.stringify(x), { status, headers: { "content-type": "application/json" } });
function sse(events, chunk = 37) {
  const bytes = new TextEncoder().encode(events.map((e) => `data: ${JSON.stringify(e)}\n\n`).join(""));
  let i = 0;
  const body = new ReadableStream({
    pull(ctl) {
      if (i >= bytes.length) return ctl.close();
      ctl.enqueue(bytes.slice(i, i + chunk));
      i += chunk;
    },
  });
  return new Response(body, { headers: { "content-type": "text/event-stream" } });
}

let chatEvents, calls;
beforeEach(() => {
  instances.length = 0;
  chatEvents = FLOW;
  calls = [];
  globalThis.fetch = vi.fn(async (url, opts) => {
    calls.push([String(url), opts]);
    const u = String(url);
    if (u.startsWith("/api/health")) return json({ ok: true, mode: "scripted", tenants: ["acme", "globex"] });
    if (u.startsWith("/api/suggestions")) return json({ cves: [{ cve: "CVE-T-1", severity: "CRITICAL", cvss: 9.5, services: 2 }] });
    if (u.startsWith("/api/decisions")) {
      return json({ decisions: u.includes("tenant=acme")
        ? [{ id: "d2", action: "patched", reasoning: "new view", created_at: Date.now() - 60000, cve: "CVE-T-0", service: "web", supersedes: "d1", superseded_by: null },
           { id: "d1", action: "accepted_risk", reasoning: "old view", created_at: Date.now() - 86400000, cve: "CVE-T-0", service: "web", superseded_by: "d2", supersedes: null }]
        : [] });
    }
    if (u.startsWith("/api/chat")) return typeof chatEvents === "function" ? chatEvents() : sse(chatEvents);
    return json({}, 404);
  });
});
afterEach(cleanup);

const triage = async () => {
  render(<App />);
  fireEvent.click(await screen.findByText(/Triage CVE-T-1/));
  await screen.findByText(/is the riskiest service/);
};

describe("triage UI", () => {
  it("shows the mode badge and quick-start suggestions from the API", async () => {
    render(<App />);
    expect(await screen.findByText("Scripted (no LLM)")).toBeTruthy();
    expect(await screen.findByText(/Triage CVE-T-1/)).toBeTruthy();
    expect(screen.getByText(/2 services, CRITICAL/)).toBeTruthy();
  });

  it("streams steps, the final answer, the ranking table and draws the graph", async () => {
    await triage();
    expect(screen.getByText("Checking exposure first.")).toBeTruthy();
    expect(screen.getByText("find_affected_services")).toBeTruthy();
    expect(screen.getByText("2 service(s) exposed")).toBeTruthy();
    expect(screen.getByText("top risk: web (P1)")).toBeTruthy();
    const table = screen.getByRole("table");
    expect(within(table).getByText("P1")).toBeTruthy();
    expect(within(table).getByText("9.1")).toBeTruthy();
    const cy = instances.at(-1);
    expect(cy.ids("nodes").sort()).toEqual(["CVE-T-1", "app@1", "batch", "lib@1", "web"]);
    expect(cy.ids("edges")).toHaveLength(4);
    expect(cy.layouts.length).toBeGreaterThan(0);
    // the first request carried the right body
    const body = JSON.parse(calls.find(([u]) => u.startsWith("/api/chat"))[1].body);
    expect(body.tenant).toBe("acme");
    expect(body.message).toMatch(/CVE-T-1/);
    expect(body.session_id).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("highlights the top-ranked chain automatically, and a different one when its row is clicked", async () => {
    await triage();
    const cy = instances.at(-1);
    expect(cy.classed("hl")).toEqual(["CVE-T-1", "app@1", "app@1>lib@1", "CVE-T-1>lib@1", "lib@1", "web", "web>app@1"].sort());
    expect(cy.classed("dim")).toEqual(["batch", "batch>lib@1"].sort());
    fireEvent.click(within(screen.getByRole("table")).getByText("batch"));
    await waitFor(() => expect(cy.classed("hl")).toEqual(["CVE-T-1", "CVE-T-1>lib@1", "batch", "batch>lib@1", "lib@1"].sort()));
    // the chain is also shown as readable breadcrumbs
    expect(screen.getByLabelText("Selected exposure chain").textContent).toContain("batch");
  });

  it("clicking a service node in the graph selects it", async () => {
    await triage();
    const cy = instances.at(-1);
    cy.tap("batch");
    await waitFor(() => expect(cy.classed("hl")).toContain("batch"));
  });

  it("Why? opens a drawer with the Cypher and raw result, and Escape closes it", async () => {
    await triage();
    fireEvent.click(screen.getAllByText("Why?")[0]);
    const drawer = await screen.findByRole("dialog");
    expect(within(drawer).getByText(/MATCH p = \(s:Service\)/)).toBeTruthy();
    expect(within(drawer).getByText(/params: \{"cve":"CVE-T-1"\}/)).toBeTruthy();
    expect(within(drawer).getByText("Cypher run against FalkorDB")).toBeTruthy();
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("renders model text safely: markdown works, HTML does not", async () => {
    chatEvents = [{ type: "final", text: "**bold** and <img src=x onerror=alert(1)> and `code`" }];
    render(<App />);
    fireEvent.click(await screen.findByText(/What should I worry about/));
    const bold = await screen.findByText("bold");
    expect(bold.tagName).toBe("STRONG");
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeTruthy();
  });

  it("switching tenant clears the chat and graph and reloads that tenant's memory", async () => {
    await triage();
    fireEvent.change(screen.getByLabelText("Tenant"), { target: { value: "globex" } });
    await screen.findByText(/Which of our services are really exposed/);
    expect(screen.queryByText(/is the riskiest service/)).toBeNull();
    await waitFor(() => expect(calls.some(([u]) => u === "/api/decisions?tenant=globex")).toBe(true));
    fireEvent.click(screen.getByRole("tab", { name: /Memory/ }));
    expect(await screen.findByText(/No decisions recorded for/)).toBeTruthy();
    fireEvent.click(screen.getAllByText(/Triage CVE-T-1/)[0]);
    await screen.findByText(/is the riskiest service/);
    const body = JSON.parse(calls.filter(([u]) => u.startsWith("/api/chat")).at(-1)[1].body);
    expect(body.tenant).toBe("globex");
  });

  it("memory tab shows decisions with supersede history", async () => {
    render(<App />);
    fireEvent.click(await screen.findByRole("tab", { name: /Memory \(2\)/ }));
    expect(await screen.findByText("replaces d1")).toBeTruthy();
    expect(screen.getByText("superseded by d2")).toBeTruthy();
    expect(screen.getByText("old view").closest("li").className).toContain("superseded");
  });

  it("shows a stream error in the chat and lets the user continue", async () => {
    chatEvents = [{ type: "meta", mode: "claude" }, { type: "error", message: "The Anthropic API key was rejected." }];
    render(<App />);
    fireEvent.click(await screen.findByText(/What should I worry about/));
    expect(await screen.findByText("The Anthropic API key was rejected.")).toBeTruthy();
    expect(screen.getByText("Claude agent")).toBeTruthy();
    await waitFor(() => expect(screen.getByRole("button", { name: "Send" })).toBeTruthy());
  });

  it("reports a stream that ends without a final answer", async () => {
    chatEvents = [{ type: "thought", text: "starting" }];
    render(<App />);
    fireEvent.click(await screen.findByText(/What should I worry about/));
    expect(await screen.findByText(/connection closed before the agent finished/)).toBeTruthy();
  });

  it("surfaces HTTP errors such as the rate limit", async () => {
    chatEvents = () => json({ error: "Rate limit: 30 requests per 10 minutes." }, 429);
    render(<App />);
    fireEvent.click(await screen.findByText(/What should I worry about/));
    expect(await screen.findByText(/Rate limit: 30 requests/)).toBeTruthy();
  });

  it("shows a helpful banner when the API is unreachable", async () => {
    globalThis.fetch = vi.fn(async () => { throw new TypeError("Failed to fetch"); });
    render(<App />);
    expect(await screen.findByText(/Cannot reach the API/)).toBeTruthy();
  });

  it("typing a message and pressing Send posts it", async () => {
    render(<App />);
    const input = await screen.findByLabelText("Message the triage agent");
    fireEvent.change(input, { target: { value: "we accepted the risk on batch" } });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await screen.findByText(/is the riskiest service/);
    const body = JSON.parse(calls.find(([u]) => u.startsWith("/api/chat"))[1].body);
    expect(body.message).toBe("we accepted the risk on batch");
    expect(input.value).toBe("");
  });
});
