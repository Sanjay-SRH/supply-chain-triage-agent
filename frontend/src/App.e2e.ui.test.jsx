// Opt-in end-to-end test: the real React app against the REAL running API and FalkorDB.
//   1) start the API (scripted mode is fine):  uvicorn backend.api:app --port 8000
//   2) cd frontend && npm run test:e2e
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { instances } from "./test-utils/fakeCytoscape.js";

vi.mock("cytoscape", async () => import("./test-utils/fakeCytoscape.js"));
import App from "./App.jsx";

const API = process.env.E2E_API;
afterEach(cleanup);

describe.skipIf(!API)("UI against the real API", () => {
  it("triages the most exposed CVE end to end", async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = (url, opts) => realFetch(String(url).startsWith("/") ? API + url : url, opts);
    render(<App />);
    const chip = (await screen.findAllByText(/^Triage CVE-/, {}, { timeout: 8000 }))[0];
    fireEvent.click(chip);
    await screen.findByText(/Riskiest services/, {}, { timeout: 15000 });
    expect(screen.getAllByText("Why?").length).toBeGreaterThanOrEqual(5);
    const rows = within(screen.getByRole("table")).getAllByRole("row");
    expect(rows.length).toBeGreaterThan(3);
    const cy = instances.at(-1);
    expect(cy.ids("nodes").length).toBeGreaterThan(10);
    expect(cy.classed("hl").length).toBeGreaterThan(3);   // top-ranked chain is highlighted
    fireEvent.click(screen.getAllByText("Why?")[0]);
    expect((await screen.findByRole("dialog")).textContent).toMatch(/MATCH/);
  }, 30000);
});
