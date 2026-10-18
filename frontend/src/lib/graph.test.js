import test from "node:test";
import assert from "node:assert/strict";
import cytoscape from "cytoscape";
import { buildStyle, chainEdgeIds, emptyGraph, mergeGraph, nodeSize, structureSignature, toElements } from "./graph.js";

const sub = (cve, extra = {}) => ({
  cve,
  nodes: [
    { id: "web", kind: "service", label: "web", tier: 1, exposure: "public" },
    { id: "lib@1", kind: "version", label: "lib@1", vulnerable: true },
    { id: cve, kind: "cve", label: cve },
  ],
  edges: [
    { id: "web>lib@1", source: "web", target: "lib@1", type: "USES" },
    { id: `${cve}>lib@1`, source: cve, target: "lib@1", type: "AFFECTS" },
  ],
  chains: { web: ["web", "lib@1", cve] },
  ...extra,
});

test("merge adds attributes from later results (e.g. score from ranking)", () => {
  let g = mergeGraph(emptyGraph(), sub("CVE-1"));
  g = mergeGraph(g, { ...sub("CVE-1"), nodes: [{ id: "web", kind: "service", label: "web", score: 9, priority: "P1" }], edges: [], chains: {} });
  assert.equal(g.nodes.web.score, 9);
  assert.equal(g.nodes.web.exposure, "public"); // earlier attribute kept
  assert.equal(Object.keys(g.nodes).length, 3);
});

test("a different CVE starts a fresh graph", () => {
  const g1 = mergeGraph(emptyGraph(), sub("CVE-1"));
  const g2 = mergeGraph(g1, sub("CVE-2"));
  assert.equal(g2.cve, "CVE-2");
  assert.ok(!("CVE-1" in g2.nodes));
});

test("node size grows with score and is capped", () => {
  assert.ok(nodeSize({ kind: "service", score: 10 }) > nodeSize({ kind: "service", score: 1 }));
  assert.equal(nodeSize({ kind: "service", score: 1000 }), 64);
  assert.equal(nodeSize({ kind: "cve" }), 48);
});

test("structure signature ignores attribute changes but sees new nodes", () => {
  const a = mergeGraph(emptyGraph(), sub("CVE-1"));
  const b = mergeGraph(a, { ...sub("CVE-1"), nodes: [{ id: "web", score: 5 }], edges: [], chains: {} });
  assert.equal(structureSignature(a), structureSignature(b));
  const c = mergeGraph(a, { cve: "CVE-1", nodes: [{ id: "x", kind: "service", label: "x" }], edges: [], chains: {} });
  assert.notEqual(structureSignature(a), structureSignature(c));
});

test("chainEdgeIds covers both orientations", () => {
  const ids = chainEdgeIds(["web", "lib@1", "CVE-1"]);
  assert.ok(ids.has("web>lib@1") && ids.has("CVE-1>lib@1") && ids.has("lib@1>CVE-1"));
});

test("Cytoscape accepts our style and elements, lays them out, and highlights one chain", () => {
  const g = mergeGraph(emptyGraph(), sub("CVE-1"));
  g.nodes.web.priority = "P1";
  const colors = Object.fromEntries(["text", "version", "edge", "cve", "service", "p1", "p2", "p3", "hl"].map((k) => [k, "#888888"]));
  const cy = cytoscape({ headless: true, elements: toElements(g), style: buildStyle(colors) });
  cy.layout({ name: "breadthfirst", roots: "#CVE-1", directed: false }).run();
  assert.equal(cy.nodes().length, 3);
  assert.equal(cy.edges().length, 2);
  assert.ok(cy.nodes().every((n) => Number.isFinite(n.position("x"))));
  assert.equal(cy.$('node[priority = "P1"]').length, 1);
  assert.equal(cy.$("node[?vulnerable]").length, 1);

  const chain = g.chains.web;
  const ids = new Set(chain);
  const eids = chainEdgeIds(chain);
  cy.elements().addClass("dim");
  const hl = cy.elements().filter((el) => (el.isNode() ? ids.has(el.id()) : eids.has(el.id())));
  hl.removeClass("dim").addClass("hl");
  assert.equal(cy.$(".hl").length, 5);
  assert.equal(cy.$(".dim").length, 0);
});
