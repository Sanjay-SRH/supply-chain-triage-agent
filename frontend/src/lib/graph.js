// Pure graph helpers shared by the UI and its tests.
export const emptyGraph = () => ({ cve: null, nodes: {}, edges: {}, chains: {} });

// Merge a subgraph from a tool result into the current graph. A different CVE starts a fresh graph.
export function mergeGraph(current, sub) {
  const base = current.cve === sub.cve ? current : emptyGraph();
  const nodes = { ...base.nodes };
  for (const n of sub.nodes) nodes[n.id] = { ...nodes[n.id], ...n };
  const edges = { ...base.edges };
  for (const e of sub.edges) edges[e.id] = e;
  return { cve: sub.cve, nodes, edges, chains: { ...base.chains, ...sub.chains } };
}

// Node size grows with risk score so the riskiest services stand out.
export function nodeSize(n) {
  if (n.kind === "cve") return 48;
  if (n.kind === "service") return 30 + Math.min(34, (n.score || 0) * 2);
  return 22;
}

export function toElements(graph) {
  const nodes = Object.values(graph.nodes).map((n) => ({
    group: "nodes",
    data: { ...n, size: nodeSize(n), bw: n.exposure === "public" ? 3 : 1 },
  }));
  const edges = Object.values(graph.edges).map((e) => ({ group: "edges", data: { ...e } }));
  return [...nodes, ...edges];
}

// Ids of the edges that make up one chain (the AFFECTS edge is stored CVE -> version, i.e. reversed).
export function chainEdgeIds(chain) {
  const ids = new Set();
  for (let i = 0; i < chain.length - 1; i++) {
    ids.add(`${chain[i]}>${chain[i + 1]}`);
    ids.add(`${chain[i + 1]}>${chain[i]}`);
  }
  return ids;
}

// Cheap signature of the *structure* so we only re-run the layout when nodes/edges were added.
export function structureSignature(graph) {
  return [graph.cve, Object.keys(graph.nodes).sort().join("|"), Object.keys(graph.edges).sort().join("|")].join("::");
}

export function buildStyle(c) {
  return [
    { selector: "node", style: { label: "data(label)", "font-size": 10, color: c.text, "text-valign": "bottom", "text-margin-y": 4,
        "text-wrap": "ellipsis", "text-max-width": 110, "background-color": c.version, width: 22, height: 22,
        "border-width": 1, "border-color": c.edge } },
    { selector: 'node[kind = "cve"]', style: { shape: "diamond", width: 48, height: 48, "background-color": c.cve,
        "font-weight": "bold", "font-size": 11, "border-width": 0 } },
    { selector: 'node[kind = "service"]', style: { shape: "round-rectangle", width: "data(size)", height: "data(size)",
        "background-color": c.service, "border-width": "data(bw)", "border-color": c.edge } },
    { selector: 'node[priority = "P1"]', style: { "background-color": c.p1 } },
    { selector: 'node[priority = "P2"]', style: { "background-color": c.p2 } },
    { selector: 'node[priority = "P3"]', style: { "background-color": c.p3 } },
    { selector: "node[?vulnerable]", style: { "border-color": c.cve, "border-width": 3 } },
    { selector: "edge", style: { width: 1.5, "line-color": c.edge, "target-arrow-color": c.edge,
        "target-arrow-shape": "triangle", "curve-style": "bezier", "arrow-scale": 0.8 } },
    { selector: 'edge[type = "AFFECTS"]', style: { "line-style": "dashed", "line-color": c.cve, "target-arrow-color": c.cve } },
    { selector: ".dim", style: { opacity: 0.18 } },
    { selector: "node.hl", style: { "border-color": c.hl, "border-width": 4, opacity: 1 } },
    { selector: "edge.hl", style: { "line-color": c.hl, "target-arrow-color": c.hl, width: 4, opacity: 1, "line-style": "solid" } },
  ];
}
