import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { buildStyle, chainEdgeIds, structureSignature, toElements } from "../lib/graph.js";

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const palette = () => ({
  text: css("--g-text"), version: css("--g-version"), edge: css("--g-edge"), cve: css("--g-cve"),
  service: css("--g-service"), p1: css("--g-p1"), p2: css("--g-p2"), p3: css("--g-p3"), hl: css("--g-hl"),
});

export default function GraphPanel({ graph, selected, onSelect }) {
  const box = useRef(null);
  const cyRef = useRef(null);
  const sigRef = useRef("");
  const selectRef = useRef(onSelect);
  selectRef.current = onSelect;
  const [failure, setFailure] = useState(null); // a graph error must never take the whole page down

  // Explicit layout area: never depend on Cytoscape deriving it from container padding/computed styles.
  const area = () => ({ x1: 0, y1: 0, w: Math.max(box.current?.clientWidth || 0, 320), h: Math.max(box.current?.clientHeight || 0, 240) });

  // Create the Cytoscape instance once.
  useEffect(() => {
    let cy;
    try {
      // layout "null": do not let Cytoscape run its default grid layout at construction time
      cy = cytoscape({ container: box.current, style: buildStyle(palette()), layout: { name: "null" }, wheelSensitivity: 0.3, minZoom: 0.2, maxZoom: 2.5 });
    } catch (e) {
      console.error("Graph failed to initialise", e);
      setFailure(String(e?.message || e));
      return undefined;
    }
    cy.on("tap", 'node[kind = "service"]', (e) => selectRef.current(e.target.id()));
    cyRef.current = cy;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const restyle = () => { try { cy.style(buildStyle(palette())); } catch (e) { console.error(e); } };
    mq.addEventListener("change", restyle);
    const ro = new ResizeObserver(() => { try { cy.resize(); } catch { /* ignore */ } });
    ro.observe(box.current);
    return () => {
      mq.removeEventListener("change", restyle);
      ro.disconnect();
      cy.destroy();
      cyRef.current = null;
      sigRef.current = "";
    };
  }, []);

  // Rebuild + re-layout only when nodes/edges were added; otherwise just refresh attributes (score, priority).
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const els = toElements(graph);
    const sig = structureSignature(graph);
    if (sig !== sigRef.current) {
      cy.batch(() => {
        cy.elements().remove();
        cy.add(els);
      });
      sigRef.current = sig;
      if (els.length) {
        try {
          cy.layout({ name: "breadthfirst", roots: '[kind = "cve"]', directed: false, padding: 24, spacingFactor: 1.15, animate: false, boundingBox: area() }).run();
          cy.fit(undefined, 24);
          setFailure(null);
        } catch (e) {
          console.error("Graph layout failed", e);
          try {
            cy.layout({ name: "grid", animate: false, boundingBox: area() }).run(); // simpler fallback layout
          } catch (e2) {
            setFailure(String(e2?.message || e2));
          }
        }
      }
    } else {
      els.forEach((el) => {
        if (el.group !== "nodes") return;
        const n = cy.getElementById(el.data.id);
        if (n.nonempty()) n.data(el.data);
      });
    }
  }, [graph]);

  // Highlight the selected service's chain; dim everything else.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    try {
      cy.elements().removeClass("hl dim");
      const chain = selected && graph.chains[selected];
      if (!chain) return;
      const ids = new Set(chain);
      const eids = chainEdgeIds(chain);
      cy.elements().addClass("dim");
      cy.elements().filter((el) => (el.isNode() ? ids.has(el.id()) : eids.has(el.id()))).removeClass("dim").addClass("hl");
    } catch (e) {
      console.error("Graph highlight failed", e);
    }
  }, [graph, selected]);

  const chain = selected ? graph.chains[selected] : null;
  const empty = Object.keys(graph.nodes).length === 0;
  return (
    <div className="graphpanel">
      <div className="graph-wrap">
        <div ref={box} className="graph" role="img" aria-label={graph.cve ? `Dependency paths exposing services to ${graph.cve}` : "Exposure graph"} />
        {empty && !failure && <div className="graph-empty">Exposure paths will be drawn here.<br />Ask about a CVE to begin.</div>}
        {failure && (
          <div className="graph-empty err" role="alert">
            The graph could not be drawn ({failure}).<br />Chat, ranking and the chain below still work.
          </div>
        )}
      </div>
      <div className="legend">
        <span><i className="lg diamond" /> CVE</span>
        <span><i className="lg rect" /> service (size = risk)</span>
        <span><i className="lg dot" /> package version</span>
        <span><i className="lg dash" /> AFFECTS</span>
        <span><i className="lg hl" /> selected chain</span>
      </div>
      {chain && (
        <div className="crumbs" aria-label="Selected exposure chain">
          {chain.map((c, i) => (
            <span key={i} className="crumb-wrap"><span className="crumb">{c}</span>{i < chain.length - 1 && <span className="arrow">→</span>}</span>
          ))}
        </div>
      )}
    </div>
  );
}
