// A tiny stand-in for Cytoscape (jsdom has no canvas). It records what the app does to the graph
// so tests can assert on nodes, layout calls and which elements are highlighted.
export const instances = [];

class Coll {
  constructor(cy, els) { this.cy = cy; this.els = els; }
  remove() { this.cy.els = this.cy.els.filter((e) => !this.els.includes(e)); return this; }
  addClass(c) { c.split(" ").forEach((x) => this.els.forEach((e) => e.classes.add(x))); return this; }
  removeClass(c) { c.split(" ").forEach((x) => this.els.forEach((e) => e.classes.delete(x))); return this; }
  filter(fn) { return new Coll(this.cy, this.els.filter(fn)); }
  nonempty() { return this.els.length > 0; }
  data(d) { this.els.forEach((e) => Object.assign(e.data, d)); }
}

export default function cytoscape() {
  const cy = {
    els: [], handlers: {}, layouts: [], destroyed: false,
    on(ev, sel, fn) { cy.handlers[`${ev}:${sel}`] = fn; },
    style() {}, resize() {}, fit() {}, batch(fn) { fn(); },
    destroy() { cy.destroyed = true; },
    elements() { return new Coll(cy, cy.els); },
    add(arr) {
      arr.forEach((a) => cy.els.push({ group: a.group, data: { ...a.data }, classes: new Set(),
        isNode() { return this.group === "nodes"; }, id() { return this.data.id; } }));
    },
    layout(o) { cy.layouts.push(o); return { run() {} }; },
    getElementById(id) { return new Coll(cy, cy.els.filter((e) => e.id() === id)); },
    // test helpers
    ids(kind) { return cy.els.filter((e) => (kind === "nodes" ? e.isNode() : !e.isNode())).map((e) => e.id()); },
    classed(cls) { return cy.els.filter((e) => e.classes.has(cls)).map((e) => e.id()).sort(); },
    tap(id) { cy.handlers['tap:node[kind = "service"]']({ target: { id: () => id } }); },
  };
  instances.push(cy);
  return cy;
}
