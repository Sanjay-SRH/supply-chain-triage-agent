import { useEffect, useRef, useState } from "react";

const chainOf = (out) => out?.chain || out?.services?.[0]?.chain || out?.ranked?.[0]?.chain || null;
const copy = (t) => navigator.clipboard?.writeText(t).catch(() => {});

// Side drawer that shows exactly how an answer was produced: the tool input, every Cypher query run, and the raw result.
export default function WhyDrawer({ step, onClose }) {
  const [full, setFull] = useState(false);
  const closeRef = useRef(null);
  useEffect(() => {
    closeRef.current?.focus();
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const json = JSON.stringify(step.output, null, 2);
  const shown = full || json.length <= 3000 ? json : json.slice(0, 3000) + "\n… (truncated)";
  const chain = chainOf(step.output);

  return (
    <div className="overlay" onClick={onClose}>
      <aside className="drawer" role="dialog" aria-label="Why this answer" onClick={(e) => e.stopPropagation()}>
        <header>
          <h2>Why this answer?</h2>
          <button ref={closeRef} className="secondary" onClick={onClose} aria-label="Close">✕</button>
        </header>
        <h3>Tool called</h3>
        <pre>{step.tool}({JSON.stringify(step.input)})</pre>
        {chain && (
          <>
            <h3>Path it followed</h3>
            <div className="crumbs">{chain.map((c, i) => <span key={i} className="crumb">{c}</span>)}</div>
          </>
        )}
        <h3>Cypher run against FalkorDB</h3>
        {step.queries.map((q, i) => (
          <div key={i} className="query">
            <div className="query-head">
              <code>{q.name}</code>
              <button className="secondary small" onClick={() => copy(q.cypher)}>Copy</button>
            </div>
            <pre>{q.cypher}</pre>
            <div className="muted small">params: {JSON.stringify(q.params)}</div>
          </div>
        ))}
        <h3>Raw result</h3>
        <pre>{shown}</pre>
        {json.length > 3000 && <button className="secondary small" onClick={() => setFull(!full)}>{full ? "Show less" : "Show all"}</button>}
      </aside>
    </div>
  );
}
