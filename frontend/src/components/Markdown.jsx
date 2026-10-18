import { Fragment } from "react";
import { parseBlocks, tokenizeInline } from "../lib/format.js";

// Renders a tiny markdown subset as React elements (never innerHTML), so model output cannot inject HTML.
function Inline({ text }) {
  return tokenizeInline(text).map((t, i) =>
    t.t === "bold" ? <strong key={i}>{t.v}</strong> : t.t === "code" ? <code key={i}>{t.v}</code> : <Fragment key={i}>{t.v}</Fragment>,
  );
}

export default function Markdown({ text }) {
  return (
    <div className="md">
      {parseBlocks(text).map((b, i) =>
        b.type === "list" ? (
          <ul key={i}>{b.items.map((it, j) => <li key={j}><Inline text={it} /></li>)}</ul>
        ) : b.type === "gap" ? (
          <div key={i} className="gap" />
        ) : (
          <p key={i}><Inline text={b.text} /></p>
        ),
      )}
    </div>
  );
}
