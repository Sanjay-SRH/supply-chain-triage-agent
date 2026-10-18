import { relativeTime } from "../lib/format.js";

export default function DecisionsPanel({ decisions, tenant, error }) {
  if (error) return <p className="err pad">{error}</p>;
  if (!decisions.length) return <p className="muted pad">No decisions recorded for <b>{tenant}</b> yet. Tell the agent what you decided and it will remember.</p>;
  return (
    <ul className="decisions">
      {decisions.map((d) => (
        <li key={d.id} className={d.superseded_by ? "superseded" : ""}>
          <div className="d-head">
            <span className={`badge action ${d.action}`}>{d.action.replaceAll("_", " ")}</span>
            <b>{d.service}</b> <span className="muted">on {d.cve}</span>
            <span className="muted right">{relativeTime(d.created_at)}</span>
          </div>
          <div className="d-why">{d.reasoning}</div>
          {d.supersedes && <div className="muted small">replaces {d.supersedes}</div>}
          {d.superseded_by && <div className="muted small">superseded by {d.superseded_by}</div>}
        </li>
      ))}
    </ul>
  );
}
