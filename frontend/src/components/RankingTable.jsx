export default function RankingTable({ table, selected, onSelect }) {
  if (!table?.rows?.length) return <p className="muted pad">Exposed services appear here, ranked by risk, once you triage a CVE.</p>;
  const ranked = table.rows.some((r) => r.score !== undefined);
  return (
    <div className="scroll">
      <table>
        <caption className="sr-only">Services exposed to {table.cve}</caption>
        <thead>
          <tr>
            {ranked && <th>Priority</th>}
            <th>Service</th><th>Tier</th><th>Exposure</th><th>Hops</th>{ranked && <th>Score</th>}
          </tr>
        </thead>
        <tbody>
          {table.rows.map((r) => (
            <tr key={r.service} className={r.service === selected ? "selected" : ""} onClick={() => onSelect(r.service)}
                tabIndex={0} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelect(r.service)} aria-selected={r.service === selected}>
              {ranked && <td><span className={`badge ${r.priority}`}>{r.priority}</span></td>}
              <td><b>{r.service}</b></td><td>{r.tier}</td><td>{r.exposure}</td><td>{r.hops}</td>{ranked && <td>{r.score}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
