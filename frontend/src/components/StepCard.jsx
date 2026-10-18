import { summarize, summarizeInput } from "../lib/format.js";

// One tool call the agent made: what it asked, what came back, and a Why? button for the Cypher behind it.
export default function StepCard({ step, onWhy }) {
  const icon = step.status === "running" ? <span className="spinner" aria-label="running" /> : step.status === "error" ? "⚠" : "✓";
  return (
    <div className={`step ${step.status}`}>
      <span className="step-icon">{icon}</span>
      <div className="step-body">
        <div className="step-title">
          <code>{step.tool}</code>
          <span className="step-input">{summarizeInput(step.input)}</span>
        </div>
        {step.status !== "running" && <div className="step-out">{summarize(step.tool, step.output)}</div>}
      </div>
      {step.status !== "running" && step.queries?.length > 0 && (
        <button className="why" onClick={() => onWhy(step)} title="Show the Cypher and raw result behind this step">Why?</button>
      )}
    </div>
  );
}
