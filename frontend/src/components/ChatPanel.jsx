import { useEffect, useRef, useState } from "react";
import Markdown from "./Markdown.jsx";
import StepCard from "./StepCard.jsx";

const triagePrompt = (cve) =>
  `Triage ${cve}: who is exposed, what is the riskiest service and why, who owns it, and have we seen this before?`;

export default function ChatPanel({ messages, busy, suggestions, onSend, onStop, onWhy, tenant }) {
  const [text, setText] = useState("");
  const endRef = useRef(null);
  useEffect(() => {
    // Block body on purpose: an effect must return nothing or a cleanup function. Returning the result of
    // scrollIntoView() (a Promise in some browsers) makes React crash with "destroy is not a function".
    endRef.current?.scrollIntoView?.({ behavior: "smooth", block: "end" });
  }, [messages]);

  const submit = (e) => {
    e.preventDefault();
    const t = text.trim();
    if (!t || busy) return;
    setText("");
    onSend(t);
  };

  return (
    <div className="chat">
      <div className="messages" aria-live="polite">
        {messages.length === 0 && (
          <div className="empty">
            <h2>Which of our services are really exposed?</h2>
            <p>
              Ask about a CVE or a package. The agent walks the dependency graph, shows the exact chain behind each
              answer, and remembers earlier decisions for <b>{tenant}</b>.
            </p>
            <div className="chips">
              {suggestions.map((s) => (
                <button key={s.cve} className="chip" onClick={() => onSend(triagePrompt(s.cve))} disabled={busy}>
                  Triage {s.cve} <span className="muted">({s.services} services, {s.severity})</span>
                </button>
              ))}
              <button className="chip" onClick={() => onSend("What should I worry about right now?")} disabled={busy}>
                What should I worry about?
              </button>
            </div>
          </div>
        )}
        {messages.map((m) =>
          m.role === "user" ? (
            <div key={m.id} className="bubble user">{m.text}</div>
          ) : (
            <div key={m.id} className={`bubble agent ${m.status}`}>
              {m.notes.map((n, i) => <p key={i} className="note">{n}</p>)}
              {m.steps.length > 0 && (
                <div className="steps">{m.steps.map((s) => <StepCard key={s.id} step={s} onWhy={onWhy} />)}</div>
              )}
              {m.status === "streaming" && !m.text && <div className="thinking"><span className="spinner" /> working…</div>}
              {m.text && (m.status === "error" ? <p className="err">{m.text}</p> : <Markdown text={m.text} />)}
            </div>
          ),
        )}
        <div ref={endRef} />
      </div>
      <form className="composer" onSubmit={submit}>
        <input
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="e.g. Triage CVE-2021-23337, or: we accepted the risk on gateway because it is internal-only"
          aria-label="Message the triage agent"
          maxLength={2000}
        />
        {busy ? (
          <button type="button" onClick={onStop} className="secondary">Stop</button>
        ) : (
          <button type="submit" disabled={!text.trim()}>Send</button>
        )}
      </form>
    </div>
  );
}
