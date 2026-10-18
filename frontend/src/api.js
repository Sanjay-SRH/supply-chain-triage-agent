import { createSSEParser } from "./lib/sse.js";

async function getJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.json();
}

export const getHealth = () => getJSON("/api/health");
export const getSuggestions = (tenant) => getJSON(`/api/suggestions?tenant=${encodeURIComponent(tenant)}`);
export const getDecisions = (tenant) => getJSON(`/api/decisions?tenant=${encodeURIComponent(tenant)}`);

export const newSessionId = () => `s${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;

// POST the question and call onEvent for every server-sent event until the stream closes.
export async function streamChat({ message, tenant, sessionId, onEvent, signal }) {
  const res = await fetch("/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, tenant, session_id: sessionId }),
    signal,
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const j = await res.json();
      msg = j.error || (Array.isArray(j.detail) ? j.detail[0]?.msg : j.detail) || msg;
    } catch {
      /* keep the HTTP status */
    }
    throw new Error(String(msg));
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const parser = createSSEParser(onEvent);
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parser.push(decoder.decode(value, { stream: true }));
  }
}
