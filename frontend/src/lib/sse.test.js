import test from "node:test";
import assert from "node:assert/strict";
import { createSSEParser } from "./sse.js";

const collect = () => {
  const events = [];
  return { events, parser: createSSEParser((e) => events.push(e)) };
};

test("parses complete events", () => {
  const { events, parser } = collect();
  parser.push('data: {"type":"a"}\n\ndata: {"type":"b"}\n\n');
  assert.deepEqual(events, [{ type: "a" }, { type: "b" }]);
});

test("handles an event split across chunks, even mid-JSON", () => {
  const { events, parser } = collect();
  parser.push('data: {"type":"fi');
  parser.push('nal","text":"hi"}');
  assert.equal(events.length, 0);
  parser.push("\n\n");
  assert.deepEqual(events, [{ type: "final", text: "hi" }]);
});

test("handles CRLF and ignores malformed or empty events", () => {
  const { events, parser } = collect();
  parser.push('data: {"type":"x"}\r\n\r\ndata: not json\n\n\n\n: comment\n\n');
  assert.deepEqual(events, [{ type: "x" }]);
});
