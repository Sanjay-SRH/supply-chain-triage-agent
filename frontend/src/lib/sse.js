// Minimal Server-Sent Events parser for fetch() streams. Handles events split across chunks.
export function createSSEParser(onEvent) {
  let buf = "";
  return {
    push(chunk) {
      buf += chunk.replace(/\r\n/g, "\n");
      const parts = buf.split("\n\n");
      buf = parts.pop(); // the last piece may be an incomplete event
      for (const part of parts) {
        const data = part
          .split("\n")
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trimStart())
          .join("\n");
        if (!data) continue;
        try {
          onEvent(JSON.parse(data));
        } catch {
          /* ignore malformed event */
        }
      }
    },
  };
}
