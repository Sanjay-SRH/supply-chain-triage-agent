import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { StrictMode } from "react";
import ChatPanel from "./components/ChatPanel.jsx";
import ErrorBoundary from "./components/ErrorBoundary.jsx";

afterEach(cleanup);
const props = { messages: [], busy: false, suggestions: [], tenant: "acme", onSend() {}, onStop() {}, onWhy() {} };

describe("browsers where scrollIntoView() returns a value", () => {
  it("does not crash on mount, update or unmount (regression: 'destroy is not a function')", () => {
    const original = Element.prototype.scrollIntoView;
    Element.prototype.scrollIntoView = () => Promise.resolve("not undefined");
    try {
      const { rerender, unmount } = render(<StrictMode><ErrorBoundary><ChatPanel {...props} /></ErrorBoundary></StrictMode>);
      rerender(<StrictMode><ErrorBoundary><ChatPanel {...props} messages={[{ id: "1", role: "user", text: "hi" }]} /></ErrorBoundary></StrictMode>);
      expect(screen.queryByRole("alert")).toBeNull();
      expect(screen.getByText("hi")).toBeTruthy();
      unmount();
    } finally {
      Element.prototype.scrollIntoView = original;
    }
  });
});
