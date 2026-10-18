import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import ErrorBoundary from "./components/ErrorBoundary.jsx";

afterEach(cleanup);
const Boom = () => { throw new Error("kaboom in render"); };

describe("ErrorBoundary", () => {
  it("shows the error instead of a blank page", () => {
    vi.spyOn(console, "error").mockImplementation(() => {});
    render(<ErrorBoundary><Boom /></ErrorBoundary>);
    expect(screen.getByRole("alert").textContent).toMatch(/kaboom in render/);
    expect(screen.getByRole("button", { name: "Reload" })).toBeTruthy();
  });
  it("renders children normally", () => {
    render(<ErrorBoundary><p>fine</p></ErrorBoundary>);
    expect(screen.getByText("fine")).toBeTruthy();
  });
});
