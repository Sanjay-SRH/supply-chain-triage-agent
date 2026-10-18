import { Component } from "react";

// Last line of defence: if anything in the UI throws while rendering, show the error instead of a blank page.
// React may report a SECOND error while tearing the broken tree down, so we keep the FIRST one (the root cause).
export default class ErrorBoundary extends Component {
  state = { error: null };
  first = null;

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    if (!this.first) this.first = { error, stack: info?.componentStack };
    console.error("UI crashed:", error, info?.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    const root = this.first?.error ?? error;
    return (
      <div className="crash" role="alert">
        <h1>Something went wrong in the UI</h1>
        <p>The app hit an error and stopped drawing. Copy the message below when asking for help.</p>
        <pre>{String(root?.stack || root?.message || root)}</pre>
        {this.first?.stack && <pre>{"Component stack:" + this.first.stack}</pre>}
        <button onClick={() => window.location.reload()}>Reload</button>
      </div>
    );
  }
}
