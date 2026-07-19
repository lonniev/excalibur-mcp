// Last-resort guard so a stray render-time throw can never white-screen the app.
// Data-loading paths already catch their own failures and show inline banners
// (a Neon 402 / denied-service state renders as a message, not a crash); this
// only catches what those miss — an unexpected error thrown during render — and
// shows a calm retry card instead of a blank page.

import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}
interface State {
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Surface it for diagnostics; the console is the only sink we have client-side.
    console.error("Unhandled render error:", error, info.componentStack);
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex min-h-screen items-center justify-center bg-white p-6 text-stone-800 dark:bg-zinc-950 dark:text-zinc-200">
        <div className="max-w-md space-y-4 text-center">
          <h1 className="text-lg font-semibold">Something went sideways</h1>
          <p className="text-sm text-stone-500 dark:text-zinc-400">
            The page hit an unexpected error. Your work is saved locally — reloading usually clears it.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="rounded-md bg-amber-400 px-4 py-2 text-sm font-medium text-zinc-950 transition-colors hover:bg-amber-300"
          >
            Reload
          </button>
        </div>
      </div>
    );
  }
}
