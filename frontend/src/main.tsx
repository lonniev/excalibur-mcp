import React from "react";
import ReactDOM from "react-dom/client";
import { configureTollbooth } from "@tollbooth-dpyc/web";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import "./index.css";
import { bootstrapTheme } from "./lib/theme";

// The MCP client, the sign-in gate and the account pieces read who this site
// is from here. Storage keys stay under "excalibur:" (patron_npub:v1,
// proof_token:v1, recent-logins:v1, session_nsec:v1), so nobody signed in
// before the move to the package is signed out by it.
configureTollbooth({
  slug: "excalibur",
  appName: "eXcalibur",
  mcpUrl: import.meta.env.VITE_MCP_URL as string,
  // The scheduler-log poll feeds the debug panel its own entries, and the
  // editor's @handle lookup is background personalization: logging either
  // call would only bury what the patron did.
  quietTools: ["get_scheduler_log", "get_x_profile"],
});

// Apply the saved theme (dark by default) before first paint — no flash.
bootstrapTheme();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
);
