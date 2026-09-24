import React from "react";
import ReactDOM from "react-dom/client";
import { configureTollbooth } from "@tollbooth-dpyc/web";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import "./index.css";
import { bootstrapTheme } from "./lib/theme";

// The shared account pieces (profile, session key, avatar) read who this site
// is from here. Storage keys stay under "excalibur:", so a held session key
// and a picked avatar survive the move to the package.
configureTollbooth({
  slug: "excalibur",
  appName: "eXcalibur",
  mcpUrl: import.meta.env.VITE_MCP_URL as string,
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
