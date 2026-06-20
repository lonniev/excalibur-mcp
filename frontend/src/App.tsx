import { createContext, useContext, useEffect, useState } from "react";
import {
  getStoredNpub,
  isLoggedIn,
  logOut as mcpLogOut,
  serviceStatus,
  type ServiceStatus,
} from "./lib/mcp";
import NpubGate from "./components/NpubGate";
import PostsPage from "./components/PostsPage";

interface SessionCtx {
  npub: string;
  logOut: () => void;
}

const Ctx = createContext<SessionCtx | null>(null);

export function useSession(): SessionCtx {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSession must be used within <App>");
  return v;
}

export default function App() {
  const [loggedIn, setLoggedIn] = useState(isLoggedIn());
  const [npub, setNpub] = useState(getStoredNpub());
  const [status, setStatus] = useState<ServiceStatus | null>(null);

  useEffect(() => {
    serviceStatus().then(setStatus).catch(() => setStatus(null));
  }, []);

  function onLogin() {
    setNpub(getStoredNpub());
    setLoggedIn(true);
  }

  function logOut() {
    mcpLogOut();
    setNpub("");
    setLoggedIn(false);
  }

  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-white border-b border-stone-200 px-4 py-3 flex items-center gap-2">
        <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
        <span className="font-semibold tracking-wide text-stone-800">eXcalibur</span>
        <span className="text-sm text-stone-400">Editorial</span>
        <div className="ml-auto flex items-center gap-3 text-xs text-stone-400">
          {status?.lifecycle && (
            <span title={status.message}>{status.lifecycle}</span>
          )}
          {loggedIn && npub && (
            <>
              <span className="font-mono text-stone-500" title={npub}>
                {npub.slice(0, 12)}…
              </span>
              <button
                onClick={logOut}
                className="text-stone-400 hover:text-red-500 transition-colors"
              >
                Log out
              </button>
            </>
          )}
        </div>
      </header>

      <main className="flex-1">
        <Ctx.Provider value={{ npub, logOut }}>
          {loggedIn ? <PostsPage /> : <NpubGate onLogin={onLogin} />}
        </Ctx.Provider>
      </main>

      <footer className="px-4 py-2 text-center text-xs text-stone-300 border-t border-stone-100">
        eXcalibur Editorial v{__APP_VERSION__} · {__BUILD_COMMIT__}
        {status?.version && ` · MCP ${status.version}`}
        {status?.tollbooth_dpyc_version && ` · SDK ${status.tollbooth_dpyc_version}`}
      </footer>
    </div>
  );
}
