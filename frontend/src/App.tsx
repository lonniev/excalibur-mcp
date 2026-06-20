import { createContext, useContext, useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, Outlet } from "react-router-dom";
import {
  getStoredNpub,
  isLoggedIn,
  logOut as mcpLogOut,
  serviceStatus,
  type ServiceStatus,
} from "./lib/mcp";
import Nav from "./components/Nav";
import NpubGate from "./components/NpubGate";
import PostsPage from "./components/PostsPage";
import PostEditorPage from "./components/PostEditorPage";
import WalletPage from "./components/WalletPage";
import ProfilePage from "./components/ProfilePage";

interface SessionCtx {
  npub: string;
  status: ServiceStatus | null;
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
    <div className="min-h-screen flex flex-col bg-stone-50 dark:bg-zinc-950 text-stone-900 dark:text-zinc-100 transition-colors">
      <Ctx.Provider value={{ npub, status, logOut }}>
        {loggedIn ? (
          <BrowserRouter>
            <Routes>
              <Route element={<Layout />}>
                <Route index element={<PostsPage />} />
                <Route path="new" element={<PostEditorPage />} />
                <Route path="post/:postId" element={<PostEditorPage />} />
                <Route path="wallet" element={<WalletPage />} />
                <Route path="profile" element={<ProfilePage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </BrowserRouter>
        ) : (
          <>
            <TopBar />
            <main className="flex-1">
              <NpubGate onLogin={onLogin} />
            </main>
            <Footer status={status} />
          </>
        )}
      </Ctx.Provider>
    </div>
  );
}

function Layout() {
  const { status } = useSession();
  return (
    <>
      <Nav />
      <main className="flex-1">
        <Outlet />
      </main>
      <Footer status={status} />
    </>
  );
}

function TopBar() {
  return (
    <header className="border-b border-stone-200 dark:border-zinc-800 px-4 py-3 flex items-center gap-2">
      <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
      <span className="font-semibold tracking-wide">eXcalibur</span>
      <span className="text-sm text-stone-400 dark:text-zinc-500">Editorial</span>
    </header>
  );
}

function Footer({ status }: { status: ServiceStatus | null }) {
  return (
    <footer className="px-4 py-2 text-center text-xs text-stone-400 dark:text-zinc-600 border-t border-stone-100 dark:border-zinc-900">
      eXcalibur Editorial v{__APP_VERSION__} · {__BUILD_COMMIT__}
      {status?.version && ` · MCP ${status.version}`}
      {status?.tollbooth_dpyc_version && ` · SDK ${status.tollbooth_dpyc_version}`}
    </footer>
  );
}
