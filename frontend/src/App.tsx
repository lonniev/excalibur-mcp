import { BrowserRouter, Routes, Route, Navigate, Outlet } from "react-router-dom";
import type { ServiceStatus } from "@tollbooth-dpyc/web";
import { AppShell } from "@tollbooth-dpyc/web/react";
import Nav from "./components/Nav";
import Hero from "./components/Hero";
import SchedulerLogSection from "./components/SchedulerLogSection";
import { lazy, Suspense } from "react";
import { Loader2 } from "lucide-react";
import PostsPage from "./components/PostsPage";
import { useT, WORDS } from "./i18n";
import { Tx } from "@tollbooth-dpyc/web/react";

// Each page past the post list is its own chunk, fetched the first time it opens.
const SnippetsPage = lazy(() => import("./components/SnippetsPage"));
const ConversationsPage = lazy(() => import("./components/ConversationsPage"));
const ContentEditorPage = lazy(() => import("./components/ContentEditorPage"));
const WalletPage = lazy(() => import("./components/WalletPage"));
const ProfilePage = lazy(() => import("./components/ProfilePage"));
const SchedulerPage = lazy(() => import("./components/SchedulerPage"));
const PerformancePage = lazy(() => import("./components/PerformancePage"));

// The session, the sign-in gate, the theme, the avatar and the debug log are
// the package's AppShell; eXcalibur brings its routes, its hero and its footer,
// and the scheduler controls it keeps in the debug log.
export default function App() {
  const t = useT();
  return (
    <AppShell
      theme="dark"
      gateOptions={{ welcome: t("ui.app.welcome") }}
      classNames={{ root: "bg-stone-50 dark:bg-zinc-950 text-stone-900 dark:text-zinc-100 transition-colors" }}
      footer={({ status }) => <Footer status={status} />}
      debug={{ children: <SchedulerLogSection /> }}
      signedOut={({ gate }) => (
        <>
          <TopBar />
          <main className="flex-1">
            <Hero />
            <div className="pb-16">{gate}</div>
          </main>
        </>
      )}
    >
      {() => (
        <BrowserRouter>
          <Routes>
            <Route element={<Layout />}>
              <Route index element={<PostsPage />} />
              <Route path="new" element={<ContentEditorPage kind="post" />} />
              <Route path="post/:postId" element={<ContentEditorPage kind="post" />} />
              <Route path="snippets" element={<SnippetsPage />} />
              <Route path="snippets/new" element={<ContentEditorPage kind="snippet" />} />
              <Route path="snippet/:snippetId" element={<ContentEditorPage kind="snippet" />} />
              <Route path="wallet" element={<WalletPage />} />
              <Route path="scheduler" element={<SchedulerPage />} />
              <Route path="performance" element={<PerformancePage />} />
              <Route path="conversations" element={<ConversationsPage />} />
              <Route path="profile" element={<ProfilePage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      )}
    </AppShell>
  );
}

function Layout() {
  return (
    <>
      <Nav />
      <main className="flex-1">
        <Suspense
          fallback={
            <div className="flex justify-center py-16 text-stone-400 dark:text-zinc-500">
              <Loader2 className="h-5 w-5 animate-spin" />
            </div>
          }
        >
          <Outlet />
        </Suspense>
      </main>
    </>
  );
}

function TopBar() {
  const t = useT();
  return (
    <header className="border-b border-stone-200 dark:border-zinc-800 px-4 py-3 flex items-center gap-2">
      <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
      <span className="font-semibold tracking-wide">eXcalibur</span>
      <span className="text-sm text-stone-400 dark:text-zinc-500">{t("ui.app.postsManager")}</span>
    </header>
  );
}

function Footer({ status }: { status: ServiceStatus | null }) {
  const t = useT();
  return (
    <footer className="border-t border-stone-100 px-4 py-3 text-center text-xs text-stone-400 dark:border-zinc-900 dark:text-zinc-600 space-y-0.5">
      <div>
        {t("ui.app.footerVersion", { version: __APP_VERSION__ })} · {__BUILD_COMMIT__}
        {status?.version && ` · MCP ${status.version}`}
        {status?.tollbooth_dpyc_version && ` · SDK ${status.tollbooth_dpyc_version}`}
      </div>
      <div>
        <Tx
          ns={WORDS}
          k="ui.app.footerMonetized"
          components={{
            tollbooth: (
              <a
                href="https://tollbooth-dpyc.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-600/80 hover:underline dark:text-amber-400/80"
              />
            ),
          }}
        />
      </div>
    </footer>
  );
}
