import { useEffect, useRef, useState } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { useSession } from "../App";
import { checkBalance } from "../lib/mcp";
import Avatar from "./Avatar";
import { avatarFor, AVATAR_EVENT } from "../lib/avatar";

export default function Nav() {
  const { npub, logOut } = useSession();
  const loc = useLocation();
  const [balance, setBalance] = useState<number | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [avatar, setAvatar] = useState(() => avatarFor(npub));
  const menuRef = useRef<HTMLDivElement>(null);

  // Keep the avatar in sync with the picker (same-tab custom event) and npub.
  useEffect(() => {
    setAvatar(avatarFor(npub));
    const h = () => setAvatar(avatarFor(npub));
    window.addEventListener(AVATAR_EVENT, h);
    return () => window.removeEventListener(AVATAR_EVENT, h);
  }, [npub]);

  // Refresh balance on navigation (cheap, free tool).
  useEffect(() => {
    let live = true;
    checkBalance()
      .then((b) => live && setBalance(b.balance_api_sats ?? null))
      .catch(() => live && setBalance(null));
    return () => {
      live = false;
    };
  }, [loc.pathname]);

  useEffect(() => {
    if (!menuOpen) return;
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [menuOpen]);

  const tab = (to: string, label: string, end = false) => (
    <NavLink
      to={to}
      end={end}
      className={({ isActive }) =>
        `px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
          isActive
            ? "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400"
            : "text-stone-500 hover:text-stone-900 hover:bg-stone-100 dark:text-zinc-400 dark:hover:text-zinc-100 dark:hover:bg-zinc-800"
        }`
      }
    >
      {label}
    </NavLink>
  );

  return (
    <header className="border-b border-stone-200 dark:border-zinc-800 px-4 py-2.5 flex items-center gap-1.5 flex-wrap">
      <Link to="/" className="flex items-center gap-2 mr-3">
        <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
        <span className="font-semibold tracking-wide">eXcalibur</span>
      </Link>

      {tab("/", "Posts", true)}
      {tab("/snippets", "Snippets")}
      {tab("/new", "Compose")}
      {tab("/scheduler", "Scheduler")}
      {tab("/wallet", "Wallet")}

      <div className="ml-auto flex items-center gap-3">
        <Link
          to="/wallet"
          className="text-sm tabular-nums text-stone-500 dark:text-zinc-400 hover:text-amber-600 dark:hover:text-amber-400 transition-colors"
          title="Credit balance"
        >
          {balance === null ? "— sats" : `${balance.toLocaleString()} sats`}
        </Link>

        <div className="relative" ref={menuRef}>
          <button onClick={() => setMenuOpen((o) => !o)} title={npub} className="block rounded-full">
            <Avatar value={avatar} size={32} />
          </button>
          {menuOpen && (
            <div className="absolute right-0 top-full mt-1.5 w-56 rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-lg overflow-hidden z-40">
              <div className="px-3 py-2 border-b border-stone-100 dark:border-zinc-800">
                <div className="text-xs text-stone-400 dark:text-zinc-500">Nostr identity</div>
                <div className="text-xs font-mono truncate text-stone-600 dark:text-zinc-300" title={npub}>
                  {npub}
                </div>
              </div>
              <Link
                to="/profile"
                onClick={() => setMenuOpen(false)}
                className="block px-3 py-2 text-sm text-stone-600 dark:text-zinc-300 hover:bg-stone-50 dark:hover:bg-zinc-800 transition-colors"
              >
                Profile &amp; theme
              </Link>
              <Link
                to="/wallet"
                onClick={() => setMenuOpen(false)}
                className="block px-3 py-2 text-sm text-stone-600 dark:text-zinc-300 hover:bg-stone-50 dark:hover:bg-zinc-800 transition-colors"
              >
                Wallet
              </Link>
              <button
                onClick={() => {
                  setMenuOpen(false);
                  logOut();
                }}
                className="w-full text-left px-3 py-2 text-sm text-stone-600 dark:text-zinc-300 hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-500/10 dark:hover:text-red-400 transition-colors"
              >
                Log out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
