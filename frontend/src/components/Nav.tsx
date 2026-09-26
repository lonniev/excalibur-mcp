// eXcalibur's top bar: the package's SiteNav (the pages, the phone menu, the
// account menu) in eXcalibur's look, with the one thing only this site keeps
// there — the credit balance, re-read on every page change (a free call).

import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { checkBalance } from "@tollbooth-dpyc/web";
import { SiteNav, matchesPath, useAppShell, type SiteNavItem } from "@tollbooth-dpyc/web/react";
import { balanceChip, navStyles } from "../lib/packageStyles";

const PAGES: readonly SiteNavItem[] = [
  { href: "/", label: "Posts", end: true },
  { href: "/snippets", label: "Snippets" },
  { href: "/new", label: "Compose" },
  { href: "/performance", label: "Performance" },
  { href: "/scheduler", label: "Scheduler" },
  { href: "/wallet", label: "Wallet" },
];

const ACCOUNT_LINKS: readonly SiteNavItem[] = [
  { href: "/profile", label: "Profile & theme" },
  { href: "/wallet", label: "Wallet" },
];

export default function Nav() {
  const { session } = useAppShell();
  const { pathname } = useLocation();
  const [balance, setBalance] = useState<number | null>(null);

  useEffect(() => {
    let live = true;
    checkBalance()
      .then((b) => live && setBalance(b.balance_api_sats ?? null))
      .catch(() => live && setBalance(null));
    return () => {
      live = false;
    };
  }, [pathname]);

  return (
    <SiteNav
      brand={
        <Link to="/" className="flex items-center gap-2 mr-3">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
          <span className="font-semibold tracking-wide">eXcalibur</span>
        </Link>
      }
      items={PAGES}
      isActive={(href, item) => matchesPath(pathname, href, item.end)}
      renderLink={({ href, children, ...rest }) => (
        <Link to={href} {...rest}>
          {children}
        </Link>
      )}
      trailing={
        <Link to="/wallet" className={balanceChip} title="Credit balance">
          {balance === null ? "— sats" : `${balance.toLocaleString()} sats`}
        </Link>
      }
      account={{ npub: session.npub, links: ACCOUNT_LINKS, onSignOut: session.signOut }}
      classNames={navStyles}
    />
  );
}
