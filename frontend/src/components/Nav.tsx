// eXcalibur's top bar: the package's SiteNav (the pages, the phone menu, the
// account menu) in eXcalibur's look, with the one thing only this site keeps
// there — the credit balance, re-read on every page change (a free call).

import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import { checkBalance } from "@tollbooth-dpyc/web";
import { SiteNav, matchesPath, useAppShell, useLanguageLocale, type SiteNavItem } from "@tollbooth-dpyc/web/react";
import { balanceChip, navStyles } from "../lib/packageStyles";
import { useT } from "../i18n";

export default function Nav() {
  const t = useT();
  const locale = useLanguageLocale();
  // Built at render, so the words follow a language change.
  const pages: readonly SiteNavItem[] = [
    { href: "/", label: t("ui.nav.posts"), end: true },
    { href: "/snippets", label: t("ui.nav.snippets") },
    { href: "/new", label: t("ui.nav.compose") },
    { href: "/performance", label: t("ui.nav.performance") },
    { href: "/conversations", label: t("ui.nav.leads") },
    { href: "/calendar", label: t("ui.nav.calendar") },
    { href: "/scheduler", label: t("ui.nav.scheduler") },
    { href: "/wallet", label: t("ui.nav.wallet") },
  ];
  const accountLinks: readonly SiteNavItem[] = [
    { href: "/profile", label: t("ui.nav.profileTheme") },
    { href: "/wallet", label: t("ui.nav.wallet") },
  ];
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
      items={pages}
      isActive={(href, item) => matchesPath(pathname, href, item.end)}
      renderLink={({ href, children, ...rest }) => (
        <Link to={href} {...rest}>
          {children}
        </Link>
      )}
      trailing={
        <Link to="/wallet" className={balanceChip} title={t("ui.nav.creditBalance")}>
          {balance === null ? t("ui.nav.balanceUnknown") : t("ui.nav.balance", { sats: balance.toLocaleString(locale) })}
        </Link>
      }
      account={{ npub: session.npub, links: accountLinks, onSignOut: session.signOut }}
      classNames={navStyles}
    />
  );
}
