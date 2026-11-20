// Profile: the package's AccountPage in eXcalibur's look, its folding groups
// carrying the panels only eXcalibur has: your language (You), your account's
// health (Money), the X connection (This site), the operator's health (Operator).

import type { ReactNode } from "react";
import type { Theme } from "@tollbooth-dpyc/web";
import { AccountPage, LanguageChooser, Tx, useAppShell } from "@tollbooth-dpyc/web/react";
import {
  accountStyles,
  buildInfoStyles,
  themeToggleStyles,
  timezonePickerStyles,
  usageStyles,
} from "../lib/packageStyles";
import XConnectPanel from "./XConnectPanel";
import { PatronFundingStatus, OperatorFundingStatus } from "./FundingStatusPanels";
import { useT, WORDS, type Translate } from "../i18n";

/** The line under each theme choice; none for light. */
const themeHint = (theme: Theme, t: Translate): string =>
  theme === "dark" ? t("ui.profilePage.themeDefault") : theme === "system" ? t("ui.profilePage.themeMatchOs") : "";

export default function ProfilePage() {
  const t = useT();
  const { session, status } = useAppShell();
  const themeLabels: Record<Theme, ReactNode> = {
    dark: <ThemeChoice theme="dark" label={t("ui.profilePage.themeDark")} hint={themeHint("dark", t)} />,
    light: <ThemeChoice theme="light" label={t("ui.profilePage.themeLight")} hint={themeHint("light", t)} />,
    system: <ThemeChoice theme="system" label={t("ui.profilePage.themeSystem")} hint={themeHint("system", t)} />,
  };
  return (
    <AccountPage
      npub={session.npub}
      onSignOut={session.signOut}
      classNames={accountStyles}
      panels={{
        you: (
          <section className={accountStyles.section}>
            <h2 className={accountStyles.sectionHeading}>{t("ui.profilePage.language")}</h2>
            <LanguageChooser />
          </section>
        ),
        money: <PatronFundingStatus />,
        site: <XConnectPanel />,
        operator: <OperatorFundingStatus />,
      }}
      usage={{ classNames: usageStyles }}
      timezone={{
        heading: t("ui.profilePage.tzHeading"),
        intro: t("ui.profilePage.tzIntro"),
        label: t("ui.profilePage.tzLabel"),
        id: "tz-select",
        autoLabel: (zone) => t("ui.profilePage.tzAuto", { zone }),
        optionLabel: (o) => `${o.label} — ${o.value}`,
        classNames: timezonePickerStyles,
        note: (pref, zone) =>
          pref === "auto"
            ? t("ui.profilePage.tzResolving", { zone })
            : t("ui.profilePage.tzUsing", { zone }),
      }}
      theme={{
        intro: t("ui.profilePage.themeIntro"),
        fallback: "dark",
        labels: themeLabels,
        classNames: themeToggleStyles,
      }}
      build={{
        status,
        frontend: {
          version: __APP_VERSION__,
          commit: __BUILD_COMMIT__,
          builtAt: __BUILD_TIME__,
          source: "https://github.com/lonniev/excalibur-mcp",
        },
        intro: <Tx ns={WORDS} k="ui.profilePage.buildIntro" components={{ sup: <sup />, i: <i /> }} />,
        classNames: buildInfoStyles,
      }}
    />
  );
}

function ThemeChoice({ theme, label, hint }: { theme: Theme; label: string; hint: string }) {
  return (
    <>
      <span className="flex items-center gap-2">
        <ThemeSwatch theme={theme} />
        <span className="text-sm font-medium">{label}</span>
      </span>
      {hint && <span className="block text-xs text-stone-400 dark:text-zinc-500 mt-1">{hint}</span>}
    </>
  );
}

function ThemeSwatch({ theme }: { theme: Theme }) {
  const base = "w-5 h-5 rounded-full border border-stone-300 dark:border-zinc-600";
  if (theme === "dark") return <span className={`${base} bg-zinc-900`} />;
  if (theme === "light") return <span className={`${base} bg-stone-100`} />;
  return <span className={`${base} bg-linear-to-r from-stone-100 to-zinc-900`} />;
}
