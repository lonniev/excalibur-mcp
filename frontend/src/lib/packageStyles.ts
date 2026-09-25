// How eXcalibur's copies of the @tollbooth-dpyc/web widgets look. The package
// brings the mechanics — the calls, the states, the words, the paging and
// filtering arithmetic, the theme plumbing — and adds no colour or type of its
// own; these classNames are the stone / zinc / amber look eXcalibur's own
// Wallet, Coupons, table, theme and time-zone pickers, usage, health and
// build panels always had, light and dark.

import type {
  BuildInfoPanelClassNames,
  CouponsPanelClassNames,
  ErrorBoundaryClassNames,
  FundingStatusClassNames,
  PageControlsClassNames,
  SortHeaderClassNames,
  TableFilterClassNames,
  TableShellClassNames,
  ThemeToggleClassNames,
  TimezonePickerClassNames,
  UsageSummaryClassNames,
  WalletPageClassNames,
} from "@tollbooth-dpyc/web/react";

/** The card every panel on Wallet and Profile sits in. */
export const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

const input =
  "rounded-lg px-3 py-1.5 text-sm bg-white dark:bg-zinc-950 border border-stone-300 dark:border-zinc-700 focus:outline-hidden focus:border-amber-400";
const errorBox =
  "rounded-lg p-3 text-xs bg-red-50 border border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400";


export const walletStyles: WalletPageClassNames = {
  // The balance's own title is the small muted label it always was.
  root: "max-w-3xl mx-auto px-4 py-6 space-y-5 [&>section:first-of-type>div:first-child]:text-xs [&>section:first-of-type>div:first-child]:font-normal [&>section:first-of-type>div:first-child]:text-stone-400 dark:[&>section:first-of-type>div:first-child]:text-zinc-500",
  heading: "text-lg font-semibold",
  section: `${card} p-5 space-y-3`,
  sectionTitle: "text-sm font-medium",
  figure: "text-3xl font-semibold tabular-nums",
  unit: "text-base font-normal text-stone-400 dark:text-zinc-500",
  stats: "flex flex-wrap gap-x-4 gap-y-1 text-xs text-stone-500 dark:text-zinc-400",
  stat: "tabular-nums",
  notice: "text-xs text-amber-600 dark:text-amber-400",
  error: errorBox,
  // Every action is a quiet chip. The one that moves a top-up forward is the
  // amber button it always was — Create invoice, pushed to the end of its row;
  // Open checkout, a link, stays the amber text link it always was.
  chip:
    "inline-flex items-center px-3 py-1.5 rounded-lg text-sm transition-colors text-stone-500 hover:bg-stone-100 dark:text-zinc-400 dark:hover:bg-zinc-800 disabled:opacity-40 disabled:pointer-events-none",
  primary: [
    "inline-flex items-center ml-auto px-4 py-2 rounded-lg text-sm transition-colors",
    "bg-amber-600 text-white hover:bg-amber-500 disabled:opacity-40 disabled:pointer-events-none",
    "[a&]:ml-0 [a&]:px-3 [a&]:py-1.5 [a&]:bg-transparent [a&]:hover:bg-transparent [a&]:hover:underline",
    "[a&]:text-amber-600 dark:[a&]:text-amber-400",
  ].join(" "),
  chipActive: "bg-amber-100 text-amber-800 dark:bg-amber-500/15 dark:text-amber-400",
  chips: "flex flex-wrap items-center gap-2",
  input: `${input} w-32`,
  invoice: "rounded-lg border border-stone-200 dark:border-zinc-800 p-3 space-y-2",
  bolt11: "font-mono text-xs break-all bg-stone-50 dark:bg-zinc-950 rounded-sm p-2",
  status: "text-xs text-stone-500 dark:text-zinc-400",
  list: "space-y-1.5 text-xs",
  row: "flex justify-between gap-3 text-stone-500 dark:text-zinc-400 tabular-nums",
};

export const couponStyles: CouponsPanelClassNames = {
  root: `${card} p-5`,
  heading: "text-sm font-medium mb-1",
  intro: "text-xs text-stone-500 dark:text-zinc-400 mb-4",
  form: "flex gap-2 mb-3",
  input: `${input} flex-1 min-w-0 py-2 uppercase`,
  // Redeem is the amber button; each row's Remove is a quiet mark that reddens.
  primary: "bg-amber-600 hover:bg-amber-500 text-white text-sm px-4 py-2 rounded-lg disabled:opacity-40 transition-colors whitespace-nowrap",
  chip: "px-2 py-1 rounded-lg transition-colors text-stone-400 hover:text-red-500 dark:text-zinc-500 dark:hover:text-red-400",
  message: "rounded-lg p-2.5 mb-3 text-xs border",
  ok: "bg-green-50 border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400",
  error: "bg-red-50 border-red-200 text-red-700 dark:bg-red-500/10 dark:border-red-500/30 dark:text-red-400",
  loading: "text-xs text-stone-400 dark:text-zinc-500 py-2",
  empty: "text-xs text-stone-400 dark:text-zinc-500 leading-relaxed",
  list: "divide-y divide-stone-100 dark:divide-zinc-800",
  row: "flex items-center gap-3 py-2.5 [&>div]:flex-1 [&>div]:min-w-0",
  name: "font-mono text-sm",
  discount: "ml-1 text-sm font-semibold text-amber-600 dark:text-amber-400",
  meta: "text-xs text-stone-400 dark:text-zinc-500 mt-0.5",
  active: "text-green-600 dark:text-green-400",
};

const filterField =
  "text-xs rounded-lg border border-stone-200 bg-stone-50 px-2 py-1.5 focus:outline-hidden focus:border-stone-400 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:focus:border-zinc-500";

// One chip class serves the search chip and Clear, so each is told apart by
// where it sits: the search chip inside `search`, Clear straight under `root`.
export const tableFilterStyles: TableFilterClassNames = {
  root: "mb-4 flex flex-wrap items-center gap-2 [&>button]:border [&>button]:border-red-200 [&>button]:py-1 [&>button]:text-red-500 [&>button]:hover:text-red-700 dark:[&>button]:border-red-500/30 dark:[&>button]:text-red-400",
  search:
    "flex items-center gap-1 [&>button]:bg-stone-900 [&>button]:text-white [&>button]:hover:bg-stone-700 dark:[&>button]:bg-zinc-700 dark:[&>button]:hover:bg-zinc-600",
  input: `${filterField} w-56 font-mono`,
  chip: "inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs",
  dates: "flex items-center gap-1 text-xs text-stone-400 dark:text-zinc-500",
  select: filterField,
  date: filterField,
};

export const sortHeaderStyles: SortHeaderClassNames = {
  cell: "px-3 py-2 text-left text-[11px] font-mono uppercase tracking-widest text-stone-400 dark:text-zinc-500",
  button:
    "inline-flex items-center gap-1 hover:text-amber-600 dark:hover:text-amber-400 transition-colors",
  active: "text-amber-600 dark:text-amber-400",
};

/** The actions column: a blank header, right-aligned. */
export const actionsHeaderStyles: SortHeaderClassNames = {
  cell: `${sortHeaderStyles.cell} text-right`,
};

export const pageControlsStyles: PageControlsClassNames = {
  root: "flex items-center justify-center gap-2 mt-4 text-xs",
  chip: "px-2.5 py-1 rounded-lg text-stone-500 enabled:hover:bg-stone-100 disabled:opacity-30 dark:text-zinc-400 dark:enabled:hover:bg-zinc-800 transition-colors",
  label: "text-stone-400 dark:text-zinc-500 tabular-nums",
};

export const tableShellStyles: TableShellClassNames = {
  root: "overflow-x-auto rounded-lg border border-stone-200 dark:border-zinc-800",
  table: "w-full text-sm",
};

// The chip's colours key off aria-checked, so the current pick never fights
// the others' border and hover for the same property.
export const themeToggleStyles: ThemeToggleClassNames = {
  root: "grid grid-cols-3 gap-2",
  chip: "rounded-lg border px-3 py-3 text-left transition-colors border-stone-200 dark:border-zinc-800 aria-[checked=false]:hover:bg-stone-50 dark:aria-[checked=false]:hover:bg-zinc-800 aria-checked:border-amber-400 aria-checked:bg-amber-50 dark:aria-checked:border-amber-500/50 dark:aria-checked:bg-amber-500/10",
};

export const errorBoundaryStyles: ErrorBoundaryClassNames = {
  root: "flex min-h-screen flex-col items-center justify-center gap-4 bg-white p-6 text-center text-stone-800 dark:bg-zinc-950 dark:text-zinc-200 [&>*]:max-w-md",
  title: "text-lg font-semibold",
  message: "text-sm text-stone-500 dark:text-zinc-400",
  detail:
    "w-full max-h-48 overflow-auto rounded-md bg-stone-100 p-3 text-left font-mono text-[11px] whitespace-pre-wrap text-stone-600 dark:bg-zinc-900 dark:text-zinc-400",
  actions: "flex flex-wrap justify-center gap-2",
  chip: "rounded-md bg-amber-400 px-4 py-2 text-sm font-medium text-zinc-950 transition-colors hover:bg-amber-300",
};

// A panel's quiet Refresh, pushed to the end of its heading row.
const refresh =
  "ml-auto text-xs text-stone-500 hover:text-amber-600 dark:text-zinc-400 dark:hover:text-amber-400 disabled:opacity-40 transition-colors";

// Rows are drawn by FundingStatusPanels (dot, word, detail, stamp); the state
// chips carry their own colour, so ok / warning / blocked add nothing here.
export const fundingStyles: FundingStatusClassNames = {
  root: `${card} p-5`,
  header: "mb-1 flex flex-wrap items-center gap-2",
  heading: "text-sm font-medium",
  chip: refresh,
  intro: "mb-3 text-xs leading-relaxed text-stone-500 dark:text-zinc-400",
  loading: "text-xs text-stone-400 dark:text-zinc-500",
  error: `mb-3 ${errorBox}`,
  list: "divide-y divide-stone-100 dark:divide-zinc-800",
  row: "flex items-start gap-3 py-2.5 first:pt-0 last:pb-0",
};

export const timezonePickerStyles: TimezonePickerClassNames = {
  label: "block text-xs text-stone-500 dark:text-zinc-400 mb-1.5",
  select:
    "w-full rounded-lg border border-stone-200 bg-stone-50 px-3 py-2 text-sm focus:outline-hidden focus:border-amber-400 dark:border-zinc-700 dark:bg-zinc-950 dark:text-zinc-200",
};

export const usageStyles: UsageSummaryClassNames = {
  root: `${card} p-5`,
  header: "mb-3 flex items-center gap-2",
  heading: "text-sm font-medium",
  chip: refresh,
  figures: "grid grid-cols-3 gap-3 text-center",
  value: "text-lg font-semibold tabular-nums",
  label: "text-xs text-stone-400 dark:text-zinc-500",
  subheading: "mt-4 mb-1 text-xs uppercase tracking-wider text-stone-400 dark:text-zinc-500",
  list: "divide-y divide-stone-100 dark:divide-zinc-800",
  row: "flex items-baseline gap-3 py-1.5 text-xs",
  tool: "flex-1 min-w-0 truncate font-mono text-stone-700 dark:text-zinc-300",
  calls: "text-stone-400 dark:text-zinc-500 tabular-nums",
  sats: "w-24 text-right text-stone-700 dark:text-zinc-300 tabular-nums",
  loading: "text-xs text-stone-400 dark:text-zinc-500",
  error: "text-xs text-stone-400 dark:text-zinc-500",
  empty: "text-xs text-stone-400 dark:text-zinc-500",
};

// The row carries the value colour so a link's amber never fights it.
export const buildInfoStyles: BuildInfoPanelClassNames = {
  root: `${card} p-5`,
  heading: "text-sm font-medium mb-1",
  intro: "text-xs text-stone-500 dark:text-zinc-400 mb-4 leading-relaxed",
  section: "text-xs uppercase tracking-wider text-stone-400 dark:text-zinc-500 mt-4 mb-1",
  row: "flex gap-3 py-1.5 border-b border-stone-100 dark:border-zinc-800 text-xs text-stone-700 dark:text-zinc-300",
  label: "w-28 shrink-0 text-stone-400 dark:text-zinc-500",
  value: "flex-1 min-w-0 font-mono break-all",
  link: "text-amber-600 dark:text-amber-400 hover:underline",
};
