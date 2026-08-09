// Display timezone preference — IANA zones only, never fixed offsets.
// Storage stays UTC; this module converts at render and input boundaries.
// Pure helpers (no React). The React hook lives in useTimezone.ts.

export type TimezonePref = "auto" | string;

export const STORAGE_KEY = "excalibur:timezone";

/** Major-city starter set (west → east), plus UTC. Labels are cities, values IANA. */
export const TIMEZONE_OPTIONS: { value: string; label: string }[] = [
  { value: "Pacific/Honolulu", label: "Honolulu" },
  { value: "America/Anchorage", label: "Anchorage" },
  { value: "America/Los_Angeles", label: "Los Angeles" },
  { value: "America/Denver", label: "Denver" },
  { value: "America/Chicago", label: "Chicago" },
  { value: "America/New_York", label: "New York" },
  { value: "America/Sao_Paulo", label: "São Paulo" },
  { value: "Europe/London", label: "London" },
  { value: "Europe/Berlin", label: "Berlin" },
  { value: "Europe/Athens", label: "Athens" },
  { value: "Asia/Dubai", label: "Dubai" },
  { value: "Asia/Kolkata", label: "Mumbai" },
  { value: "Asia/Singapore", label: "Singapore" },
  { value: "Asia/Tokyo", label: "Tokyo" },
  { value: "Australia/Sydney", label: "Sydney" },
  { value: "Pacific/Auckland", label: "Auckland" },
  { value: "UTC", label: "UTC" },
];

const OPTION_VALUES = new Set(TIMEZONE_OPTIONS.map((o) => o.value));

export function detectBrowserTimeZone(): string {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (tz && typeof tz === "string") return tz;
  } catch {
    /* ignore */
  }
  return "UTC";
}

export function isValidTimeZone(tz: string): boolean {
  try {
    Intl.DateTimeFormat("en-US", { timeZone: tz }).format(new Date());
    return true;
  } catch {
    return false;
  }
}

export function readStoredTimezonePref(): TimezonePref {
  try {
    const raw =
      typeof window !== "undefined"
        ? window.localStorage.getItem(STORAGE_KEY)
        : null;
    if (!raw || raw === "auto") return "auto";
    if (OPTION_VALUES.has(raw) || isValidTimeZone(raw)) return raw;
  } catch {
    /* ignore */
  }
  return "auto";
}

export function resolveTimeZone(pref: TimezonePref): string {
  if (pref === "auto" || !pref) return detectBrowserTimeZone();
  return isValidTimeZone(pref) ? pref : detectBrowserTimeZone();
}

export function normalizeTimezonePref(next: TimezonePref): TimezonePref {
  if (next === "auto") return "auto";
  if (OPTION_VALUES.has(next) || isValidTimeZone(next)) return next;
  return "auto";
}

export function writeTimezonePref(next: TimezonePref): TimezonePref {
  const value = normalizeTimezonePref(next);
  try {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(STORAGE_KEY, value);
      window.dispatchEvent(
        new CustomEvent("excalibur:timezone", {
          detail: resolveTimeZone(value),
        }),
      );
    }
  } catch {
    /* ignore */
  }
  return value;
}

// ── Wall-clock parts in a zone ──────────────────────────────────────────────

export type ZonedParts = {
  year: number;
  month: number; // 1–12
  day: number;
  hour: number; // 0–23
  minute: number;
  second: number;
};

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/** Calendar/clock fields of an instant as seen in `timeZone` (DST-aware). */
export function getZonedParts(date: Date, timeZone: string): ZonedParts {
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
  const map: Record<string, string> = {};
  for (const p of dtf.formatToParts(date)) {
    if (p.type !== "literal") map[p.type] = p.value;
  }
  // hourCycle h23 can still yield "24" at midnight in some engines — normalize.
  let hour = Number(map.hour ?? "0");
  if (hour === 24) hour = 0;
  return {
    year: Number(map.year),
    month: Number(map.month),
    day: Number(map.day),
    hour,
    minute: Number(map.minute ?? "0"),
    second: Number(map.second ?? "0"),
  };
}

/**
 * Offset (ms) such that `Date.UTC(wall parts) - offset === instant`.
 * Used to convert a zone wall time into a UTC instant.
 */
export function getTimeZoneOffsetMs(date: Date, timeZone: string): number {
  const p = getZonedParts(date, timeZone);
  const asUtc = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second);
  return asUtc - date.getTime();
}

/** Interpret a wall time in `timeZone` as a UTC epoch-ms instant. */
export function zonedWallTimeToUtcMs(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
  timeZone: string,
): number {
  // Iterate: guess UTC, read the zone offset at that guess, correct.
  let utc = Date.UTC(year, month - 1, day, hour, minute, second);
  for (let i = 0; i < 3; i++) {
    const offset = getTimeZoneOffsetMs(new Date(utc), timeZone);
    utc = Date.UTC(year, month - 1, day, hour, minute, second) - offset;
  }
  return utc;
}

// ── Format (render UTC → zone) ──────────────────────────────────────────────

export function formatDateTime(
  iso: string | null | undefined,
  timeZone: string,
  opts?: Intl.DateTimeFormatOptions,
): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return String(iso);
  return new Date(t).toLocaleString(undefined, { timeZone, ...opts });
}

export function formatDate(
  iso: string | null | undefined,
  timeZone: string,
  opts?: Intl.DateTimeFormatOptions,
): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return String(iso);
  return new Date(t).toLocaleDateString(undefined, { timeZone, ...opts });
}

export function formatTime(
  iso: string | null | undefined,
  timeZone: string,
  opts?: Intl.DateTimeFormatOptions,
): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return String(iso);
  return new Date(t).toLocaleTimeString(undefined, { timeZone, ...opts });
}

/** Compact "Posted" cell: month day, hour:minute in the patron zone. */
export function formatPostedShort(iso: string | null | undefined, timeZone: string): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toLocaleString(undefined, {
    timeZone,
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export function formatHourLabel(hour: number, timeZone: string): string {
  // Anchor on a fixed wall date so only the hour field matters for the label.
  const utc = zonedWallTimeToUtcMs(2024, 1, 15, hour, 0, 0, timeZone);
  return new Date(utc).toLocaleTimeString(undefined, {
    timeZone,
    hour: "numeric",
  });
}

// ── datetime-local ↔ ISO in a zone ──────────────────────────────────────────

/** UTC ISO → value for <input type="datetime-local"> in `timeZone`. */
export function isoToDatetimeLocalValue(iso: string, timeZone: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const p = getZonedParts(new Date(t), timeZone);
  return `${p.year}-${pad2(p.month)}-${pad2(p.day)}T${pad2(p.hour)}:${pad2(p.minute)}`;
}

/** <input type="datetime-local"> wall value in `timeZone` → UTC ISO. */
export function datetimeLocalValueToIso(value: string, timeZone: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/.exec(value.trim());
  if (!m) return null;
  const ms = zonedWallTimeToUtcMs(
    Number(m[1]),
    Number(m[2]),
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
    m[6] ? Number(m[6]) : 0,
    timeZone,
  );
  return new Date(ms).toISOString();
}

// ── Local-day bounds for filters (YYYY-MM-DD wall → UTC ISO) ────────────────

/** Start of the patron's local calendar day as UTC ISO (inclusive lower bound). */
export function startOfLocalDayIso(ymd: string, timeZone: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(ymd.trim());
  if (!m) return null;
  const ms = zonedWallTimeToUtcMs(Number(m[1]), Number(m[2]), Number(m[3]), 0, 0, 0, timeZone);
  return new Date(ms).toISOString();
}

/** Start of the day *after* the patron's local calendar day (exclusive upper bound). */
export function startOfNextLocalDayIso(ymd: string, timeZone: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(ymd.trim());
  if (!m) return null;
  // Civil +1 day via UTC noon trick on the Y-M-D numbers (not zone-sensitive).
  const base = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 12, 0, 0);
  const next = new Date(base + 24 * 60 * 60 * 1000);
  const y = next.getUTCFullYear();
  const mo = next.getUTCMonth() + 1;
  const d = next.getUTCDate();
  const ms = zonedWallTimeToUtcMs(y, mo, d, 0, 0, 0, timeZone);
  return new Date(ms).toISOString();
}

/**
 * Convert FE date filter (YYYY-MM-DD wall dates) into ISO bounds for the API.
 * `dateTo` becomes an exclusive upper-bound instant (start of the next local day).
 * When the API still accepts bare YYYY-MM-DD, callers may keep sending those;
 * ISO instants are preferred so the bound is the patron's midnight, not UTC's.
 */
export function localDateFilterBounds(
  dateFrom: string,
  dateTo: string,
  timeZone: string,
): { dateFrom?: string; dateTo?: string } {
  const out: { dateFrom?: string; dateTo?: string } = {};
  if (dateFrom) {
    const s = startOfLocalDayIso(dateFrom, timeZone);
    if (s) out.dateFrom = s;
  }
  if (dateTo) {
    const e = startOfNextLocalDayIso(dateTo, timeZone);
    if (e) out.dateTo = e;
  }
  return out;
}

// ── Time-of-day cohort in the patron zone ───────────────────────────────────

export type TodBucket = { median: number; n: number };

function medianOf(values: number[]): number {
  if (values.length === 0) return 0;
  const s = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 0 ? (s[mid - 1]! + s[mid]!) / 2 : s[mid]!;
}

/**
 * Bucket posts by the hour-of-day they were sent *in `timeZone`*.
 * Must compute from instants — never relabel UTC-hour keys (DST / date-line wrong).
 */
export function timeOfDayCohortInZone(
  posts: ReadonlyArray<{ last_sent_at?: string | null; latest_impressions?: number | null }>,
  timeZone: string,
): Record<string, TodBucket> {
  const buckets: Record<string, number[]> = {};
  for (const p of posts) {
    const sent = p.last_sent_at;
    const imp = p.latest_impressions;
    if (!sent || imp == null || Number.isNaN(Number(imp))) continue;
    const t = Date.parse(sent);
    if (Number.isNaN(t)) continue;
    const hour = getZonedParts(new Date(t), timeZone).hour;
    const key = pad2(hour);
    (buckets[key] ??= []).push(Number(imp));
  }
  const out: Record<string, TodBucket> = {};
  for (const [k, vals] of Object.entries(buckets)) {
    if (!vals.length) continue;
    out[k] = { median: medianOf(vals), n: vals.length };
  }
  return out;
}

/** Hour (0–23) of an ISO instant in `timeZone`. */
export function hourInZone(iso: string, timeZone: string): number | null {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return getZonedParts(new Date(t), timeZone).hour;
}
