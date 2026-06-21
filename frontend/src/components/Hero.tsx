// Unauthenticated landing hero. Typographic + a CSS gradient wash (no
// hand-drawn SVG scenery) and a single lucide glyph as the brand mark.
// Voice is descriptive-functional; the Tollbooth DPYC mention is discreet but
// always present, and pitches the real differentiator — operator-controlled
// dynamic pricing, not "no fees".

import { Swords, Feather, Sparkles, CalendarClock } from "lucide-react";
import type { ReactNode } from "react";

export default function Hero() {
  return (
    <section className="relative overflow-hidden border-b border-stone-200 dark:border-zinc-800">
      {/* ambient gradient — pure CSS, decorative only */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 bg-gradient-to-br from-amber-500/10 via-transparent to-transparent"
      />
      <div
        aria-hidden
        className="pointer-events-none absolute -top-24 -right-24 h-72 w-72 rounded-full bg-amber-400/20 blur-3xl"
      />

      <div className="relative mx-auto max-w-5xl px-6 py-16 sm:py-20">
        <div className="mb-6 flex items-center gap-3">
          <span className="grid h-12 w-12 place-items-center rounded-2xl bg-amber-500/15 text-amber-500 ring-1 ring-amber-500/30">
            <Swords className="h-6 w-6" />
          </span>
          <div>
            <div className="text-2xl font-semibold tracking-tight">
              eXcalibur <span className="font-normal text-stone-400 dark:text-zinc-500">Posts Manager</span>
            </div>
            <div className="text-xs uppercase tracking-widest text-amber-600 dark:text-amber-400">
              A Content Management System for X
            </div>
          </div>
        </div>

        <h1 className="max-w-2xl text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">
          An AI-assisted Content Management System for your X posts.
        </h1>
        <p className="mt-4 max-w-2xl text-base leading-relaxed text-stone-600 dark:text-zinc-400">
          Stay in the zone. Let your agentic assistant post thoughts or marketing copy straight to X
          through{" "}
          <a
            href="https://github.com/lonniev/excalibur-mcp"
            target="_blank"
            rel="noopener noreferrer"
            className="text-stone-700 underline-offset-2 hover:underline dark:text-zinc-300"
          >
            eXcalibur MCP
          </a>{" "}
          — the monetized MCP for X posting — or route a draft into eXcalibur Posts Manager for
          editorial fine-tuning first.
        </p>
        <p className="mt-3 max-w-2xl text-base leading-relaxed text-stone-600 dark:text-zinc-400">
          Draft in a block editor, refine flagged passages with Claude, schedule and repost, and
          keep a reusable snippet library. Sign in with a Nostr key and pay per use in Bitcoin
          Lightning — your posts, schedule, and snippets live with your npub, not a login.
        </p>

        <div className="mt-8 grid max-w-3xl gap-3 sm:grid-cols-3">
          <Feature
            icon={<Feather className="h-5 w-5" />}
            title="Block editor"
            body="X-aware Unicode formatting, dividers, and an emoji picker — what you see is what posts."
          />
          <Feature
            icon={<Sparkles className="h-5 w-5" />}
            title="Refine with Claude"
            body="Flag a region and the server rewrites it. The AI key stays vaulted — it never reaches your browser."
          />
          <Feature
            icon={<CalendarClock className="h-5 w-5" />}
            title="Schedule & reuse"
            body="Queue posts, repost a sent one, and one-click your favorite snippets into any draft."
          />
        </div>

        <p className="mt-8 text-xs text-stone-400 dark:text-zinc-500">
          Powered by{" "}
          <a
            href="https://tollbooth-dpyc.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-600/90 hover:underline dark:text-amber-400/90"
          >
            Tollbooth DPYC™
          </a>{" "}
          — operator-controlled dynamic pricing at the MCP layer.
        </p>
      </div>
    </section>
  );
}

function Feature({ icon, title, body }: { icon: ReactNode; title: string; body: string }) {
  return (
    <div className="rounded-xl border border-stone-200 bg-white/60 p-4 dark:border-zinc-800 dark:bg-zinc-900/60">
      <div className="mb-2 text-amber-500">{icon}</div>
      <div className="text-sm font-medium">{title}</div>
      <div className="mt-1 text-xs leading-relaxed text-stone-500 dark:text-zinc-400">{body}</div>
    </div>
  );
}
