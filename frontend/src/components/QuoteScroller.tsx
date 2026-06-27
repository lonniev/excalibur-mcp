// Entertaining loading screen — rotating quotes from the greats of copywriting,
// advertising, and brevity (on-brand for a posting tool), so a wait reads as
// "we're working" instead of a frozen "Loading…". Modeled on Optionality's
// QuoteScroller, but Tailwind/dark and dependency-free: the quotes are inline so
// the loading screen can never itself fail on a network hiccup. The optional
// `heading` doubles as a status line ("Opening the editor…").

import { useEffect, useRef, useState } from "react";
import { Loader2 } from "lucide-react";

interface Quote {
  text: string;
  author: string;
}

// Curated — copywriting / advertising / brevity. Keep it tight and quotable.
const QUOTES: Quote[] = [
  { text: "The consumer isn't a moron; she is your wife.", author: "David Ogilvy" },
  { text: "On the average, five times as many people read the headline as read the body copy.", author: "David Ogilvy" },
  { text: "Tell the truth, but make the truth fascinating.", author: "David Ogilvy" },
  { text: "The more informative your advertising, the more persuasive it will be.", author: "David Ogilvy" },
  { text: "The most powerful element in advertising is the truth.", author: "Bill Bernbach" },
  { text: "In advertising, not to be different is virtually suicidal.", author: "Bill Bernbach" },
  { text: "Advertising is salesmanship in print.", author: "John E. Kennedy" },
  { text: "The time to stop talking is when the other person nods his head affirmatively but says nothing.", author: "Claude C. Hopkins" },
  { text: "Don't write so that you can be understood, write so that you can't be misunderstood.", author: "William Howard Taft" },
  { text: "When you have written your headline, you have spent eighty cents out of your dollar.", author: "John Caples" },
  { text: "Make it simple. Make it memorable. Make it inviting to look at.", author: "Leo Burnett" },
  { text: "Copy is a direct conversation with the consumer.", author: "Shirley Polykoff" },
  { text: "A copywriter should have an understanding of people, an insight into them, a sympathy toward them.", author: "George Gribbin" },
  { text: "The headline is the ticket on the meat. Use it to flag down readers who are prospects.", author: "David Ogilvy" },
  { text: "Omit needless words.", author: "William Strunk Jr." },
  { text: "I didn't have time to write a short letter, so I wrote a long one instead.", author: "Mark Twain" },
  { text: "Easy reading is damn hard writing.", author: "Nathaniel Hawthorne" },
  { text: "If you can't explain it simply, you don't understand it well enough.", author: "Albert Einstein" },
];

const DWELL_MS = 3500;
const FADE_MS = 450;

export default function QuoteScroller({
  heading,
  className = "",
}: {
  heading?: string;
  className?: string;
}) {
  const [index, setIndex] = useState(() => Math.floor(Math.random() * QUOTES.length));
  const [visible, setVisible] = useState(true);
  const tick = useRef<number | undefined>(undefined);
  const fade = useRef<number | undefined>(undefined);

  useEffect(() => {
    tick.current = window.setInterval(() => {
      setVisible(false);
      fade.current = window.setTimeout(() => {
        setIndex((prev) => {
          let next = prev;
          while (next === prev) next = Math.floor(Math.random() * QUOTES.length);
          return next;
        });
        setVisible(true);
      }, FADE_MS);
    }, DWELL_MS);
    return () => {
      if (tick.current) window.clearInterval(tick.current);
      if (fade.current) window.clearTimeout(fade.current);
    };
  }, []);

  const q = QUOTES[index];

  return (
    <div className={`flex flex-col items-center justify-center px-6 text-center ${className}`}>
      <div className="mb-6 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.32em] text-amber-500">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        {heading ?? "Working…"}
      </div>
      <div
        className="mx-auto flex min-h-[7rem] max-w-xl flex-col justify-center gap-3"
        style={{ opacity: visible ? 1 : 0, transition: `opacity ${FADE_MS}ms ease` }}
      >
        <p className="font-serif text-lg italic leading-relaxed text-zinc-300">
          <span className="text-amber-500">“</span>{q.text}<span className="text-amber-500">”</span>
        </p>
        <p className="font-mono text-[10px] uppercase tracking-[0.28em] text-zinc-500">
          {q.author}
        </p>
      </div>
    </div>
  );
}
