// Refine-with-Claude — the TaxSort tactic: the MCP returns the operator's
// Anthropic key to the proven patron (free, proof-gated), and the browser
// calls Anthropic directly. No per-refine MCP call, no key in our code.

import { getAnthropicKey } from "./mcp";

let _cachedKey: string | null = null;

async function resolveKey(): Promise<string> {
  if (_cachedKey) return _cachedKey;
  const r = await getAnthropicKey();
  if (!r.key) {
    throw new Error(
      r.message || r.error || "The operator hasn't configured an Anthropic API key yet.",
    );
  }
  _cachedKey = r.key;
  return r.key;
}

export async function callClaude(system: string, user: string): Promise<string> {
  const key = await resolveKey();
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
      // Required to call the API from a browser origin.
      "anthropic-dangerous-direct-browser-access": "true",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-6",
      max_tokens: 1000,
      system,
      messages: [{ role: "user", content: user }],
    }),
  });
  if (!res.ok) {
    if (res.status === 401) _cachedKey = null; // stale key — re-fetch next time
    const t = await res.text();
    throw new Error(`Anthropic ${res.status}: ${t.slice(0, 200)}`);
  }
  const data = (await res.json()) as { content?: { type: string; text?: string }[] };
  return (data.content ?? [])
    .filter((b) => b.type === "text")
    .map((b) => b.text ?? "")
    .join("\n");
}

/// Parse Claude's reply into up to 3 suggestion strings — JSON array first,
/// then fall back to numbered/bulleted lines.
export function parseSuggestions(raw: string): string[] {
  const t = (raw || "").replace(/```json|```/g, "").trim();
  try {
    const arr = JSON.parse(t);
    if (Array.isArray(arr)) return arr.map(String).filter(Boolean).slice(0, 3);
  } catch {
    /* fall through */
  }
  return t
    .split("\n")
    .map((l) => l.replace(/^[\s\-*\d.)"]+/, "").trim())
    .filter(Boolean)
    .slice(0, 3);
}
