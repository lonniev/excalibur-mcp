/**
 * Cloudflare Pages Function — proxy /mcp to excalibur-mcp.fastmcp.app/mcp.
 *
 * Keeping the browser → MCP transport same-origin avoids CORS preflight
 * complications and lets the frontend hit a relative VITE_MCP_URL=/mcp.
 *
 * Handles POST (tool calls), GET (SSE streaming), DELETE (session close),
 * and OPTIONS (CORS preflight). Mirrors taxsort/optionality verbatim with
 * the upstream host swapped.
 */

const UPSTREAM = "https://excalibur-mcp.fastmcp.app/mcp";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "content-type, mcp-session-id, accept, last-event-id",
  "Access-Control-Expose-Headers": "mcp-session-id",
};

export async function onRequest(context) {
  const req = context.request;

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }

  const upHeaders = new Headers();
  for (const [key, value] of req.headers) {
    const lk = key.toLowerCase();
    if (lk === "content-type" || lk === "accept" || lk === "mcp-session-id" || lk === "last-event-id") {
      upHeaders.set(key, value);
    }
  }
  upHeaders.set("Host", "excalibur-mcp.fastmcp.app");

  const init = {
    method: req.method,
    headers: upHeaders,
  };

  if (req.method !== "GET" && req.method !== "HEAD" && req.method !== "DELETE") {
    init.body = req.body;
    init.duplex = "half";
  }

  try {
    const resp = await fetch(UPSTREAM, init);
    const respHeaders = new Headers(resp.headers);
    for (const [k, v] of Object.entries(CORS_HEADERS)) {
      respHeaders.set(k, v);
    }
    return new Response(resp.body, {
      status: resp.status,
      headers: respHeaders,
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: "Proxy error", detail: String(err) }), {
      status: 502,
      headers: { "Content-Type": "application/json", ...CORS_HEADERS },
    });
  }
}
