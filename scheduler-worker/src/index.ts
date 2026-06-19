/**
 * eXcalibur scheduled-post cron Worker.
 *
 * On each cron tick this Worker impersonates the OPERATOR (it holds the
 * operator's long-lived npub proof_token) and invokes the operator-only
 * `excalibur_process_scheduled_posts` MCP tool. All domain logic — selecting
 * due posts, billing each owner for post_tweet, posting, rescheduling — lives
 * server-side in excalibur-mcp. The Worker is a dumb, secret-holding trigger.
 *
 * No new credential type: this is the same npub-proof mechanism patrons use,
 * with the operator as the proven actor (enabled by the 30-day delegation cap).
 */

export interface Env {
  MCP_URL: string; // streamable-HTTP MCP endpoint (confirm path at deploy)
  OPERATOR_NPUB: string; // secret
  OPERATOR_PROOF: string; // secret — operator proof_token, ≤30-day delegation
}

export default {
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(fireDuePosts(env));
  },
};

async function fireDuePosts(env: Env): Promise<void> {
  // MCP JSON-RPC tools/call. CONFIRM the endpoint/transport at deploy — FastMCP
  // streamable HTTP may require an initialize handshake / session header.
  const payload = {
    jsonrpc: "2.0",
    id: 1,
    method: "tools/call",
    params: {
      name: "excalibur_process_scheduled_posts",
      arguments: { npub: env.OPERATOR_NPUB, proof: env.OPERATOR_PROOF },
    },
  };

  const res = await fetch(env.MCP_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    console.error(`excalibur scheduler tick failed: ${res.status} ${await res.text()}`);
    return;
  }
  console.log(`excalibur scheduler tick ok: ${res.status}`);
}
