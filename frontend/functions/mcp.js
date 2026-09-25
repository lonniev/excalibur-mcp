// Cloudflare Pages Function: /mcp → the excalibur-mcp operator on Horizon.
import { makeMcpProxy } from "@tollbooth-dpyc/web/pages-proxy";

export const onRequest = makeMcpProxy("https://excalibur-mcp.fastmcp.app/mcp");
