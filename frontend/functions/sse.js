// Cloudflare Pages Function: a plain 404 where Pages would serve the page; a real file still wins.
import { makeNotFound } from "@tollbooth-dpyc/web/pages-proxy";

export const onRequest = makeNotFound();
