import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { execSync } from 'child_process'
import { readFileSync } from 'fs'
import { agentGuide } from '@tollbooth-dpyc/web/agent-guide'

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'))

// Short git commit SHA at build time. Cloudflare Pages injects
// CF_PAGES_COMMIT_SHA; CI sets COMMIT_SHA; local dev falls back to
// `git rev-parse`; last resort is "dev" so the footer never renders
// undefined.
function resolveCommit(): string {
  if (process.env.CF_PAGES_COMMIT_SHA) return process.env.CF_PAGES_COMMIT_SHA.slice(0, 7)
  if (process.env.COMMIT_SHA) return process.env.COMMIT_SHA.slice(0, 7)
  try {
    return execSync('git rev-parse --short HEAD', { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim()
  } catch {
    return 'dev'
  }
}

export default defineConfig({
  plugins: [
    react(), tailwindcss(),
    agentGuide({
      name: "eXcalibur Posts Manager",
      summary: "An AI-assisted content management system for your X (Twitter) posts, built on eXcalibur MCP. Write block-structured drafts, refine flagged passages with AI, schedule and repost, keep a snippet library, and publish to X.",
      site: "https://excalibur.tollbooth-dpyc.com",
      mcpUrl: "https://excalibur-mcp.fastmcp.app/mcp",
      toolPrefix: "excalibur",
      source: "https://github.com/lonniev/excalibur-mcp",
      registryName: "io.github.lonniev/excalibur-mcp",
      body: "agent-guide.md",
    }),
  ],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    __BUILD_COMMIT__: JSON.stringify(resolveCommit()),
    __BUILD_TIME__: JSON.stringify(new Date().toISOString()),
  },
  build: { outDir: 'dist' },
})
