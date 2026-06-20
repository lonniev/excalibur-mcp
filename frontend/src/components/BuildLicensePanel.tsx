// Build & License — transparency footer, folded in from optionality.
// FE bundle version + git commit (Vite define-time), the MCP server version
// + Horizon commit (service_status), source repos, and the open-source /
// private-commerce licensing posture.

import type { ServiceStatus } from "../lib/mcp";

const card = "rounded-xl border border-stone-200 dark:border-zinc-800 bg-white dark:bg-zinc-900";

export default function BuildLicensePanel({ status }: { status: ServiceStatus | null }) {
  const mcpVersion = status?.version;
  const mcpCommit = status?.build_info?.fastmcp_cloud_git_commit_sha?.slice(0, 7);
  const mcpRepo = status?.build_info?.fastmcp_cloud_git_repo;
  const wheel = status?.tollbooth_dpyc_version;

  return (
    <div className={`${card} p-5`}>
      <div className="text-sm font-medium mb-1">Build &amp; license</div>
      <p className="text-xs text-stone-500 dark:text-zinc-400 mb-4 leading-relaxed">
        eXcalibur and Tollbooth-DPYC<sup>™</sup> ship as open source under the Apache License 2.0 —
        anyone can read the code, fork it, run their own operator. The <i>services</i> on top are
        private commerce: each operator sets their own tolls; patrons pre-fund a Lightning balance
        and pay per call. The protocol is shared; the businesses on it are not.
      </p>

      <Section label="Frontend" />
      <Row label="Version" value={`${__APP_VERSION__} · ${__BUILD_COMMIT__}`} />
      <Row label="Built at" value={__BUILD_TIME__} />
      <Row label="Source" href="https://github.com/lonniev/excalibur-mcp" value="github.com/lonniev/excalibur-mcp" />

      <Section label="MCP server" />
      <Row label="Version" value={mcpVersion ? `${mcpVersion}${mcpCommit ? ` · ${mcpCommit}` : ""}` : "—"} />
      <Row label="tollbooth-dpyc" value={wheel ? `wheel ${wheel}` : "—"} />
      {mcpRepo && <Row label="Source" href={mcpRepo} value={mcpRepo.replace("https://", "")} />}

      <Section label="Tollbooth-DPYC™" />
      <Row label="Marketing" href="https://tollbooth-dpyc.com" value="tollbooth-dpyc.com" />
      <Row label="Community" href="https://github.com/lonniev/dpyc-community" value="github.com/lonniev/dpyc-community" />
      <Row label="Wheel source" href="https://github.com/lonniev/tollbooth-dpyc" value="github.com/lonniev/tollbooth-dpyc" />

      <Section label="License" />
      <Row label="Apache 2.0" href="https://www.apache.org/licenses/LICENSE-2.0" value="apache.org/licenses/LICENSE-2.0" />
    </div>
  );
}

function Section({ label }: { label: string }) {
  return <div className="text-xs uppercase tracking-wider text-stone-400 dark:text-zinc-500 mt-4 mb-1 first:mt-0">{label}</div>;
}

function Row({ label, value, href }: { label: string; value: string; href?: string }) {
  return (
    <div className="flex gap-3 py-1.5 border-b border-stone-100 dark:border-zinc-800 text-xs">
      <div className="w-28 shrink-0 text-stone-400 dark:text-zinc-500">{label}</div>
      <div className="flex-1 min-w-0 font-mono break-all">
        {href ? (
          <a href={href} target="_blank" rel="noopener noreferrer" className="text-amber-600 dark:text-amber-400 hover:underline">{value}</a>
        ) : (
          <span className="text-stone-700 dark:text-zinc-300">{value}</span>
        )}
      </div>
    </div>
  );
}
