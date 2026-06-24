import * as crypto from "crypto";
import type { AdapterResult, Finding } from "../types";
import { deduplicate } from "./dedup";

// ─── Stable finding ID ────────────────────────────────────────────────────
// SHA-256 (upgraded from SHA-1) of the dedup engine's canonical key fields.
// Stable across re-scans as long as the file path, category, and code
// fingerprint don't change — survives pure line-number shifts.

function stableId(filePath: string, category: string, ruleId: string, codeSnippet?: string): string {
  const contentFp = codeSnippet
    ? crypto.createHash("sha256").update(codeSnippet.trim()).digest("hex").slice(0, 16)
    : "no-snippet";
  const key = `${filePath}\0${category}\0${ruleId}\0${contentFp}`;
  return crypto.createHash("sha256").update(key).digest("hex").slice(0, 20);
}

// ─── Main aggregation entry point ─────────────────────────────────────────

export function aggregate(
  adapterResults: AdapterResult[],
  workspaceRoot: string,
  scanId: string
): Finding[] {
  const now = Date.now();

  // Flatten, relativize, and pass to dedup engine.
  const allRaw = adapterResults.flatMap((ar) =>
    ar.rawFindings.map((raw) => ({
      raw: relativize(raw, workspaceRoot),
      tool: ar.tool,
    }))
  );

  const groups = deduplicate(allRaw);

  return groups.map((group) => {
    const f = group.primary;
    return {
      id: stableId(f.filePath, f.category, group.allRuleIds[0], f.codeSnippet),
      tool: group.allTools,
      ruleId: group.allRuleIds,
      category: f.category,
      cwe: f.cwe,
      severity: f.severity,
      filePath: f.filePath,
      startLine: f.startLine,
      endLine: f.endLine,
      message: f.message,
      codeSnippet: f.codeSnippet,
      status: "new" as const,
      firstSeen: now,
      lastSeen: now,
      scanId,
    };
  });
}

// ─── Helpers ───────────────────────────────────────────────────────────────

function relativize<T extends { filePath: string }>(raw: T, workspaceRoot: string): T {
  let fp = raw.filePath;
  if (fp.startsWith(workspaceRoot)) {
    fp = fp.slice(workspaceRoot.length).replace(/^[\\/]/, "");
  }
  return { ...raw, filePath: fp };
}
