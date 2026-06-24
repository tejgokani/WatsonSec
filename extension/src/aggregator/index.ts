import * as crypto from "crypto";
import type { AdapterResult, Finding, RawFinding } from "../types";

// ─── Stable finding ID ─────────────────────────────────────────────────────
// Hash of (filePath, ruleCategory, ruleId, contentFingerprint).
// Intentionally excludes line number from the hash when we have a snippet
// so that the finding survives minor line-number shifts from nearby edits.

function stableId(f: RawFinding): string {
  const contentFp = f.codeSnippet
    ? crypto.createHash("sha1").update(f.codeSnippet.trim()).digest("hex").slice(0, 12)
    : `L${f.startLine}`;
  const key = `${f.filePath}:${f.category}:${f.ruleId}:${contentFp}`;
  return crypto.createHash("sha1").update(key).digest("hex").slice(0, 16);
}

// ─── Dedup key ─────────────────────────────────────────────────────────────
// Two raw findings from different tools collapse into one finding when they
// share: same normalized file, overlapping line range (±3 lines), same category.

function dedupKey(f: RawFinding): string {
  // Snap to a coarse line window so line-off-by-one differences from
  // different tool parsers don't prevent merging.
  const lineWindow = Math.floor(f.startLine / 5);
  return `${f.filePath}:${f.category}:${lineWindow}`;
}

// ─── Main aggregation entry point ─────────────────────────────────────────

export function aggregate(
  adapterResults: AdapterResult[],
  workspaceRoot: string,
  scanId: string
): Finding[] {
  const now = Date.now();

  // Flatten and relativize all raw findings.
  const allRaw: Array<{ raw: RawFinding; tool: string }> = [];
  for (const ar of adapterResults) {
    for (const raw of ar.rawFindings) {
      allRaw.push({ raw: relativize(raw, workspaceRoot), tool: ar.tool });
    }
  }

  // Group by dedup key.
  const groups = new Map<string, Array<{ raw: RawFinding; tool: string }>>();
  for (const item of allRaw) {
    const key = dedupKey(item.raw);
    const group = groups.get(key) ?? [];
    group.push(item);
    groups.set(key, group);
  }

  // Collapse each group into a single Finding, merging tool lists.
  const findings: Finding[] = [];
  for (const group of groups.values()) {
    const primary = group[0].raw;
    const tools = [...new Set(group.map((g) => g.tool))];
    const ruleIds = [...new Set(group.map((g) => g.raw.ruleId))];

    // Pick the most severe finding in the group.
    const best = group.reduce((a, b) =>
      severityRank(a.raw.severity) >= severityRank(b.raw.severity) ? a : b
    ).raw;

    findings.push({
      id: stableId(primary),
      tool: tools,
      ruleId: ruleIds,
      category: best.category,
      cwe: best.cwe,
      severity: best.severity,
      filePath: best.filePath,
      startLine: best.startLine,
      endLine: best.endLine,
      message: best.message,
      codeSnippet: best.codeSnippet,
      status: "new",
      firstSeen: now,
      lastSeen: now,
      scanId,
    });
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────────────────────

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

function severityRank(s: string): number {
  return SEVERITY_RANK[s] ?? 0;
}

function relativize(raw: RawFinding, workspaceRoot: string): RawFinding {
  let fp = raw.filePath;
  if (fp.startsWith(workspaceRoot)) {
    fp = fp.slice(workspaceRoot.length).replace(/^[\\/]/, "");
  }
  return { ...raw, filePath: fp };
}
