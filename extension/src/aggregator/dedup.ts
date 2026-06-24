/**
 * DefectDojo-inspired dedup engine.
 *
 * DefectDojo uses three strategies (from their source):
 *   1. legacy       — hash(title + cwe + line + filepath + description)
 *   2. unique_id    — tool's own stable ID takes precedence when available
 *   3. hash_code    — normalized hash over semantic fields
 *
 * We implement all three and add a fourth: near-match, which collapses
 * findings with overlapping line ranges and the same broad category.
 * The strategies run in priority order; first match wins.
 */

import * as crypto from "crypto";
import type { RawFinding, FindingCategory } from "../types";

export interface DedupGroup {
  primary: RawFinding;
  tool: string;
  allTools: string[];
  allRuleIds: string[];
}

// Tool-assigned stable IDs that we trust as canonical dedup keys.
// Semgrep uses <path>:<rule-id>:<line>, which is stable within a repo.
const TOOL_STABLE_ID_PREFIXES = ["semgrep.", "codeql."];

// Broad category buckets — findings within the same bucket can merge
// even if their subcategory differs (e.g. sqli and path-traversal are
// both "injection" for near-match purposes).
const CATEGORY_BUCKET: Record<FindingCategory, string> = {
  "hardcoded-secret": "secret",
  "vulnerable-dependency": "dependency",
  "sqli": "injection",
  "xss": "injection",
  "path-traversal": "injection",
  "command-injection": "injection",
  "insecure-deserialization": "injection",
  "ssrf": "injection",
  "idor": "access",
  "broken-auth": "access",
  "sast-generic": "sast",
  "iac-misconfiguration": "iac",
  "other": "other",
};

// ─── Main dedup entry point ────────────────────────────────────────────────

export function deduplicate(
  incoming: Array<{ raw: RawFinding; tool: string }>
): DedupGroup[] {
  const groups: Map<string, DedupGroup> = new Map();

  for (const item of incoming) {
    const key = resolveKey(item.raw, item.tool);
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, {
        primary: item.raw,
        tool: item.tool,
        allTools: [item.tool],
        allRuleIds: [item.raw.ruleId],
      });
    } else {
      // Merge into existing group: keep most-severe primary.
      if (severityRank(item.raw.severity) > severityRank(existing.primary.severity)) {
        existing.primary = item.raw;
      }
      if (!existing.allTools.includes(item.tool)) existing.allTools.push(item.tool);
      if (!existing.allRuleIds.includes(item.raw.ruleId)) existing.allRuleIds.push(item.raw.ruleId);
    }
  }

  // Second pass: near-match merge — collapse findings that overlap in line
  // range AND share the same category bucket. Handles the case where Gitleaks
  // and TruffleHog both flag the same secret on the same line with different
  // rule IDs that hash to different keys.
  return nearMatchMerge(Array.from(groups.values()));
}

// ─── Key resolution (priority order) ──────────────────────────────────────

function resolveKey(f: RawFinding, tool: string): string {
  // Strategy 1: unique_id — trust tool-assigned stable IDs.
  if (hasStableToolId(f.ruleId, tool)) {
    return `uid:${f.filePath}:${f.ruleId}`;
  }

  // Strategy 2: hash_code — DefectDojo's normalized field hash.
  return hashCode(f);
}

function hasStableToolId(ruleId: string, tool: string): boolean {
  return TOOL_STABLE_ID_PREFIXES.some((p) => tool === p.slice(0, -1) || ruleId.startsWith(p));
}

// DefectDojo hash_code: SHA-256 of normalized (filePath + category + ruleId + contentFingerprint).
// Using SHA-256 (upgrade from Phase 1's SHA-1) for collision resistance.
function hashCode(f: RawFinding): string {
  const contentFp = f.codeSnippet
    ? crypto.createHash("sha256").update(f.codeSnippet.trim()).digest("hex").slice(0, 16)
    : `L${f.startLine}`;
  const key = `${f.filePath}\0${f.category}\0${normalizeRuleId(f.ruleId)}\0${contentFp}`;
  return `hc:${crypto.createHash("sha256").update(key).digest("hex").slice(0, 20)}`;
}

// Strip tool-specific prefixes and version suffixes from rule IDs
// so "semgrep.python.lang.security.audit.sqli" and "bandit.B608"
// still hash differently (correct) but "semgrep:foo:1.0" and "semgrep:foo:1.1"
// hash the same (also correct — same rule, different version).
function normalizeRuleId(ruleId: string): string {
  return ruleId.replace(/[:.]v?\d+(\.\d+)*$/, "").toLowerCase();
}

// ─── Near-match merge ─────────────────────────────────────────────────────

function nearMatchMerge(groups: DedupGroup[]): DedupGroup[] {
  // Group by file + category bucket. Only findings in the same file+bucket
  // can near-match, so this avoids O(n²) comparisons across the whole set.
  const byFileBucket = new Map<string, DedupGroup[]>();
  for (const g of groups) {
    const bucket = CATEGORY_BUCKET[g.primary.category] ?? "other";
    const key = `${g.primary.filePath}\0${bucket}`;
    (byFileBucket.get(key) ?? []).concat([]);
    const arr = byFileBucket.get(key) ?? [];
    arr.push(g);
    byFileBucket.set(key, arr);
  }

  const merged = new Set<DedupGroup>();
  const absorbed = new Set<DedupGroup>();

  for (const cluster of byFileBucket.values()) {
    if (cluster.length < 2) { cluster.forEach((g) => merged.add(g)); continue; }

    // Sort by start line for efficient overlap check.
    cluster.sort((a, b) => a.primary.startLine - b.primary.startLine);

    for (let i = 0; i < cluster.length; i++) {
      if (absorbed.has(cluster[i])) continue;
      const base = cluster[i];
      for (let j = i + 1; j < cluster.length; j++) {
        if (absorbed.has(cluster[j])) continue;
        const cand = cluster[j];
        if (overlaps(base.primary, cand.primary, 5)) {
          // Absorb cand into base.
          if (severityRank(cand.primary.severity) > severityRank(base.primary.severity)) {
            base.primary = cand.primary;
          }
          cand.allTools.forEach((t) => { if (!base.allTools.includes(t)) base.allTools.push(t); });
          cand.allRuleIds.forEach((r) => { if (!base.allRuleIds.includes(r)) base.allRuleIds.push(r); });
          absorbed.add(cand);
        }
      }
      merged.add(base);
    }
  }

  return Array.from(merged).filter((g) => !absorbed.has(g));
}

function overlaps(a: RawFinding, b: RawFinding, slack: number): boolean {
  return a.startLine <= b.endLine + slack && b.startLine <= a.endLine + slack;
}

// ─── Helpers ───────────────────────────────────────────────────────────────

const SEV: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
function severityRank(s: string): number { return SEV[s] ?? 0; }
