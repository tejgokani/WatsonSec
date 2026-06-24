import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, RawFinding } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
// TruffleHog is AGPL-3.0: safe to invoke as an unmodified subprocess.
// Do NOT modify and redistribute the binary — see TOOL_REGISTRY.md licensing section.
export const TRUFFLEHOG_PINNED_VERSION = "3.78.0";

// TruffleHog emits one JSON object per line (JSONL) on stdout.
interface TruffleHogResult {
  SourceMetadata?: {
    Data?: {
      Filesystem?: { file?: string; line?: number };
      Git?: { file?: string; line?: number };
    };
  };
  DetectorName?: string;
  DetectorType?: number;
  DecoderName?: string;
  Verified?: boolean;
  Raw?: string;
  Redacted?: string;
  RuleID?: string;
}

export class TruffleHogAdapter implements ScannerAdapter {
  readonly name = "trufflehog";
  readonly pinnedVersion = TRUFFLEHOG_PINNED_VERSION;
  readonly cadence = "fast" as const;

  shouldRun(_fingerprint: ProjectFingerprint): boolean {
    return true;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      // filesystem: scan local files (not git history).
      // --json: JSONL output.
      // --no-verification: skip external verification calls to reduce latency;
      //   findings are still reported, just marked unverified.
      let stdout = "";
      try {
        const result = await execFileAsync(
          binaryPath,
          ["filesystem", "--json", "--no-verification", workspaceRoot],
          { timeout: SCAN_TIMEOUT_MS, maxBuffer: 20 * 1024 * 1024 }
        );
        stdout = result.stdout;
      } catch (spawnErr: unknown) {
        stdout = extractStdout(spawnErr) ?? "";
        if (!stdout.trim()) throw spawnErr;
      }

      const findings = parseJsonl(stdout);
      return { tool: this.name, rawFindings: findings };
    } catch (err: unknown) {
      return { tool: this.name, rawFindings: [], error: errorMessage(err) };
    }
  }
}

function parseJsonl(output: string): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const line of output.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const r = JSON.parse(trimmed) as TruffleHogResult;
      const loc = r.SourceMetadata?.Data?.Filesystem ?? r.SourceMetadata?.Data?.Git;
      if (!loc?.file) continue;

      const detector = r.DetectorName ?? "unknown";
      const redacted = r.Redacted ?? (r.Raw ? redactValue(r.Raw) : "***");

      findings.push({
        ruleId: r.RuleID ?? `trufflehog.${detector.toLowerCase()}`,
        message: `${detector} secret detected${r.Verified ? " (verified)" : ""} — ${redacted}`,
        filePath: loc.file,
        startLine: loc.line ?? 1,
        endLine: loc.line ?? 1,
        severity: r.Verified ? "critical" : "high",
        category: "hardcoded-secret",
        codeSnippet: redacted,
      });
    } catch {
      // Skip malformed lines.
    }
  }
  return findings;
}

function redactValue(raw: string): string {
  if (raw.length <= 8) return "***";
  return raw.slice(0, 4) + "***" + raw.slice(-4);
}

function extractStdout(err: unknown): string | undefined {
  if (err && typeof err === "object" && "stdout" in err) {
    return (err as { stdout: string }).stdout;
  }
  return undefined;
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
