import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, RawFinding } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
export const GITLEAKS_PINNED_VERSION = "8.18.4";

// Gitleaks JSON output shape (does not emit SARIF natively).
interface GitleaksResult {
  RuleID: string;
  Description: string;
  StartLine: number;
  EndLine: number;
  File: string;
  Match?: string;
  Secret?: string;
  Entropy?: number;
}

export class GitleaksAdapter implements ScannerAdapter {
  readonly name = "gitleaks";
  readonly pinnedVersion = GITLEAKS_PINNED_VERSION;

  shouldRun(_fingerprint: ProjectFingerprint): boolean {
    // Secrets detection runs on any repo unconditionally.
    return true;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      // detect: scan the directory, not just git history.
      // --report-format json: machine-readable output.
      // --exit-code 0: don't fail the process when secrets are found; we check stdout.
      const { stdout } = await execFileAsync(
        binaryPath,
        [
          "detect",
          "--source", workspaceRoot,
          "--report-format", "json",
          "--report-path", "/dev/stdout",
          "--exit-code", "0",
          "--no-git",
        ],
        { timeout: SCAN_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
      );

      if (!stdout.trim() || stdout.trim() === "null") {
        return { tool: this.name, rawFindings: [] };
      }

      const results = JSON.parse(stdout) as GitleaksResult[];
      return { tool: this.name, rawFindings: results.map(toRawFinding) };
    } catch (err: unknown) {
      return {
        tool: this.name,
        rawFindings: [],
        error: errorMessage(err),
      };
    }
  }
}

function toRawFinding(r: GitleaksResult): RawFinding {
  return {
    ruleId: r.RuleID,
    message: r.Description + (r.Match ? ` — match: ${redact(r.Match)}` : ""),
    filePath: r.File,
    startLine: r.StartLine,
    endLine: r.EndLine,
    severity: "high",
    category: "hardcoded-secret",
    codeSnippet: r.Match ? redact(r.Match) : undefined,
  };
}

// Redact the actual matched secret value from snippets stored in findings.
function redact(match: string): string {
  if (match.length <= 8) return "***";
  return match.slice(0, 4) + "***" + match.slice(-4);
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
