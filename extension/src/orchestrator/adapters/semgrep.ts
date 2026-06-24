import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, SarifLog } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";
import { parseSarif } from "../../aggregator/normalizer";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
export const SEMGREP_PINNED_VERSION = "1.72.0";

export class SemgrepAdapter implements ScannerAdapter {
  readonly name = "semgrep";
  readonly pinnedVersion = SEMGREP_PINNED_VERSION;

  shouldRun(_fingerprint: ProjectFingerprint): boolean {
    // Semgrep runs on any repo — it has rules for all major languages.
    return true;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      // --config auto: uses Semgrep's registry rules matched to detected languages.
      // --sarif: machine-readable output we parse into our common schema.
      // --no-git-ignore: scan files VS Code has open even if .gitignored.
      // --timeout 25: per-rule timeout, stay inside our 30s subprocess limit.
      const { stdout } = await execFileAsync(
        binaryPath,
        [
          "--config", "auto",
          "--sarif",
          "--no-git-ignore",
          "--timeout", "25",
          "--quiet",
          workspaceRoot,
        ],
        { timeout: SCAN_TIMEOUT_MS, maxBuffer: 20 * 1024 * 1024 }
      );

      const sarif = JSON.parse(stdout) as SarifLog;
      return { tool: this.name, rawFindings: parseSarif(this.name, sarif) };
    } catch (err: unknown) {
      return {
        tool: this.name,
        rawFindings: [],
        error: errorMessage(err),
      };
    }
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
