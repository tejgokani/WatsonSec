import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, SarifLog } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";
import { parseSarif } from "../../aggregator/normalizer";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
export const TRIVY_PINNED_VERSION = "0.52.2";

export class TrivyAdapter implements ScannerAdapter {
  readonly name = "trivy";
  readonly pinnedVersion = TRIVY_PINNED_VERSION;
  readonly cadence = "fast" as const;

  shouldRun(_fingerprint: ProjectFingerprint): boolean {
    // Trivy runs on any repo — covers secrets, misconfigs, and dependencies.
    return true;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      // fs: scan filesystem (not just containers).
      // --format sarif: native SARIF output.
      // --scanners vuln,secret,misconfig: all in one pass.
      // --exit-code 0: don't fail on findings; we capture stdout.
      const { stdout } = await execFileAsync(
        binaryPath,
        [
          "fs",
          "--format", "sarif",
          "--scanners", "vuln,secret,misconfig",
          "--exit-code", "0",
          "--quiet",
          workspaceRoot,
        ],
        { timeout: SCAN_TIMEOUT_MS, maxBuffer: 20 * 1024 * 1024 }
      );

      const sarif = JSON.parse(stdout) as SarifLog;
      return { tool: this.name, rawFindings: parseSarif(this.name, sarif) };
    } catch (err: unknown) {
      return { tool: this.name, rawFindings: [], error: errorMessage(err) };
    }
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
