import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, SarifLog } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";
import { parseSarif } from "../../aggregator/normalizer";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
export const GRYPE_PINNED_VERSION = "0.78.0";

export class GrypeAdapter implements ScannerAdapter {
  readonly name = "grype";
  readonly pinnedVersion = GRYPE_PINNED_VERSION;
  readonly cadence = "fast" as const;

  shouldRun(fingerprint: ProjectFingerprint): boolean {
    return fingerprint.hasLockfile;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      // dir: prefix tells Grype to scan as a directory (auto-detects lockfiles).
      // --output sarif: native SARIF output.
      // grype exits non-zero on findings — catch it.
      let stdout = "";
      try {
        const result = await execFileAsync(
          binaryPath,
          [`dir:${workspaceRoot}`, "--output", "sarif", "--quiet"],
          { timeout: SCAN_TIMEOUT_MS, maxBuffer: 20 * 1024 * 1024 }
        );
        stdout = result.stdout;
      } catch (spawnErr: unknown) {
        stdout = extractStdout(spawnErr) ?? "";
        if (!stdout) throw spawnErr;
      }

      const sarif = JSON.parse(stdout) as SarifLog;
      return { tool: this.name, rawFindings: parseSarif(this.name, sarif) };
    } catch (err: unknown) {
      return { tool: this.name, rawFindings: [], error: errorMessage(err) };
    }
  }
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
