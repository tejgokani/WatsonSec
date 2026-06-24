import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, SarifLog } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";
import { parseSarif } from "../../aggregator/normalizer";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
export const CHECKOV_PINNED_VERSION = "3.2.0";

export class CheckovAdapter implements ScannerAdapter {
  readonly name = "checkov";
  readonly pinnedVersion = CHECKOV_PINNED_VERSION;
  readonly cadence = "fast" as const;

  shouldRun(fingerprint: ProjectFingerprint): boolean {
    return fingerprint.hasTerraform || fingerprint.hasDockerfile || fingerprint.hasK8sManifests;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      // -d: directory to scan.
      // -o sarif: native SARIF output.
      // --quiet: suppress progress noise.
      // checkov exits non-zero when it finds issues — catch it.
      let stdout = "";
      try {
        const result = await execFileAsync(
          binaryPath,
          ["-d", workspaceRoot, "-o", "sarif", "--quiet"],
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
