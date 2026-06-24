import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, SarifLog } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";
import { parseSarif } from "../../aggregator/normalizer";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
export const GOSEC_PINNED_VERSION = "2.20.0";

export class GosecAdapter implements ScannerAdapter {
  readonly name = "gosec";
  readonly pinnedVersion = GOSEC_PINNED_VERSION;
  readonly cadence = "fast" as const;

  shouldRun(fingerprint: ProjectFingerprint): boolean {
    return fingerprint.hasGo;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      // -fmt=sarif: native SARIF output.
      // ./...: scan all Go packages recursively.
      // gosec exits non-zero on findings — capture stdout.
      let stdout = "";
      try {
        const result = await execFileAsync(
          binaryPath,
          ["-fmt=sarif", "-quiet", "./..."],
          {
            timeout: SCAN_TIMEOUT_MS,
            maxBuffer: 20 * 1024 * 1024,
            cwd: workspaceRoot,
          }
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
