import type { AdapterResult, ProjectFingerprint } from "../../types";

export interface ScannerAdapter {
  readonly name: string;
  readonly pinnedVersion: string;

  // Returns true if this scanner should run given the project fingerprint.
  shouldRun(fingerprint: ProjectFingerprint): boolean;

  // Runs the scanner against the workspace root and returns raw findings.
  // Must shell out to the real binary — never emulate detection logic.
  run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult>;
}

// Shared timeout for subprocess execution (30 seconds).
export const SCAN_TIMEOUT_MS = 30_000;
