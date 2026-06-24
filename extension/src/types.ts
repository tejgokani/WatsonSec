// Core Finding schema — stable across re-scans; never use timestamps or
// raw line numbers as the primary ID (they shift on every edit).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus = "new" | "confirmed" | "resolved" | "reopened";

export type FindingCategory =
  | "hardcoded-secret"
  | "vulnerable-dependency"
  | "sqli"
  | "xss"
  | "path-traversal"
  | "command-injection"
  | "insecure-deserialization"
  | "ssrf"
  | "idor"
  | "broken-auth"
  | "sast-generic"
  | "iac-misconfiguration"
  | "other";

export interface Finding {
  id: string;                      // stable hash of (filePath, category, ruleId, contentFingerprint)
  tool: string[];                  // scanner(s) that produced it (after merge)
  ruleId: string[];                // original rule IDs from source tool(s)
  category: FindingCategory;
  cwe?: number;                    // CWE ID when available
  severity: Severity;
  filePath: string;                // workspace-relative path
  startLine: number;
  endLine: number;
  message: string;
  codeSnippet?: string;
  status: FindingStatus;
  firstSeen: number;               // unix ms
  lastSeen: number;                // unix ms
  scanId: string;                  // which scan produced the latest observation
}

// SARIF intermediate types — enough to cover what Semgrep, Trivy, Checkov emit.
export interface SarifResult {
  ruleId?: string;
  message: { text: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number; endLine?: number; snippet?: { text?: string } };
    };
  }>;
  level?: "error" | "warning" | "note" | "none";
  properties?: Record<string, unknown>;
}

export interface SarifRun {
  tool: { driver: { name: string; rules?: Array<{ id: string; properties?: Record<string, unknown> }> } };
  results?: SarifResult[];
}

export interface SarifLog {
  version: string;
  runs: SarifRun[];
}

// Raw output from each adapter before normalization.
export interface AdapterResult {
  tool: string;
  rawFindings: RawFinding[];
  error?: string;
}

export interface RawFinding {
  ruleId: string;
  message: string;
  filePath: string;
  startLine: number;
  endLine: number;
  severity: Severity;
  category: FindingCategory;
  cwe?: number;
  codeSnippet?: string;
}

// Project fingerprint — which ecosystems are present in the workspace.
export interface ProjectFingerprint {
  hasJavaScript: boolean;
  hasPython: boolean;
  hasGo: boolean;
  hasRust: boolean;
  hasTerraform: boolean;
  hasDockerfile: boolean;
  hasK8sManifests: boolean;
  hasLockfile: boolean;
  lockfilePaths: string[];
}

// Scan metadata written to the store per scan run.
export interface ScanRecord {
  scanId: string;
  startedAt: number;
  finishedAt: number;
  toolsRun: string[];
  toolsSkipped: string[];
  findingCount: number;
  errorsByTool: Record<string, string>;
}
