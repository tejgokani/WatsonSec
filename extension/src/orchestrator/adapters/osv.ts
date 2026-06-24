import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, RawFinding } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
export const OSV_PINNED_VERSION = "1.8.1";

// OSV-Scanner JSON output (simplified — captures the fields we need).
interface OsvOutput {
  results?: OsvResult[];
}

interface OsvResult {
  packages?: OsvPackage[];
}

interface OsvPackage {
  package?: { name?: string; version?: string; ecosystem?: string };
  vulnerabilities?: OsvVuln[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  severity?: Array<{ type?: string; score?: string }>;
  aliases?: string[];
  database_specific?: { severity?: string; cvss_v3?: string };
}

export class OsvAdapter implements ScannerAdapter {
  readonly name = "osv-scanner";
  readonly pinnedVersion = OSV_PINNED_VERSION;

  shouldRun(fingerprint: ProjectFingerprint): boolean {
    return fingerprint.hasLockfile;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      // --recursive: find all lockfiles under workspaceRoot.
      // --format json: machine-readable.
      // osv-scanner exits non-zero when vulnerabilities are found — catch that.
      let stdout = "";
      try {
        const result = await execFileAsync(
          binaryPath,
          ["--recursive", "--format", "json", workspaceRoot],
          { timeout: SCAN_TIMEOUT_MS, maxBuffer: 10 * 1024 * 1024 }
        );
        stdout = result.stdout;
      } catch (spawnErr: unknown) {
        // osv-scanner exits 1 when it finds vulns; stdout still contains JSON.
        if (spawnErr instanceof Error && "stdout" in spawnErr) {
          stdout = (spawnErr as NodeJS.ErrnoException & { stdout: string }).stdout ?? "";
        } else {
          throw spawnErr;
        }
      }

      const parsed = JSON.parse(stdout) as OsvOutput;
      const findings = extractFindings(parsed, workspaceRoot);
      return { tool: this.name, rawFindings: findings };
    } catch (err: unknown) {
      return { tool: this.name, rawFindings: [], error: errorMessage(err) };
    }
  }
}

function extractFindings(output: OsvOutput, workspaceRoot: string): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const result of output.results ?? []) {
    for (const pkg of result.packages ?? []) {
      for (const vuln of pkg.vulnerabilities ?? []) {
        const pkgName = pkg.package?.name ?? "unknown";
        const pkgVersion = pkg.package?.version ?? "?";
        const ecosystem = pkg.package?.ecosystem ?? "";
        const severity = osvSeverity(vuln);

        findings.push({
          ruleId: vuln.id,
          message: `${pkgName}@${pkgVersion} (${ecosystem}) — ${vuln.summary ?? vuln.id}`,
          filePath: manifestPath(workspaceRoot, ecosystem),
          startLine: 1,
          endLine: 1,
          severity,
          category: "vulnerable-dependency",
          cwe: extractCwes(vuln),
        });
      }
    }
  }
  return findings;
}

function osvSeverity(vuln: OsvVuln): RawFinding["severity"] {
  const dbSev = vuln.database_specific?.severity?.toLowerCase();
  if (dbSev === "critical") return "critical";
  if (dbSev === "high") return "high";
  if (dbSev === "moderate" || dbSev === "medium") return "medium";
  if (dbSev === "low") return "low";
  // Fall back to CVSS score range.
  const cvss = vuln.severity?.find((s) => s.score)?.score;
  if (cvss) {
    const score = parseFloat(cvss);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }
  return "medium";
}

function manifestPath(workspaceRoot: string, ecosystem: string): string {
  const map: Record<string, string> = {
    npm: "package-lock.json",
    PyPI: "requirements.txt",
    Go: "go.sum",
    crates: "Cargo.lock",
    Maven: "pom.xml",
  };
  return map[ecosystem] ?? "lockfile";
}

function extractCwes(vuln: OsvVuln): number | undefined {
  for (const alias of vuln.aliases ?? []) {
    const m = alias.match(/CWE-(\d+)/i);
    if (m) return parseInt(m[1], 10);
  }
  return undefined;
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
