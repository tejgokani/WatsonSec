import { execFile } from "child_process";
import { promisify } from "util";
import * as path from "path";
import * as fs from "fs";
import type { AdapterResult, ProjectFingerprint, SarifLog } from "../../types";
import type { ScannerAdapter } from "./base";
import { parseSarif } from "../../aggregator/normalizer";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
// CodeQL engine is proprietary; query packs are open (MIT/Apache-2.0).
export const CODEQL_PINNED_VERSION = "2.17.6";

// CodeQL is a slow-cadence tool (database creation can take minutes for large repos).
// It runs on an explicit command or every N saves, never on every save.
const CODEQL_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

// Languages CodeQL can analyze without a build interceptor.
const TRACELESSLY_SUPPORTED: Record<string, string> = {
  python: "python",
  javascript: "javascript",
  typescript: "javascript",
  ruby: "ruby",
};

export class CodeQLAdapter implements ScannerAdapter {
  readonly name = "codeql";
  readonly pinnedVersion = CODEQL_PINNED_VERSION;
  // Slow cadence: orchestrator only invokes this on explicit command or N-save trigger.
  readonly cadence = "slow" as const;

  shouldRun(fingerprint: ProjectFingerprint): boolean {
    return (
      fingerprint.hasJavaScript ||
      fingerprint.hasPython ||
      fingerprint.hasGo
    );
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    const dbPath = path.join(workspaceRoot, ".codeql-db");
    const sarifPath = path.join(workspaceRoot, ".codeql-results.sarif");
    const language = detectLanguage(workspaceRoot);

    if (!language) {
      return {
        tool: this.name,
        rawFindings: [],
        error: "No CodeQL-supported language detected (supports JS/TS, Python, Go, Ruby)",
      };
    }

    try {
      // Create or overwrite the database.
      await execFileAsync(
        binaryPath,
        [
          "database", "create",
          "--language", language,
          "--source-root", workspaceRoot,
          "--overwrite",
          dbPath,
        ],
        { timeout: CODEQL_TIMEOUT_MS, maxBuffer: 50 * 1024 * 1024 }
      );

      // Analyze with the standard security query pack for the language.
      await execFileAsync(
        binaryPath,
        [
          "database", "analyze",
          dbPath,
          `codeql/${language}-queries:codeql-suites/${language}-security-extended.qls`,
          "--format=sarif-latest",
          `--output=${sarifPath}`,
          "--sarif-add-file-contents",
        ],
        { timeout: CODEQL_TIMEOUT_MS, maxBuffer: 50 * 1024 * 1024 }
      );

      const raw = fs.readFileSync(sarifPath, "utf8");
      const sarif = JSON.parse(raw) as SarifLog;
      return { tool: this.name, rawFindings: parseSarif(this.name, sarif) };
    } catch (err: unknown) {
      return { tool: this.name, rawFindings: [], error: errorMessage(err) };
    } finally {
      // Clean up the generated SARIF file; the database stays for faster re-runs.
      try { fs.unlinkSync(sarifPath); } catch { /* ignore */ }
    }
  }
}

function detectLanguage(workspaceRoot: string): string | undefined {
  const entries = safeReaddir(workspaceRoot);
  if (entries.some((e) => e === "package.json" || e.endsWith(".js") || e.endsWith(".ts"))) {
    return TRACELESSLY_SUPPORTED["javascript"];
  }
  if (entries.some((e) => e === "requirements.txt" || e === "setup.py" || e === "pyproject.toml")) {
    return TRACELESSLY_SUPPORTED["python"];
  }
  if (entries.some((e) => e === "go.mod")) {
    return "go";
  }
  if (entries.some((e) => e === "Gemfile")) {
    return TRACELESSLY_SUPPORTED["ruby"];
  }
  return undefined;
}

function safeReaddir(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}
