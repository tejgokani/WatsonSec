import { execFile } from "child_process";
import { promisify } from "util";
import type { AdapterResult, ProjectFingerprint, RawFinding, FindingCategory } from "../../types";
import type { ScannerAdapter } from "./base";
import { SCAN_TIMEOUT_MS } from "./base";

const execFileAsync = promisify(execFile);

// Pinned version documented in orchestrator/TOOL_REGISTRY.md
export const BANDIT_PINNED_VERSION = "1.7.9";

// Bandit native JSON output (does not emit SARIF).
interface BanditOutput {
  results?: BanditResult[];
}

interface BanditResult {
  test_id: string;
  test_name: string;
  issue_text: string;
  issue_severity: "HIGH" | "MEDIUM" | "LOW";
  issue_confidence: "HIGH" | "MEDIUM" | "LOW";
  issue_cwe?: { id: number };
  filename: string;
  line_number: number;
  line_range?: number[];
  code?: string;
}

export class BanditAdapter implements ScannerAdapter {
  readonly name = "bandit";
  readonly pinnedVersion = BANDIT_PINNED_VERSION;
  readonly cadence = "fast" as const;

  shouldRun(fingerprint: ProjectFingerprint): boolean {
    return fingerprint.hasPython;
  }

  async run(workspaceRoot: string, binaryPath: string): Promise<AdapterResult> {
    try {
      let stdout = "";
      try {
        const result = await execFileAsync(
          binaryPath,
          ["-r", workspaceRoot, "-f", "json", "-q"],
          { timeout: SCAN_TIMEOUT_MS, maxBuffer: 20 * 1024 * 1024 }
        );
        stdout = result.stdout;
      } catch (spawnErr: unknown) {
        // Bandit exits non-zero when it finds issues.
        stdout = extractStdout(spawnErr) ?? "";
        if (!stdout) throw spawnErr;
      }

      const parsed = JSON.parse(stdout) as BanditOutput;
      return { tool: this.name, rawFindings: (parsed.results ?? []).map(toRawFinding) };
    } catch (err: unknown) {
      return { tool: this.name, rawFindings: [], error: errorMessage(err) };
    }
  }
}

function toRawFinding(r: BanditResult): RawFinding {
  const endLine = r.line_range ? Math.max(...r.line_range) : r.line_number;
  return {
    ruleId: r.test_id,
    message: `[${r.test_name}] ${r.issue_text}`,
    filePath: r.filename,
    startLine: r.line_number,
    endLine,
    severity: banditSeverity(r.issue_severity),
    category: banditCategory(r.test_id, r.test_name),
    cwe: r.issue_cwe?.id,
    codeSnippet: r.code,
  };
}

function banditSeverity(s: string): RawFinding["severity"] {
  switch (s) {
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    default:
      return "low";
  }
}

const BANDIT_CATEGORY_MAP: Record<string, FindingCategory> = {
  B105: "hardcoded-secret",
  B106: "hardcoded-secret",
  B107: "hardcoded-secret",
  B108: "path-traversal",
  B110: "sast-generic",
  B201: "sast-generic",
  B301: "insecure-deserialization",
  B302: "insecure-deserialization",
  B303: "sast-generic",
  B304: "sast-generic",
  B305: "sast-generic",
  B306: "path-traversal",
  B307: "command-injection",
  B308: "xss",
  B310: "ssrf",
  B311: "sast-generic",
  B312: "ssrf",
  B313: "sast-generic",
  B314: "sast-generic",
  B315: "sast-generic",
  B316: "sast-generic",
  B317: "sast-generic",
  B318: "sast-generic",
  B319: "sast-generic",
  B320: "sast-generic",
  B321: "sast-generic",
  B322: "command-injection",
  B323: "sast-generic",
  B324: "sast-generic",
  B325: "sast-generic",
  B401: "sast-generic",
  B402: "sast-generic",
  B403: "sast-generic",
  B404: "command-injection",
  B405: "sast-generic",
  B406: "sast-generic",
  B407: "sast-generic",
  B408: "sast-generic",
  B409: "sast-generic",
  B410: "sast-generic",
  B411: "sast-generic",
  B412: "sast-generic",
  B413: "sast-generic",
  B501: "sast-generic",
  B502: "sast-generic",
  B503: "sast-generic",
  B504: "sast-generic",
  B505: "sast-generic",
  B506: "sast-generic",
  B507: "sast-generic",
  B601: "command-injection",
  B602: "command-injection",
  B603: "command-injection",
  B604: "command-injection",
  B605: "command-injection",
  B606: "command-injection",
  B607: "command-injection",
  B608: "sqli",
  B609: "command-injection",
  B610: "sqli",
  B611: "sqli",
  B701: "sast-generic",
  B702: "xss",
  B703: "xss",
};

function banditCategory(testId: string, _testName: string): FindingCategory {
  return BANDIT_CATEGORY_MAP[testId] ?? "sast-generic";
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
