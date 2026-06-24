import type { SarifLog, SarifRun, SarifResult, RawFinding, Severity, FindingCategory } from "../types";

// ─── SARIF ingestion ───────────────────────────────────────────────────────

export function parseSarif(toolName: string, sarif: SarifLog): RawFinding[] {
  const findings: RawFinding[] = [];
  for (const run of sarif.runs ?? []) {
    findings.push(...parseRun(toolName, run));
  }
  return findings;
}

function parseRun(toolName: string, run: SarifRun): RawFinding[] {
  const ruleMap = buildRuleMap(run);
  return (run.results ?? []).map((r) => sarifResultToRaw(toolName, r, ruleMap));
}

function buildRuleMap(run: SarifRun): Map<string, Record<string, unknown>> {
  const map = new Map<string, Record<string, unknown>>();
  for (const rule of run.tool?.driver?.rules ?? []) {
    if (rule.id) map.set(rule.id, rule.properties ?? {});
  }
  return map;
}

function sarifResultToRaw(
  toolName: string,
  result: SarifResult,
  ruleProps: Map<string, Record<string, unknown>>
): RawFinding {
  const ruleId = result.ruleId ?? "unknown";
  const props = ruleProps.get(ruleId) ?? {};
  const loc = result.locations?.[0]?.physicalLocation;
  const region = loc?.region;

  return {
    ruleId,
    message: result.message?.text ?? "",
    filePath: normalizeUri(loc?.artifactLocation?.uri ?? ""),
    startLine: region?.startLine ?? 1,
    endLine: region?.endLine ?? region?.startLine ?? 1,
    codeSnippet: region?.snippet?.text,
    severity: sarifLevelToSeverity(result.level, props),
    category: inferCategory(ruleId, toolName, props),
    cwe: extractCwe(props),
  };
}

// ─── Severity mapping ──────────────────────────────────────────────────────

function sarifLevelToSeverity(
  level: SarifResult["level"],
  props: Record<string, unknown>
): Severity {
  // Prefer explicit severity from rule properties (Semgrep uses "severity", Trivy uses "precision").
  const explicit = (props["severity"] as string | undefined)?.toLowerCase();
  if (explicit) return normalizeSeverity(explicit);
  switch (level) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    default:
      return "info";
  }
}

function normalizeSeverity(raw: string): Severity {
  switch (raw) {
    case "critical":
    case "error":
      return "critical";
    case "high":
      return "high";
    case "medium":
    case "warning":
    case "moderate":
      return "medium";
    case "low":
    case "note":
      return "low";
    default:
      return "info";
  }
}

// ─── Category inference ────────────────────────────────────────────────────

const RULE_CATEGORY_HINTS: Array<[RegExp, FindingCategory]> = [
  [/secret|credential|token|api[_-]?key|password|private[_-]?key/i, "hardcoded-secret"],
  [/sqli|sql[_-]?injection/i, "sqli"],
  [/xss|cross[_-]?site[_-]?script/i, "xss"],
  [/path[_-]?traversal|directory[_-]?traversal/i, "path-traversal"],
  [/command[_-]?injection|os[_-]?command/i, "command-injection"],
  [/ssrf/i, "ssrf"],
  [/deserializ/i, "insecure-deserialization"],
  [/idor|broken[_-]?access|auth/i, "broken-auth"],
  [/vuln|cve|dependency|package/i, "vulnerable-dependency"],
  [/terraform|iac|dockerfile|k8s|kubernetes/i, "iac-misconfiguration"],
];

function inferCategory(
  ruleId: string,
  toolName: string,
  props: Record<string, unknown>
): FindingCategory {
  const haystack = [ruleId, toolName, String(props["tags"] ?? ""), String(props["category"] ?? "")].join(
    " "
  );
  for (const [re, cat] of RULE_CATEGORY_HINTS) {
    if (re.test(haystack)) return cat;
  }
  if (toolName.toLowerCase().includes("gitleaks") || toolName.toLowerCase().includes("trufflehog")) {
    return "hardcoded-secret";
  }
  if (toolName.toLowerCase().includes("osv") || toolName.toLowerCase().includes("grype") || toolName.toLowerCase().includes("trivy")) {
    return "vulnerable-dependency";
  }
  return "sast-generic";
}

function extractCwe(props: Record<string, unknown>): number | undefined {
  const raw = props["cwe"] ?? props["CWE"];
  if (typeof raw === "number") return raw;
  if (typeof raw === "string") {
    const m = raw.match(/(\d+)/);
    if (m) return parseInt(m[1], 10);
  }
  if (Array.isArray(raw) && raw.length > 0) {
    const m = String(raw[0]).match(/(\d+)/);
    if (m) return parseInt(m[1], 10);
  }
  return undefined;
}

function normalizeUri(uri: string): string {
  // SARIF URIs may be file:// prefixed or workspace-relative.
  return uri.replace(/^file:\/\//, "").replace(/^\//, "");
}
