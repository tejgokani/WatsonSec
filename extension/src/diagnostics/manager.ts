import * as vscode from "vscode";
import * as path from "path";
import type { Finding, Severity } from "../types";

const SOURCE = "WatsonSec";

// Maps WatsonSec findings onto VS Code's DiagnosticCollection so they appear
// in the Problems panel and as squiggly underlines in the editor.
export class DiagnosticsManager {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection(SOURCE);
  }

  update(findings: Finding[], workspaceRoot: string): void {
    // Group active findings by file.
    const byFile = new Map<string, Finding[]>();
    for (const f of findings) {
      if (f.status === "resolved") continue;
      const abs = path.isAbsolute(f.filePath)
        ? f.filePath
        : path.join(workspaceRoot, f.filePath);
      (byFile.get(abs) ?? []).concat([]);
      const arr = byFile.get(abs) ?? [];
      arr.push(f);
      byFile.set(abs, arr);
    }

    // Clear files that no longer have findings.
    this.collection.clear();

    // Set diagnostics for each file.
    for (const [absPath, filefindings] of byFile.entries()) {
      const uri = vscode.Uri.file(absPath);
      const diagnostics = filefindings.map((f) => toDiagnostic(f));
      this.collection.set(uri, diagnostics);
    }
  }

  clear(): void {
    this.collection.clear();
  }

  dispose(): void {
    this.collection.dispose();
  }
}

function toDiagnostic(finding: Finding): vscode.Diagnostic {
  const startLine = Math.max(0, finding.startLine - 1);
  const endLine = Math.max(startLine, finding.endLine - 1);

  const range = new vscode.Range(
    new vscode.Position(startLine, 0),
    new vscode.Position(endLine, Number.MAX_SAFE_INTEGER)
  );

  const diag = new vscode.Diagnostic(
    range,
    `[${finding.ruleId[0]}] ${finding.message}`,
    severityToVscode(finding.severity)
  );

  diag.source = `WatsonSec (${finding.tool.join(", ")})`;
  diag.code = {
    value: finding.ruleId[0],
    target: finding.cwe
      ? vscode.Uri.parse(`https://cwe.mitre.org/data/definitions/${finding.cwe}.html`)
      : vscode.Uri.parse(`https://github.com/tejgokani/watsonsec`),
  };

  return diag;
}

function severityToVscode(sev: Severity): vscode.DiagnosticSeverity {
  switch (sev) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
    case "info":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}
