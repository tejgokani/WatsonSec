import * as vscode from "vscode";
import * as crypto from "crypto";
import type { AdapterResult, Finding, ScanRecord } from "../types";
import type { ScannerAdapter } from "./adapters/base";
import { SemgrepAdapter } from "./adapters/semgrep";
import { GitleaksAdapter } from "./adapters/gitleaks";
import { OsvAdapter } from "./adapters/osv";
import { fingerprint } from "./fingerprint";
import { aggregate } from "../aggregator";
import { FindingsStore } from "../store";

// Phase 1 adapter set. Phase 2 will add Trivy, Checkov, CodeQL, Bandit.
const ADAPTERS: ScannerAdapter[] = [
  new SemgrepAdapter(),
  new GitleaksAdapter(),
  new OsvAdapter(),
];

function getBinaryPath(adapter: ScannerAdapter): string {
  const config = vscode.workspace.getConfiguration("watsonsec");
  const key = `${adapter.name.replace("-", "")}Path`;
  // Fallbacks: semgrepPath, gitleaksPath, osvScannerPath
  const altKey = adapter.name === "osv-scanner" ? "osvScannerPath" : `${adapter.name}Path`;
  return (config.get<string>(key) ?? config.get<string>(altKey)) ?? adapter.name;
}

export interface ScanResult {
  findings: Finding[];
  scan: ScanRecord;
}

export class Orchestrator {
  private readonly store: FindingsStore;

  constructor(store: FindingsStore) {
    this.store = store;
  }

  async runScan(workspaceRoot: string): Promise<ScanResult> {
    const scanId = crypto.randomUUID();
    const startedAt = Date.now();
    const fp = fingerprint(workspaceRoot);

    const selectedAdapters = ADAPTERS.filter((a) => a.shouldRun(fp));
    const skippedAdapters = ADAPTERS.filter((a) => !a.shouldRun(fp));

    // Run all selected adapters in parallel.
    const results: AdapterResult[] = await Promise.all(
      selectedAdapters.map((adapter) =>
        adapter.run(workspaceRoot, getBinaryPath(adapter))
      )
    );

    const errorsByTool: Record<string, string> = {};
    for (const r of results) {
      if (r.error) errorsByTool[r.tool] = r.error;
    }

    const findings = aggregate(results, workspaceRoot, scanId);
    this.store.applyNewFindings(findings, scanId);

    const scanRecord: ScanRecord = {
      scanId,
      startedAt,
      finishedAt: Date.now(),
      toolsRun: selectedAdapters.map((a) => a.name),
      toolsSkipped: skippedAdapters.map((a) => a.name),
      findingCount: findings.length,
      errorsByTool,
    };
    this.store.appendScanRecord(scanRecord);

    return { findings: this.store.getActive(), scan: scanRecord };
  }
}
