import * as vscode from "vscode";
import * as crypto from "crypto";
import type { AdapterResult, Finding, ScanRecord } from "../types";
import type { ScannerAdapter } from "./adapters/base";
import { SemgrepAdapter } from "./adapters/semgrep";
import { GitleaksAdapter } from "./adapters/gitleaks";
import { OsvAdapter } from "./adapters/osv";
import { TrivyAdapter } from "./adapters/trivy";
import { CheckovAdapter } from "./adapters/checkov";
import { BanditAdapter } from "./adapters/bandit";
import { GosecAdapter } from "./adapters/gosec";
import { GrypeAdapter } from "./adapters/grype";
import { TruffleHogAdapter } from "./adapters/trufflehog";
import { CodeQLAdapter } from "./adapters/codeql";
import { fingerprint } from "./fingerprint";
import { aggregate } from "../aggregator";
import { FindingsStore } from "../store";

// Fast adapters run on every (debounced) save.
const FAST_ADAPTERS: ScannerAdapter[] = [
  new SemgrepAdapter(),
  new GitleaksAdapter(),
  new TruffleHogAdapter(),
  new OsvAdapter(),
  new GrypeAdapter(),
  new TrivyAdapter(),
  new BanditAdapter(),
  new GosecAdapter(),
  new CheckovAdapter(),
];

// Slow adapters run only on explicit command or every N saves.
const SLOW_ADAPTERS: ScannerAdapter[] = [
  new CodeQLAdapter(),
];

const ALL_ADAPTERS = [...FAST_ADAPTERS, ...SLOW_ADAPTERS];

function getBinaryPath(adapter: ScannerAdapter): string {
  const config = vscode.workspace.getConfiguration("watsonsec");
  // Mapping: adapter.name → config key
  const KEY_MAP: Record<string, string> = {
    semgrep: "semgrepPath",
    gitleaks: "gitleaksPath",
    "osv-scanner": "osvScannerPath",
    trivy: "trivyPath",
    checkov: "checkovPath",
    bandit: "banditPath",
    gosec: "gosecPath",
    grype: "grypeePath",
    trufflehog: "trufflehogPath",
    codeql: "codeqlPath",
  };
  const key = KEY_MAP[adapter.name] ?? `${adapter.name}Path`;
  return config.get<string>(key) ?? adapter.name;
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

  // Fast scan: runs all fast adapters in parallel (triggered on save).
  async runFastScan(workspaceRoot: string): Promise<ScanResult> {
    return this.runAdapters(workspaceRoot, FAST_ADAPTERS, "fast");
  }

  // Full scan: fast + slow adapters (triggered by command or N-save counter).
  async runFullScan(workspaceRoot: string): Promise<ScanResult> {
    return this.runAdapters(workspaceRoot, ALL_ADAPTERS, "full");
  }

  private async runAdapters(
    workspaceRoot: string,
    adapters: ScannerAdapter[],
    scanType: "fast" | "full"
  ): Promise<ScanResult> {
    const scanId = `${scanType}-${crypto.randomUUID()}`;
    const startedAt = Date.now();
    const fp = fingerprint(workspaceRoot);

    const selected = adapters.filter((a) => a.shouldRun(fp));
    const skipped = ALL_ADAPTERS.filter((a) => !selected.includes(a));

    const results: AdapterResult[] = await Promise.all(
      selected.map((adapter) => adapter.run(workspaceRoot, getBinaryPath(adapter)))
    );

    const errorsByTool: Record<string, string> = {};
    for (const r of results) {
      if (r.error) errorsByTool[r.tool] = r.error;
    }

    const newFindings = aggregate(results, workspaceRoot, scanId);
    this.store.applyNewFindings(newFindings, scanId);

    const scanRecord: ScanRecord = {
      scanId,
      startedAt,
      finishedAt: Date.now(),
      toolsRun: selected.map((a) => a.name),
      toolsSkipped: skipped.map((a) => a.name),
      findingCount: newFindings.length,
      errorsByTool,
    };
    this.store.appendScanRecord(scanRecord);

    return { findings: this.store.getActive(), scan: scanRecord };
  }
}
