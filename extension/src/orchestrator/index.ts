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
import { ToolManager } from "../toolManager";

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


export interface ScanResult {
  findings: Finding[];
  scan: ScanRecord;
}

export class Orchestrator {
  private readonly store: FindingsStore;
  private readonly tools: ToolManager;

  constructor(store: FindingsStore, tools: ToolManager) {
    this.store = store;
    this.tools = tools;
  }

  async runFastScan(workspaceRoot: string): Promise<ScanResult> {
    return this.runAdapters(workspaceRoot, FAST_ADAPTERS, "fast");
  }

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

    // Ensure all needed tools are present — download missing ones (with prompts for large tools).
    await this.tools.ensureTools(selected.map((a) => a.name), fp);

    const results: AdapterResult[] = await Promise.all(
      selected.map((adapter) => adapter.run(workspaceRoot, this.tools.resolveToolPath(adapter.name)))
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
