import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { FindingsStore } from "./store";
import { Orchestrator } from "./orchestrator";
import { DashboardServer } from "./dashboard/server";
import { StatusBar } from "./statusBar";
import { exportMarkdown } from "./reports/exporter";

// Debounce timer for save-triggered scans.
let scanDebounce: ReturnType<typeof setTimeout> | null = null;

export function activate(context: vscode.ExtensionContext): void {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!workspaceRoot) return;

  const config = vscode.workspace.getConfiguration("watsonsec");
  const port = config.get<number>("dashboardPort") ?? 7891;
  const debounceMs = config.get<number>("debounceMs") ?? 2000;

  // Persistent store in extension's global storage directory.
  const store = new FindingsStore(context.globalStorageUri.fsPath);
  const orchestrator = new Orchestrator(store);
  const dashboard = new DashboardServer(store, port);
  const statusBar = new StatusBar();

  dashboard.start();

  // ─── Commands ─────────────────────────────────────────────────────────────

  const runScanCmd = vscode.commands.registerCommand("watsonsec.runScan", async () => {
    await runScan(workspaceRoot, orchestrator, statusBar, store);
  });

  const openDashboardCmd = vscode.commands.registerCommand("watsonsec.openDashboard", () => {
    vscode.env.openExternal(vscode.Uri.parse(dashboard.url));
  });

  const exportReportCmd = vscode.commands.registerCommand("watsonsec.exportReport", async () => {
    const markdown = exportMarkdown(store);
    const reportPath = path.join(workspaceRoot, "watsonsec-report.md");
    fs.writeFileSync(reportPath, markdown, "utf8");
    const doc = await vscode.workspace.openTextDocument(reportPath);
    await vscode.window.showTextDocument(doc);
    vscode.window.showInformationMessage("WatsonSec: Report saved to watsonsec-report.md");
  });

  // ─── File watcher ─────────────────────────────────────────────────────────

  const watcher = vscode.workspace.createFileSystemWatcher(
    new vscode.RelativePattern(workspaceRoot, "**/*"),
    false, // onCreate
    false, // onChange (save)
    true   // ignore delete
  );

  const triggerDebouncedScan = () => {
    if (scanDebounce) clearTimeout(scanDebounce);
    scanDebounce = setTimeout(() => {
      runScan(workspaceRoot, orchestrator, statusBar, store);
    }, debounceMs);
  };

  watcher.onDidChange(triggerDebouncedScan);
  watcher.onDidCreate(triggerDebouncedScan);

  context.subscriptions.push(runScanCmd, openDashboardCmd, exportReportCmd, statusBar, watcher);

  // Run an initial scan on activation.
  runScan(workspaceRoot, orchestrator, statusBar, store);
}

async function runScan(
  workspaceRoot: string,
  orchestrator: Orchestrator,
  statusBar: StatusBar,
  store: FindingsStore
): Promise<void> {
  statusBar.setScanning();
  try {
    const result = await orchestrator.runScan(workspaceRoot);
    statusBar.setResults(result.findings);

    const errorTools = Object.keys(result.scan.errorsByTool);
    if (errorTools.length) {
      const msg = `WatsonSec: ${errorTools.join(", ")} failed — check tool installation`;
      vscode.window.showWarningMessage(msg);
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    statusBar.setError(msg);
    console.error("[watsonsec]", err);
  }
}

export function deactivate(): void {
  if (scanDebounce) clearTimeout(scanDebounce);
}
