import * as vscode from "vscode";
import type { Finding } from "./types";

export class StatusBar {
  private readonly item: vscode.StatusBarItem;

  constructor() {
    this.item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
    this.item.command = "watsonsec.openDashboard";
    this.item.tooltip = "WatsonSec — click to open findings dashboard";
    this.setIdle();
    this.item.show();
  }

  setScanning(): void {
    this.item.text = "$(sync~spin) WatsonSec: scanning…";
    this.item.backgroundColor = undefined;
  }

  setIdle(): void {
    this.item.text = "$(shield) WatsonSec";
    this.item.backgroundColor = undefined;
  }

  setResults(findings: Finding[]): void {
    const active = findings.filter((f) => f.status !== "resolved");
    const critical = active.filter((f) => f.severity === "critical").length;
    const high = active.filter((f) => f.severity === "high").length;

    if (critical > 0) {
      this.item.text = `$(error) WatsonSec: ${critical} critical, ${high} high`;
      this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
    } else if (high > 0) {
      this.item.text = `$(warning) WatsonSec: ${high} high`;
      this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
    } else if (active.length > 0) {
      this.item.text = `$(shield) WatsonSec: ${active.length} finding${active.length === 1 ? "" : "s"}`;
      this.item.backgroundColor = undefined;
    } else {
      this.item.text = "$(pass) WatsonSec: clean";
      this.item.backgroundColor = undefined;
    }
  }

  setError(message: string): void {
    this.item.text = `$(x) WatsonSec: error`;
    this.item.tooltip = `WatsonSec error: ${message}`;
    this.item.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
  }

  dispose(): void {
    this.item.dispose();
  }
}
