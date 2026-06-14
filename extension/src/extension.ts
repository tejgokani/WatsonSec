import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { createDecorationTypes, disposeDecorationTypes, updateDecorations } from './decorationManager';
import { createStatusBar } from './statusBar';
import { initialize, onFileSaved, onFileOpened, scanCurrentFile, runFullScan, clearResolved, startRefreshLoop, stopRefreshLoop, dispose as disposeOrchestrator } from './orchestrator';
import { getFileFindings } from './resolver';

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  createDecorationTypes();
  const statusBar = createStatusBar();
  context.subscriptions.push(statusBar);

  initialize(context);

  context.subscriptions.push(
    vscode.commands.registerCommand('securitySentinel.openReport', async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage('No workspace open.');
        return;
      }
      const cfg = vscode.workspace.getConfiguration('securitySentinel');
      const reportPath = cfg.get<string>('reportPath') ?? 'security-report.md';
      const workspaceRoot = folders[0].uri.fsPath;
      const fullPath = path.resolve(workspaceRoot, reportPath);
      const safeRoot = path.resolve(workspaceRoot) + path.sep;
      if (!fullPath.startsWith(safeRoot)) {
        vscode.window.showErrorMessage('Security Sentinel: reportPath is outside the workspace — open aborted.');
        return;
      }
      if (!fs.existsSync(fullPath)) {
        fs.writeFileSync(fullPath, '# Security Sentinel — Report\n\nNo issues found yet. Run a scan to get started.\n', 'utf8');
      }
      await vscode.commands.executeCommand('vscode.open', vscode.Uri.file(fullPath), { viewColumn: vscode.ViewColumn.Beside });
    }),

    vscode.commands.registerCommand('securitySentinel.scanAll', () => { void runFullScan(); }),
    vscode.commands.registerCommand('securitySentinel.scanFile', () => { scanCurrentFile(); }),
    vscode.commands.registerCommand('securitySentinel.clearResolved', clearResolved),

    vscode.commands.registerCommand('securitySentinel.enable', () => {
      vscode.workspace.getConfiguration('securitySentinel').update('enabled', true, vscode.ConfigurationTarget.Workspace);
      vscode.window.showInformationMessage('Security Sentinel enabled.');
    }),

    vscode.commands.registerCommand('securitySentinel.disable', () => {
      vscode.workspace.getConfiguration('securitySentinel').update('enabled', false, vscode.ConfigurationTarget.Workspace);
      vscode.window.showInformationMessage('Security Sentinel disabled.');
    }),

    vscode.workspace.onDidSaveTextDocument(doc => { onFileSaved(doc); }),
    vscode.workspace.onDidOpenTextDocument(doc => { onFileOpened(doc); }),
    vscode.window.onDidChangeActiveTextEditor(editor => {
      if (editor) updateDecorations(editor, getFileFindings(editor.document.uri.fsPath));
    }),

    { dispose: disposeDecorationTypes },
    { dispose: disposeOrchestrator },
  );

  void runFullScan();
  startRefreshLoop();
}

export function deactivate(): void {
  stopRefreshLoop();
  disposeOrchestrator();
  disposeDecorationTypes();
}
