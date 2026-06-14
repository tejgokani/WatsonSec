import * as vscode from 'vscode';
import { Finding } from './types';
import * as path from 'path';

type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEVERITY_COLORS: Record<SeverityKey, string> = {
  critical: '#ff0000',
  high: '#ff6600',
  medium: '#ffcc00',
  low: '#3399ff',
  info: '#aaaaaa',
};

let decorationTypes: Record<SeverityKey, vscode.TextEditorDecorationType> | null = null;

export function createDecorationTypes(): void {
  decorationTypes = {} as Record<SeverityKey, vscode.TextEditorDecorationType>;
  for (const [sev, color] of Object.entries(SEVERITY_COLORS) as [SeverityKey, string][]) {
    decorationTypes[sev] = vscode.window.createTextEditorDecorationType({
      gutterIconPath: vscode.Uri.parse(`data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><circle cx="8" cy="8" r="6" fill="${encodeURIComponent(color)}"/></svg>`),
      gutterIconSize: 'contain',
      overviewRulerColor: color,
      overviewRulerLane: vscode.OverviewRulerLane.Right,
    });
  }
}

export function disposeDecorationTypes(): void {
  if (!decorationTypes) return;
  for (const dt of Object.values(decorationTypes)) {
    dt.dispose();
  }
  decorationTypes = null;
}

export function updateDecorations(editor: vscode.TextEditor, findings: Finding[]): void {
  if (!decorationTypes) return;

  const active = findings.filter(f => !f.resolvedAt);
  const bySeverity: Record<SeverityKey, vscode.DecorationOptions[]> = {
    critical: [], high: [], medium: [], low: [], info: [],
  };

  for (const finding of active) {
    const lineIndex = Math.max(0, finding.line - 1);
    const lineCount = editor.document.lineCount;
    if (lineIndex >= lineCount) continue;

    const range = editor.document.lineAt(lineIndex).range;
    const esc = (s: string) => s.replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));
    const hoverMessage = new vscode.MarkdownString(
      `**${esc(finding.type)}** — ${finding.severity.toUpperCase()}\n\n` +
      `**CWE:** ${esc(finding.cwe)}${finding.cve ? ` | **CVE:** ${esc(finding.cve)}` : ''}\n\n` +
      `${esc(finding.description)}\n\n` +
      `**Fix:** ${esc(finding.fix)}`
    );
    // isTrusted intentionally NOT set — prevents command: URIs from LLM output executing in the IDE
    bySeverity[finding.severity].push({ range, hoverMessage });
  }

  for (const sev of Object.keys(bySeverity) as SeverityKey[]) {
    editor.setDecorations(decorationTypes[sev], bySeverity[sev]);
  }
}

export function updateDecorationsForFile(filePath: string, findings: Finding[]): void {
  for (const editor of vscode.window.visibleTextEditors) {
    if (editor.document.uri.fsPath === filePath || path.normalize(editor.document.uri.fsPath) === path.normalize(filePath)) {
      updateDecorations(editor, findings);
    }
  }
}
