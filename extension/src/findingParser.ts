import * as crypto from 'crypto';
import { Finding } from './types';

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

function makeSeverity(s: unknown): Finding['severity'] {
  if (typeof s === 'string' && SEVERITIES.has(s)) return s as Finding['severity'];
  return 'info';
}

function makeId(filePath: string, line: number, type: string): string {
  return crypto.createHash('sha256').update(`${filePath}|${line}|${type}`).digest('hex').slice(0, 16);
}

export function parseFindings(raw: unknown, filePath: string, lineOffset: number): Finding[] {
  let parsed: unknown;
  let text: string;
  if (typeof raw === 'string') {
    text = raw;
  } else {
    try { text = JSON.stringify(raw); } catch { return []; }
  }

  try {
    parsed = JSON.parse(text);
  } catch {
    // try to extract JSON array from text
    const match = text.match(/\[[\s\S]*\]/);
    if (!match) return [];
    try {
      parsed = JSON.parse(match[0]);
    } catch {
      return [];
    }
  }

  if (!Array.isArray(parsed)) return [];

  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const item of parsed) {
    if (typeof item !== 'object' || item === null) continue;
    const obj = item as Record<string, unknown>;
    const line = typeof obj['line'] === 'number' ? obj['line'] + lineOffset : lineOffset + 1;
    const type = typeof obj['type'] === 'string' ? obj['type'] : 'Unknown';
    const id = makeId(filePath, line, type);
    if (seen.has(id)) continue;
    seen.add(id);

    findings.push({
      id,
      filePath,
      line,
      severity: makeSeverity(obj['severity']),
      type,
      cwe: typeof obj['cwe'] === 'string' ? obj['cwe'] : 'CWE-Unknown',
      cve: typeof obj['cve'] === 'string' ? obj['cve'] : undefined,
      description: typeof obj['description'] === 'string' ? obj['description'] : '',
      fix: typeof obj['fix'] === 'string' ? obj['fix'] : '',
    });
  }

  return findings;
}
