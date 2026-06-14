import { Finding, ResolutionDiff } from './types';

const store = new Map<string, Finding[]>();

function matchesByLineAndType(a: Finding, b: Finding, tolerance = 3): boolean {
  return a.type === b.type && Math.abs(a.line - b.line) <= tolerance;
}

export function updateFindings(filePath: string, newFindings: Finding[]): ResolutionDiff {
  const existing = store.get(filePath) ?? [];
  const active = existing.filter(f => !f.resolvedAt);

  const resolved: Finding[] = [];
  const unchanged: Finding[] = [];
  const added: Finding[] = [];

  for (const old of active) {
    const stillExists = newFindings.some(n => matchesByLineAndType(old, n));
    if (stillExists) {
      unchanged.push(old);
    } else {
      resolved.push({ ...old, resolvedAt: new Date() });
    }
  }

  const resolvedFindings = existing.filter(f => f.resolvedAt);
  resolvedFindings.push(...resolved);

  for (const n of newFindings) {
    const alreadyTracked = existing.some(e => matchesByLineAndType(e, n));
    if (!alreadyTracked) {
      added.push(n);
    }
  }

  store.set(filePath, [...unchanged, ...added, ...resolvedFindings]);

  return { resolved, added, unchanged };
}

export function getAllFindings(): Finding[] {
  const all: Finding[] = [];
  for (const findings of store.values()) {
    all.push(...findings);
  }
  return all;
}

export function getFileFindings(filePath: string): Finding[] {
  return store.get(filePath) ?? [];
}

export function clearResolved(): void {
  for (const [key, findings] of store.entries()) {
    store.set(key, findings.filter(f => !f.resolvedAt));
  }
}

export function clearFile(filePath: string): void {
  store.delete(filePath);
}
