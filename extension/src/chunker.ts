import * as path from 'path';
import { CodeChunk } from './types';

const CHUNK_SIZE = 300;
const OVERLAP = 20;
const MAX_FILE_BYTES = 500 * 1024;
const MAX_CHUNK_BYTES = 80_000;
const MIN_LINES = 5;

const EXCLUDED_DIRS = new Set(['node_modules', 'vendor', '.git', 'dist', 'build', '.next']);
const EXCLUDED_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.tar', '.gz', '.exe', '.bin', '.woff', '.woff2', '.ttf', '.eot', '.ico', '.svg']);
const EXCLUDED_FILES = new Set(['package-lock.json', 'yarn.lock', 'Cargo.lock', 'security-report.md']);

const LANGUAGE_MAP: Record<string, string> = {
  '.ts': 'TypeScript', '.tsx': 'TypeScript',
  '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript',
  '.py': 'Python', '.php': 'PHP', '.go': 'Go', '.rs': 'Rust',
  '.java': 'Java', '.rb': 'Ruby', '.cs': 'C#', '.cpp': 'C++', '.c': 'C',
  '.html': 'HTML', '.css': 'CSS', '.sh': 'Shell', '.yaml': 'YAML', '.yml': 'YAML',
  '.json': 'JSON', '.env': 'Env',
};

export function shouldExclude(filePath: string): boolean {
  const normalized = path.normalize(filePath);
  const parts = normalized.split(path.sep);
  if (parts.some(p => EXCLUDED_DIRS.has(p))) return true;
  const base = path.basename(normalized);
  if (EXCLUDED_FILES.has(base)) return true;
  const ext = path.extname(normalized).toLowerCase();
  if (EXCLUDED_EXTENSIONS.has(ext)) return true;
  return false;
}

// Called after file content is read — avoids a redundant statSync
export function shouldExcludeByContent(content: string): boolean {
  return Buffer.byteLength(content, 'utf8') > MAX_FILE_BYTES;
}

export function getLanguage(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  return LANGUAGE_MAP[ext] ?? 'Unknown';
}

export function chunkFile(filePath: string, content: string): CodeChunk[] {
  const lines = content.split('\n');
  if (lines.length < MIN_LINES) return [];

  const language = getLanguage(filePath);
  const chunks: CodeChunk[] = [];

  let start = 0;
  while (start < lines.length) {
    const end = Math.min(start + CHUNK_SIZE, lines.length);
    let chunkContent = lines.slice(start, end).join('\n');

    // Cap chunk at MAX_CHUNK_BYTES to handle minified files with huge lines
    if (Buffer.byteLength(chunkContent, 'utf8') > MAX_CHUNK_BYTES) {
      chunkContent = Buffer.from(chunkContent).subarray(0, MAX_CHUNK_BYTES).toString('utf8');
      // Trim to last newline to avoid sending a split mid-line
      const lastNl = chunkContent.lastIndexOf('\n');
      if (lastNl > 0) chunkContent = chunkContent.slice(0, lastNl);
    }

    chunks.push({
      filePath,
      language,
      content: chunkContent,
      startLine: start + 1,
      endLine: end,
    });

    if (end >= lines.length) break;
    start = end - OVERLAP;
  }

  return chunks;
}
