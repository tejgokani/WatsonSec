export interface Finding {
  id: string;
  filePath: string;
  line: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  type: string;
  cwe: string;
  cve?: string;
  description: string;
  fix: string;
  resolvedAt?: Date;
}

export interface CodeChunk {
  filePath: string;
  language: string;
  content: string;
  startLine: number;
  endLine: number;
}

export interface ResolutionDiff {
  resolved: Finding[];
  added: Finding[];
  unchanged: Finding[];
}

export type ProjectType =
  | 'Node.js / Express'
  | 'Next.js'
  | 'Python'
  | 'PHP / Laravel'
  | 'Go'
  | 'Rust'
  | 'Java / Spring'
  | 'Ruby / Rails'
  | 'Node.js generic'
  | 'Unknown';
