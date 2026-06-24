import * as fs from "fs";
import * as path from "path";
import type { ProjectFingerprint } from "../types";

const LOCKFILES = [
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "requirements.txt",
  "Pipfile.lock",
  "poetry.lock",
  "go.sum",
  "Cargo.lock",
  "Gemfile.lock",
  "composer.lock",
];

// Manifest-file detection only — no LLM inference about project type.
// Checks only the top two directory levels to stay fast on large repos.
export function fingerprint(workspaceRoot: string): ProjectFingerprint {
  const fp: ProjectFingerprint = {
    hasJavaScript: false,
    hasPython: false,
    hasGo: false,
    hasRust: false,
    hasTerraform: false,
    hasDockerfile: false,
    hasK8sManifests: false,
    hasLockfile: false,
    lockfilePaths: [],
  };

  const entries = safeReaddir(workspaceRoot);

  for (const entry of entries) {
    const full = path.join(workspaceRoot, entry);
    const lc = entry.toLowerCase();

    if (lc === "package.json" || lc === "package-lock.json" || lc === "yarn.lock" || lc === "pnpm-lock.yaml") {
      fp.hasJavaScript = true;
    }
    if (lc === "requirements.txt" || lc === "pyproject.toml" || lc === "pipfile" || lc === "pipfile.lock" || lc === "setup.py") {
      fp.hasPython = true;
    }
    if (lc === "go.mod" || lc === "go.sum") {
      fp.hasGo = true;
    }
    if (lc === "cargo.toml" || lc === "cargo.lock") {
      fp.hasRust = true;
    }
    if (lc.endsWith(".tf")) {
      fp.hasTerraform = true;
    }
    if (lc === "dockerfile" || lc.startsWith("dockerfile.")) {
      fp.hasDockerfile = true;
    }
    if (LOCKFILES.includes(entry)) {
      fp.hasLockfile = true;
      fp.lockfilePaths.push(full);
    }

    // One level deep: check subdirectories for k8s manifests and additional lockfiles.
    if (isDir(full)) {
      const sub = safeReaddir(full);
      for (const subEntry of sub) {
        const subFull = path.join(full, subEntry);
        const subLc = subEntry.toLowerCase();
        if (subLc.endsWith(".yaml") || subLc.endsWith(".yml")) {
          if (isK8sManifest(subFull)) fp.hasK8sManifests = true;
        }
        if (LOCKFILES.includes(subEntry)) {
          fp.hasLockfile = true;
          fp.lockfilePaths.push(subFull);
        }
      }
    }
  }

  return fp;
}

function safeReaddir(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}

function isDir(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function isK8sManifest(filePath: string): boolean {
  try {
    const content = fs.readFileSync(filePath, "utf8").slice(0, 500);
    return /apiVersion:\s+\S+/.test(content) && /kind:\s+\S+/.test(content);
  } catch {
    return false;
  }
}
