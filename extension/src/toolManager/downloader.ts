import * as fs from "fs";
import * as path from "path";
import * as https from "https";
import * as http from "http";
import * as crypto from "crypto";
import { execFile } from "child_process";
import { promisify } from "util";
import type { ToolManifest } from "./manifest";
import { releaseBaseUrl } from "./manifest";

const execFileAsync = promisify(execFile);

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

function get(url: string, hops = 0): Promise<http.IncomingMessage> {
  return new Promise((resolve, reject) => {
    if (hops > 5) { reject(new Error("Too many redirects")); return; }
    const mod = url.startsWith("https:") ? https : http;
    mod.get(url, { headers: { "User-Agent": "watsonsec/1.0.0" } }, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        res.resume();
        get(res.headers.location!, hops + 1).then(resolve, reject);
        return;
      }
      resolve(res);
    }).on("error", reject);
  });
}

export async function downloadFile(
  url: string,
  destPath: string,
  onProgress: (pct: number) => void
): Promise<void> {
  const res = await get(url);
  if (res.statusCode !== 200) throw new Error(`HTTP ${res.statusCode} for ${url}`);
  const total = parseInt(res.headers["content-length"] ?? "0", 10);
  let received = 0;
  return new Promise((resolve, reject) => {
    const out = fs.createWriteStream(destPath);
    res.on("data", (chunk: Buffer) => {
      received += chunk.length;
      if (total > 0) onProgress(Math.floor((received / total) * 100));
    });
    res.pipe(out);
    out.on("finish", () => { out.close(); resolve(); });
    out.on("error", reject);
    res.on("error", reject);
  });
}

async function fetchText(url: string): Promise<string> {
  const res = await get(url);
  if (res.statusCode !== 200) throw new Error(`HTTP ${res.statusCode}`);
  const chunks: Buffer[] = [];
  return new Promise((resolve, reject) => {
    res.on("data", (c: Buffer) => chunks.push(c));
    res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    res.on("error", reject);
  });
}

// ─── Checksum verification ────────────────────────────────────────────────────

export async function verifyChecksum(
  filePath: string,
  manifest: ToolManifest,
  assetName: string
): Promise<void> {
  if (!manifest.checksumAsset) return;

  const checksumUrl = `${releaseBaseUrl(manifest)}/${manifest.checksumAsset}`;
  let text: string;
  try {
    text = await fetchText(checksumUrl);
  } catch {
    return; // checksums file unavailable — skip rather than block
  }

  const actual = crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  for (const line of text.split("\n")) {
    const [hash, name] = line.trim().split(/\s+/);
    if (name === assetName) {
      if (hash !== actual) {
        throw new Error(`Checksum mismatch for ${assetName}: expected ${hash}, got ${actual}`);
      }
      return;
    }
  }
  // Entry not found in checksums file — proceed without blocking.
}

// ─── Archive extraction ───────────────────────────────────────────────────────

export async function extractBinary(
  archivePath: string,
  destDir: string,
  format: "tar.gz" | "zip" | "bare",
  binaryInArchive: string
): Promise<string> {
  const baseName = path.basename(binaryInArchive);
  const exeSuffix = process.platform === "win32" && !baseName.endsWith(".exe") ? ".exe" : "";
  const finalPath = path.join(destDir, baseName + exeSuffix);

  if (format === "bare") {
    fs.copyFileSync(archivePath, finalPath);
    if (process.platform !== "win32") fs.chmodSync(finalPath, 0o755);
    return finalPath;
  }

  const extractDir = archivePath + "_extracted";
  fs.mkdirSync(extractDir, { recursive: true });

  try {
    if (format === "tar.gz") {
      await execFileAsync("tar", ["-xzf", archivePath, "-C", extractDir]);
    } else if (process.platform === "win32") {
      await execFileAsync("powershell", [
        "-Command",
        `Expand-Archive -Path "${archivePath}" -DestinationPath "${extractDir}" -Force`,
      ]);
    } else {
      await execFileAsync("unzip", ["-o", "-q", archivePath, "-d", extractDir]);
    }

    // Walk extracted tree to find the binary (handles nested dirs like codeql/codeql).
    const found = findInTree(extractDir, baseName);
    if (!found) throw new Error(`Binary '${baseName}' not found after extracting ${path.basename(archivePath)}`);

    fs.copyFileSync(found, finalPath);
    if (process.platform !== "win32") fs.chmodSync(finalPath, 0o755);
  } finally {
    fs.rmSync(extractDir, { recursive: true, force: true });
  }

  return finalPath;
}

function findInTree(dir: string, name: string): string {
  const winName = name + ".exe";
  try {
    for (const entry of fs.readdirSync(dir)) {
      if (entry === name || entry === winName) return path.join(dir, entry);
      const full = path.join(dir, entry);
      try {
        if (fs.statSync(full).isDirectory()) {
          const found = findInTree(full, name);
          if (found) return found;
        }
      } catch { /* skip */ }
    }
  } catch { /* skip */ }
  return "";
}

// ─── pip-based tools ──────────────────────────────────────────────────────────

export async function installViaPip(pipPackage: string): Promise<void> {
  const pip = process.platform === "win32" ? "pip" : "pip3";
  try {
    await execFileAsync(pip, ["install", "--user", "--quiet", pipPackage]);
  } catch {
    // Fall back to unversioned pip if pip3 is absent.
    await execFileAsync("pip", ["install", "--user", "--quiet", pipPackage]);
  }
}
