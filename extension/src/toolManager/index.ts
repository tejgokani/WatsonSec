import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import {
  TOOL_MANIFESTS,
  getManifest,
  platformKey,
  releaseBaseUrl,
  LARGE_MB_THRESHOLD,
} from "./manifest";
import { downloadFile, extractBinary, verifyChecksum, installViaPip } from "./downloader";
import type { ProjectFingerprint } from "../types";

// workspaceState key prefix for "never download this tool for this project".
const NEVER_PREFIX = "watsonsec.neverDownload.";

// sentinel filename used to record a successful pip install in the managed dir
const PIP_SENTINEL_SUFFIX = ".pip-installed";

export class ToolManager {
  private readonly binDir: string;
  private readonly state: vscode.Memento;
  // Simple in-memory cache: toolKey → resolved absolute path (or bare name).
  private readonly cache = new Map<string, string>();

  constructor(context: vscode.ExtensionContext) {
    this.binDir = path.join(context.globalStoragePath, "bin");
    this.state = context.workspaceState;
    fs.mkdirSync(this.binDir, { recursive: true });
  }

  // ─── Path resolution ─────────────────────────────────────────────────────

  // Returns the best binary path for a tool. Resolution order:
  //   1. User-configured path in VS Code settings (if the file exists)
  //   2. Managed bin dir (downloaded by us)
  //   3. Tool name (let the OS PATH resolve at subprocess spawn time)
  resolveToolPath(toolKey: string): string {
    if (this.cache.has(toolKey)) return this.cache.get(toolKey)!;

    const m = getManifest(toolKey);
    if (m) {
      const config = vscode.workspace.getConfiguration("watsonsec");
      const userPath = config.get<string>(m.settingKey);
      if (userPath && userPath !== toolKey && fs.existsSync(userPath)) {
        this.cache.set(toolKey, userPath);
        return userPath;
      }
    }

    const managed = this.managedBinPath(toolKey);
    if (managed && fs.existsSync(managed)) {
      this.cache.set(toolKey, managed);
      return managed;
    }

    // Fall through to OS PATH — subprocess spawn will fail with ENOENT if missing.
    return toolKey;
  }

  isManaged(toolKey: string): boolean {
    const p = this.managedBinPath(toolKey);
    return !!p && fs.existsSync(p);
  }

  // ─── Prompt / download gate ───────────────────────────────────────────────

  isNever(toolKey: string): boolean {
    return !!this.state.get<boolean>(`${NEVER_PREFIX}${toolKey}`);
  }

  async markNever(toolKey: string): Promise<void> {
    await this.state.update(`${NEVER_PREFIX}${toolKey}`, true);
  }

  // Called before each scan. Checks which tools are missing, prompts for
  // large ones, auto-downloads small ones.
  async ensureTools(
    toolKeys: string[],
    fingerprint: ProjectFingerprint
  ): Promise<void> {
    const missing = toolKeys.filter(
      (k) => !this.isManaged(k) && !this.isNever(k) && !!getManifest(k)
    );
    if (missing.length === 0) return;

    const small = missing.filter((k) => (getManifest(k)!.approximateMb) < LARGE_MB_THRESHOLD);
    const large = missing.filter((k) => (getManifest(k)!.approximateMb) >= LARGE_MB_THRESHOLD);

    // Small tools: download automatically with a single progress notification.
    if (small.length > 0) {
      const names = small.map((k) => getManifest(k)!.displayName).join(", ");
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: `WatsonSec: Downloading scanners (${names})`,
          cancellable: false,
        },
        async (progress) => {
          for (const key of small) {
            const m = getManifest(key)!;
            progress.report({ message: `${m.displayName} — ~${m.approximateMb} MB` });
            await this.downloadTool(key).catch((err) => {
              console.error(`[watsonsec/toolManager] Failed to download ${key}:`, err);
            });
          }
        }
      );
    }

    // Large tools: explicit prompt per tool before downloading.
    for (const key of large) {
      const m = getManifest(key)!;
      const why = m.whyNeeded(fingerprint);
      const detail = `${m.displayName} • ${m.approximateMb} MB download\n\n${why}`;

      const action = await vscode.window.showInformationMessage(
        `WatsonSec needs ${m.displayName} to scan this project`,
        { detail, modal: false },
        `Download (${m.approximateMb} MB)`,
        "Not now",
        "Never for this project"
      );

      if (action?.startsWith("Download")) {
        await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: `WatsonSec: Downloading ${m.displayName}`,
            cancellable: false,
          },
          async (progress) => {
            await this.downloadTool(key, (pct) => {
              progress.report({ message: `${pct}%` });
            }).catch((err) => {
              vscode.window.showErrorMessage(
                `WatsonSec: Failed to download ${m.displayName} — ${(err as Error).message}`
              );
            });
          }
        );
      } else if (action === "Never for this project") {
        await this.markNever(key);
      }
      // "Not now" → no-op; will prompt again next activation.
    }
  }

  // ─── Download implementation ──────────────────────────────────────────────

  private async downloadTool(
    toolKey: string,
    onProgress: (pct: number) => void = () => {}
  ): Promise<void> {
    const m = getManifest(toolKey);
    if (!m) throw new Error(`No manifest for tool: ${toolKey}`);

    // pip-based tools (Bandit, Checkov) — no binary to download.
    if (m.pipPackage) {
      await installViaPip(m.pipPackage);
      // Write a sentinel so isManaged() returns true next time.
      fs.writeFileSync(
        path.join(this.binDir, toolKey + PIP_SENTINEL_SUFFIX),
        m.pipPackage,
        "utf8"
      );
      this.cache.delete(toolKey);
      return;
    }

    const pKey = platformKey();
    const asset = m.platforms[pKey];
    if (!asset) {
      throw new Error(`No binary release for ${toolKey} on ${pKey}. Install manually and set watsonsec.${m.settingKey}`);
    }

    const downloadUrl = `${releaseBaseUrl(m)}/${asset.name}`;
    const tmpPath = path.join(this.binDir, `_tmp_${asset.name}`);

    try {
      await downloadFile(downloadUrl, tmpPath, onProgress);
      await verifyChecksum(tmpPath, m, asset.name);
      await extractBinary(tmpPath, this.binDir, asset.format, m.binaryInArchive);
      this.cache.delete(toolKey); // clear so resolveToolPath picks up managed path
    } finally {
      if (fs.existsSync(tmpPath)) fs.rmSync(tmpPath, { force: true });
    }
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────

  private managedBinPath(toolKey: string): string | null {
    const m = getManifest(toolKey);
    if (!m) return null;
    if (m.pipPackage) {
      // pip sentinel file signals a successful install.
      return path.join(this.binDir, toolKey + PIP_SENTINEL_SUFFIX);
    }
    const exe = process.platform === "win32" ? ".exe" : "";
    return path.join(this.binDir, path.basename(m.binaryInArchive) + exe);
  }
}
