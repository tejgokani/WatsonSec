import * as https from "https";
import * as vscode from "vscode";

// Pinned versions by tool name — kept in sync with TOOL_REGISTRY.md.
// When a new version is detected, the user is notified to update their
// binary and update the pin here + in TOOL_REGISTRY.md.
const PINNED_VERSIONS: Record<string, string> = {
  semgrep: "1.72.0",
  gitleaks: "8.18.4",
  "osv-scanner": "1.8.1",
  trivy: "0.52.2",
  checkov: "3.2.0",
  bandit: "1.7.9",
  gosec: "2.20.0",
  grype: "0.78.0",
  trufflehog: "3.78.0",
  codeql: "2.17.6",
};

// GitHub releases API endpoints for each tool.
const RELEASE_URLS: Record<string, string> = {
  semgrep: "https://api.github.com/repos/semgrep/semgrep/releases/latest",
  gitleaks: "https://api.github.com/repos/gitleaks/gitleaks/releases/latest",
  "osv-scanner": "https://api.github.com/repos/google/osv-scanner/releases/latest",
  trivy: "https://api.github.com/repos/aquasecurity/trivy/releases/latest",
  checkov: "https://api.github.com/repos/bridgecrewio/checkov/releases/latest",
  bandit: "https://api.github.com/repos/PyCQA/bandit/releases/latest",
  gosec: "https://api.github.com/repos/securego/gosec/releases/latest",
  grype: "https://api.github.com/repos/anchore/grype/releases/latest",
  trufflehog: "https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest",
  codeql: "https://api.github.com/repos/github/codeql-cli-binaries/releases/latest",
};

export interface UpdateResult {
  tool: string;
  pinned: string;
  latest: string;
  needsUpdate: boolean;
}

// Checks all pinned tools against their latest GitHub release.
// Never auto-upgrades — surfaces update info to the user so they can
// review the changelog before bumping, since rule changes affect findings.
export async function checkForUpdates(): Promise<UpdateResult[]> {
  const results: UpdateResult[] = [];
  const checks = Object.entries(RELEASE_URLS).map(async ([tool, url]) => {
    try {
      const latest = await fetchLatestVersion(url);
      const pinned = PINNED_VERSIONS[tool] ?? "unknown";
      if (latest && latest !== pinned) {
        results.push({ tool, pinned, latest, needsUpdate: true });
      }
    } catch {
      // Network failures are silent — don't interrupt development.
    }
  });

  await Promise.allSettled(checks);
  return results;
}

function fetchLatestVersion(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        headers: {
          "User-Agent": "watsonsec-updater/1.0",
          Accept: "application/vnd.github+json",
        },
        timeout: 5000,
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          try {
            const json = JSON.parse(data) as { tag_name?: string };
            const version = (json.tag_name ?? "").replace(/^v/, "");
            resolve(version);
          } catch {
            reject(new Error("Failed to parse release JSON"));
          }
        });
      }
    );
    req.on("error", reject);
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout")); });
  });
}

// Shows a single notification if any tool has a newer version available.
// Call this on extension activation (not on every scan) to avoid spam.
export async function notifyIfUpdatesAvailable(): Promise<void> {
  const updates = await checkForUpdates();
  const outdated = updates.filter((u) => u.needsUpdate);
  if (!outdated.length) return;

  const items = outdated.map((u) => `${u.tool} ${u.pinned} → ${u.latest}`).join(", ");
  const action = await vscode.window.showInformationMessage(
    `WatsonSec: Newer scanner versions available: ${items}`,
    "View TOOL_REGISTRY.md"
  );
  if (action === "View TOOL_REGISTRY.md") {
    vscode.env.openExternal(
      vscode.Uri.parse("https://github.com/tejgokani/watsonsec/blob/main/orchestrator/TOOL_REGISTRY.md")
    );
  }
}
