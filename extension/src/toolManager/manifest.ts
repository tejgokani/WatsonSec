import type { ProjectFingerprint } from "../types";

export type ArchiveFormat = "tar.gz" | "zip" | "bare";

// Platform key: "${process.platform}-${arch}" where arch is "x64" or "arm64".
// Example: "darwin-arm64", "linux-x64", "win32-x64".
export type PlatformKey = string;

export interface PlatformAsset {
  name: string;
  format: ArchiveFormat;
}

export interface ToolManifest {
  // Must match ScannerAdapter.name exactly.
  key: string;
  displayName: string;
  version: string;
  // "owner/repo" on GitHub. Download URL: /releases/download/<tag>/<assetName>.
  repo: string;
  // VS Code config setting key (e.g. "semgrepPath").
  settingKey: string;
  // Approximate download size in MB — drives the silent vs. prompt threshold.
  approximateMb: number;
  description: string;
  // Returns a contextual reason for the prompt, using detected fingerprint.
  whyNeeded: (fp: ProjectFingerprint) => string;
  // Per-platform binary assets. Empty for pip-based tools.
  platforms: Partial<Record<PlatformKey, PlatformAsset>>;
  // Relative path of binary inside archive. "tool/tool" for nested (e.g. CodeQL).
  binaryInArchive: string;
  // If present: "gitleaks_8.18.4_checksums.txt"-style file fetched for SHA-256 verify.
  checksumAsset?: string;
  // If set: install via pip instead of binary download.
  pipPackage?: string;
}

// Tools ≥ this threshold get a confirmation prompt before downloading.
export const LARGE_MB_THRESHOLD = 50;

// GitHub release download base URL.
export function releaseBaseUrl(m: ToolManifest): string {
  const tag = m.key === "codeql"
    ? `codeql-bundle-v${m.version}`
    : `v${m.version}`;
  return `https://github.com/${m.repo}/releases/download/${tag}`;
}

// Runtime platform key.
export function platformKey(): PlatformKey {
  const arch = process.arch === "arm64" ? "arm64" : "x64";
  return `${process.platform}-${arch}`;
}

export const TOOL_MANIFESTS: ToolManifest[] = [
  {
    key: "semgrep",
    displayName: "Semgrep",
    version: "1.72.0",
    repo: "semgrep/semgrep",
    settingKey: "semgrepPath",
    approximateMb: 130,
    description: "Static analysis across 30+ languages — WatsonSec's primary SAST engine",
    whyNeeded: () => "Semgrep is the core SAST scanner. Without it WatsonSec has no pattern-based analysis",
    binaryInArchive: "semgrep",
    platforms: {
      "darwin-arm64": { name: "semgrep-v1.72.0-macos-arm64.zip",     format: "zip"    },
      "darwin-x64":   { name: "semgrep-v1.72.0-macos-x86_64.zip",    format: "zip"    },
      "linux-x64":    { name: "semgrep-v1.72.0-ubuntu-22.04.tar.gz", format: "tar.gz" },
      "linux-arm64":  { name: "semgrep-v1.72.0-ubuntu-arm64.tar.gz", format: "tar.gz" },
    },
  },
  {
    key: "gitleaks",
    displayName: "Gitleaks",
    version: "8.18.4",
    repo: "zricethezav/gitleaks",
    settingKey: "gitleaksPath",
    approximateMb: 12,
    description: "Detects hardcoded secrets and credentials in source and git history",
    whyNeeded: () => "Gitleaks scans every file for accidentally committed secrets (API keys, passwords, tokens)",
    binaryInArchive: "gitleaks",
    checksumAsset: "gitleaks_8.18.4_checksums.txt",
    platforms: {
      "darwin-arm64": { name: "gitleaks_8.18.4_darwin_arm64.tar.gz",  format: "tar.gz" },
      "darwin-x64":   { name: "gitleaks_8.18.4_darwin_x64.tar.gz",    format: "tar.gz" },
      "linux-x64":    { name: "gitleaks_8.18.4_linux_x64.tar.gz",     format: "tar.gz" },
      "linux-arm64":  { name: "gitleaks_8.18.4_linux_arm64.tar.gz",   format: "tar.gz" },
      "win32-x64":    { name: "gitleaks_8.18.4_windows_x64.zip",      format: "zip"    },
    },
  },
  {
    key: "trufflehog",
    displayName: "TruffleHog",
    version: "3.78.0",
    repo: "trufflesecurity/trufflehog",
    settingKey: "trufflehogPath",
    approximateMb: 25,
    description: "Deep secret scanning with 700+ credential detectors and entropy analysis",
    whyNeeded: () => "TruffleHog catches secrets Gitleaks misses — OAuth tokens, cloud credentials, and more",
    binaryInArchive: "trufflehog",
    checksumAsset: "trufflehog_3.78.0_checksums.txt",
    platforms: {
      "darwin-arm64": { name: "trufflehog_3.78.0_darwin_arm64.tar.gz",  format: "tar.gz" },
      "darwin-x64":   { name: "trufflehog_3.78.0_darwin_amd64.tar.gz",  format: "tar.gz" },
      "linux-x64":    { name: "trufflehog_3.78.0_linux_amd64.tar.gz",   format: "tar.gz" },
      "linux-arm64":  { name: "trufflehog_3.78.0_linux_arm64.tar.gz",   format: "tar.gz" },
      "win32-x64":    { name: "trufflehog_3.78.0_windows_amd64.tar.gz", format: "tar.gz" },
    },
  },
  {
    key: "osv-scanner",
    displayName: "OSV-Scanner",
    version: "1.8.1",
    repo: "google/osv-scanner",
    settingKey: "osvScannerPath",
    approximateMb: 15,
    description: "Scans lockfiles against Google's Open Source Vulnerability database",
    whyNeeded: (fp) =>
      `Your repo has ${fp.lockfilePaths.length ? fp.lockfilePaths.join(", ") : "lockfiles"} — OSV-Scanner checks them for known CVEs`,
    binaryInArchive: "osv-scanner",
    checksumAsset: "osv-scanner_v1.8.1_checksums.txt",
    platforms: {
      "darwin-arm64": { name: "osv-scanner_v1.8.1_darwin_arm64",      format: "bare" },
      "darwin-x64":   { name: "osv-scanner_v1.8.1_darwin_amd64",      format: "bare" },
      "linux-x64":    { name: "osv-scanner_v1.8.1_linux_amd64",       format: "bare" },
      "linux-arm64":  { name: "osv-scanner_v1.8.1_linux_arm64",       format: "bare" },
      "win32-x64":    { name: "osv-scanner_v1.8.1_windows_amd64.exe", format: "bare" },
    },
  },
  {
    key: "grype",
    displayName: "Grype",
    version: "0.78.0",
    repo: "anchore/grype",
    settingKey: "grypeePath",
    approximateMb: 30,
    description: "Container and filesystem CVE scanner against Anchore's vulnerability database",
    whyNeeded: (fp) =>
      `Your repo has lockfiles — Grype checks ${fp.lockfilePaths.slice(0, 2).join(", ")} for exploitable CVEs`,
    binaryInArchive: "grype",
    checksumAsset: "grype_0.78.0_checksums.txt",
    platforms: {
      "darwin-arm64": { name: "grype_0.78.0_darwin_arm64.tar.gz",  format: "tar.gz" },
      "darwin-x64":   { name: "grype_0.78.0_darwin_amd64.tar.gz",  format: "tar.gz" },
      "linux-x64":    { name: "grype_0.78.0_linux_amd64.tar.gz",   format: "tar.gz" },
      "linux-arm64":  { name: "grype_0.78.0_linux_arm64.tar.gz",   format: "tar.gz" },
      "win32-x64":    { name: "grype_0.78.0_windows_amd64.zip",    format: "zip"    },
    },
  },
  {
    key: "trivy",
    displayName: "Trivy",
    version: "0.52.2",
    repo: "aquasecurity/trivy",
    settingKey: "trivyPath",
    approximateMb: 50,
    description: "All-in-one scanner: vulnerabilities, misconfigs, and secrets in one pass",
    whyNeeded: () => "Trivy runs vuln + secret + misconfig checks in a single pass — works on any repo",
    binaryInArchive: "trivy",
    checksumAsset: "trivy_0.52.2_checksums.txt",
    platforms: {
      "darwin-arm64": { name: "trivy_0.52.2_macOS-ARM64.tar.gz",   format: "tar.gz" },
      "darwin-x64":   { name: "trivy_0.52.2_macOS-64bit.tar.gz",   format: "tar.gz" },
      "linux-x64":    { name: "trivy_0.52.2_Linux-64bit.tar.gz",   format: "tar.gz" },
      "linux-arm64":  { name: "trivy_0.52.2_Linux-ARM64.tar.gz",   format: "tar.gz" },
      "win32-x64":    { name: "trivy_0.52.2_windows-64bit.zip",    format: "zip"    },
    },
  },
  {
    key: "gosec",
    displayName: "gosec",
    version: "2.20.0",
    repo: "securego/gosec",
    settingKey: "gosecPath",
    approximateMb: 8,
    description: "Go-specific security scanner — unsafe packages, weak crypto, shell injection",
    whyNeeded: () => "Your repo has .go files — gosec catches Go-specific vulnerabilities no generic scanner sees",
    binaryInArchive: "gosec",
    checksumAsset: "gosec_2.20.0_checksums.txt",
    platforms: {
      "darwin-arm64": { name: "gosec_2.20.0_darwin_arm64.tar.gz",  format: "tar.gz" },
      "darwin-x64":   { name: "gosec_2.20.0_darwin_amd64.tar.gz",  format: "tar.gz" },
      "linux-x64":    { name: "gosec_2.20.0_linux_amd64.tar.gz",   format: "tar.gz" },
      "linux-arm64":  { name: "gosec_2.20.0_linux_arm64.tar.gz",   format: "tar.gz" },
      "win32-x64":    { name: "gosec_2.20.0_windows_amd64.zip",    format: "zip"    },
    },
  },
  {
    key: "syft",
    displayName: "Syft",
    version: "1.4.1",
    repo: "anchore/syft",
    settingKey: "syftPath",
    approximateMb: 45,
    description: "Generates Software Bill of Materials (SBOM) for supply-chain compliance",
    whyNeeded: () => "Syft catalogs every package for compliance and supply-chain visibility",
    binaryInArchive: "syft",
    checksumAsset: "syft_1.4.1_checksums.txt",
    platforms: {
      "darwin-arm64": { name: "syft_1.4.1_darwin_arm64.tar.gz",  format: "tar.gz" },
      "darwin-x64":   { name: "syft_1.4.1_darwin_amd64.tar.gz",  format: "tar.gz" },
      "linux-x64":    { name: "syft_1.4.1_linux_amd64.tar.gz",   format: "tar.gz" },
      "linux-arm64":  { name: "syft_1.4.1_linux_arm64.tar.gz",   format: "tar.gz" },
      "win32-x64":    { name: "syft_1.4.1_windows_amd64.zip",    format: "zip"    },
    },
  },
  {
    key: "codeql",
    displayName: "CodeQL",
    version: "2.17.6",
    repo: "github/codeql-action",
    settingKey: "codeqlPath",
    approximateMb: 900,
    description: "Deep dataflow / taint-tracking analysis — catches complex injection and SSRF flaws",
    whyNeeded: (fp) => {
      const langs: string[] = [];
      if (fp.hasJavaScript) langs.push("JS/TS");
      if (fp.hasPython) langs.push("Python");
      if (fp.hasGo) langs.push("Go");
      return `Your ${langs.join("/")} codebase qualifies for CodeQL taint tracking — finds injection, SSRF, and deserialization flaws that pattern-matching misses`;
    },
    binaryInArchive: "codeql/codeql",
    platforms: {
      "darwin-arm64": { name: "codeql-bundle-osx64.tar.gz",   format: "tar.gz" },
      "darwin-x64":   { name: "codeql-bundle-osx64.tar.gz",   format: "tar.gz" },
      "linux-x64":    { name: "codeql-bundle-linux64.tar.gz", format: "tar.gz" },
      "linux-arm64":  { name: "codeql-bundle-linux64.tar.gz", format: "tar.gz" },
      "win32-x64":    { name: "codeql-bundle-win64.zip",      format: "zip"    },
    },
  },
  {
    key: "bandit",
    displayName: "Bandit",
    version: "1.7.9",
    repo: "PyCQA/bandit",
    settingKey: "banditPath",
    approximateMb: 5,
    description: "Python security linter — SQL injection, eval, subprocess shell=True, weak crypto",
    whyNeeded: () => "Your repo has .py files — Bandit catches Python-specific security issues no generic scanner sees",
    binaryInArchive: "bandit",
    platforms: {},
    pipPackage: "bandit==1.7.9",
  },
  {
    key: "checkov",
    displayName: "Checkov",
    version: "3.2.0",
    repo: "bridgecrewio/checkov",
    settingKey: "checkovPath",
    approximateMb: 50,
    description: "IaC security scanner — Terraform, Dockerfile, and Kubernetes misconfigurations",
    whyNeeded: (fp) => {
      const what: string[] = [];
      if (fp.hasTerraform) what.push("Terraform configs");
      if (fp.hasDockerfile) what.push("Dockerfiles");
      if (fp.hasK8sManifests) what.push("Kubernetes manifests");
      return `Your ${what.join(", ")} — Checkov finds misconfigurations before they reach production`;
    },
    binaryInArchive: "checkov",
    platforms: {},
    pipPackage: "checkov==3.2.0",
  },
];

export function getManifest(key: string): ToolManifest | undefined {
  return TOOL_MANIFESTS.find((m) => m.key === key);
}
