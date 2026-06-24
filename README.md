# WatsonSec

**Local-first, open-source security engine for AI-generated ("vibe coded") code.**

WatsonSec is a VS Code extension that orchestrates real, deterministic open-source
security scanners against your code on every save, normalizes and deduplicates their
findings, and surfaces them through a local dashboard, a markdown report, and an MCP
bridge your coding agent can query.

> **The core principle:** A real scanner running its entropy/regex engine against
> actual bytes is not the same as an LLM reasoning about "how secrets look." WatsonSec
> runs the real tools and uses the agent only for what tools can't do — correlation,
> prioritization, business-logic analysis, and report-writing.

## What's implemented

### Phase 1 — Core pipeline
| Feature | Status |
|---|---|
| File watcher (debounced scan on save) | ✅ |
| Semgrep CE — SAST for all major languages | ✅ |
| Gitleaks — hardcoded secret detection | ✅ |
| OSV-Scanner — dependency vulnerability detection | ✅ |
| SARIF-first normalization | ✅ |
| Cross-tool dedup (same finding from 2 tools → 1 entry) | ✅ |
| Stable finding IDs (survive line-number shifts) | ✅ |
| Status tracking (new → confirmed → resolved → reopened) | ✅ |
| Local web dashboard (localhost:7891) | ✅ |
| One-click Markdown report export | ✅ |
| Project fingerprinting (conditional tool selection) | ✅ |

### Phase 2 — Full scanner coverage + graph + diagnostics
| Feature | Status |
|---|---|
| Trivy — secrets + misconfigs + dependency vulns in one pass | ✅ |
| Checkov — Terraform, Dockerfile, k8s IaC misconfiguration | ✅ |
| Bandit — Python SAST (B-series rules) | ✅ |
| gosec — Go SAST (G-series rules) | ✅ |
| Grype — dependency vulnerability scanning (all ecosystems) | ✅ |
| TruffleHog — deep entropy + regex secret detection (AGPL-3.0) | ✅ |
| CodeQL — deep SAST with slow-cadence analysis database | ✅ |
| VS Code inline diagnostics (Problems panel + squiggly lines) | ✅ |
| File-level dependency graph (dashboard → Graph tab) | ✅ |
| Tiered scan cadence: fast (on save) + slow (every N saves or on demand) | ✅ |
| Self-update checker (notifies when newer scanner versions exist) | ✅ |

### Phase 3 — MCP bridge
| Feature | Status |
|---|---|
| `watsonsec-mcp` — read-only MCP server for coding agents | ✅ |
| `get_findings` — query active findings by severity/category | ✅ |
| `get_findings_for_file` — findings for the file you just wrote | ✅ |
| `get_summary` — security posture snapshot | ✅ |
| `get_recent_scans` — scan history and tool errors | ✅ |

## Requirements

Install the scanner binaries you want to use:

```bash
# Phase 1 (always-on)
pip install semgrep==1.72.0
brew install gitleaks                         # or: github.com/gitleaks/gitleaks/releases
brew install osv-scanner                      # or: go install github.com/google/osv-scanner/...

# Phase 2 — language-conditional
pip install trivy                             # or: github.com/aquasecurity/trivy/releases
pip install checkov==3.2.0                    # Terraform/k8s/Dockerfile only
pip install bandit==1.7.9                     # Python repos only
go install github.com/securego/gosec/v2/cmd/gosec@latest  # Go repos only
brew install grype                            # repos with lockfiles

# Phase 2 — secrets (AGPL-3.0, invoke as unmodified binary)
brew install trufflehog                       # or: github.com/trufflesecurity/trufflehog/releases

# Phase 2 — slow SAST (runs every N saves, not on every save)
# Install from: github.com/github/codeql-action or VS Code CodeQL extension
```

## Commands

Open the Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`):

| Command | Description |
|---|---|
| `WatsonSec: Run Fast Scan` | Run all fast scanners immediately |
| `WatsonSec: Run Full Scan (includes CodeQL)` | Run all scanners including slow-cadence CodeQL |
| `WatsonSec: Open Dashboard` | Open the local findings dashboard in your browser |
| `WatsonSec: Export Markdown Report` | Write `watsonsec-report.md` to the workspace root |

## MCP bridge setup

Add to your coding agent's MCP configuration:

```json
{
  "watsonsec": {
    "command": "node",
    "args": [
      "/path/to/watsonsec/mcp-bridge/dist/server.js",
      "--store", "/path/to/your-project/.watsonsec/findings.json"
    ]
  }
}
```

The MCP server exposes four read-only tools: `get_findings`, `get_findings_for_file`,
`get_summary`, and `get_recent_scans`. Resolution is always driven by re-scans —
the agent cannot mark findings resolved via the MCP bridge.

## Configuration

| Setting | Default | Description |
|---|---|---|
| `watsonsec.semgrepPath` | `semgrep` | Path to the semgrep binary |
| `watsonsec.gitleaksPath` | `gitleaks` | Path to the gitleaks binary |
| `watsonsec.osvScannerPath` | `osv-scanner` | Path to the osv-scanner binary |
| `watsonsec.trivyPath` | `trivy` | Path to the trivy binary |
| `watsonsec.checkovPath` | `checkov` | Path to the checkov binary |
| `watsonsec.banditPath` | `bandit` | Path to the bandit binary |
| `watsonsec.gosecPath` | `gosec` | Path to the gosec binary |
| `watsonsec.grypeePath` | `grype` | Path to the grype binary |
| `watsonsec.trufflehogPath` | `trufflehog` | Path to the trufflehog binary |
| `watsonsec.codeqlPath` | `codeql` | Path to the codeql binary |
| `watsonsec.dashboardPort` | `7891` | Local port for the findings dashboard |
| `watsonsec.debounceMs` | `2000` | Milliseconds to wait after save before scanning |
| `watsonsec.slowScanSaveInterval` | `15` | Fast scans between full scans (0 = no auto full scans) |

## Roadmap

- **Phase 4** — Evaluate DefectDojo's dedup engine; function-level dataflow graph; Syft SBOM export

See [ARCHITECTURE.md](ARCHITECTURE.md) and [AGENTS.md](AGENTS.md) for the full design.

## Structure

```
extension/          VS Code extension (TypeScript)
  src/
    orchestrator/   Scanner adapters + tiered execution engine
    aggregator/     SARIF normalization + cross-tool dedup
    store/          Findings persistence (JSON)
    dashboard/      Local HTTP server + dashboard + graph tab
    reports/        Markdown exporter
    diagnostics/    VS Code Problems panel integration
    graph/          File-level dependency graph builder
    updater/        Scanner version self-update checker
mcp-bridge/         Standalone MCP server for coding agents
orchestrator/       TOOL_REGISTRY.md — pinned versions + licenses
fixtures/           Known-vulnerable samples for adapter regression tests
  semgrep/          Python: SQLi, command injection, eval, path traversal
  gitleaks/         Fake AWS/GitHub/generic credentials
  osv/              package-lock.json with known-CVE dependencies
  trivy/            Insecure Dockerfile
  checkov/          Insecure Terraform (S3, SG, IAM, RDS)
  bandit/           Python: exec, hardcoded password, pickle, MD5, SQLi
  gosec/            Go: MD5, shell injection, open redirect
```

## License

MIT
