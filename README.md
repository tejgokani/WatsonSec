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

## Phase 1 — what works today

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

## Requirements

Install the scanner binaries before activating the extension:

```bash
# Semgrep
pip install semgrep==1.72.0

# Gitleaks
brew install gitleaks   # or download from github.com/gitleaks/gitleaks/releases

# OSV-Scanner
brew install osv-scanner   # or go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

## Commands

Open the VS Code Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`):

| Command | Description |
|---|---|
| `WatsonSec: Run Full Scan` | Run all enabled scanners immediately |
| `WatsonSec: Open Dashboard` | Open the local findings dashboard in your browser |
| `WatsonSec: Export Markdown Report` | Write `watsonsec-report.md` to the workspace root |

## Configuration

| Setting | Default | Description |
|---|---|---|
| `watsonsec.semgrepPath` | `semgrep` | Path to the semgrep binary |
| `watsonsec.gitleaksPath` | `gitleaks` | Path to the gitleaks binary |
| `watsonsec.osvScannerPath` | `osv-scanner` | Path to the osv-scanner binary |
| `watsonsec.dashboardPort` | `7891` | Local port for the findings dashboard |
| `watsonsec.debounceMs` | `2000` | Milliseconds to wait after save before scanning |

## Roadmap

- **Phase 2** — Trivy (containers + IaC), Checkov (Terraform/k8s), CodeQL, Bandit (Python), Grype/Syft
- **Phase 3** — MCP bridge (let your coding agent query live findings)
- **Phase 4** — Evaluate DefectDojo for the dedup engine; security graph visualization

See [ARCHITECTURE.md](ARCHITECTURE.md) and [AGENTS.md](AGENTS.md) for the full design.

## Structure

```
extension/          VS Code extension (TypeScript)
  src/
    orchestrator/   Scanner adapters + execution engine
    aggregator/     SARIF normalization + cross-tool dedup
    store/          Findings persistence (JSON)
    dashboard/      Local HTTP server + dashboard HTML
    reports/        Markdown exporter
orchestrator/       TOOL_REGISTRY.md — pinned versions + licenses
fixtures/           Known-vulnerable samples for adapter regression tests
```

## License

MIT
