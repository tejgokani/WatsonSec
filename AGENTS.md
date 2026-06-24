# AGENTS.md — watsonsec

watsonsec is a VS Code extension that acts as a local-first, open-source security
engine for AI-generated ("vibe coded") code. It orchestrates real open-source
scanners, normalizes and deduplicates their findings, tracks them over time, and
exposes them through a local dashboard, a one-click markdown report, and an MCP
bridge so a coding agent can query and act on live findings.

This file is read by any AI coding agent working in this repository, regardless
of which tool the human is using. If you are Claude Code specifically, also read
`CLAUDE.md` for tool-specific notes — but the rules in this file take priority
whenever the two disagree.

Full technical design lives in `ARCHITECTURE.md`. Read it before making any
structural change to the pipeline.

## What this project is, in one paragraph

A file watcher triggers a scanner orchestrator that runs real, deterministic
open-source security tools (Semgrep, Gitleaks, TruffleHog, OSV-Scanner, Trivy,
Grype, Syft, Checkov, CodeQL, etc.) as subprocesses. Their output is normalized
(SARIF where possible), merged and deduplicated, written to a persistent
findings store, and surfaced via a local web dashboard, a markdown export, and
an MCP server the coding agent can query.

## The one rule that matters most

**Never have an agent emulate a scanner's detection logic instead of running
the actual tool.** An LLM reasoning about "how Gitleaks finds secrets" is not
the same as Gitleaks running its entropy/regex engine against real bytes. An
LLM listing "known CVEs" from memory is not the same as OSV-Scanner querying a
live, maintained vulnerability database — and is a direct path to hallucinated
CVE IDs or missed real ones. Every scanner integration in this repo must shell
out to the real upstream binary and parse its real output. The agent's job is
triage, correlation, prioritization, and report-writing on top of that real
output — never a replacement for it.

## Proposed repo structure

```
watsonsec/
  extension/        VS Code extension host (TypeScript) — file watcher, UI, commands
  orchestrator/      Scanner adapters + execution engine (spawns subprocesses)
  aggregator/        Normalization, correlation, dedup logic
  store/             Findings persistence (schema in ARCHITECTURE.md)
  dashboard/         Local web server + graph/list UI
  mcp-bridge/         MCP server exposing findings to coding agents
  reports/           Markdown report templates + exporter
  fixtures/          Known-vulnerable code samples used to test each adapter
  docs/
    ARCHITECTURE.md
    AGENTS.md
    CLAUDE.md
```

Nothing above exists yet at time of writing — this is the target layout for the
first real commits, not a description of current code.

## Setup, build, test

This section is intentionally a stub until Phase 0 lands (see roadmap in
`ARCHITECTURE.md`). When real commands exist, they belong here verbatim —
do not guess at commands or invent ones that "should" work.

## Adding a new scanner adapter

Every scanner integration must, at minimum:

1. Declare its upstream license in `orchestrator/TOOL_REGISTRY.md` (Apache-2.0
   and MIT tools are safe to bundle; AGPL-3.0 (TruffleHog) and GPL-3.0 (MobSF)
   need a license callout — see Architecture doc, "Licensing" section).
2. Run the real binary as a subprocess — no shelling out to a network API in
   place of the local tool unless the tool is inherently a database lookup
   (OSV-Scanner, Grype) rather than a local static analysis.
3. Map its output to the common `Finding` schema (see `ARCHITECTURE.md`), using
   SARIF as the intermediate format wherever the tool supports it natively.
4. Ship a fixture in `fixtures/<tool-name>/` containing a small file with a
   known, intentional finding, plus a test asserting the adapter still
   produces that finding after any change. Scanner integrations break
   silently when upstream tools change their CLI flags or output schema —
   the fixture is the tripwire.
5. Declare which project fingerprints should enable it (e.g. Checkov only
   runs if `*.tf`, `*.yaml` under a `k8s/` path, or a `Dockerfile` is present).

## Execution model rules

- Lightweight, fast tools (Semgrep, Gitleaks, Bandit) run on file save, debounced.
- Heavy tools that build an analysis database (CodeQL) run on a slower,
  separate cadence — never on every save.
- Tools that require a deployed/running target (ZAP, Nuclei) or live
  infrastructure (Falco, OPA, Sigstore, OSSF Scorecard) are explicitly **out
  of scope** for in-editor execution. Do not add them to the orchestrator —
  see "Non-goals" in `ARCHITECTURE.md`.

## Findings must be stable across re-scans

A finding's identity must survive a re-scan that no longer reproduces it, so
it can transition to `resolved` instead of just vanishing. Never generate a
finding ID from anything that changes between scans of unmodified code (e.g.
a timestamp or a raw line number alone — use file path + rule ID + a stable
content hash of the surrounding context instead).

## Security expectations for contributors (including agents)

This is a security tool — its own supply chain matters more than average.

- Never commit real secrets, even as test fixtures. Use obviously-fake
  patterns (`AKIAFAKEFAKEFAKEFAKE`) that still trigger the relevant detector.
- Pin scanner binary versions explicitly; don't silently auto-upgrade without
  a changelog entry, since rule changes can shift what gets flagged.
- If a scanner is distributed as a downloaded binary rather than a package
  manager dependency, verify its checksum before executing it.

## Commit and PR conventions

- One logical change per commit. A new scanner adapter, a dashboard change,
  and a schema migration are three commits, not one.
- PR description must state which `Finding` fields, if any, changed shape,
  since the store schema is the most consequential thing to break silently.
