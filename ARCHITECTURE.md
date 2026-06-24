# ARCHITECTURE.md — watsonsec

## Mission

watsonsec is a local-first, open-source security engine for VS Code, built for
a world where an AI agent is writing most of the code. It runs real,
deterministic open-source security tools against every file as it's saved,
correlates and deduplicates their output, tracks each finding's status over
time, and surfaces the result through a local dashboard, a one-click markdown
report, and an MCP bridge the coding agent itself can query.

It is explicitly **not** an attempt to have an LLM re-derive what dedicated
scanners already do well. See "Core design principle" below.

## Core design principle: hybrid, not agent-only

Two ways to read "use the agent to do the audit with the combined logic of
these open sources":

1. The agent reasons about the code using its training-time knowledge of how
   these tools work, without running them.
2. The agent orchestrates the real tools and reasons over their real output.

watsonsec is built on (2). Reasoning is necessary, but it can't be a
substitute for execution:

- Secret detection depends on entropy analysis and hundreds of credential
  regexes running against actual bytes (Gitleaks, TruffleHog) — not on an LLM
  recognizing "this looks like a key."
- Dependency vulnerability detection depends on querying a live, maintained
  CVE/OSV database (OSV-Scanner, Grype, Trivy) — an LLM listing CVEs from
  memory will hallucinate IDs or miss recent ones entirely.
- SAST dataflow/taint analysis (Semgrep, CodeQL, Bandit) depends on actually
  parsing the AST and tracing data through it — not on pattern-matching a
  prompt against a code snippet.

The agent's real value-add sits on top of this: correlating findings across
tools, deciding which of several true positives is actually exploitable in
context, catching business-logic flaws (IDOR, broken authorization) that no
rule-based tool can structurally express, and writing the final
human-readable report. This is the same split commercial platforms in this
space (Semgrep's own AI layer, OX Security's VibeSec, Aikido) have converged
on — watsonsec's bet is doing it as an open, local-first extension instead of
a paid backend.

## Pipeline overview

```
File watcher (on save, debounced)
        |
        v
Scanner orchestrator  --- runs project-fingerprint-selected tools in parallel
        |
        v
Normalizer  --- maps every tool's output to a common Finding schema (SARIF-first)
        |
        v
Aggregator & dedup  --- merges duplicate findings across tools, assigns stable IDs
        |
        v
Findings store  --- persistent, tracks status over time (new/confirmed/resolved/reopened)
        |
        +--> Web dashboard (localhost) — live list + security graph
        +--> Markdown report exporter — one-click, pulled from the store
        +--> MCP bridge — exposes current findings as a tool for the coding agent
```

## Component breakdown

### 1. File watcher

Triggers a scan on save, debounced (not on every keystroke). Heavy tools that
build an analysis database (CodeQL) run on a separate, slower cadence —
e.g. every N saves or on an explicit command — never inline with every save.

### 2. Scanner orchestrator

Two responsibilities:

- **Project fingerprinting** — detect which ecosystems are present
  (`package.json` → JS/TS + npm audit/OSV-Scanner; `requirements.txt`/`pyproject.toml`
  → Python + Bandit; `Cargo.toml` → Rust; `*.tf`/k8s yaml/`Dockerfile` → Checkov;
  any repo → Gitleaks/TruffleHog/Semgrep always run). This is what makes the
  extension "read the project itself" without asking the user anything — it's
  manifest-file detection, not an LLM inferring project type from prose.
- **Execution** — spawn each selected tool as a subprocess, in parallel,
  with a timeout. Each adapter is responsible for invoking the real upstream
  binary and returning raw output to the normalizer.

### 3. Normalizer

SARIF (Static Analysis Results Interchange Format) is the unifying format —
CodeQL, Semgrep, Trivy, and Checkov all emit it natively. Tools that don't
(Gitleaks, TruffleHog) get a thin adapter that maps their native JSON output
into the same `Finding` shape. One ingester, not N custom parsers.

### 4. Aggregator & dedup

The hardest, most consequential component. Two tools flagging the same
hardcoded secret on the same line with different rule IDs must collapse into
one finding, not two. Correlation key: file path + line range + a normalized
vulnerability category (not raw rule ID, since rule IDs differ by tool).
DefectDojo (OWASP) already solves a version of this problem — parsing 200+
scanner formats and deduplicating across sources — and is worth evaluating as
a base to build on or learn from rather than re-deriving dedup logic from
scratch.

### 5. Findings store

Each finding needs a stable identity so a re-scan that no longer reproduces
it can mark it `resolved` instead of silently dropping it (which would also
hide a regression if it reappears later). Minimum schema:

```
Finding {
  id            // stable hash of (file_path, rule_category, content_fingerprint)
  tool          // which scanner(s) produced it, after merge
  ruleId        // original rule id(s) from source tool(s)
  category      // normalized category, e.g. "hardcoded-secret", "sqli", "vulnerable-dependency"
  cwe           // CWE id if available
  severity      // normalized critical/high/medium/low
  file, line
  message
  status        // new | confirmed | resolved | reopened
  firstSeen, lastSeen
}
```

### 6. Web dashboard

A local server (no external network exposure by default) rendering:

- A live, filterable list of current findings, removed gracefully (not just
  deleted) when a re-scan no longer reproduces them.
- A security graph: nodes are files, functions, secrets, and dependencies;
  edges represent import/data-flow relationships and which findings sit on
  which edges. This is the most ambitious and least-validated part of the
  design — start with a simple file-level dependency graph before attempting
  function-level dataflow visualization.

### 7. Markdown report exporter

One click, pulled entirely from the findings store (never re-runs scanners).
Should include: summary counts by severity/category, full finding list with
file/line, and a note on which tools were run and which were skipped for the
project's detected fingerprint (so the report is honest about its own
coverage, not just its findings).

### 8. MCP bridge

Exposes current findings to the coding agent as a queryable tool — e.g.
"what's currently flagged in the file I just wrote." Primarily read-only.
Resolution status should be driven by re-scans, not by an agent self-reporting
that it fixed something, to avoid the store silently drifting from reality.

### 9. Self-update

Each scanner adapter tracks its own pinned tool version. A periodic job
checks upstream for new releases/rule updates and surfaces them as an
explicit changelog entry rather than silently auto-upgrading — rule changes
can shift what gets flagged, and that should be visible, not invisible.

## Tool registry

| Category | Tool | License | Fits in-extension execution? |
|---|---|---|---|
| Secrets | Gitleaks | MIT | Yes |
| Secrets | TruffleHog | AGPL-3.0 | Yes (see Licensing note) |
| SCA / dependencies | OSV-Scanner | Apache-2.0 | Yes |
| SCA / dependencies | Grype | Apache-2.0 | Yes |
| SCA / dependencies | OWASP Dependency-Check | Apache-2.0 | Yes |
| Container / multi-scan | Trivy | Apache-2.0 | Yes (also covers IaC + secrets) |
| SBOM | Syft | Apache-2.0 | Yes |
| SAST | Semgrep (CE) | LGPL-2.1 | Yes |
| SAST | CodeQL | Mixed (queries open, engine proprietary) | Yes, debounced/slower cadence |
| SAST | SonarQube CE | LGPL-3.0 | Yes |
| SAST (language-specific) | Bandit, gosec, Brakeman | Apache-2.0 / MIT | Yes, conditional on detected language |
| IaC | Checkov | Apache-2.0 | Yes, conditional on `*.tf`/k8s/Dockerfile present |
| Container posture | Kubescape | Apache-2.0 | Yes, conditional on k8s manifests present |
| Aggregation | DefectDojo | BSD-3 | Evaluate as base for the aggregator, not a runtime dependency |

## Non-goals (explicitly out of scope for in-extension execution)

These are real, valuable, benchmark-grade tools — they just operate at a
different point in the lifecycle than "a file just got saved in this editor,"
and bolting them into the orchestrator would misrepresent what they do:

- **OWASP ZAP, Nuclei** — DAST; need a running, deployed application to
  attack. Not relevant to a local source tree.
- **Falco** — eBPF-based runtime detection; needs a live kernel to watch.
  Nothing to monitor on a developer's laptop pre-deploy.
- **OPA** — policy-as-code evaluated against deployed infrastructure state,
  not source files.
- **Sigstore/cosign** — signs a finished artifact at release time; not a
  flaw-finder.
- **OSSF Scorecard** — scores an external dependency's repo health, not your
  own code.

If watsonsec ever grows a deploy-time or CI companion mode, these belong
there — not in the editor extension.

## Licensing notes

Most of the registry (Trivy, Grype, Syft, Checkov, OSV-Scanner, Gitleaks,
Kubescape, Semgrep CE) is Apache-2.0, MIT, or LGPL — safe to orchestrate as
separate subprocesses regardless of whether watsonsec itself is ever
monetized. **TruffleHog is AGPL-3.0** — the license that matters if watsonsec
is ever offered as a hosted/SaaS endpoint rather than a local extension,
since AGPL's network-use clause can trigger source-disclosure obligations in
that scenario. Invoking a published binary as an unmodified subprocess does
not itself trigger copyleft obligations — the risk only arises from
modifying-and-redistributing a tool's own source, which is not the model
here. Revisit this section before any decision to host findings centrally
rather than keeping everything local.

## Known hard problems

- **Noise.** Combining scanners without real dedup/correlation produces a
  louder tool, not a better one — this is the actual hard engineering
  problem, not the integrations themselves.
- **Performance.** Running multiple scanners on every save needs careful
  debouncing and a tiered cadence (fast tools on save, heavy tools on a
  slower schedule) or the editor becomes unusable on large repos.
- **Maintenance burden.** Each upstream tool ships its own breaking changes
  on its own schedule. Fixture tests per adapter (see `AGENTS.md`) are the
  primary defense against silent breakage.
- **Graph fidelity.** A genuinely useful security graph (not just a static
  file tree) requires real dataflow analysis, which is a multi-week problem
  on its own — treat it as a stretch goal, not part of the MVP.

## Phased roadmap

- **Phase 0** — Findings schema + aggregator/dedup logic, validated against
  fixture data from at least two overlapping tools (e.g. Semgrep + Bandit on
  the same Python sample) before any UI exists.
- **Phase 1 (MVP)** — File watcher + Gitleaks + Semgrep + OSV-Scanner, flat
  findings list in a minimal dashboard. No graph, no MCP bridge yet.
  Validates the core pipeline end to end.
- **Phase 2** — Add CodeQL, Checkov, Trivy/Grype/Syft. Markdown export.
  Project fingerprinting to conditionally enable tools.
  Begin the dependency-graph view (file-level, not function-level yet).
- **Phase 3** — MCP bridge for agent queries. Self-update job for tool
  versions/rulesets.
- **Phase 4** — Evaluate adopting or learning from DefectDojo's dedup engine
  directly rather than maintaining a bespoke one; revisit graph fidelity.
