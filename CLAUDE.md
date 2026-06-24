# CLAUDE.md — watsonsec

This file covers Claude Code-specific notes only. For project conventions,
repo structure, and the rules that apply to every agent regardless of tool,
read `AGENTS.md` first — it is canonical. This file only adds what's specific
to working as Claude in this repo.

## Context you should always load before touching the pipeline

Before modifying `orchestrator/`, `aggregator/`, or `store/`, read
`ARCHITECTURE.md` in full. The aggregation/dedup layer is the part of this
project most likely to silently regress, and the architecture doc explains
why each design choice (stable finding IDs, SARIF-first normalization,
hybrid agent-plus-real-tools execution) was made the way it was. Don't
re-derive the design from scratch in a single session — extend it.

## The hybrid principle, restated for you specifically

When asked to "have the agent check for X security issue," your default
move should be: is there already a deterministic tool in `TOOL_REGISTRY.md`
that checks for X? If yes, wire up or extend that adapter — do not write a
prompt asking yourself to detect X by reading the file. Reserve your own
reasoning for the things no deterministic tool here can do: cross-finding
correlation, business-logic flaws (IDOR, broken authorization), prioritizing
which of many findings actually matters in context, and writing the
human-readable report. This split is the entire reason this project exists
instead of just running Semgrep alone.

## When asked to add a new scanner

Follow the five-step checklist in `AGENTS.md` under "Adding a new scanner
adapter." Do not skip step 4 (the fixture test) even for a quick prototype —
silent adapter breakage is the single most likely failure mode of this
project given how many independent upstream tools it depends on.

## Working with the local dashboard and MCP bridge

- The dashboard (`dashboard/`) reads only from the findings store — it should
  never call a scanner directly. If a feature seems to need that, the
  feature belongs in the orchestrator, not the dashboard.
- The MCP bridge (`mcp-bridge/`) should expose read access to current
  findings as its primary surface. Be conservative about adding
  write-capable tools (e.g. "mark finding resolved") — a re-scan should be
  the source of truth for resolution, not an agent's self-report that it
  fixed something.

## Things not to do

- Don't add ZAP, Nuclei, Falco, OPA, Sigstore/cosign, or OSSF Scorecard to the
  in-extension orchestrator. They're real, valuable tools, but they operate
  on a running app, live infrastructure, or an external repo — not the local
  file being edited. See "Non-goals" in `ARCHITECTURE.md` if asked to
  reconsider this.
- Don't invent CLI flags or output formats for any upstream tool. If you're
  not certain of a tool's actual current interface, say so and look it up
  rather than guessing — a wrong assumption here produces a silently broken
  adapter, which is exactly the failure mode this project is trying to avoid
  introducing into other people's code.
