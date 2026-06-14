# Agent task list — Security Sentinel

This file tracks every task in the project. Claude Code should check this at the start of each session, pick up where the last session left off, and mark tasks complete as they are done.

Format: `[x]` = done, `[-]` = in progress, `[ ]` = not started, `[!]` = blocked

---

## Phase 0 — Project foundation

- [x] Write `project.md` — full architecture and intent
- [x] Write `claude.md` — Claude Code session instructions
- [x] Write `agent.md` — this file
- [x] Build website landing page (`index.html`)
- [x] Build website docs page (`docs.html`)

---

## Phase 1 — Extension scaffold

- [x] Initialize VS Code extension project with `yo code` or manual scaffold
  - TypeScript, strict mode, no bundler initially (esbuild added in Phase 3)
  - `publisher` field: set to actual publisher ID when marketplace account is created
- [x] Create `tsconfig.json` with strict settings
- [x] Create `package.json` with all commands, configuration contributions, and activation events
  - Activation: `onStartupFinished` + `workspaceContains:**`
  - Commands: all 7 from `claude.md`
  - Configuration: all 5 properties from `claude.md`
- [x] Create `src/types.ts` — `Finding` interface and all shared types
- [x] Create `src/extension.ts` — activation, disposables, command registration

**Checkpoint:** `tsc --noEmit` passes. Extension loads in Extension Development Host without errors.

---

## Phase 2 — Core scanning pipeline

- [x] Build `src/claudeClient.ts`
- [x] Build `src/chunker.ts`
- [x] Build `src/promptEngine.ts`
- [x] Build `src/findingParser.ts`

**Checkpoint:** Can scan a single hardcoded JS file and print findings to console.

---

## Phase 3 — Resolution and state management

- [x] Build `src/resolver.ts`
- [x] Build `src/orchestrator.ts`

**Checkpoint:** Save a file with a SQL injection, see finding appear. Fix it, save again, see it resolved.

---

## Phase 4 — Editor integration

- [x] Build `src/decorationManager.ts`
- [x] Build `src/statusBar.ts`

**Checkpoint:** Open a vulnerable file. Red gutter icon appears on the vulnerable line. Hover shows full finding detail. Status bar shows count.

---

## Phase 5 — Report generation

- [x] Build `src/reportWriter.ts`
- [x] Wire `securitySentinel.openReport` command

**Checkpoint:** Full scan runs, `security-report.md` is generated with correct structure, opens on icon click.

---

## Phase 6 — API key onboarding

- [x] Implement `securitySentinel.setApiKey` command
- [x] Implement first-run detection

**Checkpoint:** Fresh install flow works. Key is stored securely. Removing the key and re-entering it works.

---

## Phase 7 — Build and packaging

- [x] Add `esbuild` bundler config
- [x] Add `vsce` packaging with `.vscodeignore`
- [x] Create gutter icon SVGs for each severity (in `assets/`)
- [x] Create extension icon 128x128 PNG

**Checkpoint:** `vsce package` produces a `.vsix` file that installs cleanly in VS Code.

---

## Phase 8 — Polish and edge cases

- [x] Handle workspaces with no files gracefully
- [x] Handle API rate limit errors with exponential backoff (4 retries, exponential + jitter)
- [x] Handle files that change while being scanned (cancel + re-queue via CancellationTokenSource per file)
- [x] Handle very large workspaces (1000+ files) — batch of 10, open files first, then by mtime
- [x] Add progress notification during initial full scan (`vscode.window.withProgress`, cancellable)
- [ ] Test on a real vulnerable project (DVWA, WebGoat, or a synthetic vulnerable Node.js app)
- [x] Write `README.md` for marketplace listing

---

## Decisions log

_Record any significant decisions made during development here, with reasoning._

| Date | Decision | Reason |
|---|---|---|
| — | Use `claude-sonnet-4-6` not Haiku | Haiku misses too many subtle vulnerabilities in testing |
| — | 300-line chunks with 20-line overlap | Balances context quality against token cost |
| — | Temperature 0 | Security analysis should be deterministic |
| — | Atomic report writes | Prevents VS Code from showing a half-written file on open |
| 2026-06-14 | Switched from Anthropic SDK to vscode.lm API | No API key needed — works with any agent in session |
| 2026-06-14 | CancellationTokenSource per file | Cancels stale scan instantly when file is re-saved |
| 2026-06-14 | Batch of 10 in full scan | Prevents thousands of promises queuing for large workspaces |
| 2026-06-14 | 4 retries with exponential backoff + jitter | LM API can return Blocked/NotFound when model is busy |

---

## Known issues / blockers

_None yet._
