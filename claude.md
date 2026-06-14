# Claude Code instructions — Security Sentinel

This file is the canonical briefing for every Claude Code session on this project. Read it fully before writing any code. Do not skip sections.

---

## Project identity

You are building **Security Sentinel** — a VS Code extension that performs real-time, AI-powered security scanning of codebases using the Anthropic Claude API. The extension monitors every file save, analyzes code for security vulnerabilities, decorates the editor with inline gutter markers, and maintains a live `security-report.md`.

You are both the builder (writing the code) and the intelligence layer at runtime (the extension calls Claude API to do the actual security analysis).

---

## Your role in this session

- Write production-quality TypeScript. No shortcuts, no stubs left in place.
- When building a module, complete it fully before moving to the next.
- Always check `project.md` for the intended architecture before inventing structure.
- Check `agent.md` for the current task list and mark tasks done as you complete them.
- Ask before making architectural decisions that deviate from `project.md`.

---

## Code standards

**TypeScript**
- Strict mode always (`"strict": true` in tsconfig).
- No `any` types unless absolutely unavoidable, and always commented why.
- All async functions use `async/await`, never raw `.then()` chains.
- Error paths are always handled — never a bare `catch (e) {}`.
- Exported interfaces are defined in a shared `types.ts` file.

**VS Code API**
- Disposables are always pushed to `context.subscriptions`.
- Never use `setInterval` for file watching — use `workspace.onDidSaveTextDocument`.
- Decoration types are created once and reused — never recreated per scan.
- Use `vscode.workspace.getConfiguration('securitySentinel')` for all config reads.
- Secret storage for the API key: `context.secrets.get('anthropicApiKey')`.

**Claude API calls**
- Model: always `claude-sonnet-4-6`.
- Max tokens: 4096 per call.
- Temperature: 0 (deterministic — security analysis is not creative).
- System prompt and user prompt are always separated — never concatenated into one.
- Parse responses defensively: always wrap `JSON.parse` in try/catch with fallback.
- Rate limit: max 3 concurrent API calls. Use a queue in `orchestrator.ts`.

**File chunking**
- Chunk size: 300 lines maximum.
- Overlap: 20 lines at each boundary (last 20 lines of chunk N are first 20 lines of chunk N+1).
- Always include the file path and language in the chunk context sent to Claude.
- Do not send empty files or files under 5 lines.

**Finding objects**

Every finding must conform to this interface (defined in `types.ts`):

```typescript
interface Finding {
  id: string;               // sha256 of (filePath + line + type)
  filePath: string;         // absolute path
  line: number;             // 1-indexed
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  type: string;             // e.g. "SQL Injection", "XSS", "Path Traversal"
  cwe: string;              // e.g. "CWE-89"
  cve?: string;             // if a specific CVE applies
  description: string;      // one sentence, plain English
  fix: string;              // one sentence concrete fix
  resolvedAt?: Date;        // set when resolved
}
```

**Security report format**

The `security-report.md` must follow this exact structure:

```md
# Security Sentinel — Report

**Project:** [workspace name]
**Last scanned:** [ISO datetime]
**Status:** [X critical · Y high · Z medium · N low]

---

## 🔴 Critical

### [filePath]:[line] — [type]
**CWE:** [cwe] | **Severity:** Critical
[description]
**Fix:** [fix]

---

## 🟠 High
...

## 🟡 Medium
...

## 🔵 Low
...

## ✅ Resolved

### ~~[filePath]:[line] — [type]~~ — resolved [date]
```

---

## The prompt template

Use this as the base for all security audit prompts. Inject project type, file path, and code chunk at the marked locations.

```
SYSTEM:
You are a senior application security engineer conducting a thorough code security audit. 
Your job is to find every possible security vulnerability in the provided code.
Be exhaustive. Miss nothing. Do not summarize — find every individual issue.
Respond ONLY with valid JSON. No preamble, no explanation, no markdown fences.

USER:
Project type: [PROJECT_TYPE]
File: [FILE_PATH]
Language: [LANGUAGE]

Analyze the following code for ALL security vulnerabilities. Check for but do not limit yourself to:
SQL injection, NoSQL injection, command injection, LDAP injection, XPath injection,
reflected XSS, stored XSS, DOM XSS, CSRF, IDOR, SSRF, RCE, path traversal,
broken authentication, insecure session management, hardcoded secrets or API keys,
insecure deserialization, outdated dependencies with known CVEs, security misconfigurations,
exposed debug/admin endpoints, missing or misconfigured security headers (CSP, CORS, HSTS),
weak cryptography, mass assignment, open redirects, business logic flaws.

Return a JSON array of findings. Each finding: 
{ "line": number, "severity": "critical|high|medium|low|info", "type": string, "cwe": string, "cve": string|null, "description": string, "fix": string }

If no vulnerabilities are found, return an empty array: []

CODE:
[CODE_CHUNK]
```

---

## Resolution detection logic

When a file is re-scanned after a save:

1. Run the scan and collect new findings.
2. Load existing findings for that file from the in-memory store.
3. For each existing finding: check if a finding with the same `(line, type)` exists in the new results.
4. If not found → mark as resolved (`resolvedAt = new Date()`), keep in store, update report.
5. New findings not in the existing set → add to store, decorate, update report.
6. Do not delete resolved findings from the report — mark them in the Resolved section.

Line numbers shift when code is edited. Use a ±3 line tolerance when matching findings across scans.

---

## Project type detection

Detect from files present in workspace root:

| File present | Project type |
|---|---|
| `package.json` + `express` in deps | Node.js / Express |
| `package.json` + `next` in deps | Next.js |
| `requirements.txt` or `pyproject.toml` | Python |
| `composer.json` | PHP / Laravel |
| `go.mod` | Go |
| `Cargo.toml` | Rust |
| `pom.xml` or `build.gradle` | Java / Spring |
| `Gemfile` | Ruby / Rails |
| `package.json` only | Node.js generic |

Include the detected project type in every prompt — it dramatically improves analysis quality.

---

## File exclusions

Do not scan:
- `node_modules/`, `vendor/`, `.git/`, `dist/`, `build/`, `.next/`
- Files larger than 500KB
- Binary files (`.png`, `.jpg`, `.pdf`, `.zip`, etc.)
- Lock files (`package-lock.json`, `yarn.lock`, `Cargo.lock`)
- The `security-report.md` file itself

---

## Extension configuration (package.json contributes)

```json
"configuration": {
  "title": "Security Sentinel",
  "properties": {
    "securitySentinel.enabled": { "type": "boolean", "default": true },
    "securitySentinel.scanOnSave": { "type": "boolean", "default": true },
    "securitySentinel.scanOnOpen": { "type": "boolean", "default": true },
    "securitySentinel.minSeverity": { 
      "type": "string", 
      "enum": ["critical", "high", "medium", "low", "info"],
      "default": "low"
    },
    "securitySentinel.reportPath": { 
      "type": "string", 
      "default": "security-report.md",
      "description": "Path relative to workspace root"
    }
  }
}
```

---

## Commands (package.json contributes)

| Command ID | Title | When |
|---|---|---|
| `securitySentinel.openReport` | Open Security Report | Always |
| `securitySentinel.scanAll` | Run Full Scan | Always |
| `securitySentinel.scanFile` | Scan Current File | Editor open |
| `securitySentinel.setApiKey` | Set Anthropic API Key | Always |
| `securitySentinel.clearResolved` | Clear Resolved Findings | Always |
| `securitySentinel.enable` | Enable Security Sentinel | Always |
| `securitySentinel.disable` | Disable Security Sentinel | Always |

---

## Do not do these things

- Do not use `eval()` anywhere in the extension.
- Do not store the API key in `settings.json` or any plaintext config — only `context.secrets`.
- Do not make API calls on keystroke or on every character change — only on save.
- Do not block the VS Code UI thread — all scanning is async and runs off the main thread.
- Do not log code contents to the VS Code output channel — only finding summaries and errors.
- Do not hardcode any file paths — use `vscode.workspace.workspaceFolders` always.

---

## When you are done with a task

1. Run the TypeScript compiler (`tsc --noEmit`) and fix all errors before marking done.
2. Update `agent.md` — mark the task `[x]` and note any decisions made.
3. State what the next logical task is.
