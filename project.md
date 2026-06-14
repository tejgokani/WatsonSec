# Security Sentinel

> Real-time AI-powered security scanning, living inside your VS Code session.

---

## What it is

Security Sentinel is a VS Code extension that runs a continuous, intelligent security audit across your entire codebase — from the moment you open a project to every file save. It uses Claude (via the Anthropic API) as its reasoning engine, giving it the ability to understand context, not just pattern-match.

When it finds a vulnerability, it marks the exact line in your editor with a gutter icon, logs the finding to a live `security-report.md`, and tells you exactly how to fix it — with CVE references, severity ratings, and remediation steps.

When you fix the issue, it knows. The finding is marked resolved.

---

## What it is not

- It is not a linter. Linters match patterns. This reasons about code.
- It is not a one-shot scanner. It runs continuously alongside your work.
- It is not language-specific. It detects the project type and adjusts its analysis accordingly.
- It does not require a GPU, a local model, or any special hardware. It runs on any Mac, Windows, or Linux machine with a VS Code installation and an Anthropic API key.

---

## The problem it solves

Security issues get introduced during development, not after deployment — but most developers only run security scans in CI/CD, when the code is already written and merged. By the time a scanner flags something, fixing it means context-switching out of a flow state, digging back into old code, and often reopening PRs.

Security Sentinel moves the security audit into the editor, running it in the background while you work, so issues are caught at the moment they're introduced — not discovered after the fact.

---

## How it works

1. **Session start** — the extension reads the project root, detects the stack (Node.js, Python, PHP, Go, Rust, Java, Ruby, etc.), and runs a full initial scan of every file.
2. **File watch** — every time you save a file, the extension re-scans that file and its direct imports.
3. **Chunking** — large files are split into overlapping chunks with shared context at the boundaries, so no vulnerability gets missed at a split point.
4. **Claude API call** — each chunk is sent to Claude with a project-type-aware security audit prompt. Claude returns a structured JSON array of findings.
5. **Finding parser** — findings are mapped to exact file paths and line numbers, deduplicated across chunks, and assigned severity levels and CVE/CWE tags.
6. **Gutter decorations** — the VS Code editor decorates the vulnerable lines with colored icons (🔴 critical, 🟡 medium, 🔵 low).
7. **Report writer** — `security-report.md` is updated in place, organized by severity, with full descriptions and fix suggestions.
8. **Resolution detection** — on the next scan of a modified file, resolved findings are diffed out and marked `[RESOLVED]` in the report.

---

## Vulnerability coverage

The prompt engine is designed to cover every class of web and application vulnerability, including but not limited to:

- Injection: SQL, NoSQL, Command, LDAP, XPath
- Cross-site scripting (XSS): reflected, stored, DOM-based
- Cross-site request forgery (CSRF)
- Insecure direct object references (IDOR)
- Server-side request forgery (SSRF)
- Remote code execution (RCE)
- Path traversal / directory traversal
- Broken authentication and session management
- Hardcoded secrets, API keys, credentials
- Insecure deserialization
- Outdated dependencies with known CVEs
- Security misconfigurations
- Exposed debug endpoints and admin panels
- Missing or misconfigured security headers (CSP, CORS, HSTS, X-Frame-Options)
- Insecure cryptography (weak algorithms, improper key handling)
- Mass assignment vulnerabilities
- Open redirects
- Business logic flaws (where inferrable from code structure)

---

## Project structure

```
security-sentinel/
├── extension/
│   ├── src/
│   │   ├── extension.ts          # VS Code activation + lifecycle
│   │   ├── orchestrator.ts       # Scan queue, file watching, session init
│   │   ├── chunker.ts            # File splitting with overlap
│   │   ├── promptEngine.ts       # Project-type-aware prompt builder
│   │   ├── claudeClient.ts       # Anthropic API calls
│   │   ├── findingParser.ts      # JSON → Finding objects + CVE mapping
│   │   ├── resolver.ts           # Diff-based resolution detection
│   │   ├── decorationManager.ts  # Gutter icons + inline highlights
│   │   └── reportWriter.ts       # security-report.md generation
│   ├── package.json              # VS Code extension manifest
│   └── tsconfig.json
├── website/
│   ├── index.html                # Landing page
│   └── docs.html                 # Documentation page
├── project.md                    # This file
├── claude.md                     # Claude Code instructions
└── agent.md                      # Agentic task definitions
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Extension runtime | TypeScript + VS Code Extension API |
| AI engine | Anthropic Claude API (`claude-sonnet-4-6`) |
| File watching | VS Code `workspace.onDidSaveTextDocument` |
| Editor decorations | VS Code `TextEditorDecorationType` |
| Report format | Markdown (`.md`) opened via `vscode.open` |
| Website | Vanilla HTML/CSS/JS (no framework) |
| Distribution | VS Code Marketplace + website install link |

---

## Security of the extension itself

- The Anthropic API key is stored in VS Code's secret storage (`context.secrets`), not in plaintext config.
- No code is stored or logged outside the local session.
- The extension only reads files within the open workspace.
- API calls go directly to `api.anthropic.com` — no proxy, no third-party intermediary.

---

## Status

In active development. See `agent.md` for current task breakdown and `claude.md` for Claude Code session instructions.
