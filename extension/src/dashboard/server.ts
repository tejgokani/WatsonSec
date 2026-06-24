import * as http from "http";
import type { FindingsStore } from "../store";

export class DashboardServer {
  private server: http.Server | null = null;
  private readonly store: FindingsStore;
  private readonly port: number;

  constructor(store: FindingsStore, port: number) {
    this.store = store;
    this.port = port;
  }

  start(): void {
    if (this.server) return;
    this.server = http.createServer((req, res) => this.handle(req, res));
    this.server.listen(this.port, "127.0.0.1", () => {
      console.log(`[watsonsec] Dashboard running at http://127.0.0.1:${this.port}`);
    });
  }

  stop(): void {
    this.server?.close();
    this.server = null;
  }

  get url(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  private handle(req: http.IncomingMessage, res: http.ServerResponse): void {
    const url = req.url ?? "/";

    if (url === "/api/findings") {
      res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
      res.end(JSON.stringify(this.store.getAll()));
      return;
    }

    if (url === "/api/scans") {
      res.writeHead(200, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
      res.end(JSON.stringify(this.store.getRecentScans()));
      return;
    }

    if (url === "/" || url === "/index.html") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(dashboardHtml());
      return;
    }

    res.writeHead(404);
    res.end("Not found");
  }
}

function dashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WatsonSec — Security Findings</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --text: #e2e8f0;
    --muted: #718096;
    --critical: #fc5c65;
    --high: #fd9644;
    --medium: #fed330;
    --low: #26de81;
    --info: #45aaf2;
    --new: #45aaf2;
    --confirmed: #fd9644;
    --resolved: #26de81;
    --reopened: #fc5c65;
    --radius: 6px;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    --mono: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', 'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 18px; font-weight: 700; letter-spacing: -0.3px; }
  header .badge { background: #4a4e69; color: #fff; font-size: 11px; padding: 2px 8px; border-radius: 20px; }
  .toolbar { padding: 12px 24px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; border-bottom: 1px solid var(--border); }
  .toolbar label { color: var(--muted); font-size: 12px; }
  select, input { background: var(--surface); border: 1px solid var(--border); color: var(--text); padding: 6px 10px; border-radius: var(--radius); font-size: 13px; outline: none; }
  select:focus, input:focus { border-color: var(--info); }
  button.refresh { margin-left: auto; background: var(--info); color: #000; border: none; padding: 7px 16px; border-radius: var(--radius); cursor: pointer; font-weight: 600; font-size: 13px; }
  button.refresh:hover { opacity: 0.85; }
  .stats { display: flex; gap: 12px; padding: 16px 24px; flex-wrap: wrap; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px 18px; min-width: 110px; text-align: center; }
  .stat-card .num { font-size: 28px; font-weight: 700; line-height: 1; }
  .stat-card .lbl { font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card.critical .num { color: var(--critical); }
  .stat-card.high .num { color: var(--high); }
  .stat-card.medium .num { color: var(--medium); }
  .stat-card.low .num { color: var(--low); }
  .findings-table { padding: 0 24px 40px; }
  table { width: 100%; border-collapse: collapse; }
  thead th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); padding: 10px 12px; border-bottom: 1px solid var(--border); }
  tbody tr { border-bottom: 1px solid var(--border); transition: background 0.1s; }
  tbody tr:hover { background: var(--surface); }
  td { padding: 10px 12px; vertical-align: top; }
  .sev { display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 3px; text-transform: uppercase; letter-spacing: 0.3px; }
  .sev.critical { background: #3d1a1a; color: var(--critical); }
  .sev.high { background: #3a2210; color: var(--high); }
  .sev.medium { background: #38330a; color: var(--medium); }
  .sev.low { background: #0d3322; color: var(--low); }
  .sev.info { background: #0d2033; color: var(--info); }
  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 5px; }
  .status-dot.new { background: var(--new); }
  .status-dot.confirmed { background: var(--confirmed); }
  .status-dot.resolved { background: var(--resolved); }
  .status-dot.reopened { background: var(--reopened); }
  .filepath { font-family: var(--mono); font-size: 12px; color: var(--info); }
  .message { max-width: 400px; word-break: break-word; }
  .tool-chip { display: inline-block; font-size: 10px; background: #1e2233; border: 1px solid var(--border); padding: 1px 6px; border-radius: 3px; margin-right: 3px; color: var(--muted); }
  .empty { text-align: center; padding: 60px; color: var(--muted); }
  .empty h2 { font-size: 20px; margin-bottom: 8px; }
  .last-scan { font-size: 12px; color: var(--muted); margin-left: auto; }
</style>
</head>
<body>
<header>
  <h1>🔐 WatsonSec</h1>
  <span class="badge" id="total-badge">—</span>
  <span class="last-scan" id="last-scan-text"></span>
</header>

<div class="toolbar">
  <label>Severity</label>
  <select id="filter-sev">
    <option value="">All</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
  </select>
  <label>Status</label>
  <select id="filter-status">
    <option value="">All</option>
    <option value="new">New</option>
    <option value="confirmed">Confirmed</option>
    <option value="resolved">Resolved</option>
    <option value="reopened">Reopened</option>
  </select>
  <label>Tool</label>
  <select id="filter-tool">
    <option value="">All</option>
  </select>
  <input type="search" id="filter-search" placeholder="Search message / file…" style="width:220px">
  <button class="refresh" onclick="load()">⟳ Refresh</button>
</div>

<div class="stats">
  <div class="stat-card critical"><div class="num" id="count-critical">0</div><div class="lbl">Critical</div></div>
  <div class="stat-card high"><div class="num" id="count-high">0</div><div class="lbl">High</div></div>
  <div class="stat-card medium"><div class="num" id="count-medium">0</div><div class="lbl">Medium</div></div>
  <div class="stat-card low"><div class="num" id="count-low">0</div><div class="lbl">Low</div></div>
</div>

<div class="findings-table">
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Status</th>
        <th>File</th>
        <th>Message</th>
        <th>Rule</th>
        <th>Tool(s)</th>
        <th>First seen</th>
      </tr>
    </thead>
    <tbody id="tbody"></tbody>
  </table>
  <div id="empty" class="empty" style="display:none">
    <h2>No findings yet</h2>
    <p>Save a file to trigger a scan, or run WatsonSec: Run Full Scan from the command palette.</p>
  </div>
</div>

<script>
let allFindings = [];
let allTools = new Set();

async function load() {
  try {
    const [findingsRes, scansRes] = await Promise.all([
      fetch('/api/findings'), fetch('/api/scans')
    ]);
    allFindings = await findingsRes.json();
    const scans = await scansRes.json();

    allTools = new Set(allFindings.flatMap(f => f.tool));
    updateToolFilter();
    updateLastScan(scans[0]);
    render();
  } catch(e) {
    console.error('Failed to load findings:', e);
  }
}

function updateToolFilter() {
  const sel = document.getElementById('filter-tool');
  const existing = new Set(Array.from(sel.options).map(o => o.value).filter(Boolean));
  for (const t of allTools) {
    if (!existing.has(t)) {
      const opt = document.createElement('option');
      opt.value = t; opt.textContent = t;
      sel.appendChild(opt);
    }
  }
}

function updateLastScan(scan) {
  const el = document.getElementById('last-scan-text');
  if (!scan) { el.textContent = ''; return; }
  const d = new Date(scan.startedAt);
  el.textContent = 'Last scan: ' + d.toLocaleTimeString();
}

function render() {
  const sevFilter = document.getElementById('filter-sev').value;
  const statusFilter = document.getElementById('filter-status').value;
  const toolFilter = document.getElementById('filter-tool').value;
  const searchFilter = document.getElementById('filter-search').value.toLowerCase();

  const filtered = allFindings.filter(f => {
    if (sevFilter && f.severity !== sevFilter) return false;
    if (statusFilter && f.status !== statusFilter) return false;
    if (toolFilter && !f.tool.includes(toolFilter)) return false;
    if (searchFilter && !f.message.toLowerCase().includes(searchFilter) && !f.filePath.toLowerCase().includes(searchFilter)) return false;
    return true;
  });

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of allFindings) {
    if (counts[f.severity] !== undefined && f.status !== 'resolved') counts[f.severity]++;
  }
  document.getElementById('count-critical').textContent = counts.critical;
  document.getElementById('count-high').textContent = counts.high;
  document.getElementById('count-medium').textContent = counts.medium;
  document.getElementById('count-low').textContent = counts.low;
  document.getElementById('total-badge').textContent = allFindings.filter(f => f.status !== 'resolved').length + ' active';

  const tbody = document.getElementById('tbody');
  const empty = document.getElementById('empty');

  if (!filtered.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  const sevOrder = {critical:0,high:1,medium:2,low:3,info:4};
  filtered.sort((a,b) => (sevOrder[a.severity]??5)-(sevOrder[b.severity]??5));

  tbody.innerHTML = filtered.map(f => {
    const line = f.startLine === f.endLine ? f.startLine : f.startLine + '-' + f.endLine;
    const tools = f.tool.map(t => '<span class="tool-chip">' + esc(t) + '</span>').join('');
    const rules = f.ruleId.join(', ');
    const ts = new Date(f.firstSeen).toLocaleDateString();
    return '<tr>' +
      '<td><span class="sev ' + f.severity + '">' + f.severity + '</span></td>' +
      '<td><span class="status-dot ' + f.status + '"></span>' + f.status + '</td>' +
      '<td class="filepath">' + esc(f.filePath) + ':' + line + '</td>' +
      '<td class="message">' + esc(f.message) + '</td>' +
      '<td class="filepath" title="' + esc(rules) + '">' + esc(f.ruleId[0] ?? '') + '</td>' +
      '<td>' + tools + '</td>' +
      '<td>' + ts + '</td>' +
      '</tr>';
  }).join('');
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

['filter-sev','filter-status','filter-tool','filter-search'].forEach(id => {
  document.getElementById(id).addEventListener('input', render);
});

load();
setInterval(load, 30000);
</script>
</body>
</html>`;
}
