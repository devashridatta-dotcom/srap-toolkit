"""Browser dashboard for SBOM upload and SRAP triage."""

from __future__ import annotations

import argparse
import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Optional
from urllib.parse import urlparse

from .asserter import SRAPAsserter
from .cra_annotator import CRAAnnotator
from .scorer import DOMAIN_WEIGHTS, SRSScorer


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
VALID_SR_CLASSES = {"SR-0", "SR-1", "SR-2", "SR-3"}


def analyze_sbom(
    sbom: dict[str, Any],
    domain: str,
    default_sr: str = "SR-0",
    product_name: str = "Uploaded Product",
    manufacturer: str = "Unknown",
    version: Optional[str] = None,
) -> dict[str, Any]:
    """Annotate an SBOM, score vulnerabilities, and build dashboard payloads."""
    if domain not in DOMAIN_WEIGHTS:
        raise ValueError(f"Unknown domain '{domain}'. Valid: {sorted(DOMAIN_WEIGHTS.keys())}")
    if default_sr not in VALID_SR_CLASSES:
        raise ValueError(f"Unknown SR class '{default_sr}'. Valid: {sorted(VALID_SR_CLASSES)}")

    annotated = copy.deepcopy(sbom)
    SRAPAsserter().assert_all_unknown(annotated, domain=domain, default_sr=default_sr)

    components = annotated.get("components", [])
    component_by_ref = _component_ref_map(components)
    vulnerabilities = annotated.get("vulnerabilities", [])
    scorer = SRSScorer()
    rows = []

    for vuln in vulnerabilities:
        cve = vuln.get("id") or vuln.get("cve") or "UNKNOWN"
        cvss = _extract_cvss(vuln)
        epss = _extract_epss(vuln)
        kev = _extract_kev(vuln)
        affected_components = _affected_components(vuln, component_by_ref)

        if not affected_components:
            affected_components = [None]

        for comp in affected_components:
            props = _properties(comp or {})
            row_domain = props.get("srap:domain") or domain
            sr_class = props.get("srap:safety_relevance_class") or default_sr
            result = scorer.score(
                cve=cve,
                cvss=cvss,
                epss=epss,
                kev=kev,
                domain=row_domain,
                sr_class=sr_class,
            )
            row = result.to_dict()
            row.update(
                {
                    "component_name": (comp or {}).get("name", "Unmapped component"),
                    "component_version": (comp or {}).get("version"),
                    "purl": (comp or {}).get("purl"),
                    "bom_ref": (comp or {}).get("bom-ref"),
                    "vulnerability_source": (vuln.get("source") or {}).get("name"),
                    "severity": _extract_severity(vuln),
                }
            )
            rows.append(row)

    rows.sort(key=lambda item: item["srs_score_display"], reverse=True)
    cra_package = CRAAnnotator(product_name, manufacturer, version).generate(annotated)

    return {
        "summary": {
            "component_count": len(components),
            "vulnerability_count": len(vulnerabilities),
            "triage_counts": _count_by(rows, "triage_recommendation"),
            "class_counts": _count_by(rows, "srs_class"),
            "sr_summary": SRAPAsserter().get_sr_summary(annotated),
            "max_srs": rows[0]["srs_score_display"] if rows else 0.0,
        },
        "rows": rows,
        "annotated_sbom": annotated,
        "cra_evidence": cra_package,
        "triage_report": {"summary": _count_by(rows, "triage_recommendation"), "results": rows},
    }


def run_dashboard(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Run the dashboard HTTP server until interrupted."""
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    url = f"http://{host}:{port}"
    print(f"SRAP dashboard running at {url}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SRAP dashboard.")
    finally:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SRAP Toolkit dashboard")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    run_dashboard(host=args.host, port=args.port)


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "SRAPDashboard/0.1"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._send_text(INDEX_HTML, "text/html; charset=utf-8")
        elif path == "/api/domains":
            self._send_json({"domains": sorted(DOMAIN_WEIGHTS.keys()), "weights": DOMAIN_WEIGHTS})
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/analyze":
            self.send_error(404)
            return

        try:
            payload = self._read_json_body()
            result = analyze_sbom(
                sbom=payload["sbom"],
                domain=payload.get("domain", "automotive"),
                default_sr=payload.get("default_sr", "SR-0"),
                product_name=payload.get("product_name") or "Uploaded Product",
                manufacturer=payload.get("manufacturer") or "Unknown",
                version=payload.get("version") or None,
            )
            self._send_json(result)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, status=400)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")

    def _read_json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise TypeError("Expected JSON object")
        return payload

    def _send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, body: str, content_type: str, status: int = 200) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def _component_ref_map(components: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    refs = {}
    for comp in components:
        for key in ("bom-ref", "purl", "name"):
            value = comp.get(key)
            if value:
                refs[value] = comp
    return refs


def _affected_components(
    vulnerability: dict[str, Any],
    component_by_ref: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    components = []
    for affected in vulnerability.get("affects", []):
        ref = affected.get("ref") if isinstance(affected, dict) else None
        comp = component_by_ref.get(ref)
        if comp and comp not in components:
            components.append(comp)
    return components


def _properties(item: dict[str, Any]) -> dict[str, Any]:
    return {
        prop.get("name"): prop.get("value")
        for prop in item.get("properties", [])
        if isinstance(prop, dict) and prop.get("name")
    }


def _extract_cvss(vulnerability: dict[str, Any]) -> float:
    for rating in vulnerability.get("ratings", []):
        if isinstance(rating, dict) and rating.get("score") is not None:
            return float(rating["score"])
    return float(vulnerability.get("cvss", 0.0) or 0.0)


def _extract_severity(vulnerability: dict[str, Any]) -> Optional[str]:
    for rating in vulnerability.get("ratings", []):
        if isinstance(rating, dict) and rating.get("severity"):
            return rating["severity"]
    return vulnerability.get("severity")


def _extract_epss(vulnerability: dict[str, Any]) -> float:
    if vulnerability.get("epss") is not None:
        return float(vulnerability["epss"])
    props = _properties(vulnerability)
    for key in ("srap:epss", "epss"):
        if props.get(key) is not None:
            return float(props[key])
    return 0.0


def _extract_kev(vulnerability: dict[str, Any]) -> bool:
    if vulnerability.get("kev") is not None:
        return bool(vulnerability["kev"])
    props = _properties(vulnerability)
    value = props.get("srap:kev") or props.get("kev")
    if value is None:
        return False
    return str(value).lower() in {"1", "true", "yes", "kev"}


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = row.get(key) or "UNKNOWN"
        counts[value] = counts.get(value, 0) + 1
    return counts


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SRAP Toolkit Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #17202a;
      --muted: #667085;
      --line: #d8dee8;
      --blue: #2563eb;
      --green: #168a5b;
      --amber: #a56209;
      --red: #bd2e2e;
      --violet: #6d43a6;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font: 14px/1.45 "Segoe UI", Arial, sans-serif;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 56px;
      padding: 0 24px;
      border-bottom: 1px solid var(--line);
      background: #fff;
    }
    h1 { font-size: 18px; margin: 0; font-weight: 650; }
    main { padding: 18px 24px 28px; }
    .toolbar {
      display: grid;
      grid-template-columns: minmax(220px, 1.2fr) repeat(5, minmax(130px, 0.8fr)) auto;
      gap: 10px;
      align-items: end;
      padding: 14px;
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 8px;
    }
    label { display: grid; gap: 5px; color: var(--muted); font-size: 12px; }
    input, select, button {
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--ink);
      padding: 7px 9px;
      font: inherit;
    }
    button {
      border-color: var(--blue);
      background: var(--blue);
      color: #fff;
      font-weight: 650;
      cursor: pointer;
      white-space: nowrap;
    }
    button.secondary {
      background: #fff;
      color: var(--blue);
    }
    button:disabled { opacity: 0.55; cursor: not-allowed; }
    .metrics {
      display: grid;
      grid-template-columns: repeat(6, minmax(120px, 1fr));
      gap: 10px;
      margin-top: 14px;
    }
    .metric {
      min-height: 76px;
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 8px;
      padding: 12px;
    }
    .metric span { color: var(--muted); font-size: 12px; }
    .metric strong { display: block; margin-top: 5px; font-size: 24px; }
    .workspace {
      display: grid;
      grid-template-columns: minmax(0, 1fr) 340px;
      gap: 14px;
      margin-top: 14px;
      align-items: start;
    }
    .panel {
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 8px;
      overflow: hidden;
    }
    .panel-head {
      min-height: 44px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
    }
    h2 { margin: 0; font-size: 14px; }
    .downloads { display: flex; gap: 8px; flex-wrap: wrap; }
    .downloads button { width: auto; min-height: 32px; padding: 5px 9px; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td {
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: middle;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    th { color: var(--muted); font-size: 12px; font-weight: 650; background: #fbfcfe; }
    tr { cursor: pointer; }
    tr:hover td { background: #f8fbff; }
    .pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 78px;
      min-height: 24px;
      border-radius: 999px;
      padding: 2px 8px;
      color: #fff;
      font-size: 12px;
      font-weight: 650;
    }
    .BLOCK_RELEASE, .CRITICAL { background: var(--red); }
    .ESCALATE, .HIGH { background: var(--amber); }
    .MONITOR, .MEDIUM { background: var(--blue); }
    .DEFER, .LOW { background: var(--green); }
    .detail {
      padding: 12px;
      display: grid;
      gap: 12px;
    }
    .kv {
      display: grid;
      grid-template-columns: 120px 1fr;
      gap: 6px 10px;
      margin: 0;
    }
    .kv dt { color: var(--muted); }
    .kv dd { margin: 0; overflow-wrap: anywhere; }
    .bars { display: grid; gap: 8px; }
    .bar-row {
      display: grid;
      grid-template-columns: 72px 1fr 48px;
      gap: 8px;
      align-items: center;
      color: var(--muted);
      font-size: 12px;
    }
    .bar {
      height: 8px;
      border-radius: 999px;
      background: #e7ebf2;
      overflow: hidden;
    }
    .bar i {
      display: block;
      height: 100%;
      background: var(--violet);
      border-radius: inherit;
    }
    .empty {
      padding: 28px;
      color: var(--muted);
      text-align: center;
    }
    .status { color: var(--muted); }
    @media (max-width: 1100px) {
      .toolbar { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .workspace { grid-template-columns: 1fr; }
    }
    @media (max-width: 680px) {
      header { padding: 0 14px; }
      main { padding: 14px; }
      .toolbar, .metrics { grid-template-columns: 1fr; }
      th:nth-child(3), td:nth-child(3), th:nth-child(4), td:nth-child(4) { display: none; }
    }
  </style>
</head>
<body>
  <header>
    <h1>SRAP Toolkit</h1>
    <span class="status" id="status">Ready</span>
  </header>
  <main>
    <section class="toolbar">
      <label>SBOM JSON<input id="file" type="file" accept=".json,application/json"></label>
      <label>Domain<select id="domain"></select></label>
      <label>Default SR<select id="defaultSr"><option>SR-0</option><option>SR-1</option><option>SR-2</option><option>SR-3</option></select></label>
      <label>Product<input id="product" value="Uploaded Product"></label>
      <label>Manufacturer<input id="manufacturer" value="Unknown"></label>
      <label>Version<input id="version"></label>
      <button id="run">Run Analysis</button>
    </section>

    <section class="metrics">
      <div class="metric"><span>Components</span><strong id="componentCount">0</strong></div>
      <div class="metric"><span>Vulnerabilities</span><strong id="vulnCount">0</strong></div>
      <div class="metric"><span>Block</span><strong id="blockCount">0</strong></div>
      <div class="metric"><span>Escalate</span><strong id="escalateCount">0</strong></div>
      <div class="metric"><span>Monitor</span><strong id="monitorCount">0</strong></div>
      <div class="metric"><span>Max SRS</span><strong id="maxSrs">0.0</strong></div>
    </section>

    <section class="workspace">
      <div class="panel">
        <div class="panel-head">
          <h2>Vulnerability Triage</h2>
          <div class="downloads">
            <button class="secondary" id="downloadAnnotated" disabled>Annotated SBOM</button>
            <button class="secondary" id="downloadCra" disabled>CRA Evidence</button>
            <button class="secondary" id="downloadTriage" disabled>Triage JSON</button>
          </div>
        </div>
        <div id="tableWrap" class="empty">Upload an SBOM JSON to populate triage results.</div>
      </div>
      <aside class="panel">
        <div class="panel-head"><h2>Selected Finding</h2></div>
        <div id="details" class="empty">Select a result row.</div>
      </aside>
    </section>
  </main>
  <script>
    const state = { result: null, selected: null };
    const $ = (id) => document.getElementById(id);

    async function loadDomains() {
      const res = await fetch('/api/domains');
      const data = await res.json();
      $('domain').innerHTML = data.domains.map((d) =>
        `<option ${d === 'automotive' ? 'selected' : ''}>${d}</option>`
      ).join('');
    }

    function setStatus(text) { $('status').textContent = text; }

    async function runAnalysis() {
      const file = $('file').files[0];
      if (!file) { setStatus('Select an SBOM JSON file'); return; }
      setStatus('Analyzing');
      $('run').disabled = true;
      try {
        const sbom = JSON.parse(await file.text());
        const payload = {
          sbom,
          domain: $('domain').value,
          default_sr: $('defaultSr').value,
          product_name: $('product').value,
          manufacturer: $('manufacturer').value,
          version: $('version').value
        };
        const res = await fetch('/api/analyze', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Analysis failed');
        state.result = data;
        state.selected = data.rows[0] || null;
        render();
        setStatus('Analysis complete');
      } catch (err) {
        setStatus(err.message);
      } finally {
        $('run').disabled = false;
      }
    }

    function render() {
      const result = state.result;
      const summary = result.summary;
      $('componentCount').textContent = summary.component_count;
      $('vulnCount').textContent = summary.vulnerability_count;
      $('blockCount').textContent = summary.triage_counts.BLOCK_RELEASE || 0;
      $('escalateCount').textContent = summary.triage_counts.ESCALATE || 0;
      $('monitorCount').textContent = summary.triage_counts.MONITOR || 0;
      $('maxSrs').textContent = Number(summary.max_srs || 0).toFixed(1);
      for (const id of ['downloadAnnotated', 'downloadCra', 'downloadTriage']) $(id).disabled = false;
      renderTable(result.rows);
      renderDetails(state.selected);
    }

    function renderTable(rows) {
      if (!rows.length) {
        $('tableWrap').className = 'empty';
        $('tableWrap').textContent = 'No vulnerabilities found in the uploaded SBOM.';
        return;
      }
      $('tableWrap').className = '';
      $('tableWrap').innerHTML = `<table>
        <thead><tr>
          <th style="width: 150px">CVE</th>
          <th>Component</th>
          <th style="width: 120px">Domain</th>
          <th style="width: 80px">SR</th>
          <th style="width: 80px">SRS</th>
          <th style="width: 132px">Action</th>
        </tr></thead>
        <tbody>${rows.map((row, index) => `<tr data-index="${index}">
          <td title="${escapeHtml(row.cve)}">${escapeHtml(row.cve)}</td>
          <td title="${escapeHtml(row.component_name)}">${escapeHtml(row.component_name)}</td>
          <td>${escapeHtml(row.domain)}</td>
          <td>${escapeHtml(row.sr_class)}</td>
          <td>${Number(row.srs_score_display).toFixed(2)}</td>
          <td><span class="pill ${row.triage_recommendation}">${row.triage_recommendation}</span></td>
        </tr>`).join('')}</tbody>
      </table>`;
      $('tableWrap').querySelectorAll('tr[data-index]').forEach((tr) => {
        tr.addEventListener('click', () => {
          state.selected = rows[Number(tr.dataset.index)];
          renderDetails(state.selected);
        });
      });
    }

    function renderDetails(row) {
      if (!row) {
        $('details').className = 'empty';
        $('details').textContent = 'Select a result row.';
        return;
      }
      $('details').className = 'detail';
      $('details').innerHTML = `<dl class="kv">
        <dt>CVE</dt><dd>${escapeHtml(row.cve)}</dd>
        <dt>Component</dt><dd>${escapeHtml(row.component_name)}</dd>
        <dt>Version</dt><dd>${escapeHtml(row.component_version || '')}</dd>
        <dt>Class</dt><dd><span class="pill ${row.srs_class}">${row.srs_class}</span></dd>
        <dt>Action</dt><dd><span class="pill ${row.triage_recommendation}">${row.triage_recommendation}</span></dd>
        <dt>CRA</dt><dd>${escapeHtml(row.cra_article || '')}</dd>
      </dl>
      <div class="bars">${Object.entries(row.signal_contributions).map(([name, value]) =>
        `<div class="bar-row"><span>${name}</span><div class="bar"><i style="width:${Math.min(100, value * 400)}%"></i></div><span>${Number(value).toFixed(3)}</span></div>`
      ).join('')}</div>`;
    }

    function downloadJson(name, value) {
      const blob = new Blob([JSON.stringify(value, null, 2)], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    }

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (ch) => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;'
      }[ch]));
    }

    $('run').addEventListener('click', runAnalysis);
    $('downloadAnnotated').addEventListener('click', () => downloadJson('srap-annotated-sbom.json', state.result.annotated_sbom));
    $('downloadCra').addEventListener('click', () => downloadJson('cra-evidence-package.json', state.result.cra_evidence));
    $('downloadTriage').addEventListener('click', () => downloadJson('srap-triage-report.json', state.result.triage_report));
    loadDomains().catch((err) => setStatus(err.message));
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
