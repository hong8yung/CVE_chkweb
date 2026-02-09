from __future__ import annotations

import argparse
from decimal import Decimal
from html import escape

from flask import Flask, request

from nvd_fetch import fetch_cves_from_db
from settings import load_settings

app = Flask(__name__)


def to_score_text(score: Decimal | None) -> str:
    return "N/A" if score is None else str(score)


@app.get("/")
def index() -> str:
    product = (request.args.get("product") or "").strip()
    vendor = (request.args.get("vendor") or "").strip()

    min_cvss_raw = (request.args.get("min_cvss") or "0").strip()
    limit_raw = (request.args.get("limit") or "50").strip()

    try:
        min_cvss = float(min_cvss_raw)
    except ValueError:
        min_cvss = 0.0

    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 500))

    rows: list[tuple[str, Decimal | None, str]] = []
    error_text = ""
    if product or vendor:
        try:
            settings = load_settings(".env")
            rows = fetch_cves_from_db(settings, product, vendor or None, min_cvss, limit)
        except Exception as exc:  # pragma: no cover
            error_text = str(exc)

    rows_html = "".join(
        f"<tr><td class='id'>{escape(cve_id)}</td><td class='score'>{escape(to_score_text(score))}</td><td class='desc'>{escape(description)}</td></tr>"
        for cve_id, score, description in rows
    )
    if not rows_html:
        rows_html = "<tr><td colspan='3'>No results</td></tr>"

    error_html = f"<p class='error'>Error: {escape(error_text)}</p>" if error_text else ""

    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CVE Query</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg: #f7f4ee;
      --panel: #fffdf8;
      --ink: #1e2b31;
      --muted: #5e6c73;
      --line: #d7d5cc;
      --accent: #c2482e;
      --accent-2: #0f6f65;
      --shadow: 0 14px 36px rgba(30, 43, 49, 0.12);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: 'Space Grotesk', 'Segoe UI', sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at 8% 0%, rgba(194, 72, 46, 0.16), transparent 36%),
        radial-gradient(circle at 100% 100%, rgba(15, 111, 101, 0.2), transparent 45%),
        var(--bg);
      min-height: 100vh;
    }}
    .wrap {{
      width: min(1120px, 94vw);
      margin: 34px auto 54px;
      animation: rise 280ms ease-out;
    }}
    .hero {{
      margin-bottom: 14px;
      padding: 20px 22px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: linear-gradient(135deg, #fffdf8, #fef8ed);
      box-shadow: var(--shadow);
    }}
    h1 {{
      margin: 0;
      font-size: clamp(24px, 3vw, 34px);
      letter-spacing: 0.2px;
    }}
    .sub {{
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 14px;
    }}
    .panel {{
      border: 1px solid var(--line);
      border-radius: 18px;
      background: var(--panel);
      box-shadow: var(--shadow);
      overflow: hidden;
    }}
    form {{
      padding: 16px;
      display: grid;
      grid-template-columns: repeat(5, minmax(140px, 1fr));
      gap: 10px;
      align-items: end;
      background: linear-gradient(180deg, #fffdf8, #fff9ef);
      border-bottom: 1px solid var(--line);
    }}
    label {{
      font-size: 12px;
      color: var(--muted);
      display: block;
      margin-bottom: 5px;
      font-weight: 500;
    }}
    input {{
      width: 100%;
      padding: 10px 11px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      color: var(--ink);
      outline: none;
      transition: border-color 140ms ease, box-shadow 140ms ease;
    }}
    input:focus {{
      border-color: var(--accent-2);
      box-shadow: 0 0 0 3px rgba(15, 111, 101, 0.15);
    }}
    button {{
      width: 100%;
      padding: 11px 14px;
      border: 0;
      border-radius: 10px;
      color: #fff;
      background: linear-gradient(135deg, var(--accent-2), #168173);
      font-weight: 700;
      cursor: pointer;
      transition: transform 100ms ease, filter 160ms ease;
    }}
    button:hover {{ filter: brightness(1.04); }}
    button:active {{ transform: translateY(1px); }}
    .meta {{
      margin: 0;
      padding: 12px 16px 4px;
      color: var(--muted);
      font-size: 13px;
    }}
    .error {{
      margin: 8px 16px 0;
      padding: 10px 11px;
      border: 1px solid rgba(194, 72, 46, 0.35);
      background: rgba(194, 72, 46, 0.08);
      border-radius: 10px;
      color: #8f2917;
      font-size: 13px;
    }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    thead th {{
      position: sticky;
      top: 0;
      background: #f2eee4;
      text-align: left;
      font-size: 12px;
      letter-spacing: 0.4px;
      text-transform: uppercase;
      color: var(--muted);
    }}
    th, td {{
      border-top: 1px solid var(--line);
      padding: 10px 12px;
      vertical-align: top;
      font-size: 14px;
    }}
    tbody tr:hover {{ background: #fff8ec; }}
    .id {{ width: 190px; white-space: nowrap; font-weight: 700; color: #123a44; }}
    .score {{ width: 92px; white-space: nowrap; }}
    @keyframes rise {{
      from {{ opacity: 0; transform: translateY(10px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    @media (max-width: 900px) {{
      .wrap {{ width: min(1120px, 96vw); margin-top: 16px; }}
      form {{ grid-template-columns: 1fr 1fr; }}
      .search-btn {{ grid-column: 1 / -1; }}
      table, thead, tbody, th, td, tr {{ display: block; }}
      thead {{ display: none; }}
      td {{
        border-top: 0;
        padding: 6px 12px;
      }}
      tbody tr {{
        padding: 8px 0;
        border-top: 1px solid var(--line);
      }}
      td.id::before {{ content: "CVE ID"; display: block; font-size: 12px; color: var(--muted); }}
      td.score::before {{ content: "CVSS"; display: block; font-size: 12px; color: var(--muted); }}
      td.desc::before {{ content: "Description"; display: block; font-size: 12px; color: var(--muted); }}
    }}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="hero">
      <h1>CVE Explorer</h1>
      <p class="sub">Search by vendor and product using normalized CPE mappings.</p>
    </section>
    <section class="panel">
      <form method="get">
        <div>
          <label for="vendor">Vendor</label>
          <input id="vendor" name="vendor" value="{escape(vendor)}" placeholder="e.g. ivanti">
        </div>
        <div>
          <label for="product">Product</label>
          <input id="product" name="product" value="{escape(product)}" placeholder="e.g. endpoint_manager_mobile">
        </div>
        <div>
          <label for="min_cvss">Min CVSS</label>
          <input id="min_cvss" name="min_cvss" value="{escape(str(min_cvss))}">
        </div>
        <div>
          <label for="limit">Limit (1-500)</label>
          <input id="limit" name="limit" value="{escape(str(limit))}">
        </div>
        <div class="search-btn">
          <button type="submit">Search CVEs</button>
        </div>
      </form>
      <p class="meta">Results: {len(rows)}</p>
      {error_html}
      <table>
        <thead>
          <tr><th>CVE ID</th><th>CVSS</th><th>Description</th></tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </section>
  </main>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="Run local web UI for CVE query")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    parser.add_argument("--port", type=int, default=8888, help="Bind port")
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
