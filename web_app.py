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
    if product:
        try:
            settings = load_settings(".env")
            rows = fetch_cves_from_db(settings, product, vendor or None, min_cvss, limit)
        except Exception as exc:  # pragma: no cover
            error_text = str(exc)

    rows_html = "".join(
        f"<tr><td>{escape(cve_id)}</td><td>{escape(to_score_text(score))}</td><td>{escape(description)}</td></tr>"
        for cve_id, score, description in rows
    )
    if not rows_html:
        rows_html = "<tr><td colspan='3'>No results</td></tr>"

    error_html = f"<p style='color:#b00020;'>Error: {escape(error_text)}</p>" if error_text else ""

    return f"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CVE Query</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 24px; }}
    form {{ display: grid; grid-template-columns: repeat(5, minmax(120px, 220px)); gap: 8px; align-items: end; }}
    label {{ font-size: 12px; color: #444; display: block; margin-bottom: 4px; }}
    input {{ width: 100%; padding: 8px; box-sizing: border-box; }}
    button {{ padding: 10px 14px; cursor: pointer; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f5f5f5; }}
    .muted {{ color: #666; font-size: 13px; margin-top: 10px; }}
  </style>
</head>
<body>
  <h1>CVE Query</h1>
  <form method="get">
    <div>
      <label for="vendor">Vendor</label>
      <input id="vendor" name="vendor" value="{escape(vendor)}" placeholder="e.g. nginx">
    </div>
    <div>
      <label for="product">Product (required)</label>
      <input id="product" name="product" value="{escape(product)}" placeholder="e.g. nginx" required>
    </div>
    <div>
      <label for="min_cvss">Min CVSS</label>
      <input id="min_cvss" name="min_cvss" value="{escape(str(min_cvss))}">
    </div>
    <div>
      <label for="limit">Limit (1-500)</label>
      <input id="limit" name="limit" value="{escape(str(limit))}">
    </div>
    <div>
      <button type="submit">Search</button>
    </div>
  </form>
  <p class="muted">Results: {len(rows)}</p>
  {error_html}
  <table>
    <thead>
      <tr><th>CVE ID</th><th>CVSS</th><th>Description</th></tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
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
