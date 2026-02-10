from __future__ import annotations

import argparse
from datetime import datetime
from html import escape
from urllib.parse import urlencode

from flask import Flask, request

from classification import IMPACT_TYPE_OPTIONS
from nvd_fetch import fetch_cves_from_db
from settings import load_settings

app = Flask(__name__)


def to_score_text(score: object) -> str:
    return "N/A" if score is None else str(score)


def shorten(text: str, limit: int = 130) -> str:
    clean = " ".join(text.split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1] + "..."


def format_last_modified(value: object) -> str:
    if isinstance(value, datetime):
        base = value.strftime("%Y-%m-%d %H:%M:%S")
        offset = value.utcoffset()
        if offset is None:
            return f"{base} UTC"
        total_minutes = int(offset.total_seconds() // 60)
        sign = "+" if total_minutes >= 0 else "-"
        abs_minutes = abs(total_minutes)
        hours = abs_minutes // 60
        minutes = abs_minutes % 60
        if hours == 0 and minutes == 0:
            tz_text = "UTC+00"
        else:
            tz_text = f"UTC{sign}{hours:02d}:{minutes:02d}"
        return f"{base} {tz_text}"
    return str(value)


@app.get("/")
def index() -> str:
    sort_key_param = request.args.get("sort_key")
    product = (request.args.get("product") or "").strip()
    vendor = (request.args.get("vendor") or "").strip()
    last_modified_start_raw = (request.args.get("last_modified_start") or "").strip()
    last_modified_end_raw = (request.args.get("last_modified_end") or "").strip()
    cpe_missing_only = request.args.get("cpe_missing_only") == "1"
    selected_impacts = [value.strip() for value in request.args.getlist("impact_type") if value.strip()]
    no_filter_input = (
        not product
        and not vendor
        and not last_modified_start_raw
        and not last_modified_end_raw
        and not cpe_missing_only
        and not selected_impacts
    )
    sort_map = {
        "cvss_desc": ("cvss", "desc"),
        "cvss_asc": ("cvss", "asc"),
        "last_modified_desc": ("last_modified", "desc"),
        "last_modified_asc": ("last_modified", "asc"),
    }

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
    no_filter_input = no_filter_input and (min_cvss == 0.0) and (limit == 50)

    if sort_key_param:
        sort_key = sort_key_param.strip()
    else:
        sort_key = "last_modified_desc" if no_filter_input else "cvss_desc"
    sort_by, sort_order = sort_map.get(sort_key, ("cvss", "desc"))

    last_modified_start: datetime | None = None
    last_modified_end: datetime | None = None
    rows: list[dict[str, object]] = []
    error_text = ""

    try:
        if last_modified_start_raw:
            last_modified_start = datetime.fromisoformat(last_modified_start_raw)
        if last_modified_end_raw:
            last_modified_end = datetime.fromisoformat(last_modified_end_raw)
    except ValueError:
        error_text = "Invalid Last Modified datetime. Use format YYYY-MM-DDTHH:MM."

    if (
        not error_text
        and last_modified_start is not None
        and last_modified_end is not None
        and last_modified_start > last_modified_end
    ):
        error_text = "Last Modified Start must be earlier than or equal to End."

    if not error_text:
        try:
            settings = load_settings(".env")
            rows = fetch_cves_from_db(
                settings,
                product,
                vendor or None,
                selected_impacts or None,
                min_cvss,
                limit,
                sort_by=sort_by,
                sort_order=sort_order,
                last_modified_start=last_modified_start,
                last_modified_end=last_modified_end,
                cpe_missing_only=cpe_missing_only,
            )
        except Exception as exc:  # pragma: no cover
            error_text = str(exc)

    row_chunks: list[str] = []
    for row in rows:
        cve_id = escape(str(row.get("id", "UNKNOWN")))
        score_text = escape(to_score_text(row.get("cvss_score")))
        vuln_type = escape(str(row.get("vuln_type", "Other")))
        last_modified = escape(format_last_modified(row.get("last_modified_at", "N/A")))
        description = str(row.get("description", ""))
        summary = escape(shorten(description))
        full_description = escape(description)
        cpe_entries = row.get("cpe_entries") or []
        cpe_badges = "".join(
            f"<span class='cpe-chip'>{escape(str(cpe_value))}</span>" for cpe_value in cpe_entries[:10]
        )
        if not cpe_badges:
            cpe_badges = "<span class='cpe-chip'>-</span>"
        cpe_for_copy = escape(", ".join(str(cpe_value) for cpe_value in cpe_entries)) if cpe_entries else "-"

        row_chunks.append(
            "<tr>"
            f"<td class='id'>{cve_id}</td>"
            f"<td class='score'>{score_text}</td>"
            f"<td class='lastmod'>{last_modified}</td>"
            f"<td class='vtype'>{vuln_type}</td>"
            "<td class='desc'>"
            f"<details><summary>{summary}</summary><div class='detail-body'>{full_description}</div></details>"
            "</td>"
            f"<td class='cpe'><div class='cpe-wrap'>{cpe_badges}</div></td>"
            "<td class='actions'>"
            f"<button type='button' class='copy-btn' data-copy='{cve_id}'>Copy CVE</button>"
            f"<button type='button' class='copy-btn alt' data-copy='{cpe_for_copy}'>Copy CPE</button>"
            "</td>"
            "</tr>"
        )
    rows_html = "".join(row_chunks)
    if not rows_html:
        rows_html = "<tr><td colspan='7'>No results</td></tr>"

    base_query: dict[str, object] = {
        "vendor": vendor,
        "product": product,
        "min_cvss": str(min_cvss),
        "limit": str(limit),
    }
    if last_modified_start_raw:
        base_query["last_modified_start"] = last_modified_start_raw
    if last_modified_end_raw:
        base_query["last_modified_end"] = last_modified_end_raw
    if selected_impacts:
        base_query["impact_type"] = selected_impacts
    if cpe_missing_only:
        base_query["cpe_missing_only"] = "1"

    def build_sort_href(target: str) -> str:
        if target == "cvss":
            next_key = "cvss_asc" if sort_key == "cvss_desc" else "cvss_desc"
        else:
            next_key = "last_modified_asc" if sort_key == "last_modified_desc" else "last_modified_desc"
        query = dict(base_query)
        query["sort_key"] = next_key
        return "?" + urlencode(query, doseq=True)

    cvss_sort_href = build_sort_href("cvss")
    last_modified_sort_href = build_sort_href("last_modified")
    cvss_sort_marker = "▼" if sort_key == "cvss_desc" else ("▲" if sort_key == "cvss_asc" else "")
    last_modified_sort_marker = (
        "▼" if sort_key == "last_modified_desc" else ("▲" if sort_key == "last_modified_asc" else "")
    )

    impact_options_html = "".join(
        "<label class='impact-option'>"
        f"<input type='checkbox' name='impact_type' value='{escape(option)}' {'checked' if option in selected_impacts else ''}>"
        f"<span>{escape(option)}</span>"
        "</label>"
        for option in IMPACT_TYPE_OPTIONS
    )
    impact_summary = "All impact types" if not selected_impacts else f"Impact Type ({len(selected_impacts)} selected)"
    impact_selected_html = (
        "".join(f"<span class='impact-chip'>{escape(value)}</span>" for value in selected_impacts)
        if selected_impacts
        else "<span class='impact-chip muted-chip'>No filter</span>"
    )
    cpe_missing_checked = "checked" if cpe_missing_only else ""

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
      overflow: visible;
    }}
    form {{
      padding: 16px;
      display: grid;
      grid-template-columns:
        minmax(150px, 1.25fr)
        minmax(180px, 1.5fr)
        minmax(90px, 0.65fr)
        minmax(220px, 1.9fr)
        minmax(90px, 0.65fr)
        minmax(120px, 0.85fr);
      gap: 10px;
      align-items: start;
      background: linear-gradient(180deg, #fffdf8, #fff9ef);
      border-bottom: 1px solid var(--line);
    }}
    .field-lastmod-start {{ grid-column: 1 / 2; }}
    .field-lastmod-end {{ grid-column: 2 / 3; }}
    .field-vendor {{ grid-column: 1 / 3; }}
    .field-product {{ grid-column: 3 / 5; }}
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
    select {{
      width: 100%;
      padding: 10px 11px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      color: var(--ink);
      outline: none;
    }}
    input:focus {{
      border-color: var(--accent-2);
      box-shadow: 0 0 0 3px rgba(15, 111, 101, 0.15);
    }}
    select:focus {{
      border-color: var(--accent-2);
      box-shadow: 0 0 0 3px rgba(15, 111, 101, 0.15);
    }}
    .impact-details {{
      position: relative;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      overflow: visible;
    }}
    .impact-details > summary {{
      list-style: none;
      cursor: pointer;
      padding: 10px 11px;
      font-size: 14px;
      user-select: none;
    }}
    .impact-details > summary::-webkit-details-marker {{ display: none; }}
    .impact-details[open] > summary {{
      border-bottom: 1px solid var(--line);
      background: #f9fbfa;
    }}
    .impact-list {{
      position: absolute;
      top: calc(100% + 6px);
      left: 0;
      width: 320px;
      max-width: min(86vw, 360px);
      z-index: 60;
      max-height: 240px;
      overflow: auto;
      padding: 8px;
      display: grid;
      gap: 4px;
      border: 1px solid var(--line);
      border-radius: 10px;
      background: #fff;
      box-shadow: 0 12px 28px rgba(25, 39, 45, 0.18);
    }}
    .impact-option {{
      display: grid;
      grid-template-columns: 16px minmax(0, 1fr);
      align-items: center;
      gap: 9px;
      font-size: 13px;
      min-height: 34px;
      padding: 6px 8px;
      border-radius: 6px;
      line-height: 1.2;
    }}
    .impact-option input[type="checkbox"] {{
      width: 14px;
      height: 14px;
      margin: 0;
      accent-color: #0f6f65;
    }}
    .impact-option span {{
      display: inline-block;
      min-width: 0;
      font-weight: 500;
      color: #2f3f45;
    }}
    .impact-option:hover {{ background: #f6faf9; }}
    .impact-selected {{
      margin-top: 6px;
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }}
    .impact-chip {{
      border: 1px solid #cfddd9;
      background: #f0faf7;
      color: #1a5852;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      white-space: nowrap;
    }}
    .muted-chip {{
      border-color: #d6d9d7;
      background: #f6f7f6;
      color: #6b7471;
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
    .search-btn {{ align-self: end; }}
    .field-cvss, .field-limit {{ max-width: 110px; }}
    .field-cpe-missing {{
      display: flex;
      align-items: end;
      padding-bottom: 8px;
    }}
    .field-cpe-missing label {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin: 0;
      font-size: 13px;
      color: #2f3f45;
      cursor: pointer;
    }}
    .field-cpe-missing input[type="checkbox"] {{
      width: 15px;
      height: 15px;
      margin: 0;
      accent-color: #0f6f65;
    }}
    .actions-bar {{
      display: flex;
      gap: 8px;
      align-items: end;
      align-self: end;
      grid-column: 5 / 7;
    }}
    .secondary-btn {{
      width: auto;
      background: #f1f4f3;
      color: #1f4048;
      border: 1px solid #ccd6d3;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 10px 12px;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 600;
      min-height: 42px;
      cursor: pointer;
      white-space: nowrap;
    }}
    .secondary-btn:hover {{ background: #e8edeb; }}
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
    thead th a {{
      color: inherit;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 5px;
    }}
    thead th a:hover {{ color: #1e5a53; }}
    .sort-mark {{ font-size: 11px; opacity: 0.9; }}
    th, td {{
      border-top: 1px solid var(--line);
      padding: 10px 12px;
      vertical-align: top;
      font-size: 14px;
    }}
    tbody tr:hover {{ background: #fff8ec; }}
    .id {{ width: 190px; white-space: nowrap; font-weight: 700; color: #123a44; }}
    .score {{ width: 92px; white-space: nowrap; }}
    .actions {{ width: 120px; white-space: nowrap; }}
    .copy-btn {{
      width: auto;
      font-size: 11px;
      padding: 5px 8px;
      border-radius: 999px;
      border: 1px solid #bfd1cb;
      background: #ecf7f4;
      color: #164f49;
      margin-right: 6px;
      margin-top: 3px;
      cursor: pointer;
    }}
    .copy-btn.alt {{
      background: #eef3f7;
      border-color: #c5d0d9;
      color: #2d4658;
    }}
    .copy-btn:hover {{ filter: brightness(0.98); }}
    .desc details {{ cursor: pointer; position: relative; }}
    .desc summary {{ color: #334b53; font-weight: 500; }}
    .desc summary:hover {{ color: #0f6f65; }}
    .detail-body {{
      margin-top: 8px;
      padding: 10px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: #fff;
      line-height: 1.5;
      width: min(920px, 82vw);
      min-width: 520px;
      max-width: 100%;
      box-shadow: 0 10px 22px rgba(30, 43, 49, 0.12);
    }}
    .cpe-wrap {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .cpe-chip {{
      display: inline-block;
      border: 1px solid #cfddd9;
      background: #f0faf7;
      color: #1a5852;
      padding: 3px 7px;
      border-radius: 999px;
      font-size: 12px;
      white-space: nowrap;
    }}
    @keyframes rise {{
      from {{ opacity: 0; transform: translateY(10px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    @media (max-width: 900px) {{
      .wrap {{ width: min(1120px, 96vw); margin-top: 16px; }}
      form {{ grid-template-columns: 1fr 1fr; }}
      .field-lastmod-start,
      .field-lastmod-end,
      .field-vendor,
      .field-product,
      .field-cvss,
      .field-impact,
      .field-cpe-missing,
      .field-limit {{
        grid-column: auto;
      }}
      .search-btn {{ grid-column: 1 / -1; }}
      .actions-bar {{ grid-column: 1 / -1; justify-content: flex-start; }}
      .impact-list {{ width: min(92vw, 360px); }}
      .detail-body {{
        width: 100%;
        min-width: 0;
      }}
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
      td.lastmod::before {{ content: "Last Modified"; display: block; font-size: 12px; color: var(--muted); }}
      td.vtype::before {{ content: "Type"; display: block; font-size: 12px; color: var(--muted); }}
      td.desc::before {{ content: "Description"; display: block; font-size: 12px; color: var(--muted); }}
      td.cpe::before {{ content: "CPE"; display: block; font-size: 12px; color: var(--muted); }}
      td.actions::before {{ content: "Actions"; display: block; font-size: 12px; color: var(--muted); }}
    }}
  </style>
</head>
<body>
  <main class="wrap">
    <section class="hero">
      <h1>CVE Explorer</h1>
      <p class="sub">Search by vendor/product and Last Modified range using normalized CPE mappings.</p>
    </section>
    <section class="panel">
      <form method="get">
        <div class="field-lastmod-start">
          <label for="last_modified_start">Last Modified Start</label>
          <input id="last_modified_start" name="last_modified_start" type="datetime-local" value="{escape(last_modified_start_raw)}">
        </div>
        <div class="field-lastmod-end">
          <label for="last_modified_end">Last Modified End</label>
          <input id="last_modified_end" name="last_modified_end" type="datetime-local" value="{escape(last_modified_end_raw)}">
        </div>
        <div class="field-cvss">
          <label for="min_cvss">Min CVSS</label>
          <input id="min_cvss" name="min_cvss" type="number" min="0" max="10" step="0.1" value="{escape(str(min_cvss))}">
        </div>
        <div class="field-impact">
          <label for="impact_type">Impact Type</label>
          <details class="impact-details">
            <summary>{escape(impact_summary)}</summary>
            <div class="impact-list">
              {impact_options_html}
            </div>
          </details>
          <div class="impact-selected">{impact_selected_html}</div>
        </div>
        <div class="field-limit">
          <label for="limit">Limit (1-500)</label>
          <input id="limit" name="limit" type="number" min="1" max="500" step="1" value="{escape(str(limit))}">
        </div>
        <div class="field-cpe-missing">
          <label for="cpe_missing_only">
            <input id="cpe_missing_only" name="cpe_missing_only" type="checkbox" value="1" {cpe_missing_checked}>
            CPE missing only
          </label>
        </div>
        <div class="search-btn">
          <button type="submit">Search CVEs</button>
        </div>
        <div class="field-vendor">
          <label for="vendor">Vendor</label>
          <input id="vendor" name="vendor" value="{escape(vendor)}" placeholder="e.g. ivanti">
        </div>
        <div class="field-product">
          <label for="product">Product</label>
          <input id="product" name="product" value="{escape(product)}" placeholder="e.g. endpoint_manager_mobile">
        </div>
        <input type="hidden" name="sort_key" value="{escape(sort_key)}">
        <div class="actions-bar">
          <a class="secondary-btn" href="/">Reset Filters</a>
          <button id="share-url-btn" type="button" class="secondary-btn">Share URL</button>
        </div>
      </form>
      <p class="meta">Results: {len(rows)}</p>
      {error_html}
      <table>
        <thead>
          <tr>
            <th>CVE ID</th>
            <th><a href="{escape(cvss_sort_href)}">CVSS <span class="sort-mark">{escape(cvss_sort_marker)}</span></a></th>
            <th><a href="{escape(last_modified_sort_href)}">Last Modified <span class="sort-mark">{escape(last_modified_sort_marker)}</span></a></th>
            <th>Type</th>
            <th>Description</th>
            <th>CPE</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </section>
  </main>
</body>
<script>
  (() => {{
    const form = document.querySelector("form");
    const impactDetails = document.querySelector(".impact-details");
    const shareButton = document.querySelector("#share-url-btn");
    const copyButtons = document.querySelectorAll(".copy-btn");

    if (impactDetails) {{
      document.addEventListener("click", (event) => {{
        if (!impactDetails.open) return;
        if (impactDetails.contains(event.target)) return;
        impactDetails.open = false;
      }});

      document.addEventListener("keydown", (event) => {{
        if (event.key === "Escape" && impactDetails.open) {{
          impactDetails.open = false;
        }}
      }});
    }}

    if (shareButton) {{
      shareButton.addEventListener("click", async () => {{
        const url = window.location.href;
        try {{
          await navigator.clipboard.writeText(url);
          shareButton.textContent = "Copied URL";
          setTimeout(() => {{ shareButton.textContent = "Share URL"; }}, 1200);
        }} catch (_) {{
          window.prompt("Copy URL:", url);
        }}
      }});
    }}

    copyButtons.forEach((btn) => {{
      btn.addEventListener("click", async () => {{
        const text = btn.dataset.copy || "";
        try {{
          await navigator.clipboard.writeText(text);
          const before = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(() => {{ btn.textContent = before; }}, 900);
        }} catch (_) {{
          window.prompt("Copy value:", text);
        }}
      }});
    }});
  }})();
</script>
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
