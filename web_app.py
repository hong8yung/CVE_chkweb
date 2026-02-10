from __future__ import annotations

import argparse
import math
import re
import time
from io import BytesIO
from datetime import datetime, timedelta
from html import escape
from urllib.parse import urlencode

from flask import Flask, request, send_file
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill

from classification import IMPACT_TYPE_OPTIONS
from nvd_fetch import fetch_cves_from_db, fetch_incremental_checkpoint
from settings import load_settings

app = Flask(__name__)

COUNT_CACHE_TTL_SECONDS = 120
COUNT_CACHE_MAX_ENTRIES = 200
_count_cache: dict[str, tuple[int, float]] = {}


def _build_count_cache_key(
    product: str,
    vendor: str,
    keyword: str,
    selected_impacts: list[str],
    min_cvss: float,
    last_modified_start_raw: str,
    last_modified_end_raw: str,
    cpe_missing_only: bool,
) -> str:
    return "|".join(
        [
            product.lower(),
            vendor.lower(),
            keyword.lower(),
            ",".join(sorted(value.lower() for value in selected_impacts)),
            f"{min_cvss:.1f}",
            last_modified_start_raw,
            last_modified_end_raw,
            "1" if cpe_missing_only else "0",
        ]
    )


def _get_cached_count(key: str) -> int | None:
    cached = _count_cache.get(key)
    if not cached:
        return None
    value, ts = cached
    if time.time() - ts > COUNT_CACHE_TTL_SECONDS:
        _count_cache.pop(key, None)
        return None
    return value


def _set_cached_count(key: str, value: int) -> None:
    if len(_count_cache) >= COUNT_CACHE_MAX_ENTRIES:
        oldest_key = min(_count_cache.items(), key=lambda item: item[1][1])[0]
        _count_cache.pop(oldest_key, None)
    _count_cache[key] = (value, time.time())


def parse_datetime_local(raw_value: str) -> datetime | None:
    value = raw_value.strip()
    if not value:
        return None
    return datetime.fromisoformat(value)


def format_cvss_badge(score: object) -> tuple[str, str]:
    if score is None:
        return ("None 0.0", "cvss-none")

    try:
        value = float(score)
    except (TypeError, ValueError):
        return ("None 0.0", "cvss-none")

    value = max(0.0, min(value, 10.0))
    if value == 0.0:
        return (f"None {value:.1f}", "cvss-none")
    if value <= 3.9:
        return (f"Low {value:.1f}", "cvss-low")
    if value <= 6.9:
        return (f"Medium {value:.1f}", "cvss-medium")
    if value <= 8.9:
        return (f"High {value:.1f}", "cvss-high")
    return (f"Critical {value:.1f}", "cvss-critical")


def shorten(text: str, limit: int = 130) -> str:
    clean = " ".join(text.split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1] + "..."


def format_cpe_for_wrap(value: object) -> str:
    text = str(value)
    tokens = re.split(r"([:/._-])", text)
    chunks: list[str] = []
    for token in tokens:
        if token in {":", "/", ".", "_", "-"}:
            chunks.append(f"{escape(token)}<wbr>")
        else:
            chunks.append(escape(token))
    return "".join(chunks)


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


@app.get("/export.xlsx")
def export_xlsx() -> object:
    sort_key_param = request.args.get("sort_key")
    product = (request.args.get("product") or "").strip()
    vendor = (request.args.get("vendor") or "").strip()
    keyword = (request.args.get("keyword") or "").strip()
    last_modified_start_raw = (request.args.get("last_modified_start") or "").strip()
    last_modified_end_raw = (request.args.get("last_modified_end") or "").strip()
    cpe_missing_only = request.args.get("cpe_missing_only") == "1"
    selected_impacts = [value.strip() for value in request.args.getlist("impact_type") if value.strip()]
    export_scope = (request.args.get("export_scope") or "page").strip().lower()
    if export_scope not in {"page", "all"}:
        export_scope = "page"

    sort_map = {
        "cvss_desc": ("cvss", "desc"),
        "cvss_asc": ("cvss", "asc"),
        "last_modified_desc": ("last_modified", "desc"),
        "last_modified_asc": ("last_modified", "asc"),
    }

    min_cvss_raw = (request.args.get("min_cvss") or "0").strip()
    limit_raw = (request.args.get("limit") or "50").strip()
    page_raw = (request.args.get("page") or "1").strip()

    try:
        min_cvss = float(min_cvss_raw)
    except ValueError:
        min_cvss = 0.0

    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 500))

    try:
        page = int(page_raw)
    except ValueError:
        page = 1
    page = max(1, page)

    sort_key = (sort_key_param or "cvss_desc").strip()
    sort_by, sort_order = sort_map.get(sort_key, ("cvss", "desc"))

    try:
        last_modified_start = parse_datetime_local(last_modified_start_raw)
        last_modified_end = parse_datetime_local(last_modified_end_raw)
    except ValueError:
        return "Invalid Last Modified datetime. Use format YYYY-MM-DDTHH:MM.", 400
    if (
        last_modified_start is not None
        and last_modified_end is not None
        and last_modified_start > last_modified_end
    ):
        return "Last Modified Start must be earlier than or equal to End.", 400

    settings = load_settings(".env")
    count_cache_key = _build_count_cache_key(
        product,
        vendor,
        keyword,
        selected_impacts,
        min_cvss,
        last_modified_start_raw,
        last_modified_end_raw,
        cpe_missing_only,
    )

    rows: list[dict[str, object]] = []
    total_count = _get_cached_count(count_cache_key)
    if export_scope == "page":
        rows, _ = fetch_cves_from_db(
            settings,
            product,
            vendor or None,
            keyword or None,
            selected_impacts or None,
            min_cvss,
            limit,
            offset=(page - 1) * limit,
            sort_by=sort_by,
            sort_order=sort_order,
            last_modified_start=last_modified_start,
            last_modified_end=last_modified_end,
            cpe_missing_only=cpe_missing_only,
            include_total_count=False,
        )
    else:
        batch_size = 1000
        offset = 0
        while True:
            batch_rows, batch_total = fetch_cves_from_db(
                settings,
                product,
                vendor or None,
                keyword or None,
                selected_impacts or None,
                min_cvss,
                batch_size,
                offset=offset,
                sort_by=sort_by,
                sort_order=sort_order,
                last_modified_start=last_modified_start,
                last_modified_end=last_modified_end,
                cpe_missing_only=cpe_missing_only,
                include_total_count=(total_count is None and offset == 0),
            )
            if batch_total is not None:
                total_count = batch_total
                _set_cached_count(count_cache_key, batch_total)
            if not batch_rows:
                break
            rows.extend(batch_rows)
            offset += len(batch_rows)
            if total_count is not None and offset >= total_count:
                break

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "CVE Results"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filter_summary_parts: list[str] = []
    if keyword:
        filter_summary_parts.append(f"keyword={keyword}")
    if vendor:
        filter_summary_parts.append(f"vendor={vendor}")
    if product:
        filter_summary_parts.append(f"product={product}")
    if selected_impacts:
        filter_summary_parts.append(f"impact_type={', '.join(selected_impacts)}")
    if last_modified_start_raw:
        filter_summary_parts.append(f"last_modified_start={last_modified_start_raw}")
    if last_modified_end_raw:
        filter_summary_parts.append(f"last_modified_end={last_modified_end_raw}")
    if cpe_missing_only:
        filter_summary_parts.append("cpe_missing_only=1")
    filter_summary_parts.append(f"min_cvss={min_cvss}")
    filter_summary_parts.append(f"limit={limit}")
    filter_summary_parts.append(f"sort={sort_key}")
    filter_summary_parts.append(f"export_scope={export_scope}")
    filter_summary = "; ".join(filter_summary_parts)

    sheet.append(["Search Time", generated_at])
    sheet.append(["Filter Summary", filter_summary])
    sheet.append([])

    headers = [
        "CVE ID",
        "CVSS Severity",
        "CVSS Score",
        "Impact Type",
        "Last Modified",
        "Description",
        "CPE Entries",
    ]
    sheet.append(headers)
    meta_label_fill = PatternFill(fill_type="solid", start_color="E8F1EF", end_color="E8F1EF")
    header_fill = PatternFill(fill_type="solid", start_color="F2EEE4", end_color="F2EEE4")
    sheet["A1"].font = Font(bold=True, color="0F6F65")
    sheet["A2"].font = Font(bold=True, color="0F6F65")
    sheet["A1"].fill = meta_label_fill
    sheet["A2"].fill = meta_label_fill
    sheet["B1"].alignment = Alignment(horizontal="left")
    sheet["B2"].alignment = Alignment(horizontal="left", wrap_text=True)

    header_row = 4
    for col in range(1, len(headers) + 1):
        cell = sheet.cell(row=header_row, column=col)
        cell.font = Font(bold=True, color="2F3F45")
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center")

    for row in rows:
        severity_label, _ = format_cvss_badge(row.get("cvss_score"))
        severity = severity_label.split(" ", 1)[0]
        score_value = row.get("cvss_score")
        score_text = "0.0" if score_value is None else str(score_value)
        cpe_entries = row.get("cpe_entries") or []
        sheet.append(
            [
                str(row.get("id", "UNKNOWN")),
                severity,
                score_text,
                str(row.get("vuln_type", "Other")),
                format_last_modified(row.get("last_modified_at", "N/A")),
                str(row.get("description", "")),
                "\n".join(str(cpe) for cpe in cpe_entries) if cpe_entries else "",
            ]
        )

    sheet.column_dimensions["A"].width = 20
    sheet.column_dimensions["B"].width = 14
    sheet.column_dimensions["C"].width = 10
    sheet.column_dimensions["D"].width = 28
    sheet.column_dimensions["E"].width = 24
    sheet.column_dimensions["F"].width = 90
    sheet.column_dimensions["G"].width = 70

    for row_idx in range(5, sheet.max_row + 1):
        sheet.cell(row=row_idx, column=6).alignment = Alignment(vertical="top", wrap_text=True)
        sheet.cell(row=row_idx, column=7).alignment = Alignment(vertical="top", wrap_text=True)
        sheet.cell(row=row_idx, column=1).alignment = Alignment(vertical="top")
        sheet.cell(row=row_idx, column=2).alignment = Alignment(horizontal="center", vertical="top")
        sheet.cell(row=row_idx, column=3).alignment = Alignment(horizontal="center", vertical="top")
        sheet.cell(row=row_idx, column=4).alignment = Alignment(vertical="top")
        sheet.cell(row=row_idx, column=5).alignment = Alignment(vertical="top")

    output = BytesIO()
    workbook.save(output)
    output.seek(0)
    scope_text = "all" if export_scope == "all" else f"page{page}"
    filename = f"cve_export_{scope_text}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(
        output,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.get("/")
def index() -> str:
    sort_key_param = request.args.get("sort_key")
    product = (request.args.get("product") or "").strip()
    vendor = (request.args.get("vendor") or "").strip()
    keyword = (request.args.get("keyword") or "").strip()
    user_supplied_last_modified = bool(request.args.get("last_modified_start") or request.args.get("last_modified_end"))
    last_modified_start_raw = (request.args.get("last_modified_start") or "").strip()
    last_modified_end_raw = (request.args.get("last_modified_end") or "").strip()
    if not last_modified_start_raw and not last_modified_end_raw:
        now_local = datetime.now().replace(second=0, microsecond=0)
        last_modified_end_raw = now_local.isoformat(timespec="minutes")
        last_modified_start_raw = (now_local - timedelta(days=7)).isoformat(timespec="minutes")
    cpe_missing_only = request.args.get("cpe_missing_only") == "1"
    selected_impacts = [value.strip() for value in request.args.getlist("impact_type") if value.strip()]
    no_filter_input = (
        not product
        and not vendor
        and not keyword
        and not user_supplied_last_modified
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

    page_raw = (request.args.get("page") or "1").strip()
    try:
        page = int(page_raw)
    except ValueError:
        page = 1
    page = max(1, page)
    offset = (page - 1) * limit

    no_filter_input = no_filter_input and (min_cvss == 0.0) and (limit == 50)

    if sort_key_param:
        sort_key = sort_key_param.strip()
    else:
        sort_key = "last_modified_desc" if no_filter_input else "cvss_desc"
    sort_by, sort_order = sort_map.get(sort_key, ("cvss", "desc"))

    last_modified_start: datetime | None = None
    last_modified_end: datetime | None = None
    rows: list[dict[str, object]] = []
    total_count = 0
    error_text = ""
    checkpoint_text = "기록 없음"
    count_cache_key = _build_count_cache_key(
        product,
        vendor,
        keyword,
        selected_impacts,
        min_cvss,
        last_modified_start_raw,
        last_modified_end_raw,
        cpe_missing_only,
    )
    cached_total = _get_cached_count(count_cache_key)
    should_fetch_total_count = (page == 1) or (cached_total is None)

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
            try:
                checkpoint_value = fetch_incremental_checkpoint(settings)
                checkpoint_text = format_last_modified(checkpoint_value) if checkpoint_value else "기록 없음"
            except Exception:
                checkpoint_text = "조회 실패"
            rows, total_count = fetch_cves_from_db(
                settings,
                product,
                vendor or None,
                keyword or None,
                selected_impacts or None,
                min_cvss,
                limit,
                offset=offset,
                sort_by=sort_by,
                sort_order=sort_order,
                last_modified_start=last_modified_start,
                last_modified_end=last_modified_end,
                cpe_missing_only=cpe_missing_only,
                include_total_count=should_fetch_total_count,
            )
            if total_count is None:
                total_count = cached_total or 0
            else:
                _set_cached_count(count_cache_key, total_count)
        except Exception as exc:  # pragma: no cover
            error_text = str(exc)

    row_chunks: list[str] = []
    for row in rows:
        cve_id = escape(str(row.get("id", "UNKNOWN")))
        score_label, score_class = format_cvss_badge(row.get("cvss_score"))
        score_text = escape(score_label)
        vuln_type = escape(str(row.get("vuln_type", "Other")))
        last_modified = escape(format_last_modified(row.get("last_modified_at", "N/A")))
        description = str(row.get("description", ""))
        summary = escape(shorten(description))
        full_description = escape(description)
        cpe_entries = row.get("cpe_entries") or []
        cpe_badges = "".join(
            f"<span class='cpe-chip'>{format_cpe_for_wrap(cpe_value)}</span>" for cpe_value in cpe_entries[:10]
        )
        if not cpe_badges:
            cpe_badges = "<span class='cpe-chip'>-</span>"
        cpe_for_copy = escape(", ".join(str(cpe_value) for cpe_value in cpe_entries)) if cpe_entries else "-"

        row_chunks.append(
            "<tr>"
            f"<td class='id'>{cve_id}</td>"
            f"<td class='score'><span class='cvss-chip {escape(score_class)}'>{score_text}</span></td>"
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
        "keyword": keyword,
        "min_cvss": str(min_cvss),
        "limit": str(limit),
        "page": str(page),
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
    total_pages = max(1, math.ceil(total_count / limit)) if total_count > 0 else 1
    if page > total_pages:
        page = total_pages
    page_start = max(1, page - 2)
    page_end = min(total_pages, page + 2)
    pager_links: list[str] = []
    for page_no in range(page_start, page_end + 1):
        page_query = dict(base_query)
        page_query["page"] = str(page_no)
        page_href = "?" + urlencode(page_query, doseq=True)
        if page_no == page:
            pager_links.append(f"<span class='page-link current'>{page_no}</span>")
        else:
            pager_links.append(f"<a class='page-link' href='{escape(page_href)}'>{page_no}</a>")
    prev_href = ""
    next_href = ""
    if page > 1:
        prev_query = dict(base_query)
        prev_query["page"] = str(page - 1)
        prev_href = "?" + urlencode(prev_query, doseq=True)
    if page < total_pages:
        next_query = dict(base_query)
        next_query["page"] = str(page + 1)
        next_href = "?" + urlencode(next_query, doseq=True)
    prev_link_html = (
        f"<a class='page-link' href='{escape(prev_href)}'>Prev</a>"
        if prev_href
        else "<span class='page-link disabled'>Prev</span>"
    )
    next_link_html = (
        f"<a class='page-link' href='{escape(next_href)}'>Next</a>"
        if next_href
        else "<span class='page-link disabled'>Next</span>"
    )
    pager_html = (
        "<div class='pager'>"
        f"{prev_link_html}"
        f"{''.join(pager_links)}"
        f"{next_link_html}"
        "</div>"
    )

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
      width: min(1600px, 90vw);
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
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 14px;
      flex-wrap: wrap;
    }}
    .hero-copy {{ min-width: 260px; }}
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
    .checkpoint-badge {{
      margin-left: auto;
      border: 1px solid #c8d8d3;
      border-radius: 11px;
      padding: 8px 10px;
      background: rgba(255, 255, 255, 0.8);
      font-size: 12px;
      color: #27424a;
      line-height: 1.35;
      text-align: right;
    }}
    .checkpoint-badge strong {{
      display: block;
      color: #123a44;
      font-size: 11px;
      letter-spacing: 0.2px;
      text-transform: uppercase;
      margin-bottom: 2px;
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
    .field-keyword {{ grid-column: 1 / 3; }}
    .field-vendor {{ grid-column: 3 / 5; }}
    .field-product {{ grid-column: 5 / 7; }}
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
      grid-column: 1 / 7;
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
    .export-dialog {{
      border: 1px solid #cfdad6;
      border-radius: 14px;
      padding: 0;
      width: min(92vw, 420px);
      box-shadow: 0 18px 42px rgba(18, 58, 68, 0.26);
    }}
    .export-dialog::backdrop {{
      background: rgba(21, 40, 48, 0.42);
      backdrop-filter: blur(2px);
    }}
    .export-dialog-body {{
      padding: 18px;
    }}
    .export-dialog h3 {{
      margin: 0 0 8px;
      font-size: 17px;
      color: #123a44;
    }}
    .export-dialog p {{
      margin: 0;
      color: #4b5f64;
      font-size: 13px;
      line-height: 1.45;
    }}
    .export-dialog-actions {{
      margin-top: 16px;
      display: flex;
      gap: 8px;
      justify-content: flex-end;
      flex-wrap: wrap;
    }}
    .dialog-btn {{
      width: auto;
      min-height: 36px;
      padding: 8px 11px;
      font-size: 12px;
      border-radius: 9px;
    }}
    .dialog-btn.page {{
      background: #eef3f2;
      color: #21464f;
      border: 1px solid #c6d6d1;
    }}
    .dialog-btn.cancel {{
      background: #f8f4f0;
      color: #6e4f3d;
      border: 1px solid #dfc9b8;
    }}
    .meta {{
      margin: 0;
      padding: 12px 16px 4px;
      color: var(--muted);
      font-size: 13px;
      text-align: right;
    }}
    .pager {{
      margin: 8px 16px 0;
      display: flex;
      justify-content: flex-end;
      align-items: center;
      gap: 6px;
      flex-wrap: wrap;
    }}
    .page-link {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 32px;
      padding: 5px 9px;
      border: 1px solid #ccd6d3;
      border-radius: 8px;
      background: #fff;
      color: #1f4048;
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
    }}
    .page-link.current {{
      background: #e5f3ef;
      border-color: #9ec2b8;
      color: #0f6f65;
    }}
    .page-link.disabled {{
      background: #f1f3f2;
      border-color: #d9dfdc;
      color: #9aa4a1;
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
      text-align: center;
      vertical-align: middle;
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
      justify-content: center;
      gap: 5px;
      width: 100%;
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
    .cvss-chip {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 84px;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid transparent;
    }}
    .cvss-critical {{
      color: #9f1f1f;
      background: #fde8e8;
      border-color: #efb6b6;
    }}
    .cvss-high {{
      color: #9a4a00;
      background: #fff1e4;
      border-color: #f0c79c;
    }}
    .cvss-medium {{
      color: #7b6400;
      background: #fff8d8;
      border-color: #ead88a;
    }}
    .cvss-low {{
      color: #4b4f55;
      background: #eef0f3;
      border-color: #d3d8de;
    }}
    .cvss-none {{
      color: #8f98a3;
      background: #1b1f24;
      border-color: #2f3842;
    }}
    td.cpe, td.actions {{
      vertical-align: middle;
      text-align: left;
    }}
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
    .desc {{
      position: relative;
      overflow: visible;
    }}
    .desc details {{ cursor: pointer; position: relative; overflow: visible; }}
    .desc summary {{ color: #334b53; font-weight: 500; }}
    .desc summary:hover {{ color: #0f6f65; }}
    .desc details[open] summary {{
      color: #0c645b;
    }}
    .detail-body {{
      position: absolute;
      top: calc(100% + 8px);
      left: 0;
      z-index: 80;
      margin-top: 0;
      padding: 10px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: #fff;
      line-height: 1.5;
      width: min(920px, 82vw);
      min-width: 520px;
      max-width: 100%;
      max-height: 420px;
      overflow: auto;
      box-shadow: 0 10px 22px rgba(30, 43, 49, 0.12);
    }}
    .cpe-wrap {{
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      align-items: center;
      justify-content: flex-start;
    }}
    .cpe-chip {{
      display: inline-block;
      border: 1px solid #cfddd9;
      background: #f0faf7;
      color: #1a5852;
      padding: 3px 7px;
      border-radius: 999px;
      font-size: 12px;
      white-space: normal;
      overflow-wrap: break-word;
      word-break: normal;
      max-width: 100%;
    }}
    @keyframes rise {{
      from {{ opacity: 0; transform: translateY(10px); }}
      to {{ opacity: 1; transform: translateY(0); }}
    }}
    @media (max-width: 900px) {{
      .wrap {{ width: min(1120px, 96vw); margin-top: 16px; }}
      .checkpoint-badge {{ width: 100%; margin-left: 0; text-align: left; }}
      form {{ grid-template-columns: 1fr 1fr; }}
      .field-lastmod-start,
      .field-lastmod-end,
      .field-vendor,
      .field-product,
      .field-keyword,
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
        position: static;
        width: 100%;
        min-width: 0;
        max-height: none;
        margin-top: 8px;
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
      <div class="hero-copy">
        <h1>CVE Explorer</h1>
        <p class="sub">Search by vendor/product and Last Modified range using normalized CPE mappings.</p>
      </div>
      <div class="checkpoint-badge">
        <strong>최종 증분 수집 시각</strong>
        {escape(checkpoint_text)}
      </div>
    </section>
    <section class="panel">
      <form method="get">
        <div class="field-lastmod-start">
          <label for="last_modified_start">Last Modified Start</label>
          <input id="last_modified_start" name="last_modified_start" type="text" inputmode="numeric" placeholder="YYYY-MM-DDTHH:MM" pattern="\\d{{4}}-\\d{{2}}-\\d{{2}}T\\d{{2}}:\\d{{2}}" title="YYYY-MM-DDTHH:MM (24-hour)" value="{escape(last_modified_start_raw)}">
        </div>
        <div class="field-lastmod-end">
          <label for="last_modified_end">Last Modified End</label>
          <input id="last_modified_end" name="last_modified_end" type="text" inputmode="numeric" placeholder="YYYY-MM-DDTHH:MM" pattern="\\d{{4}}-\\d{{2}}-\\d{{2}}T\\d{{2}}:\\d{{2}}" title="YYYY-MM-DDTHH:MM (24-hour)" value="{escape(last_modified_end_raw)}">
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
        <div class="field-keyword">
          <label for="keyword">Keyword (description/vendor/product)</label>
          <input id="keyword" name="keyword" value="{escape(keyword)}" placeholder="e.g. ssl, ivanti, endpoint">
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
          <button id="export-xlsx-btn" type="button" class="secondary-btn">Export Excel</button>
          <button id="share-url-btn" type="button" class="secondary-btn">Share URL</button>
        </div>
      </form>
      <p class="meta">Results: {total_count} total (showing {len(rows)})</p>
      {pager_html}
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
  <dialog id="export-dialog" class="export-dialog">
    <form method="dialog" class="export-dialog-body">
      <h3>엑셀 내보내기 범위 선택</h3>
      <p>현재 검색 조건 결과를 엑셀로 다운로드합니다. 전체 결과 또는 현재 페이지만 선택하세요.</p>
      <div class="export-dialog-actions">
        <button type="button" class="dialog-btn" data-export-scope="all">전체 결과</button>
        <button type="button" class="dialog-btn page" data-export-scope="page">현재 페이지만</button>
        <button type="button" class="dialog-btn cancel" data-export-scope="cancel">취소</button>
      </div>
    </form>
  </dialog>
</body>
<script>
  (() => {{
    const form = document.querySelector("form");
    const impactDetails = document.querySelector(".impact-details");
    const shareButton = document.querySelector("#share-url-btn");
    const exportButton = document.querySelector("#export-xlsx-btn");
    const exportDialog = document.querySelector("#export-dialog");
    const copyButtons = document.querySelectorAll(".copy-btn");

    const openExportDialog = () => {{
      if (!exportDialog || typeof exportDialog.showModal !== "function") {{
        return Promise.resolve(window.confirm("전체 결과를 내보낼까요?\\n확인: 전체 결과\\n취소: 현재 페이지만") ? "all" : "page");
      }}
      return new Promise((resolve) => {{
        const buttons = exportDialog.querySelectorAll("[data-export-scope]");
        const onSelect = (event) => {{
          const target = event.currentTarget;
          const scope = target?.dataset?.exportScope || "cancel";
          cleanup();
          exportDialog.close();
          resolve(scope);
        }};
        const onClose = () => {{
          cleanup();
          resolve("cancel");
        }};
        const cleanup = () => {{
          buttons.forEach((btn) => btn.removeEventListener("click", onSelect));
          exportDialog.removeEventListener("close", onClose);
        }};
        buttons.forEach((btn) => btn.addEventListener("click", onSelect));
        exportDialog.addEventListener("close", onClose, {{ once: true }});
        exportDialog.showModal();
      }});
    }};

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

    if (exportButton) {{
      exportButton.addEventListener("click", async () => {{
        const exportScope = await openExportDialog();
        if (exportScope === "cancel") {{
          return;
        }}
        const params = new URLSearchParams(window.location.search);
        if (form) {{
          const formData = new FormData(form);
          for (const [key, value] of formData.entries()) {{
            params.set(key, String(value));
          }}
          if (!formData.has("cpe_missing_only")) {{
            params.delete("cpe_missing_only");
          }}
        }}
        params.set("export_scope", exportScope);
        window.location.href = `/export.xlsx?${{params.toString()}}`;
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
