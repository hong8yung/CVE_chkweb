import argparse
import math
from datetime import datetime
from typing import Any

import psycopg2

from settings import Settings, load_settings


def fetch_incremental_checkpoint(settings: Settings) -> datetime | None:
    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT value_ts FROM ingest_checkpoint WHERE key = %s", ("daily_last_modified_sync",))
            row = cur.fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return row[0]


def fetch_cves_from_db(
    settings: Settings,
    product: str | None,
    vendor: str | None,
    keyword: str | None,
    impact_types: list[str] | None,
    min_cvss: float,
    limit: int,
    offset: int = 0,
    sort_by: str = "cvss",
    sort_order: str = "desc",
    last_modified_start: Any | None = None,
    last_modified_end: Any | None = None,
    cpe_missing_only: bool = False,
    include_total_count: bool = True,
) -> tuple[list[dict[str, Any]], int | None]:
    where_clauses = [
        "c.cvss_score >= %s",
    ]
    params: list[Any] = [min_cvss]

    if product and vendor:
        where_clauses.append(
            """
            EXISTS (
                SELECT 1
                FROM cve_cpe AS f
                WHERE f.cve_id = c.id
                  AND f.vulnerable = TRUE
                  AND f.product ILIKE %s
                  AND f.vendor ILIKE %s
            )
            """
        )
        params.append(f"%{product}%")
        params.append(f"%{vendor}%")
    elif product:
        where_clauses.append(
            """
            EXISTS (
                SELECT 1
                FROM cve_cpe AS f
                WHERE f.cve_id = c.id
                  AND f.vulnerable = TRUE
                  AND f.product ILIKE %s
            )
            """
        )
        params.append(f"%{product}%")
    elif vendor:
        where_clauses.append(
            """
            EXISTS (
                SELECT 1
                FROM cve_cpe AS f
                WHERE f.cve_id = c.id
                  AND f.vulnerable = TRUE
                  AND f.vendor ILIKE %s
            )
            """
        )
        params.append(f"%{vendor}%")
    if keyword:
        where_clauses.append(
            """
            (
                EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(COALESCE(c.raw #> '{cve,descriptions}', '[]'::jsonb)) AS d
                    WHERE d ->> 'value' ILIKE %s
                )
                OR EXISTS (
                    SELECT 1
                    FROM cve_cpe AS k
                    WHERE k.cve_id = c.id
                      AND k.vulnerable = TRUE
                      AND (
                        k.vendor ILIKE %s
                        OR k.product ILIKE %s
                      )
                )
            )
            """
        )
        params.append(f"%{keyword}%")
        params.append(f"%{keyword}%")
        params.append(f"%{keyword}%")
    if impact_types:
        where_clauses.append("c.impact_type = ANY(%s)")
        params.append(impact_types)
    if last_modified_start is not None:
        where_clauses.append("c.last_modified_at >= %s")
        params.append(last_modified_start)
    if last_modified_end is not None:
        where_clauses.append("c.last_modified_at <= %s")
        params.append(last_modified_end)
    if cpe_missing_only:
        where_clauses.append(
            """
            NOT EXISTS (
                SELECT 1
                FROM cve_cpe AS f
                WHERE f.cve_id = c.id
                  AND f.vulnerable = TRUE
            )
            """
        )

    where_sql = " AND ".join(where_clauses)
    sort_key = (sort_by or "cvss").lower()
    sort_dir = "ASC" if (sort_order or "desc").lower() == "asc" else "DESC"
    order_by_sql = {
        "cvss": f"c.cvss_score {sort_dir} NULLS LAST, c.published_at DESC",
        "last_modified": f"c.last_modified_at {sort_dir} NULLS LAST, c.cvss_score DESC NULLS LAST",
    }.get(sort_key, f"c.cvss_score {sort_dir} NULLS LAST, c.published_at DESC")

    sql = f"""
    SELECT
      c.id,
      c.cvss_score,
      c.last_modified_at,
      c.impact_type,
      c.raw,
      COALESCE(
        array_agg(DISTINCT
          CASE
            WHEN cc.version IS NULL OR cc.version = '' OR cc.version = '*' THEN cc.vendor || ':' || cc.product
            ELSE cc.vendor || ':' || cc.product || ':' || cc.version
          END
        ) FILTER (WHERE cc.cve_id IS NOT NULL),
        ARRAY[]::text[]
      ) AS cpe_entries
    FROM cve AS c
    LEFT JOIN cve_cpe AS cc ON cc.cve_id = c.id AND cc.vulnerable = TRUE
    WHERE {where_sql}
    GROUP BY c.id, c.cvss_score, c.last_modified_at, c.impact_type, c.raw, c.published_at
    ORDER BY {order_by_sql}
    LIMIT %s
    OFFSET %s
    """
    count_sql = f"""
    SELECT COUNT(*)::int
    FROM cve AS c
    WHERE {where_sql}
    """

    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )
    total_count: int | None = None
    try:
        with conn.cursor() as cur:
            if include_total_count:
                cur.execute(count_sql, params)
                total_count = int(cur.fetchone()[0])

            query_params = list(params)
            query_params.append(limit)
            query_params.append(max(0, offset))
            cur.execute(sql, query_params)
            rows = cur.fetchall()
    finally:
        conn.close()

    parsed_rows: list[dict[str, Any]] = []
    for cve_id, cvss_score, last_modified_at, impact, raw, cpe_entries in rows:
        description = extract_english_description(raw)
        parsed_rows.append(
            {
                "id": cve_id,
                "cvss_score": cvss_score,
                "last_modified_at": last_modified_at,
                "description": description,
                "vuln_type": impact or "Other",
                "cpe_entries": cpe_entries or [],
            }
        )
    return parsed_rows, total_count


def extract_english_description(raw_item: Any) -> str:
    if not isinstance(raw_item, dict):
        return ""
    cve = raw_item.get("cve", {})
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for desc in descriptions:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            return str(desc.get("value", ""))
    return ""


def print_cves(cves: list[dict[str, Any]], min_cvss: float, total_count: int) -> None:
    print(f"Filtered CVEs (min CVSS {min_cvss}): total {total_count}, showing {len(cves)}")
    for item in cves:
        cve_id = str(item.get("id", "UNKNOWN"))
        score = item.get("cvss_score")
        description = str(item.get("description", ""))
        vuln_type = str(item.get("vuln_type", "Other"))
        last_modified = item.get("last_modified_at")
        last_modified_text = "N/A" if last_modified is None else str(last_modified)
        cpe_entries = item.get("cpe_entries") or []
        cpe_preview = ", ".join(cpe_entries[:3]) if cpe_entries else "-"
        score_text = "N/A" if score is None else str(score)
        print(
            f"{cve_id} | CVSS {score_text} | {vuln_type} | LastMod {last_modified_text} | CPE {cpe_preview} | "
            f"{description[:120]}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch CVEs from local PostgreSQL")
    parser.add_argument("--product", default=None, help="Product keyword, e.g., nginx")
    parser.add_argument("--vendor", default=None, help="Vendor keyword, e.g., nginx")
    parser.add_argument("--keyword", default=None, help="Search keyword across description/vendor/product")
    parser.add_argument("--impact-type", default=None, help="Impact type filter, e.g., Remote Code Execution")
    parser.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS score")
    parser.add_argument("--limit", type=int, default=50, help="Maximum number of rows to print")
    parser.add_argument("--page", type=int, default=1, help="Page number (1-based)")
    parser.add_argument("--sort-by", default="cvss", choices=["cvss", "last_modified"], help="Sort field")
    parser.add_argument("--sort-order", default="desc", choices=["asc", "desc"], help="Sort order")
    parser.add_argument(
        "--last-modified-start",
        default=None,
        help="Lower bound of last_modified_at (ISO datetime, e.g. 2025-01-01T00:00:00)",
    )
    parser.add_argument(
        "--last-modified-end",
        default=None,
        help="Upper bound of last_modified_at (ISO datetime, e.g. 2025-12-31T23:59:59)",
    )
    parser.add_argument(
        "--cpe-missing-only",
        action="store_true",
        help="Return only CVEs without vulnerable CPE mappings",
    )
    parser.add_argument("--config", default=".env", help="Path to settings file")
    args = parser.parse_args()
    product = (args.product or "").strip() or None
    vendor = (args.vendor or "").strip() or None
    keyword = (args.keyword or "").strip() or None
    impact_type = (args.impact_type or "").strip() or None
    impact_types = [impact_type] if impact_type else None

    settings = load_settings(args.config)
    page = max(1, args.page)
    offset = (page - 1) * max(1, args.limit)
    cves, total_count = fetch_cves_from_db(
        settings,
        product,
        vendor,
        keyword,
        impact_types,
        args.min_cvss,
        args.limit,
        offset=offset,
        sort_by=args.sort_by,
        sort_order=args.sort_order,
        last_modified_start=args.last_modified_start,
        last_modified_end=args.last_modified_end,
        cpe_missing_only=args.cpe_missing_only,
        include_total_count=True,
    )

    print_cves(cves, args.min_cvss, total_count or 0)
    if total_count is not None:
        total_pages = max(1, math.ceil(total_count / max(1, args.limit)))
        print(f"Page: {page}/{total_pages}")


if __name__ == "__main__":
    main()
