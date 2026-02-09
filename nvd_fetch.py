import argparse
from decimal import Decimal
from typing import Any

import psycopg2

from settings import Settings, load_settings


def fetch_cves_from_db(
    settings: Settings, product: str | None, vendor: str | None, min_cvss: float, limit: int
) -> list[tuple[str, Decimal | None, str]]:
    if not product and not vendor:
        raise ValueError("At least one of --product or --vendor is required")

    where_clauses = [
        "cc.vulnerable = TRUE",
        "c.cvss_score >= %s",
    ]
    params: list[Any] = [min_cvss]

    if product and vendor:
        where_clauses.append("cc.product ILIKE %s")
        where_clauses.append("cc.vendor ILIKE %s")
        params.append(f"%{product}%")
        params.append(f"%{vendor}%")
    elif product:
        where_clauses.append("cc.product ILIKE %s")
        params.append(f"%{product}%")
    elif vendor:
        where_clauses.append("cc.vendor ILIKE %s")
        params.append(f"%{vendor}%")

    where_sql = " AND ".join(where_clauses)

    sql = f"""
    SELECT q.id, q.cvss_score, q.raw
    FROM (
        SELECT c.id, c.cvss_score, c.raw, c.published_at
        FROM cve AS c
        JOIN cve_cpe AS cc ON cc.cve_id = c.id
        WHERE {where_sql}
        GROUP BY c.id, c.cvss_score, c.raw, c.published_at
    ) AS q
    ORDER BY q.cvss_score DESC NULLS LAST, q.published_at DESC
    LIMIT %s
    """
    params.append(limit)

    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    finally:
        conn.close()

    parsed_rows: list[tuple[str, Decimal | None, str]] = []
    for cve_id, cvss_score, raw in rows:
        description = extract_english_description(raw)
        parsed_rows.append((cve_id, cvss_score, description))
    return parsed_rows


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


def print_cves(cves: list[tuple[str, Decimal | None, str]], min_cvss: float) -> None:
    print(f"Filtered CVEs (min CVSS {min_cvss}): {len(cves)}")
    for cve_id, score, description in cves:
        score_text = "N/A" if score is None else str(score)
        print(f"{cve_id} | CVSS {score_text} | {description[:120]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch CVEs from local PostgreSQL")
    parser.add_argument("--product", default=None, help="Product keyword, e.g., nginx")
    parser.add_argument("--vendor", default=None, help="Vendor keyword, e.g., nginx")
    parser.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS score")
    parser.add_argument("--limit", type=int, default=50, help="Maximum number of rows to print")
    parser.add_argument("--config", default=".env", help="Path to settings file")
    args = parser.parse_args()
    product = (args.product or "").strip() or None
    vendor = (args.vendor or "").strip() or None
    if not product and not vendor:
        parser.error("At least one of --product or --vendor must be provided")

    settings = load_settings(args.config)
    cves = fetch_cves_from_db(settings, product, vendor, args.min_cvss, args.limit)

    print_cves(cves, args.min_cvss)


if __name__ == "__main__":
    main()
