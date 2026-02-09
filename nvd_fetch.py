import argparse
from decimal import Decimal
from typing import Any

import psycopg2

from settings import Settings, load_settings


def fetch_cves_from_db(settings: Settings, product: str, min_cvss: float, limit: int) -> list[tuple[str, Decimal | None, str]]:
    sql = """
    SELECT id, cvss_score, raw
    FROM cve
    WHERE cvss_score >= %s
      AND (
        id ILIKE %s
        OR raw::text ILIKE %s
      )
    ORDER BY cvss_score DESC NULLS LAST, published_at DESC
    LIMIT %s
    """
    like_keyword = f"%{product}%"

    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (min_cvss, like_keyword, like_keyword, limit))
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
    parser.add_argument("--product", required=True, help="Product keyword, e.g., nginx")
    parser.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS score")
    parser.add_argument("--limit", type=int, default=50, help="Maximum number of rows to print")
    parser.add_argument("--config", default=".env", help="Path to settings file")
    args = parser.parse_args()

    settings = load_settings(args.config)
    cves = fetch_cves_from_db(settings, args.product, args.min_cvss, args.limit)

    print_cves(cves, args.min_cvss)


if __name__ == "__main__":
    main()
