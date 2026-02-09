import argparse
import re
from decimal import Decimal
from typing import Any

import psycopg2

from settings import Settings, load_settings


def fetch_cves_from_db(
    settings: Settings, product: str | None, vendor: str | None, min_cvss: float, limit: int
) -> list[dict[str, Any]]:
    if not product and not vendor:
        raise ValueError("At least one of --product or --vendor is required")

    where_clauses = [
        "f.vulnerable = TRUE",
        "c.cvss_score >= %s",
    ]
    params: list[Any] = [min_cvss]

    if product and vendor:
        where_clauses.append("f.product ILIKE %s")
        where_clauses.append("f.vendor ILIKE %s")
        params.append(f"%{product}%")
        params.append(f"%{vendor}%")
    elif product:
        where_clauses.append("f.product ILIKE %s")
        params.append(f"%{product}%")
    elif vendor:
        where_clauses.append("f.vendor ILIKE %s")
        params.append(f"%{vendor}%")

    where_sql = " AND ".join(where_clauses)

    sql = f"""
    SELECT
      c.id,
      c.cvss_score,
      c.last_modified_at,
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
    JOIN cve_cpe AS f ON f.cve_id = c.id
    LEFT JOIN cve_cpe AS cc ON cc.cve_id = c.id AND cc.vulnerable = TRUE
    WHERE {where_sql}
    GROUP BY c.id, c.cvss_score, c.last_modified_at, c.raw, c.published_at
    ORDER BY c.cvss_score DESC NULLS LAST, c.published_at DESC
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

    parsed_rows: list[dict[str, Any]] = []
    for cve_id, cvss_score, last_modified_at, raw, cpe_entries in rows:
        description = extract_english_description(raw)
        vuln_type = classify_vulnerability_type(description)
        parsed_rows.append(
            {
                "id": cve_id,
                "cvss_score": cvss_score,
                "last_modified_at": last_modified_at,
                "description": description,
                "vuln_type": vuln_type,
                "cpe_entries": cpe_entries or [],
            }
        )
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


def classify_vulnerability_type(description: str) -> str:
    text = description.lower()
    if re.search(r"\brce\b", text):
        return "Remote Code Execution"

    rules = [
        ("remote code execution", "Remote Code Execution"),
        ("authentication bypass", "Authentication Bypass"),
        ("auth bypass", "Authentication Bypass"),
        ("privilege escalation", "Privilege Escalation"),
        ("sql injection", "SQL Injection"),
        ("command injection", "Command Injection"),
        ("code injection", "Code Injection"),
        ("cross-site scripting", "Cross-Site Scripting"),
        ("xss", "Cross-Site Scripting"),
        ("path traversal", "Path Traversal"),
        ("directory traversal", "Path Traversal"),
        ("ssrf", "Server-Side Request Forgery"),
        ("request forgery", "Server-Side Request Forgery"),
        ("deserialization", "Insecure Deserialization"),
        ("denial of service", "Denial of Service"),
        ("dos", "Denial of Service"),
        ("information disclosure", "Information Disclosure"),
        ("out-of-bounds", "Memory Corruption"),
        ("buffer overflow", "Memory Corruption"),
        ("use-after-free", "Memory Corruption"),
    ]
    for keyword, label in rules:
        if keyword in text:
            return label
    return "Other"


def print_cves(cves: list[dict[str, Any]], min_cvss: float) -> None:
    print(f"Filtered CVEs (min CVSS {min_cvss}): {len(cves)}")
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
