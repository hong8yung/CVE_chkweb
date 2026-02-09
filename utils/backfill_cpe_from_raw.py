from __future__ import annotations

import argparse
from typing import Any

import psycopg2
from psycopg2.extras import execute_values

from settings import load_settings


def split_cpe23(criteria: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False

    for ch in criteria:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == ":":
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)

    parts.append("".join(current))
    return parts


def parse_cpe23(criteria: str) -> tuple[str, str, str, str] | None:
    if not criteria.startswith("cpe:2.3:"):
        return None

    parts = split_cpe23(criteria)
    if len(parts) < 6:
        return None
    part = parts[2].strip()
    vendor = parts[3].strip().lower()
    product = parts[4].strip().lower()
    version = parts[5].strip()
    if not part or not vendor or not product:
        return None
    return part, vendor, product, version


def extract_cpe_matches(cve: dict[str, Any]) -> list[tuple[str, str, str, str, str, bool]]:
    # Key by criteria to avoid duplicate PK collisions in one INSERT VALUES batch.
    parsed_by_criteria: dict[str, tuple[str, str, str, str, str, bool]] = {}
    configurations = cve.get("configurations") or []
    if not isinstance(configurations, list):
        return []

    def walk_node(node: dict[str, Any]) -> None:
        cpe_matches = node.get("cpeMatch") or []
        if isinstance(cpe_matches, list):
            for match in cpe_matches:
                if not isinstance(match, dict):
                    continue
                criteria = str(match.get("criteria", "")).strip()
                cpe = parse_cpe23(criteria)
                if cpe is None:
                    continue
                vulnerable = bool(match.get("vulnerable", False))
                existing = parsed_by_criteria.get(criteria)
                if existing is None:
                    parsed_by_criteria[criteria] = (*cpe, criteria, vulnerable)
                else:
                    part, vendor, product, version, criteria_text, existing_vulnerable = existing
                    parsed_by_criteria[criteria] = (
                        part,
                        vendor,
                        product,
                        version,
                        criteria_text,
                        existing_vulnerable or vulnerable,
                    )

        children = node.get("children") or []
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    walk_node(child)

    for config in configurations:
        if not isinstance(config, dict):
            continue
        nodes = config.get("nodes") or []
        if not isinstance(nodes, list):
            continue
        for node in nodes:
            if isinstance(node, dict):
                walk_node(node)

    return list(parsed_by_criteria.values())


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill cve_cpe table from existing cve.raw JSON")
    parser.add_argument("--config", default=".env", help="Path to settings file")
    parser.add_argument("--batch-size", type=int, default=1000, help="Rows fetched per batch")
    args = parser.parse_args()

    settings = load_settings(args.config)
    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )

    processed = 0
    written = 0
    try:
        last_id = ""
        while True:
            with conn.cursor() as read_cur:
                read_cur.execute(
                    "SELECT id, raw FROM cve WHERE id > %s ORDER BY id LIMIT %s",
                    (last_id, args.batch_size),
                )
                rows = read_cur.fetchall()
            if not rows:
                break

            for cve_id, raw in rows:
                raw_item = raw if isinstance(raw, dict) else {}
                cve = raw_item.get("cve", {})
                cpe_rows = extract_cpe_matches(cve if isinstance(cve, dict) else {})

                with conn.cursor() as write_cur:
                    write_cur.execute("DELETE FROM cve_cpe WHERE cve_id = %s", (cve_id,))
                    if cpe_rows:
                        execute_values(
                            write_cur,
                            """
                            INSERT INTO cve_cpe (
                                cve_id, part, vendor, product, version, criteria, vulnerable
                            ) VALUES %s
                            ON CONFLICT (cve_id, criteria) DO UPDATE SET
                                part = EXCLUDED.part,
                                vendor = EXCLUDED.vendor,
                                product = EXCLUDED.product,
                                version = EXCLUDED.version,
                                vulnerable = EXCLUDED.vulnerable
                            """,
                            [
                                (
                                    cve_id,
                                    part,
                                    vendor,
                                    product,
                                    version,
                                    criteria,
                                    vulnerable,
                                )
                                for part, vendor, product, version, criteria, vulnerable in cpe_rows
                            ],
                        )
                        written += len(cpe_rows)
                processed += 1

            last_id = rows[-1][0]
            conn.commit()
            print(f"Processed CVEs: {processed}, inserted/updated CPE rows: {written}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
