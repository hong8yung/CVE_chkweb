from __future__ import annotations

import argparse
from typing import Any

import psycopg2

from classification import IMPACT_CLASSIFICATION_VERSION, classify_impact_type
from settings import load_settings


def extract_english_description(raw_item: Any) -> str:
    if not isinstance(raw_item, dict):
        return ""
    cve = raw_item.get("cve", {})
    if not isinstance(cve, dict):
        return ""
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for desc in descriptions:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            return str(desc.get("value", ""))
    return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill cve.impact_type from existing cve.raw JSON")
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

            with conn.cursor() as write_cur:
                for cve_id, raw in rows:
                    description = extract_english_description(raw)
                    impact_type = classify_impact_type(description)
                    write_cur.execute(
                        """
                        UPDATE cve
                        SET impact_type = %s,
                            classification_version = %s,
                            updated_at = now()
                        WHERE id = %s
                        """,
                        (impact_type, IMPACT_CLASSIFICATION_VERSION, cve_id),
                    )
                    processed += 1

            last_id = rows[-1][0]
            conn.commit()
            print(f"Processed CVEs: {processed}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
