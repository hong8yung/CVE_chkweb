from __future__ import annotations

import argparse
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

import psycopg2
import requests
from psycopg2.extras import Json, execute_values

from classification import IMPACT_CLASSIFICATION_VERSION, classify_impact_type
from settings import Settings, load_settings

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest CVEs from NVD API to PostgreSQL")
    parser.add_argument(
        "--mode",
        required=True,
        choices=["initial", "incremental"],
        help="initial: backfill by published date, incremental: sync by last modified",
    )
    parser.add_argument("--config", default=".env", help="Path to settings file")
    return parser.parse_args()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_nvd_ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def parse_nvd_ts(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def subtract_years_safe(value: datetime, years: int) -> datetime:
    try:
        return value.replace(year=value.year - years)
    except ValueError:
        return value.replace(month=2, day=28, year=value.year - years)


def chunk_ranges(start: datetime, end: datetime, days: int) -> Iterable[tuple[datetime, datetime]]:
    cursor = start
    delta = timedelta(days=days)
    while cursor < end:
        window_end = min(cursor + delta, end)
        yield cursor, window_end
        cursor = window_end


def request_with_retry(url: str, params: dict[str, Any], headers: dict[str, str], timeout: int) -> dict[str, Any]:
    for attempt in range(3):
        response = requests.get(url, params=params, headers=headers, timeout=timeout)
        if response.status_code in (429, 500, 502, 503, 504) and attempt < 2:
            time.sleep(2**attempt)
            continue
        response.raise_for_status()
        return response.json()
    raise RuntimeError("Request retry exhausted")


def extract_cvss(cve: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    metrics = cve.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        items = metrics.get(key) or []
        if not items:
            continue
        metric = items[0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")
        return score, version, severity
    return None, None, None


def extract_english_description_from_cve(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    if not isinstance(descriptions, list):
        return ""
    for desc in descriptions:
        if isinstance(desc, dict) and desc.get("lang") == "en":
            return str(desc.get("value", ""))
    return ""


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
    # cpe:2.3:<part>:<vendor>:<product>:<version>:...
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
                    # If same criteria appears multiple times, preserve True if any entry is vulnerable.
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


def upsert_cves(conn: psycopg2.extensions.connection, vulnerabilities: list[dict[str, Any]]) -> int:
    upsert_sql = """
    INSERT INTO cve (
        id,
        published_at,
        last_modified_at,
        cvss_score,
        cvss_version,
        severity,
        impact_type,
        classification_version,
        source_identifier,
        raw,
        updated_at
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
    ON CONFLICT (id) DO UPDATE SET
        published_at = EXCLUDED.published_at,
        last_modified_at = EXCLUDED.last_modified_at,
        cvss_score = EXCLUDED.cvss_score,
        cvss_version = EXCLUDED.cvss_version,
        severity = EXCLUDED.severity,
        impact_type = EXCLUDED.impact_type,
        classification_version = EXCLUDED.classification_version,
        source_identifier = EXCLUDED.source_identifier,
        raw = EXCLUDED.raw,
        updated_at = now()
    """

    count = 0
    with conn.cursor() as cur:
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            score, version, severity = extract_cvss(cve)
            published_at = parse_nvd_ts(cve["published"])
            last_modified_at = parse_nvd_ts(cve["lastModified"])
            description = extract_english_description_from_cve(cve)
            impact_type = classify_impact_type(description)

            cur.execute(
                upsert_sql,
                (
                    cve_id,
                    published_at,
                    last_modified_at,
                    score,
                    version,
                    severity,
                    impact_type,
                    IMPACT_CLASSIFICATION_VERSION,
                    cve.get("sourceIdentifier"),
                    Json(item),
                ),
            )

            cpe_rows = extract_cpe_matches(cve)
            cur.execute("DELETE FROM cve_cpe WHERE cve_id = %s", (cve_id,))
            if cpe_rows:
                execute_values(
                    cur,
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
            count += 1
    conn.commit()
    return count


def get_checkpoint(conn: psycopg2.extensions.connection) -> datetime | None:
    with conn.cursor() as cur:
        cur.execute("SELECT value_ts FROM ingest_checkpoint WHERE key = %s", ("daily_last_modified_sync",))
        row = cur.fetchone()
    if not row:
        return None
    return row[0].astimezone(timezone.utc)


def set_checkpoint(conn: psycopg2.extensions.connection, ts: datetime) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ingest_checkpoint (key, value_ts, updated_at)
            VALUES (%s, %s, now())
            ON CONFLICT (key) DO UPDATE SET value_ts = EXCLUDED.value_ts, updated_at = now()
            """,
            ("daily_last_modified_sync", ts),
        )
    conn.commit()


def create_job_log(conn: psycopg2.extensions.connection, job_type: str, start: datetime, end: datetime) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO ingest_job_log (job_type, window_start, window_end, status)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (job_type, start, end, "running"),
        )
        job_id = cur.fetchone()[0]
    conn.commit()
    return job_id


def finish_job_log(
    conn: psycopg2.extensions.connection,
    job_id: int,
    status: str,
    requested_count: int,
    upserted_count: int,
    failed_count: int,
    error_message: str | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE ingest_job_log
            SET status = %s,
                requested_count = %s,
                upserted_count = %s,
                failed_count = %s,
                error_message = %s,
                finished_at = now()
            WHERE id = %s
            """,
            (status, requested_count, upserted_count, failed_count, error_message, job_id),
        )
    conn.commit()


def fetch_window(settings: Settings, start: datetime, end: datetime, mode: str) -> tuple[int, int]:
    headers = {"apiKey": settings.nvd_api_key}
    total_requested = 0
    upserted = 0

    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )
    try:
        start_index = 0
        while True:
            params: dict[str, Any] = {
                "resultsPerPage": settings.nvd_results_per_page,
                "startIndex": start_index,
            }
            if mode == "initial":
                params["pubStartDate"] = to_nvd_ts(start)
                params["pubEndDate"] = to_nvd_ts(end)
            else:
                params["lastModStartDate"] = to_nvd_ts(start)
                params["lastModEndDate"] = to_nvd_ts(end)

            payload = request_with_retry(NVD_API_URL, params=params, headers=headers, timeout=settings.nvd_timeout_seconds)
            vulnerabilities = payload.get("vulnerabilities", [])
            total_results = payload.get("totalResults", 0)

            if not vulnerabilities:
                break

            total_requested += len(vulnerabilities)
            upserted += upsert_cves(conn, vulnerabilities)

            start_index += len(vulnerabilities)
            if start_index >= total_results:
                break

        return total_requested, upserted
    finally:
        conn.close()


def run_initial(settings: Settings) -> None:
    end = utc_now()
    start = subtract_years_safe(end, settings.initial_lookback_years)

    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )
    job_id = create_job_log(conn, "initial_lookback", start, end)
    conn.close()

    total_requested = 0
    total_upserted = 0

    try:
        for chunk_start, chunk_end in chunk_ranges(start, end, settings.incremental_window_days):
            requested, upserted = fetch_window(settings, chunk_start, chunk_end, mode="initial")
            total_requested += requested
            total_upserted += upserted

        conn = psycopg2.connect(
            host=settings.db_host,
            port=settings.db_port,
            dbname=settings.db_name,
            user=settings.db_user,
            password=settings.db_password,
        )
        finish_job_log(conn, job_id, "success", total_requested, total_upserted, 0)
        conn.close()
    except Exception as exc:
        conn = psycopg2.connect(
            host=settings.db_host,
            port=settings.db_port,
            dbname=settings.db_name,
            user=settings.db_user,
            password=settings.db_password,
        )
        finish_job_log(conn, job_id, "failed", total_requested, total_upserted, 1, str(exc))
        conn.close()
        raise


def run_incremental(settings: Settings) -> None:
    now = utc_now()

    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )
    checkpoint = get_checkpoint(conn)
    conn.close()

    if checkpoint is None:
        checkpoint = now - timedelta(days=settings.incremental_window_days)

    start = checkpoint - timedelta(hours=1)
    end = now

    conn = psycopg2.connect(
        host=settings.db_host,
        port=settings.db_port,
        dbname=settings.db_name,
        user=settings.db_user,
        password=settings.db_password,
    )
    job_id = create_job_log(conn, "daily_sync", start, end)
    conn.close()

    total_requested = 0
    total_upserted = 0

    try:
        for chunk_start, chunk_end in chunk_ranges(start, end, settings.incremental_window_days):
            requested, upserted = fetch_window(settings, chunk_start, chunk_end, mode="incremental")
            total_requested += requested
            total_upserted += upserted

        conn = psycopg2.connect(
            host=settings.db_host,
            port=settings.db_port,
            dbname=settings.db_name,
            user=settings.db_user,
            password=settings.db_password,
        )
        set_checkpoint(conn, end)
        finish_job_log(conn, job_id, "success", total_requested, total_upserted, 0)
        conn.close()
    except Exception as exc:
        conn = psycopg2.connect(
            host=settings.db_host,
            port=settings.db_port,
            dbname=settings.db_name,
            user=settings.db_user,
            password=settings.db_password,
        )
        finish_job_log(conn, job_id, "failed", total_requested, total_upserted, 1, str(exc))
        conn.close()
        raise


def main() -> None:
    args = parse_args()
    settings = load_settings(args.config)

    if args.mode == "initial":
        run_initial(settings)
    else:
        run_incremental(settings)


if __name__ == "__main__":
    main()
