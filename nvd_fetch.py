import argparse
from typing import Any, Dict, List

import requests

from settings import load_nvd_api_key

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cves(product: str, api_key: str) -> List[Dict[str, Any]]:
    params = {
        "keywordSearch": product,
        "resultsPerPage": 200,
    }
    headers = {"apiKey": api_key}

    response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
    response.raise_for_status()
    data = response.json()
    return data.get("vulnerabilities", [])


def extract_cvss_score(cve: Dict[str, Any]) -> float:
    metrics = cve.get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            metric = metrics[key][0]
            return metric.get("cvssData", {}).get("baseScore", 0.0)
    return 0.0


def filter_cves(cves: List[Dict[str, Any]], min_cvss: float) -> List[Dict[str, Any]]:
    filtered = []
    for item in cves:
        score = extract_cvss_score(item)
        if score >= min_cvss:
            filtered.append(item)
    return filtered


def print_cves(cves: List[Dict[str, Any]]) -> None:
    for item in cves:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        description = ""
        descriptions = cve.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        score = extract_cvss_score(item)
        print(f"{cve_id} | CVSS {score} | {description[:120]}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch CVEs from NVD API 2.0")
    parser.add_argument("--product", required=True, help="Product keyword, e.g., nginx")
    parser.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS score")
    parser.add_argument("--config", default=".env", help="Path to settings file")
    args = parser.parse_args()

    api_key = load_nvd_api_key(args.config)
    cves = fetch_cves(args.product, api_key)
    filtered = filter_cves(cves, args.min_cvss)

    print(f"Total CVEs: {len(cves)}")
    print(f"Filtered CVEs (min CVSS {args.min_cvss}): {len(filtered)}")
    print_cves(filtered)


if __name__ == "__main__":
    main()
