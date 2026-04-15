"""CVE lookup and enrichment utilities using the NIST NVD API v2."""

from __future__ import annotations

import time
from typing import Any, Dict, List

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT_SECONDS = 10

# NVD allows 5 requests / 30 seconds without API key.
# 6 seconds between requests keeps us inside that window.
REQUEST_DELAY_SECONDS = 6.0


def _extract_description(cve_item: Dict[str, Any]) -> str:
    """Extract an English description when available."""
    descriptions = cve_item.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"]

    # Fall back to the first description entry if English is missing.
    if descriptions:
        return descriptions[0].get("value", "")

    return "No description available."


def _extract_severity(cve_item: Dict[str, Any]) -> str:
    """Extract severity from CVSS metrics, preferring modern versions."""
    metrics = cve_item.get("metrics", {})

    metric_keys = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for metric_key in metric_keys:
        entries = metrics.get(metric_key, [])
        if not entries:
            continue

        first_entry = entries[0]
        cvss_data = first_entry.get("cvssData", {})
        severity = cvss_data.get("baseSeverity") or first_entry.get("baseSeverity")
        if severity:
            return str(severity)

    return "Unknown"


def lookup_cves(service_name: str, max_results: int = 5) -> List[Dict[str, str]]:
    """
    Query NVD CVE API by service keyword and return a normalized CVE list.

    Each item includes:
    - cve_id
    - description
    - severity
    - published
    """
    if not service_name:
        return []

    params = {"keywordSearch": service_name, "resultsPerPage": max_results}

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        payload = response.json()
    except requests.exceptions.Timeout:
        print(f"[CVE lookup error] Request timed out while searching CVEs for: {service_name}")
        return []
    except requests.exceptions.RequestException as err:
        print(f"[CVE lookup error] Network/API error for '{service_name}': {err}")
        return []
    except ValueError as err:
        print(f"[CVE lookup error] Failed to parse API response for '{service_name}': {err}")
        return []

    vulnerabilities = payload.get("vulnerabilities", [])
    cves: List[Dict[str, str]] = []

    for vuln in vulnerabilities[:max_results]:
        cve_data = vuln.get("cve", {})
        cves.append(
            {
                "cve_id": cve_data.get("id", "Unknown"),
                "description": _extract_description(cve_data),
                "severity": _extract_severity(cve_data),
                "published": cve_data.get("published", "Unknown"),
            }
        )

    return cves


def enrich_results(
    assessed_results: List[Dict[str, Any]], max_cves: int = 3
) -> List[Dict[str, Any]]:
    """
    Add CVE data to assessed scan findings.

    For each finding, try to query by product/version first, then service name.
    A `cves` key is added with a list of CVE dictionaries.
    """
    enriched_results: List[Dict[str, Any]] = []

    for index, finding in enumerate(assessed_results):
        enriched = dict(finding)
        cves: List[Dict[str, str]] = []

        product_version = str(enriched.get("product_version", "") or "").strip()
        service_name = str(enriched.get("service", "") or "").strip()

        # Prefer a more specific product/version lookup when available.
        if product_version:
            cves = lookup_cves(product_version, max_results=max_cves)

        # Fall back to service name if product lookup returned nothing.
        if not cves and service_name:
            cves = lookup_cves(service_name, max_results=max_cves)

        enriched["cves"] = cves
        enriched_results.append(enriched)

        # Delay between API requests to respect the unauthenticated NVD rate limit.
        # We skip delay after the last item.
        is_last = index == len(assessed_results) - 1
        if not is_last and (product_version or service_name):
            time.sleep(REQUEST_DELAY_SECONDS)

    return enriched_results
