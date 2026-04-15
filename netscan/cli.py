"""Command-line interface for the NetScan security scanner."""

from __future__ import annotations

import argparse
from typing import Any, Dict, List

# Support both package execution and direct script execution.
try:
    from .cve import enrich_results
    from .report import generate_reports
    from .risk import assess_risk, summarise_risks
    from .scanner import scan_os, scan_tcp, scan_udp
except ImportError:  # pragma: no cover
    from cve import enrich_results
    from report import generate_reports
    from risk import assess_risk, summarise_risks
    from scanner import scan_os, scan_tcp, scan_udp


def _build_parser() -> argparse.ArgumentParser:
    """Create and return the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="NetScan - network port scanner and security risk assessment tool."
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "--ports",
        default="1-1024",
        help='Port range/list to scan, e.g. "1-1024" or "22,80,443"',
    )
    parser.add_argument(
        "--udp",
        action="store_true",
        help="Enable UDP scanning (typically requires root privileges)",
    )
    parser.add_argument(
        "--os",
        action="store_true",
        help="Enable OS detection scan (typically requires root privileges)",
    )
    parser.add_argument(
        "--cve",
        action="store_true",
        help="Enable CVE enrichment lookups from NVD",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Directory where reports will be saved",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip saving JSON/HTML reports",
    )
    return parser


def _print_banner() -> None:
    """Print CLI banner and authorized-use warning."""
    print("=" * 70)
    print("NetScan - Network Port Scanner Security Tool")
    print("WARNING: Use this tool only on systems you are authorized to test.")
    print("=" * 70)


def _print_summary(summary: Dict[str, Any]) -> None:
    """Print a terminal summary of findings grouped by risk level."""
    counts = summary.get("counts", {})
    critical_count = counts.get("Critical", 0)
    high_count = counts.get("High", 0)
    medium_count = counts.get("Medium", 0)
    low_count = counts.get("Low", 0)

    print("\nScan Summary")
    print("-" * 70)
    print(f"Critical findings: {critical_count}")
    print(f"High findings:     {high_count}")
    print(f"Medium findings:   {medium_count}")
    print(f"Low findings:      {low_count}")
    print("-" * 70)

    critical_findings = summary.get("critical_findings", [])
    high_findings = summary.get("high_findings", [])

    if critical_findings:
        print("\nCritical Findings:")
        for finding in critical_findings:
            host = finding.get("host", "-")
            port = finding.get("port", "-")
            service = finding.get("service", "-")
            reason = finding.get("risk_reason", "-")
            print(f"- {host}:{port} ({service}) -> {reason}")

    if high_findings:
        print("\nHigh Findings:")
        for finding in high_findings:
            host = finding.get("host", "-")
            port = finding.get("port", "-")
            service = finding.get("service", "-")
            reason = finding.get("risk_reason", "-")
            print(f"- {host}:{port} ({service}) -> {reason}")


def main() -> None:
    """Run the full scan, risk analysis, optional CVE enrichment, and reporting flow."""
    parser = _build_parser()
    args = parser.parse_args()

    _print_banner()
    print(f"[+] Target: {args.target}")
    print(f"[+] TCP ports: {args.ports}")

    # Stage 1: TCP scan always runs.
    print("[*] Running TCP scan...")
    tcp_results = scan_tcp(args.target, args.ports)
    all_results: List[Dict[str, Any]] = list(tcp_results)
    print(f"[+] TCP scan complete: {len(tcp_results)} findings collected.")

    # Stage 2: Optional UDP scan.
    if args.udp:
        print("[*] Running UDP scan...")
        udp_results = scan_udp(args.target, args.ports)
        all_results.extend(udp_results)
        print(f"[+] UDP scan complete: {len(udp_results)} findings collected.")

    # Stage 3: Optional OS detection scan.
    if args.os:
        print("[*] Running OS detection scan...")
        os_results = scan_os(args.target)
        all_results.extend(os_results)
        print(f"[+] OS detection complete: {len(os_results)} findings collected.")

    print(f"[+] Total raw findings: {len(all_results)}")

    # Stage 4: Risk assessment and summary always run.
    print("[*] Assessing risk levels...")
    assessed_results = assess_risk(all_results)

    print("[*] Building risk summary...")
    summary = summarise_risks(assessed_results)

    # Stage 5: Optional CVE enrichment.
    final_results: List[Dict[str, Any]] = assessed_results
    if args.cve:
        print("[*] Enriching results with CVE lookups (this may take some time)...")
        final_results = enrich_results(assessed_results)
        print("[+] CVE enrichment complete.")

    # Stage 6: Print terminal summary.
    _print_summary(summary)

    # Stage 7: Optional report generation.
    if args.no_report:
        print("[*] Report generation skipped (--no-report set).")
    else:
        print(f"[*] Generating reports in: {args.output}")
        generate_reports(final_results, summary, args.target, args.output)

    print("[+] Scan workflow complete.")


if __name__ == "__main__":
    main()
