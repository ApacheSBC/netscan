"""Risk assessment helpers for network scan results."""

from typing import Any, Dict, List


# Known ports that commonly expose higher security risk when reachable.
# The reason text is intentionally short and actionable for quick triage.
RISKY_PORTS: Dict[int, Dict[str, str]] = {
    21: {
        "service": "FTP",
        "risk_level": "High",
        "reason": "FTP often transmits credentials in plaintext and is frequently misconfigured.",
    },
    22: {
        "service": "SSH",
        "risk_level": "Medium",
        "reason": "SSH is secure but exposed services can be targeted by brute-force attacks.",
    },
    23: {
        "service": "Telnet",
        "risk_level": "Critical",
        "reason": "Telnet is unencrypted and exposes credentials and session data in plaintext.",
    },
    25: {
        "service": "SMTP",
        "risk_level": "Medium",
        "reason": "Open or misconfigured SMTP can enable spam relays and mail abuse.",
    },
    53: {
        "service": "DNS",
        "risk_level": "Medium",
        "reason": "Exposed DNS can be abused for amplification attacks or zone transfer leakage.",
    },
    80: {
        "service": "HTTP",
        "risk_level": "High",
        "reason": "HTTP is unencrypted and can expose credentials and session data in plaintext.",
    },
    110: {
        "service": "POP3",
        "risk_level": "High",
        "reason": "POP3 commonly uses weak or plaintext authentication if TLS is not enforced.",
    },
    135: {
        "service": "RPC",
        "risk_level": "High",
        "reason": "RPC exposure can enable remote enumeration and exploitation on Windows hosts.",
    },
    139: {
        "service": "NetBIOS",
        "risk_level": "High",
        "reason": "NetBIOS can leak host/share information and is commonly abused in internal attacks.",
    },
    443: {
        "service": "HTTPS",
        "risk_level": "Low",
        "reason": "HTTPS is expected for secure web services but should still be hardened and patched.",
    },
    445: {
        "service": "SMB",
        "risk_level": "Critical",
        "reason": "SMB exposure is high risk due to remote exploit history and lateral movement abuse.",
    },
    1433: {
        "service": "MSSQL",
        "risk_level": "High",
        "reason": "Public database exposure can allow credential attacks and sensitive data access.",
    },
    1521: {
        "service": "Oracle DB",
        "risk_level": "High",
        "reason": "Oracle listener exposure can reveal database metadata and increase attack surface.",
    },
    3306: {
        "service": "MySQL",
        "risk_level": "High",
        "reason": "Exposed MySQL can allow unauthorized access or brute-force database logins.",
    },
    3389: {
        "service": "RDP",
        "risk_level": "Critical",
        "reason": "RDP is frequently targeted for brute-force and remote access compromise attempts.",
    },
    5432: {
        "service": "PostgreSQL",
        "risk_level": "High",
        "reason": "Exposed PostgreSQL instances increase risk of data theft and privilege abuse.",
    },
    5900: {
        "service": "VNC",
        "risk_level": "High",
        "reason": "VNC may use weak authentication and can expose remote desktop control.",
    },
    6379: {
        "service": "Redis",
        "risk_level": "Critical",
        "reason": "Unauthenticated Redis exposure can lead to data loss and remote code execution.",
    },
    8080: {
        "service": "HTTP-Alt",
        "risk_level": "Medium",
        "reason": "Alternate web ports often host admin panels or less-monitored web services.",
    },
    27017: {
        "service": "MongoDB",
        "risk_level": "Critical",
        "reason": "Exposed MongoDB can allow unauthorized data access when auth is misconfigured.",
    },
}


def assess_risk(scan_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add risk metadata to each scan result item based on known risky ports.

    Expected input item shape (from scanner.py):
    {
        "host": str,
        "state": str,
        "protocol": str,
        "port": int | None,
        "service": str,
        "product_version": str
    }
    """
    assessed: List[Dict[str, Any]] = []

    for result in scan_results:
        # Copy each result so we do not mutate the caller's original list.
        assessed_item = dict(result)
        port = assessed_item.get("port")

        # Default classification for unknown/non-risky ports.
        risk_level = "Low"
        risk_reason = "No specific high-risk profile matched for this port."

        # Only evaluate known integer port values against the risk dictionary.
        if isinstance(port, int) and port in RISKY_PORTS:
            risk_info = RISKY_PORTS[port]
            risk_level = risk_info["risk_level"]
            risk_reason = risk_info["reason"]

        assessed_item["risk_level"] = risk_level
        assessed_item["risk_reason"] = risk_reason
        assessed.append(assessed_item)

    return assessed


def summarise_risks(assessed_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Summarise assessed results by risk level and isolate top-priority findings.

    Returns:
    {
        "counts": {"Critical": int, "High": int, "Medium": int, "Low": int},
        "critical_findings": [...],
        "high_findings": [...]
    }
    """
    summary: Dict[str, Any] = {
        "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "critical_findings": [],
        "high_findings": [],
    }

    for finding in assessed_results:
        level = finding.get("risk_level", "Low")

        # Keep counters stable even if unexpected levels are present.
        if level not in summary["counts"]:
            summary["counts"][level] = 0

        summary["counts"][level] += 1

        # Separate the most urgent findings for quick remediation review.
        if level == "Critical":
            summary["critical_findings"].append(finding)
        elif level == "High":
            summary["high_findings"].append(finding)

    return summary
