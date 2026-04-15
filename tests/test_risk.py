"""Unit tests for risk classification and summarization logic."""

from netscan.risk import assess_risk, summarise_risks


def test_assess_risk_assigns_critical_for_smb_port_445() -> None:
    """Port 445 should map to Critical because SMB is a high-impact exposed service."""
    scan_results = [
        {
            "host": "192.168.1.10",
            "state": "open",
            "protocol": "tcp",
            "port": 445,
            "service": "microsoft-ds",
            "product_version": "SMB",
        }
    ]

    assessed = assess_risk(scan_results)

    assert len(assessed) == 1
    assert assessed[0]["risk_level"] == "Critical"
    assert "SMB" in assessed[0]["risk_reason"]


def test_assess_risk_assigns_medium_for_ssh_port_22() -> None:
    """Port 22 should map to Medium based on the predefined SSH risk profile."""
    scan_results = [
        {
            "host": "192.168.1.11",
            "state": "open",
            "protocol": "tcp",
            "port": 22,
            "service": "ssh",
            "product_version": "OpenSSH",
        }
    ]

    assessed = assess_risk(scan_results)

    assert len(assessed) == 1
    assert assessed[0]["risk_level"] == "Medium"
    assert "brute-force" in assessed[0]["risk_reason"]


def test_assess_risk_assigns_low_and_default_reason_for_unknown_port() -> None:
    """Unknown ports should fall back to Low risk with the default explanatory reason."""
    scan_results = [
        {
            "host": "192.168.1.12",
            "state": "open",
            "protocol": "tcp",
            "port": 99999,
            "service": "unknown",
            "product_version": "",
        }
    ]

    assessed = assess_risk(scan_results)

    assert len(assessed) == 1
    assert assessed[0]["risk_level"] == "Low"
    assert (
        assessed[0]["risk_reason"]
        == "No specific high-risk profile matched for this port."
    )


def test_assess_risk_returns_empty_list_for_empty_input() -> None:
    """An empty scan result set should produce an empty assessed result set."""
    assessed = assess_risk([])
    assert assessed == []


def test_summarise_risks_counts_critical_and_high_findings() -> None:
    """Summary counts should accurately reflect the distribution of risk levels."""
    assessed_results = [
        {"host": "host1", "port": 445, "risk_level": "Critical", "risk_reason": "x"},
        {"host": "host2", "port": 3389, "risk_level": "Critical", "risk_reason": "y"},
        {"host": "host3", "port": 21, "risk_level": "High", "risk_reason": "z"},
        {"host": "host4", "port": 80, "risk_level": "High", "risk_reason": "w"},
        {"host": "host5", "port": 22, "risk_level": "Medium", "risk_reason": "v"},
    ]

    summary = summarise_risks(assessed_results)

    assert summary["counts"]["Critical"] == 2
    assert summary["counts"]["High"] == 2
    assert summary["counts"]["Medium"] == 1
    assert summary["counts"]["Low"] == 0


def test_summarise_risks_populates_critical_and_high_lists() -> None:
    """Critical and High findings should be separated into dedicated output lists."""
    assessed_results = [
        {
            "host": "host1",
            "port": 445,
            "service": "smb",
            "risk_level": "Critical",
            "risk_reason": "critical reason",
        },
        {
            "host": "host2",
            "port": 21,
            "service": "ftp",
            "risk_level": "High",
            "risk_reason": "high reason",
        },
        {
            "host": "host3",
            "port": 22,
            "service": "ssh",
            "risk_level": "Medium",
            "risk_reason": "medium reason",
        },
    ]

    summary = summarise_risks(assessed_results)

    assert len(summary["critical_findings"]) == 1
    assert len(summary["high_findings"]) == 1
    assert summary["critical_findings"][0]["port"] == 445
    assert summary["high_findings"][0]["port"] == 21


def test_summarise_risks_returns_zero_counts_for_empty_input() -> None:
    """When no findings exist, all known risk-level counters should stay at zero."""
    summary = summarise_risks([])

    assert summary["counts"]["Critical"] == 0
    assert summary["counts"]["High"] == 0
    assert summary["counts"]["Medium"] == 0
    assert summary["counts"]["Low"] == 0
    assert summary["critical_findings"] == []
    assert summary["high_findings"] == []
