"""Network scanning helpers built on top of python-nmap."""

from typing import Any, Dict, List

import nmap


def _format_results(scanner: nmap.PortScanner) -> List[Dict[str, Any]]:
    """Convert python-nmap scan data to a flat list of dictionaries."""
    results: List[Dict[str, Any]] = []

    # Iterate over all discovered hosts in the scanner results.
    for host in scanner.all_hosts():
        host_state = scanner[host].state() if "status" in scanner[host] else "unknown"

        # Iterate over each protocol block (e.g. tcp, udp) for this host.
        for protocol in scanner[host].all_protocols():
            ports = scanner[host][protocol]

            # Add one normalized dictionary per scanned port.
            for port in sorted(ports.keys()):
                service = ports[port]
                product = service.get("product", "")
                version = service.get("version", "")

                # Combine product + version when both are present.
                if product and version:
                    product_version = f"{product} {version}"
                else:
                    product_version = product or version or ""

                results.append(
                    {
                        "host": host,
                        "state": service.get("state", host_state),
                        "protocol": protocol,
                        "port": port,
                        "service": service.get("name", ""),
                        "product_version": product_version,
                    }
                )

    return results


def scan_tcp(target: str, ports: str) -> List[Dict[str, Any]]:
    """
    Scan TCP ports with service/version detection.

    Uses nmap arguments:
    -sV : probe open ports to determine service/version
    -T4 : faster timing template
    """
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, ports=ports, arguments="-sV -T4")
        return _format_results(scanner)
    except nmap.PortScannerError as err:
        print(f"[TCP scan error] Failed to run nmap scan on {target}: {err}")
    except Exception as err:  # noqa: BLE001
        print(f"[TCP scan error] Unexpected error while scanning {target}: {err}")

    return []


def scan_udp(target: str, ports: str) -> List[Dict[str, Any]]:
    """
    Scan UDP ports (root privileges required by nmap for reliable UDP scans).

    Uses nmap arguments:
    -sU : UDP scan
    -T4 : faster timing template
    """
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, ports=ports, arguments="-sU -T4")
        return _format_results(scanner)
    except nmap.PortScannerError as err:
        print(
            f"[UDP scan error] Failed to run UDP scan on {target}. "
            f"Root privileges may be required: {err}"
        )
    except Exception as err:  # noqa: BLE001
        print(f"[UDP scan error] Unexpected error while scanning {target}: {err}")

    return []


def scan_os(target: str) -> List[Dict[str, Any]]:
    """
    Attempt OS detection (root privileges required by nmap).

    Uses nmap argument:
    -O : enable OS fingerprinting
    """
    try:
        scanner = nmap.PortScanner()
        scanner.scan(hosts=target, arguments="-O")

        # OS detection does not always include per-port entries.
        # We still return a normalized list and include any discovered ports.
        results = _format_results(scanner)

        # If no ports were returned but host data exists, add a host-level result.
        if not results:
            for host in scanner.all_hosts():
                host_state = scanner[host].state() if "status" in scanner[host] else "unknown"
                os_name = ""

                os_matches = scanner[host].get("osmatch", [])
                if os_matches:
                    os_name = os_matches[0].get("name", "")

                results.append(
                    {
                        "host": host,
                        "state": host_state,
                        "protocol": "n/a",
                        "port": None,
                        "service": "os-detection",
                        "product_version": os_name,
                    }
                )

        return results
    except nmap.PortScannerError as err:
        print(
            f"[OS scan error] Failed to run OS detection on {target}. "
            f"Root privileges may be required: {err}"
        )
    except Exception as err:  # noqa: BLE001
        print(f"[OS scan error] Unexpected error while scanning {target}: {err}")

    return []
