# portscanner_tool.py

import socket
from langchain_core.tools import tool
from typing import List, Dict

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

def scan_ports(hostname: str, ports: List[int]) -> Dict[int, str]:
    open_ports = {}
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return {"error": f"Could not resolve {hostname}"}

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((ip, port))
                open_ports[port] = COMMON_PORTS.get(port, "Unknown")
            except (socket.timeout, ConnectionRefusedError):
                continue
    return open_ports

@tool
def run_port_scanner(live_domains: List[str]) -> Dict[str, Dict[int, str]]:
    """
    Scan a list of live domains for open common ports.

    This function iterates over each given domain, attempts to resolve its IP address,
    and checks a predefined list of common ports (e.g., 22, 80, 443, 3306).
    It returns a mapping of each domain to its open ports and their corresponding service names.

    Args:
        live_domains (List[str]): A list of subdomains or domains to scan.

    Returns:
        Dict[str, Dict[int, str]]: A dictionary where each key is a domain and the value is
        another dictionary mapping open port numbers to their known service names.
        If the domain cannot be resolved, an "error" key is returned in place of ports.
    """
    results = {}
    for domain in live_domains:
        open_ports = scan_ports(domain, list(COMMON_PORTS.keys()))
        results[domain] = open_ports
    return results

