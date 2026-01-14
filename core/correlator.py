from typing import Dict, List
from utils.logger import get_logger

log = get_logger("correlator")


class Correlator:
    def __init__(self, target: str = None):
        self.target = target
        self.correlations = {}

    def process(self, results: List[Dict]) -> Dict:
        """
        Process and correlate results from multiple modules.
        Returns a dictionary with categorized and linked findings.
        """
        correlated = {
            "summary": self._generate_summary(results),
            "domains": {},
            "subdomains": [],
            "ip_addresses": [],
            "ports": [],
            "technologies": [],
            "vulnerabilities": [],
            "endpoints": [],
            "raw": {}
        }

        for entry in results:
            module = entry.get("module", "unknown")
            data = entry.get("data", {})
            timestamp = entry.get("timestamp", "")

            # Store raw result
            correlated["raw"][module] = {
                "timestamp": timestamp,
                "data": data
            }

            # Correlate based on module type
            self._correlate_module(correlated, module, data)

        log.info(f"Correlation complete: {len(correlated['subdomains'])} subdomains, "
                 f"{len(correlated['ip_addresses'])} IPs, {len(correlated['ports'])} ports found")

        return correlated

    def _correlate_module(self, correlated: Dict, module: str, data: any):
        """Correlate data from specific modules."""

        if "whois" in module and isinstance(data, dict):
            correlated["domains"]["whois"] = data
            # Extract IPs from nameservers
            if "nameservers" in data:
                for ns in data["nameservers"]:
                    if ns not in correlated["ip_addresses"]:
                        correlated["ip_addresses"].append(ns)

        elif "asn" in module and isinstance(data, dict):
            correlated["domains"]["asn"] = data

        elif "reverse_whois" in module:
            if isinstance(data, list):
                correlated["domains"]["reverse_whois"] = data
            elif isinstance(data, dict):
                correlated["domains"]["reverse_whois"] = data

        elif module in ["subdomains.crtsh", "subdomains.securitytrails"] and isinstance(data, list):
            correlated["subdomains"].extend(data)
            # Remove duplicates
            correlated["subdomains"] = list(set(correlated["subdomains"]))

        elif "dns" in module and isinstance(data, dict):
            correlated["domains"]["dns"] = data
            # Extract IPs from A/AAAA records
            for record_type in ["a", "aaaa", "aaaaa"]:
                if record_type in data:
                    ips = data[record_type] if isinstance(data[record_type], list) else [data[record_type]]
                    for ip in ips:
                        if ip not in correlated["ip_addresses"]:
                            correlated["ip_addresses"].append(ip)

        elif "portscan" in module and isinstance(data, list):
            correlated["ports"].extend(data)
            for port in data:
                if "ip" in port and port["ip"] not in correlated["ip_addresses"]:
                    correlated["ip_addresses"].append(port["ip"])
                if "service" in port and "technologies" in port["service"]:
                    correlated["technologies"].extend(port["service"]["technologies"])

        elif module in ["infra.shodan", "infra.censys"] and isinstance(data, dict):
            correlated["raw"][module] = data
            if "hostnames" in data:
                correlated["subdomains"].extend(data["hostnames"])
            if "ip" in data:
                if data["ip"] not in correlated["ip_addresses"]:
                    correlated["ip_addresses"].append(data["ip"])
            if "ports" in data:
                for port in data["ports"]:
                    correlated["ports"].append({"port": port, "source": module})

        elif "wayback" in module and isinstance(data, list):
            correlated["endpoints"].extend(data)

        elif "urls" in module and isinstance(data, list):
            correlated["endpoints"].extend(data)

        elif "params" in module and isinstance(data, dict):
            correlated["raw"][module] = data

        elif "buckets" in module and isinstance(data, list):
            correlated["raw"][module] = data

        elif "js" in module and isinstance(data, list):
            correlated["raw"][module] = data
            for item in data:
                if "url" in item and item["url"] not in correlated["endpoints"]:
                    correlated["endpoints"].append(item["url"])

    def _generate_summary(self, results: List[Dict]) -> Dict:
        """Generate a summary of the reconnaissance results."""
        return {
            "modules_executed": len(results),
            "modules_with_data": sum(1 for r in results if r.get("data")),
            "target": self.target
        }
