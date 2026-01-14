import subprocess
import json
import os
from typing import List, Dict, Optional
from utils.logger import get_logger

log = get_logger("engine")


class Engine:
    def __init__(self, target: str, timeout: int = 300):
        self.target = target
        self.timeout = timeout
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _run_command(self, command: List[str], timeout: int = None) -> Optional[Dict]:
        """
        Execute a command and return parsed JSON output.
        """
        try:
            log.debug(f"Executing command: {' '.join(command)}")

            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout
            )

            if proc.returncode != 0:
                stderr = proc.stderr.strip()
                if stderr:
                    log.warning(stderr)
                return None

            output = proc.stdout.strip()
            if not output:
                return None

            return json.loads(output)

        except subprocess.TimeoutExpired:
            log.warning(f"Timeout executing: {' '.join(command)}")
        except json.JSONDecodeError as e:
            log.warning(f"Module did not return valid JSON: {e}")
        except Exception as e:
            log.error(f"Execution error: {e}")

        return None

    def run_python_module(self, module_name: str, *args) -> Optional[Dict]:
        """
        Run a Python-based recon module.
        """
        module_path = os.path.join(self.base_dir, "modules", f"{module_name}.py")
        if not os.path.exists(module_path):
            log.error(f"Module not found: {module_path}")
            return None

        cmd = ["python3", module_path, self.target] + list(args)
        return self._run_command(cmd)

    def run_binary(self, binary_name: str, *args) -> Optional[Dict]:
        """
        Run a compiled Go/C/C++ recon module.
        """
        binary_path = os.path.join(self.base_dir, "bin", binary_name)
        if not os.path.exists(binary_path):
            log.error(f"Binary not found: {binary_path}")
            return None

        cmd = [binary_path, self.target] + list(args)
        return self._run_command(cmd)

    def run_passive(self) -> List[Dict]:
        """
        Execute passive recon modules.
        """
        results = []

        passive_modules = [
            ("domains.whois", "WHOIS lookup"),
            ("domains.asn", "ASN enumeration"),
            ("subdomains.crtsh", "CRT.sh enumeration"),
            ("subdomains.securitytrails", "SecurityTrails"),
            ("dns.records", "DNS records"),
            ("web.wayback", "Wayback archives"),
            ("web.urls", "URL discovery"),
            ("domains.reverse_whois", "Reverse WHOIS"),
        ]

        for module_name, desc in passive_modules:
            log.info(f"Running passive module: {desc}")
            result = self.run_python_module(module_name)
            if result:
                results.append(result)
                log.info(f"Completed: {desc} - {len(result.get('data', [])) if isinstance(result.get('data'), (list, dict)) else 'done'} results")
            else:
                log.warning(f"No results from: {desc}")

        return results

    def run_active(self) -> List[Dict]:
        """
        Execute active recon modules (opt-in).
        """
        results = []

        active_modules = [
            ("active.portscan", "Port scanning"),
            ("infra.shodan", "Shodan reconnaissance"),
            ("infra.censys", "Censys search"),
            ("cloud.buckets", "Cloud bucket discovery"),
            ("js.secrets", "JavaScript analysis"),
            ("web.params", "Parameter discovery"),
        ]

        for module_name, desc in active_modules:
            log.info(f"Running active module: {desc}")
            result = self.run_python_module(module_name)
            if result:
                results.append(result)
                log.info(f"Completed: {desc} - {len(result.get('data', [])) if isinstance(result.get('data'), (list, dict)) else 'done'} results")
            else:
                log.warning(f"No results from: {desc}")

        return results
