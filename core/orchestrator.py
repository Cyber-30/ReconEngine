import json
import os
from datetime import datetime
from core.engine import Engine
from core.correlator import Correlator
from utils.logger import get_logger

log = get_logger("orchestrator")


class Orchestrator:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.output_format = args.output
        self.output_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "output"
        )
        os.makedirs(self.output_dir, exist_ok=True)

        self.engine = Engine(self.target)
        self.correlator = Correlator(self.target)

    def _save_results(self, results: dict, filename: str):
        """Save results to the output directory."""
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        log.info(f"Results saved to: {filepath}")
        return filepath

    def run(self):
        log.info(f"Starting reconnaissance on target: {self.target}")
        log.info(f"Output format: {self.output_format}")
        log.info("-" * 60)

        results = []
        modules_run = []

        # Passive reconnaissance
        if self.args.passive or self.args.all:
            log.info("[*] Running passive reconnaissance...")
            passive_results = self.engine.run_passive()
            results.extend(passive_results)
            modules_run.extend(["whois", "asn", "crtsh", "securitytrails", "dns", "wayback", "urls", "reverse_whois"])

        # Active reconnaissance
        if self.args.active or self.args.all:
            log.info("[*] Running active reconnaissance...")
            active_results = self.engine.run_active()
            results.extend(active_results)
            modules_run.extend(["portscan", "shodan", "censys", "buckets", "js_secrets", "params"])

        log.info("-" * 60)
        log.info(f"Completed {len(results)} module(s)")

        # Process and correlate results
        log.info("[*] Processing and correlating results...")
        correlated = self.correlator.process(results)

        # Generate output
        output_data = {
            "target": self.target,
            "timestamp": datetime.utcnow().isoformat(),
            "modules_run": modules_run,
            "results_count": len(results),
            "output_format": self.output_format,
            "data": correlated
        }

        # Save in requested format
        if self.output_format == "json":
            self._save_results(output_data, f"{self.target}_recon.json")
        elif self.output_format == "html":
            self._generate_html_report(output_data)
        elif self.output_format == "csv":
            self._generate_csv_report(correlated)

        log.info(f"Reconnaissance complete for: {self.target}")
        return output_data

    def _generate_html_report(self, data: dict):
        """Generate an HTML report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconEngine Report - {data['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00ff88; }}
        h2 {{ color: #00d4ff; margin-top: 30px; }}
        .module {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }}
        .data {{ background: #0f0f23; padding: 10px; border-radius: 5px; font-family: monospace; white-space: pre-wrap; }}
        .stats {{ color: #888; }}
        pre {{ color: #aaffaa; }}
        a {{ color: #00d4ff; }}
    </style>
</head>
<body>
    <h1>🔍 ReconEngine Report</h1>
    <p><strong>Target:</strong> {data['target']}</p>
    <p><strong>Timestamp:</strong> {data['timestamp']}</p>
    <p><strong>Modules Run:</strong> {', '.join(data['modules_run'])}</p>
    <p><strong>Results:</strong> {data['results_count']} modules returned data</p>

    <h2>Results</h2>
"""
        for module, module_data in data['data'].items():
            html += f"""
    <div class="module">
        <h3>📦 {module}</h3>
        <div class="data"><pre>{json.dumps(module_data, indent=2, default=str)}</pre></div>
    </div>
"""

        html += """
</body>
</html>"""

        self._save_results({"html": html}, f"{self.target}_recon.html")
        log.info(f"HTML report generated")

    def _generate_csv_report(self, data: dict):
        """Generate a CSV report."""
        import csv
        csv_path = os.path.join(self.output_dir, f"{self.target}_recon.csv")

        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Module', 'Key', 'Value'])
            for module, module_data in data.items():
                if isinstance(module_data, dict):
                    for key, value in module_data.items():
                        writer.writerow([module, key, value])
                elif isinstance(module_data, list):
                    for item in module_data:
                        writer.writerow([module, 'item', item])
                else:
                    writer.writerow([module, 'value', module_data])

        log.info(f"CSV report generated: {csv_path}")
