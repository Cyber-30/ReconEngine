#!/usr/bin/env python3
"""
ShadowRecon Engine - Menu-driven interactive reconnaissance framework
"""
import os
import sys
import json
import time
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box
from core.engine import Engine
from core.correlator import Correlator
from utils.logger import setup_logger, get_logger

# Initialize console
console = Console()
log = get_logger("shadowrecon")


class ShadowRecon:
    """Menu-driven reconnaissance engine."""
    
    def __init__(self):
        self.target: Optional[str] = None
        self.results: Dict[str, Any] = {}
        self.console_results: Dict[str, Any] = {}
        self.output_dir = Path(__file__).parent / "output"
        self.output_dir.mkdir(exist_ok=True)
        setup_logger()
    
    def clear_screen(self):
        """Clear the console screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        """Display the application banner."""
        self.clear_screen()
        banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║        ██████╗ ██████╗  █████╗ ██████╗ ██╗     ██╗     ██╗  ██╗   ║
║       ██╔════╝██╔═══██╗██╔══██╗██╔══██╗██║     ██║     ╚██╗██╔╝   ║
║       ██║     ██║   ██║███████║██████╔╝██║     ██║      ╚███║    ║
║       ██║     ██║   ██║██╔══██║██╔══██╗██║     ██║      ██╔██╗   ║
║       ╚██████╗╚██████╔╝██║  ██║██║  ██║███████╗███████╗██╔╝ ██╗  ║
║        ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝  ║
║                                                                   ║
║                    🔍 SHADOWRECON ENGINE                          ║
║              Menu-driven Reconnaissance Framework                 ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""
        console.print(Panel(banner, style="bold cyan", box=box.DOUBLE))
    
    def print_menu(self):
        """Display the main menu."""
        target_info = f"[bold yellow]Target: {self.target}[/bold yellow]" if self.target else "[bold red]No target set[/bold red]"
        
        menu = f"""
        ╔════════════════════════════════════════════╗
        ║         SHADOWRECON ENGINE                 ║
        ╚════════════════════════════════════════════╝
        
        {target_info}
        
        [1] Set Target
        [2] Run Passive Recon
        [3] Run Active Recon [yellow][Warning][/yellow]
        [4] Show Results
        [5] Export Results
        [6] Clear Session
        [7] Exit
        
        """
        console.print(menu)
    
    def set_target(self):
        """Prompt user to set the target."""
        console.print("\n[bold cyan]Set Target[/bold cyan]")
        console.print("-" * 40)
        
        target = Prompt.ask("Enter target (domain / IP / organization)").strip()
        
        if not target:
            console.print("[red]Error: Target cannot be empty[/red]")
            return
        
        self.target = target
        self.results = {}
        self.console_results = {}
        console.print(f"[green]✓ Target set to: {self.target}[/green]")
        time.sleep(1)
    
    def run_passive_recon(self):
        """Execute passive reconnaissance modules."""
        if not self.target:
            console.print("[red]Error: No target set. Please set a target first.[/red]")
            time.sleep(1)
            return
        
        console.print("\n[bold cyan]Running Passive Reconnaissance...[/bold cyan]")
        console.print("-" * 40)
        
        engine = Engine(self.target)
        passive_modules = [
            ("domains/whois", "WHOIS Lookup", "whois"),
            ("domains/asn", "ASN Enumeration", "asn"),
            ("subdomains/crtsh", "CRT.sh Subdomains", "crtsh"),
            ("subdomains/securitytrails", "SecurityTrails", "securitytrails"),
            ("dns/records", "DNS Records", "dns"),
            ("web/wayback", "Wayback Archives", "wayback"),
            ("web/urls", "URL Discovery", "urls"),
            ("domains/reverse_whois", "Reverse WHOIS", "reverse_whois"),
        ]
        
        all_results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Executing passive reconnaissance...", total=len(passive_modules))
            
            for module_path, module_name, key in passive_modules:
                start_time = time.time()
                
                # Update progress
                progress.update(task, description=f"Executing {module_name}...")
                
                # Run module
                result = engine.run_python_module(module_path)
                
                elapsed = time.time() - start_time
                
                if result and result.get("data"):
                    # Merge results without duplication
                    if key in self.console_results:
                        if isinstance(self.console_results[key], list) and isinstance(result.get("data"), list):
                            # Merge lists, remove duplicates
                            existing = set(self.console_results[key]) if all(isinstance(x, str) for x in self.console_results[key]) else self.console_results[key]
                            new_data = set(result["data"]) if all(isinstance(x, str) for x in result["data"]) else result["data"]
                            self.console_results[key] = list(existing.union(new_data))
                        elif isinstance(self.console_results[key], dict) and isinstance(result.get("data"), dict):
                            # Merge dicts
                            self.console_results[key].update(result["data"])
                    else:
                        self.console_results[key] = result.get("data")
                    
                    all_results.append(result)
                    console.print(f"[green]  ✓ {module_name:<25} ✓ {elapsed:.1f}s[/green]")
                else:
                    console.print(f"[yellow]  ○ {module_name:<25} ○ {elapsed:.1f}s[/yellow]")
                
                progress.advance(task)
        
        # Store results
        self.results = self.console_results.copy()
        
        console.print(f"\n[bold green]Passive reconnaissance complete![/bold green]")
        console.print(f"[bold]Modules executed: {len(all_results)}/{len(passive_modules)}[/bold]")
        time.sleep(2)
    
    def run_active_recon(self):
        """Execute active reconnaissance modules with confirmation."""
        if not self.target:
            console.print("[red]Error: No target set. Please set a target first.[/red]")
            time.sleep(1)
            return
        
        # Show warning and get confirmation
        console.print("\n[bold red]⚠️  WARNING: Active Scanning[/bold red]")
        console.print("-" * 60)
        console.print("[yellow]Active reconnaissance may:[/yellow]")
        console.print("  • Generate network traffic to target systems")
        console.print("  • Be detected by intrusion detection systems")
        console.print("  • Potentially be considered intrusive")
        console.print("  • Take longer to complete")
        console.print()
        
        if not Confirm.ask("Do you want to proceed with active reconnaissance?", default=False):
            console.print("[yellow]Active reconnaissance cancelled.[/yellow]")
            time.sleep(1)
            return
        
        console.print("\n[bold cyan]Running Active Reconnaissance...[/bold cyan]")
        console.print("-" * 40)
        
        engine = Engine(self.target)
        active_modules = [
            ("active/portscan", "Port Scanning", "portscan"),
            ("infra/shodan", "Shodan Search", "shodan"),
            ("infra/censys", "Censys Search", "censys"),
            ("cloud/buckets", "Cloud Buckets", "buckets"),
            ("js/secrets", "JS Secrets", "secrets"),
            ("web/params", "Parameter Discovery", "params"),
        ]
        
        all_results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Executing active reconnaissance...", total=len(active_modules))
            
            for module_path, module_name, key in active_modules:
                start_time = time.time()
                
                # Update progress
                progress.update(task, description=f"Executing {module_name}...")
                
                # Run module
                result = engine.run_python_module(module_path)
                
                elapsed = time.time() - start_time
                
                if result and result.get("data"):
                    # Merge results without duplication
                    if key in self.console_results:
                        if isinstance(self.console_results[key], list) and isinstance(result.get("data"), list):
                            existing = set(self.console_results[key]) if all(isinstance(x, (str, dict)) for x in self.console_results[key]) else self.console_results[key]
                            new_data = set(result["data"]) if all(isinstance(x, (str, dict)) for x in result["data"]) else result["data"]
                            self.console_results[key] = list(existing.union(new_data))
                        elif isinstance(self.console_results[key], dict) and isinstance(result.get("data"), dict):
                            self.console_results[key].update(result["data"])
                    else:
                        self.console_results[key] = result.get("data")
                    
                    all_results.append(result)
                    console.print(f"[green]  ✓ {module_name:<25} ✓ {elapsed:.1f}s[/green]")
                else:
                    console.print(f"[yellow]  ○ {module_name:<25} ○ {elapsed:.1f}s[/yellow]")
                
                progress.advance(task)
        
        # Update results
        self.results = self.console_results.copy()
        
        console.print(f"\n[bold green]Active reconnaissance complete![/bold green]")
        console.print(f"[bold]Modules executed: {len(all_results)}/{len(active_modules)}[/bold]")
        time.sleep(2)
    
    def show_results(self):
        """Display categorized results in a readable format."""
        if not self.target:
            console.print("[red]Error: No target set. Please set a target first.[/red]")
            time.sleep(1)
            return
        
        if not self.results:
            console.print("[yellow]No results available. Run reconnaissance first.[/yellow]")
            time.sleep(1)
            return
        
        self.clear_screen()
        
        console.print(Panel(f"[bold cyan]Reconnaissance Results for: {self.target}[/bold cyan]", style="cyan"))
        console.print()
        
        # Subdomains
        subdomains = self.results.get("crtsh", []) + self.results.get("securitytrails", [])
        if isinstance(self.results.get("whois"), dict):
            subdomains.extend(self.results.get("whois", {}).get("nameservers", []))
        subdomains = list(set(subdomains))
        if subdomains:
            console.print(Panel(f"[bold]Subdomains ({len(subdomains)})[/bold]\n" + "\n".join(sorted(subdomains)[:50]), 
                              title="[blue]🌐 Subdomains[/blue]", style="blue"))
            console.print()
        
        # DNS Records
        dns = self.results.get("dns", {})
        if dns:
            table = Table(title="[blue]📡 DNS Records[/blue]", box=box.SIMPLE)
            table.add_column("Record Type", style="cyan")
            table.add_column("Value", style="white")
            for record_type, records in dns.items():
                if isinstance(records, list):
                    for record in records[:10]:
                        table.add_row(record_type.upper(), str(record))
                else:
                    table.add_row(record_type.upper(), str(records))
            console.print(table)
            console.print()
        
        # WHOIS Info
        whois = self.results.get("whois", {})
        if whois and isinstance(whois, dict):
            table = Table(title="[blue]ℹ️ WHOIS Information[/blue]", box=box.SIMPLE)
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            
            important_fields = ["domain_name", "registrar", "creation_date", "expiration_date", "status"]
            for field in important_fields:
                if field in whois and whois[field]:
                    table.add_row(field.replace("_", " ").title(), str(whois[field])[:100])
            
            console.print(table)
            console.print()
        
        # ASN Info
        asn = self.results.get("asn", {})
        if asn and isinstance(asn, dict):
            table = Table(title="[blue]🔢 ASN Information[/blue]", box=box.SIMPLE)
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            
            for field, value in asn.items():
                if value and not field.startswith("_"):
                    table.add_row(field.replace("_", " ").title(), str(value)[:100])
            
            console.print(table)
            console.print()
        
        # Ports
        ports = self.results.get("portscan", [])
        if isinstance(self.results.get("shodan"), dict):
            shodan_ports = self.results["shodan"].get("ports", [])
            if shodan_ports:
                ports.extend(shodan_ports)
        if isinstance(self.results.get("censys"), dict):
            censys_ports = self.results["censys"].get("ports", [])
            if censys_ports:
                ports.extend(censys_ports)
        ports = list(set(ports))
        if ports:
            console.print(Panel(f"[bold]Ports ({len(ports)})[/bold]\n" + str(ports)[:500], 
                              title="[red]🔌 Ports[/red]", style="red"))
            console.print()
        
        # Endpoints / URLs
        endpoints = self.results.get("wayback", []) + self.results.get("urls", []) + self.results.get("params", {}).get("urls", [])
        endpoints = list(set(endpoints))
        if endpoints:
            console.print(Panel(f"[bold]Endpoints ({len(endpoints)})[/bold]\n" + "\n".join(sorted(endpoints)[:30]), 
                              title="[green]🔗 Endpoints[/green]", style="green"))
            console.print()
        
        # Secrets found
        secrets = self.results.get("secrets", [])
        if secrets:
            console.print(Panel(f"[bold]Secrets Found ({len(secrets)})[/bold]\n" + str(secrets)[:500], 
                              title="[red]🔓 Secrets[/red]", style="red"))
            console.print()
        
        # Cloud buckets
        buckets = self.results.get("buckets", [])
        if buckets:
            console.print(Panel(f"[bold]Cloud Buckets ({len(buckets)})[/bold]\n" + "\n".join(sorted(buckets)[:20]), 
                              title="[yellow]☁️ Cloud Buckets[/yellow]", style="yellow"))
            console.print()
        
        console.print("[dim]Press Enter to continue...[/dim]")
        input()
    
    def export_results(self):
        """Export results in the selected format."""
        if not self.target:
            console.print("[red]Error: No target set. Please set a target first.[/red]")
            time.sleep(1)
            return
        
        if not self.results:
            console.print("[yellow]No results available. Run reconnaissance first.[/yellow]")
            time.sleep(1)
            return
        
        console.print("\n[bold cyan]Export Results[/bold cyan]")
        console.print("-" * 40)
        console.print("[1] JSON")
        console.print("[2] CSV")
        console.print("[3] HTML")
        
        choice = Prompt.ask("Select export format", choices=["1", "2", "3"], default="1")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if choice == "1":
            filename = self.output_dir / f"{self.target}_{timestamp}.json"
            with open(filename, "w") as f:
                json.dump({
                    "target": self.target,
                    "timestamp": timestamp,
                    "results": self.results
                }, f, indent=2, default=str)
            console.print(f"[green]✓ Results exported to: {filename}[/green]")
        
        elif choice == "2":
            filename = self.output_dir / f"{self.target}_{timestamp}.csv"
            with open(filename, "w") as f:
                f.write("Category,Key,Value\n")
                for category, data in self.results.items():
                    if isinstance(data, dict):
                        for key, value in data.items():
                            f.write(f"{category},{key},{str(value).replace(',', ';')}\n")
                    elif isinstance(data, list):
                        for item in data:
                            f.write(f"{category},item,{str(item).replace(',', ';')}\n")
            console.print(f"[green]✓ Results exported to: {filename}[/green]")
        
        elif choice == "3":
            filename = self.output_dir / f"{self.target}_{timestamp}.html"
            
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowRecon Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #00ff88; }}
        h2 {{ color: #00d4ff; margin-top: 30px; }}
        .section {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }}
        .data {{ background: #0f0f23; padding: 10px; border-radius: 5px; font-family: monospace; }}
        pre {{ color: #aaffaa; }}
        a {{ color: #00d4ff; }}
        .warning {{ color: #ff6b6b; }}
    </style>
</head>
<body>
    <h1>🔍 ShadowRecon Report</h1>
    <p><strong>Target:</strong> {self.target}</p>
    <p><strong>Timestamp:</strong> {timestamp}</p>
"""
            
            for category, data in self.results.items():
                html_content += f'<div class="section"><h2>{category}</h2><div class="data"><pre>{json.dumps(data, indent=2, default=str)}</pre></div></div>\n'
            
            html_content += "</body></html>"
            
            with open(filename, "w") as f:
                f.write(html_content)
            
            console.print(f"[green]✓ Results exported to: {filename}[/green]")
        
        time.sleep(2)
    
    def clear_session(self):
        """Clear the current session."""
        if not Confirm.ask("Are you sure you want to clear the session?"):
            return
        
        self.target = None
        self.results = {}
        self.console_results = {}
        console.print("[green]✓ Session cleared[/green]")
        time.sleep(1)
    
    def run(self):
        """Main application loop."""
        while True:
            self.print_banner()
            self.print_menu()
            
            choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")
            
            if choice == "1":
                self.set_target()
            elif choice == "2":
                self.run_passive_recon()
            elif choice == "3":
                self.run_active_recon()
            elif choice == "4":
                self.show_results()
            elif choice == "5":
                self.export_results()
            elif choice == "6":
                self.clear_session()
            elif choice == "7":
                console.print("\n[bold cyan]Thank you for using ShadowRecon![/bold cyan]")
                console.print("[dim]Exiting...[/dim]")
                break


def main():
    """Entry point."""
    try:
        app = ShadowRecon()
        app.run()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]Interrupted by user. Exiting...[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Error: {e}[/bold red]")
        if "--debug" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

