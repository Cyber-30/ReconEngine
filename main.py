import argparse
import sys
from core.orchestrator import Orchestrator
from utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(
        prog="recon-engine",
        description="🔍 ReconEngine - Powerful reconnaissance framework for security research",
        epilog="""
Examples:
  python3 main.py example.com --passive
  python3 main.py example.com --all
  python3 main.py 192.168.1.1 --active --output html
  python3 main.py company.com --all --output json
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("target", help="Target domain / IP / organization")
    parser.add_argument("--passive", action="store_true",
                        help="Run passive reconnaissance only")
    parser.add_argument("--active", action="store_true",
                        help="Run active reconnaissance (opt-in)")
    parser.add_argument("--all", action="store_true",
                        help="Run both passive and active reconnaissance")
    parser.add_argument("--output", choices=["json", "html", "csv"], default="json",
                        help="Output format (default: json)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Module timeout in seconds (default: 300)")

    args = parser.parse_args()

    # Validate arguments
    if not any([args.passive, args.active, args.all]):
        parser.error("At least one of --passive, --active, or --all is required")

    # Setup logging
    log_file = "logs/recon.log"
    setup_logger(debug=args.debug, log_file=log_file)

    # Run orchestrator
    try:
        orchestrator = Orchestrator(args)
        results = orchestrator.run()

        # Print summary
        if results:
            print("\n" + "=" * 60)
            print("📊 RECON SUMMARY")
            print("=" * 60)
            print(f"Target: {results['target']}")
            print(f"Modules Run: {results['results_count']}")
            print(f"Output: {results['output_format']}")
            print("=" * 60)

    except KeyboardInterrupt:
        print("\n⚠️  Reconnaissance interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
