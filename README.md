# ReconEngine - Powerful Reconnaissance Framework

🔍 A comprehensive reconnaissance framework for security research and penetration testing.

## Features

### Passive Reconnaissance
- **WHOIS Lookup** - Domain registration and contact information
- **DNS Records** - A, AAAA, MX, NS, TXT, SOA, SRV, CNAME records
- **Subdomain Enumeration** - CRT.sh, SecurityTrails integration
- **ASN Lookup** - Autonomous System Number information
- **Wayback Machine** - Historical URL discovery
- **Reverse WHOIS** - Find domains owned by same entity

### Active Reconnaissance
- **Port Scanning** - Multi-threaded port scanner with banner grabbing
- **Shodan Integration** - Host and vulnerability data
- **Censys Integration** - Certificate and service enumeration
- **IP Intelligence** - Geolocation and reputation data
- **Cloud Bucket Discovery** - S3, Azure, GCP bucket enumeration
- **JavaScript Analysis** - Secret scanning and endpoint discovery
- **Parameter Discovery** - Sensitive URL parameter detection

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ReconEngine.git
cd ReconEngine

# Install dependencies
pip install python-whois dnspython requests

# Make scripts executable
chmod +x bin/*
```

## Usage

### Basic Commands

```bash
# Passive reconnaissance only
python3 main.py example.com --passive

# Active reconnaissance only
python3 main.py example.com --active

# Full reconnaissance (passive + active)
python3 main.py example.com --all

# Different output formats
python3 main.py example.com --all --output json
python3 main.py example.com --all --output html
python3 main.py example.com --all --output csv

# Debug mode
python3 main.py example.com --all --debug
```

### Output Formats

- **JSON** - Structured data for further processing
- **HTML** - Visual report with dark theme
- **CSV** - Spreadsheet-compatible format

## Configuration

Edit `config/api_keys.yaml` to add API keys for enhanced functionality:

```yaml
shodan:
  key: "YOUR_SHODAN_API_KEY"

virustotal:
  key: "YOUR_VIRUSTOTAL_API_KEY"

securitytrails:
  key: "YOUR_SECURITYTRAILS_API_KEY"
```

### Free APIs (No Key Required)
- CRT.sh for subdomains
- ip-api.com for geolocation
- Team Cymru for ASN lookup
- Wayback Machine for archives

## Project Structure

```
ReconEngine/
├── main.py              # CLI entry point
├── core/
│   ├── orchestrator.py  # Main execution controller
│   ├── engine.py        # Module execution engine
│   └── correlator.py    # Results correlation
├── modules/
│   ├── domains/         # Domain-based modules
│   │   ├── whois.py
│   │   ├── asn.py
│   │   └── reverse_whois.py
│   ├── subdomains/      # Subdomain enumeration
│   │   ├── crtsh.py
│   │   └── securitytrails.py
│   ├── dns/             # DNS enumeration
│   │   └── records.py
│   ├── active/          # Active reconnaissance
│   │   └── portscan.py
│   ├── infra/           # Infrastructure modules
│   │   ├── shodan.py
│   │   ├── censys.py
│   │   └── ipintel.py
│   ├── web/             # Web reconnaissance
│   │   ├── urls.py
│   │   ├── wayback.py
│   │   └── params.py
│   ├── cloud/           # Cloud storage
│   │   └── buckets.py
│   └── js/              # JavaScript analysis
│       ├── secrets.py
│       └── jsfinder.py
├── config/
│   └── api_keys.yaml    # API configuration
├── output/              # Generated reports
├── logs/                # Execution logs
└── utils/
    └── logger.py        # Logging utilities
```

## Module Output Format

All modules return JSON in this format:

```json
{
    "module": "module.name",
    "target": "example.com",
    "timestamp": "2024-01-01T00:00:00",
    "data": {
        // Module-specific data
    }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your module following the existing pattern
4. Submit a pull request

## Legal Notice

⚠️ **For authorized security research only.** 
Use this tool only on targets you have permission to test.

## License

MIT License - See LICENSE file for details

