# Security Incident Timeline Analyzer

A Python-based CLI tool that ingests security logs (Linux auth.log, with extensible support for Nginx and libpcap), detects attack patterns using sophisticated heuristics, and generates beautiful interactive HTML timeline reports.

## The Concept

Instead of manually scrolling through thousands of raw log lines, this tool ingests a raw firewall, server, or Windows Event log file, parses out indicators of compromise (IoCs), and outputs a beautiful interactive HTML timeline of the incident.

Perfect for **incident response analysts, security engineers, and blue teamers** who need to quickly understand the attack chain and timeline of compromise.

## Architecture

```
[ Raw Logs ] (auth.log, Nginx, PCAP data)
     │
     ▼
┌────────────────────────────────────────────────────────┐
│ 1. INGESTION & PARSING ENGINE (core/parsers.py)       │
│    - Regex pattern extraction                          │
│    - Normalization into unified schema                 │
│    - Extensible parser interface for multiple formats  │
└────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────┐
│ 2. HEURISTIC DETECTION & ENRICHMENT (core/engine.py)  │
│    - Brute Force Detection (sliding time-window)       │
│    - Impossible Travel Detection (geolocation-aware)   │
│    - IP Geolocation Enrichment (ip-api.com)           │
└────────────────────────────────────────────────────────┘
     │
     ▼
┌────────────────────────────────────────────────────────┐
│ 3. VISUALIZATION ENGINE (core/reporter.py)            │
│    - Jinja2 HTML template rendering                    │
│    - Interactive timeline component                    │
│    - KPI metrics dashboard                             │
└────────────────────────────────────────────────────────┘
     │
     ▼
[ Interactive HTML Report / Dashboard ]
```

## Data Schema

Every parsed security event is normalized into a unified format:

```python
{
    "timestamp": "2026-05-20T09:15:45",    # ISO 8601 format
    "source_ip": "192.168.1.100",          # Attacker/source IP
    "destination_ip": null,                # Destination (if applicable)
    "event_type": "AUTH_FAILURE",          # AUTH_SUCCESS, AUTH_FAILURE, ALERT_*
    "severity": "INFO",                    # INFO, LOW, MEDIUM, HIGH, CRITICAL
    "description": "Failed SSH login...",  # Human-readable summary
    "metadata": {                          # Flexible enrichment data
        "user": "root",
        "port": "54001",
        "country": "United States",
        "city": "Mountain View",
        "isp": "Google LLC"
    }
}
```

## Detection Features

### Brute Force Detection
- Groups authentication attempts by source IP
- For each successful login, checks the preceding 5-minute window
- If ≥3 failed attempts detected before success → generates **ALERT_BRUTE_FORCE_SUCCESS** (CRITICAL)
- Marks the successful login as HIGH severity

### Impossible Travel Detection  
- Tracks per-user login locations and timestamps
- Detects when same user logs in from different countries within 15 minutes
- Generates **ALERT_IMPOSSIBLE_TRAVEL** (HIGH severity)
- Example: User logs in from California, then 10 minutes later from Japan

### IP Geolocation Enrichment
- Queries [ip-api.com](http://ip-api.com) for each unique IP
- Extracts: country, city, ISP
- Includes in-memory caching to respect API rate limits
- Gracefully handles API failures with fallback values

## Installation

### Prerequisites
- Python 3.8+
- pip or conda

### Setup

```bash
# Clone the repository (if applicable)
cd auto-log-incident-report

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Analyze a log file with default settings
python analyzer.py --log-file /var/log/auth.log
```

This generates an interactive HTML report at `data/output_timeline.html`.

### Advanced Options

```bash
# Specify custom output location
python analyzer.py --log-file /var/log/auth.log --output data/incident_2026-05-20.html

# Disable geolocation enrichment (faster for testing)
python analyzer.py --log-file sample_data/sample_auth.log --no-geolocation

# Use sample test data
python analyzer.py --log-file sample_data/sample_auth.log
```

### CLI Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `--log-file` | ✓ | — | Path to the security log file |
| `--output` | ✗ | `data/output_timeline.html` | Output HTML file path |
| `--parser-type` | ✗ | `auto` | Log format: `auth-log`, `nginx`, or `auto` |
| `--no-geolocation` | ✗ | — | Skip geolocation enrichment (faster) |

## Sample Incident Report

A pre-generated sample report with test data is included:

### Viewing the Report

1. **Generate the sample report:**
   ```bash
   python analyzer.py --log-file sample_data/sample_auth.log
   ```

2. **Open in your browser:**
   ```bash
   open data/output_timeline.html  # macOS
   # or
   xdg-open data/output_timeline.html  # Linux
   # or manually navigate to the file in your browser
   ```

### Sample Report Features

The generated HTML dashboard includes:

- **KPI Cards**: Quick view of total events, failed logins, and critical alerts
- **Interactive Timeline**: Vertical, chronological event cards with collapsible details
- **Severity Visualization**:
  - 🔴 **CRITICAL**: Thick red border with soft glow (brute force successes)
  - 🟠 **HIGH**: Bold amber border (high-risk authentication)
  - 🟢 **LOW/INFO**: Clean gray styling (routine events)
- **Live Filtering**:
  - Show All Events
  - Alerts Only (shows detected attack patterns)
  - High/Critical Only (focuses on the most concerning events)
- **Event Details**: Expandable cards showing user, location, ISP, source IP, and full description

### Example: What the Sample Report Shows

The included `sample_data/sample_auth.log` contains:

- **35+ authentication events** (mix of routine and malicious activity)
- **1 Brute Force Attack**: 9 failed password attempts from `192.168.1.100` followed by successful root login
  - Marked as CRITICAL alert
  - Summary shows the attack chain: "9 failed attempts from 192.168.1.100 followed by successful login for 'root'"
- **2 Impossible Travel Events**: User `alice` logging in from US then Japan within minutes
  - Marked as HIGH severity
  - Summary includes timestamp delta and geographic jump details

## Project Structure

```
auto-log-incident-report/
├── analyzer.py                    # CLI entry point
├── requirements.txt               # Python dependencies
├── README.md                      # This file
specifications
│
├── core/
│   ├── __init__.py
│   ├── parsers.py                # Log parsing & schema
│   ├── engine.py                 # Detection & enrichment
│   └── reporter.py               # HTML report generation
│
├── templates/
│   └── timeline_template.html    # Jinja2 dashboard template
│
├── sample_data/
│   ├── sample_auth.log           # Test data
│   └── output_timeline.html      # Generated report
│
└── data/
    └── output_timeline.html      # Default output location
```

## How It Works

1. **Parse** (`core/parsers.py`):
   - Reads log file line-by-line
   - Extracts using regex patterns (e.g., `Failed password for <user> from <ip>`)
   - Normalizes to unified LogEvent schema

2. **Detect** (`core/engine.py`):
   - Converts events to pandas DataFrame
   - Queries geolocation API for each unique IP (with caching)
   - Runs brute force detection: groups by IP, checks 5-min windows
   - Runs impossible travel detection: tracks per-user state across locations
   - Generates synthetic alert events for detected threats

3. **Report** (`core/reporter.py`):
   - Renders Jinja2 template with event data
   - Converts events to JSON for JavaScript
   - Calculates KPI metrics
   - Writes standalone HTML file

4. **Visualize** (browser):
   - Loads HTML report
   - JavaScript renders timeline with filtering
   - User can expand cards, apply filters, review details

## Extensibility

The parser architecture supports multiple log formats:

### Current Parsers
- **AuthLogParser**: Linux `/var/log/auth.log` (SSH events)

### Future Parsers (Ready to Implement)
- **NginxLogParser**: HTTP access/error logs
- **LibpcapParser**: Network packet captures
- **WindowsEventParser**: Windows Event Viewer logs

### Adding a New Parser

```python
from core.parsers import BaseParser, LogEvent

class MyCustomParser(BaseParser):
    def parse(self, lines: List[str]) -> List[LogEvent]:
        events = []
        for line in lines:
            # Your parsing logic here
            event = LogEvent(...)
            events.append(event)
        return events
```

Then use it:
```bash
python analyzer.py --log-file mylog.txt --parser-type my-custom
```

## Performance Considerations

- **Geolocation API Rate Limits**: Free tier allows ~45 requests/minute. The tool implements in-memory caching during execution.
- **Large Logs**: Tested with 100+ events. For production logs with millions of entries, consider streaming or batch processing.
- **API Failures**: Gracefully falls back to "Unknown" for geolocation if API is unavailable.

## Security Notes

- Generated HTML reports are **standalone files** with no external dependencies (except CDN Tailwind CSS)
- Reports contain **no sensitive data** outside the original log metadata
- IP geolocation is via public API; consider privacy implications for internal IPs
- Events are not persisted anywhere except the output HTML file

## Troubleshooting

### No events parsed
- Ensure log file exists and is readable: `cat sample_data/sample_auth.log`
- Check log format matches expected regex patterns
- Run with `--no-geolocation` to skip API calls

### Impossible travel not detected
- Requires geolocation enrichment enabled (default)
- Needs events from different countries within 15 minutes for same user
- Check that users have location data in metadata (visible in HTML report)

### Slow performance
- Use `--no-geolocation` to skip API calls
- Check IP address uniqueness (many IPs = many API calls)

### API rate limiting
- Tool implements caching; if still hitting limits, add delays or use `--no-geolocation`

## License

This project is part of a security incident analysis portfolio.

## Contributing

The codebase is designed for extensibility. Key areas for contribution:

1. **New parsers** (Nginx, libpcap, Windows Event Log)
2. **Additional heuristics** (data exfiltration, privilege escalation patterns)
3. **UI enhancements** (export to CSV/JSON, timeline zoom, date range filters)
4. **Performance optimizations** (streaming parsers, async geolocation)
