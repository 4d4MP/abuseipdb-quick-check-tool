# AbuseIPDB Quick Check Tool

A modern command-line tool that queries the [AbuseIPDB](https://www.abuseipdb.com/)
API to assess IP addresses for reported abuse. Features a rich terminal UI with
colored output, animated progress indicators, and flexible input/output options.

## Features

- **Quick lookups**: Pass a single IP as an argument — `python abuseipdb_cli.py 8.8.8.8`
- **Flexible input**: Enter IPs interactively (comma/semicolon-separated) or
  provide a CSV file via `-i`.
- **Parallel queries**: Up to ten requests run concurrently with an animated
  progress bar.
- **Rich terminal UI**: Color-coded tables, risk-level summary panel, and
  styled prompts.
- **API key caching**: The key is cached for 1 hour after first entry so you
  don't have to re-enter it every time. Use `--clear-key` to reset.
- **Script-friendly**: Provide the key via the `ABUSEIPDB_API_KEY` env var,
  use `--json` for machine-readable output, or `--no-color` to disable
  formatting.
- **Input validation**: IPv4 and IPv6 addresses are validated before requests.
- **Configurable filtering**: Use `-t N` to show only IPs with a confidence
  score ≥ N, or `-x` as a shortcut for `-t 100`.
- **Verbose mode**: Use `-v` to see extra fields (ISP, lastReportedAt,
  numDistinctUsers).
- **CSV output**: Save results to a CSV file with `-o`.

## Requirements

- Python 3.8 or higher
- `requests` library
- `rich` library

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Quick single-IP lookup
python abuseipdb_cli.py 8.8.8.8

# Interactive mode (prompts for IPs in a loop)
python abuseipdb_cli.py

# Read IPs from a CSV file and print results
python abuseipdb_cli.py -i ips.csv

# Read from CSV and write results to another CSV file
python abuseipdb_cli.py -i ips.csv -o results.csv

# Show only high-confidence results (score ≥ 50)
python abuseipdb_cli.py -i ips.csv -t 50

# Verbose output with extra fields
python abuseipdb_cli.py -i ips.csv -v

# JSON output for piping
python abuseipdb_cli.py -i ips.csv --json

# Limit report age to 30 days
python abuseipdb_cli.py -i ips.csv -d 30

# Clear cached API key
python abuseipdb_cli.py --clear-key

# Plain output (no colors)
python abuseipdb_cli.py -i ips.csv --no-color
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `ip` (positional) | Single IP address for a quick lookup |
| `-i` / `--input-file` | CSV file with one IP per line |
| `-o` / `--output-file` | Write results to a CSV file |
| `-t N` / `--threshold N` | Only show IPs with score ≥ N |
| `-x` / `--exclude` | Shortcut for `-t 100` |
| `-d N` / `--days N` | Max age in days for reports (default: 90) |
| `-v` / `--verbose` | Show ISP, lastReportedAt, numDistinctUsers |
| `--json` | Output as JSON |
| `--no-color` | Disable colored output |
| `--clear-key` | Clear cached API key and re-prompt |
| `--version` | Show version |
| `-h` / `--help` | Show help |

## API Key

The tool resolves the API key in this order:

1. `ABUSEIPDB_API_KEY` environment variable (best for scripting)
2. Cached key from `~/.config/abuseipdb/.api_key` (valid for 1 hour)
3. Interactive prompt (the entered key is then cached)

Use `--clear-key` to delete the cached key and enter a new one.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE)
file for details.
