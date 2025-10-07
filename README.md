# AbuseIPDB Quick Check Tool

This command‑line tool queries the [AbuseIPDB](https://www.abuseipdb.com/) API to
assess IP addresses for reported abuse. It supports interactive entry of IPs
or reading them from a CSV file, runs up to ten API requests in parallel, and
displays a progress bar during execution. Results can be printed as a
well‑formatted table in the console or written directly to a CSV file.

## Features

- **Flexible input**: Enter a comma/semicolon‑separated list of IPs interactively
  or provide an input CSV file via a flag.
- **Parallel queries**: Up to ten queries are dispatched concurrently for
  improved performance.
- **Progress indicator**: A terminal progress bar shows how many queries have
  completed.
- **Script-friendly authentication**: Provide the API key via the
  `ABUSEIPDB_API_KEY` environment variable or interactively when omitted.
- **Input validation**: IPv4 and IPv6 addresses are validated before requests
  are sent so malformed entries are skipped with a clear message.
- **Filter by confidence**: Optionally exclude results with an
  `abuseConfidenceScore` less than `100` using the `-x/--exclude` flag.
- **CSV output**: Save results to a CSV file instead of printing a table.

## Requirements

- Python 3.8 or higher
- `requests` library (`pip install requests`)

## Usage

```bash
# interactive mode (prompts for IPs and API key)
python abuseipdb_cli.py

# read IPs from a CSV file and print results
python abuseipdb_cli.py -i ips.csv

# read from CSV and write results to another CSV file
python abuseipdb_cli.py -i ips.csv -o results.csv

# exclude results with confidence score below 100
python abuseipdb_cli.py -i ips.csv -x

# display command help without prompting for API key
python abuseipdb_cli.py -h
```

When run without `-i/--input-file`, the script prompts for IP addresses and
continues to run in a loop until you provide an empty input. When an input
file is specified, the program processes the file once and exits.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE)
file for details.
