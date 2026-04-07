#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""
AbuseIPDB Quick Check Tool
==========================

A modern command-line utility that queries the AbuseIPDB API to assess IP
addresses for abuse activity.  It features a rich terminal UI with colored
output, animated progress indicators, and flexible input/output options.

Usage:
    python abuseipdb_cli.py 8.8.8.8                    # quick single-IP lookup
    python abuseipdb_cli.py                             # interactive prompt
    python abuseipdb_cli.py -i ips.csv                  # read IPs from CSV
    python abuseipdb_cli.py -i ips.csv -o out.csv       # write results to CSV
    python abuseipdb_cli.py -i ips.csv -t 50 -v         # threshold + verbose
    python abuseipdb_cli.py -i ips.csv --json            # JSON output for piping
    cat ips.txt | python abuseipdb_cli.py -              # read IPs from stdin
    python abuseipdb_cli.py -i ips.csv --sort score      # sort by score
    python abuseipdb_cli.py -i ips.csv --export report.html  # HTML report

The API key is resolved in order: ABUSEIPDB_API_KEY env var → cached key
(valid for 1 hour) → interactive prompt.

License: Apache License 2.0
"""

from __future__ import annotations

import argparse
import csv
import html as html_mod
import json
import os
import re
import stat
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial
from pathlib import Path
import ipaddress

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TaskProgressColumn,
)
from rich.prompt import Prompt
from rich.text import Text
from rich import box

try:
    import argcomplete

    _HAS_ARGCOMPLETE = True
except ImportError:
    _HAS_ARGCOMPLETE = False

__version__ = "2.1.0"

# ---------------------------------------------------------------------------
# Column definitions
# ---------------------------------------------------------------------------

HEADERS_DEFAULT = [
    "ipAddress",
    "abuseConfidenceScore",
    "totalReports",
    "domain",
    "countryCode",
    "usageType",
    "isTor",
]

HEADERS_VERBOSE = HEADERS_DEFAULT + [
    "isp",
    "lastReportedAt",
    "numDistinctUsers",
]

ENV_API_KEY = "ABUSEIPDB_API_KEY"
CACHE_DIR = Path.home() / ".config" / "abuseipdb"
CACHE_FILE = CACHE_DIR / ".api_key"
CACHE_TTL = 3600  # 1 hour


def get_headers(verbose: bool) -> list[str]:
    """Return the appropriate header list."""
    return HEADERS_VERBOSE if verbose else HEADERS_DEFAULT


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="AbuseIPDB Quick Check Tool — fast IP reputation lookups with a modern CLI.",
        epilog=(
            "Examples:\n"
            "  python abuseipdb_cli.py 8.8.8.8\n"
            "  python abuseipdb_cli.py -i ips.csv -v\n"
            "  python abuseipdb_cli.py -i ips.csv -o out.csv -t 50\n"
            "  python abuseipdb_cli.py --json -i ips.csv\n"
            "  cat ips.txt | python abuseipdb_cli.py -\n"
            "  python abuseipdb_cli.py -i ips.csv --sort score\n"
            "  python abuseipdb_cli.py -i ips.csv --export report.html\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "ip",
        nargs="?",
        default=None,
        help="Single IP address for a quick lookup.",
    )
    parser.add_argument(
        "-i",
        "--input-file",
        help="Path to a CSV file containing one IP address per line.",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        help="Path to a CSV file to write results instead of printing them.",
    )
    parser.add_argument(
        "-x",
        "--exclude",
        action="store_true",
        help="Exclude results with abuseConfidenceScore < 100 (shortcut for -t 100).",
    )
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=None,
        metavar="N",
        help="Only show results with abuseConfidenceScore >= N.",
    )
    parser.add_argument(
        "-d",
        "--days",
        type=int,
        default=90,
        metavar="N",
        help="Max age in days for abuse reports (default: 90).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show additional fields: ISP, lastReportedAt, numDistinctUsers.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON (for piping).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (useful for scripts/piping).",
    )
    parser.add_argument(
        "--sort",
        choices=["score", "reports", "country", "ip"],
        default=None,
        help="Sort results by field (score, reports, country, ip).",
    )
    parser.add_argument(
        "--export",
        metavar="FILE.html",
        default=None,
        help="Export results as a self-contained HTML report.",
    )
    parser.add_argument(
        "--clear-key",
        action="store_true",
        help="Clear the cached API key and prompt for a new one.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    if _HAS_ARGCOMPLETE:
        argcomplete.autocomplete(parser)

    return parser.parse_args()


# ---------------------------------------------------------------------------
# API key caching
# ---------------------------------------------------------------------------


def _load_cached_key() -> str | None:
    """Return the cached API key if it exists and has not expired."""
    try:
        data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        if time.time() < data.get("expires", 0):
            return data.get("key", "").strip() or None
    except (OSError, json.JSONDecodeError, KeyError):
        pass
    return None


def _save_cached_key(key: str) -> None:
    """Persist the API key with a 1-hour TTL."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"key": key, "expires": time.time() + CACHE_TTL})
        CACHE_FILE.write_text(payload, encoding="utf-8")
        CACHE_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        pass  # best-effort caching


def _clear_cached_key() -> None:
    """Delete the cached key file."""
    try:
        CACHE_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def resolve_api_key(console: Console, clear_cache: bool = False) -> str:
    """Return the AbuseIPDB API key from env → cache → interactive prompt.

    The key is cached to ``~/.config/abuseipdb/.api_key`` for 1 hour so
    users don't have to re-enter it on every invocation.
    """
    if clear_cache:
        _clear_cached_key()
        console.print("[yellow]Cached API key cleared.[/]")

    # 1. Environment variable always wins
    env_key = os.environ.get(ENV_API_KEY, "").strip()
    if env_key:
        return env_key

    # 2. Check cache
    cached = _load_cached_key()
    if cached:
        console.print("[dim]Using cached API key (valid for up to 1 hour).[/]")
        return cached

    # 3. Interactive prompt → cache
    key = Prompt.ask(
        "[bold cyan]Enter your AbuseIPDB API key[/]", password=True, console=console
    )
    _save_cached_key(key)
    return key


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------


def normalize_ip(ip: str) -> str | None:
    """Return a stripped IP string or ``None`` if invalid."""
    sanitized = ip.strip().strip("'\"")
    if not sanitized:
        return None
    try:
        ipaddress.ip_address(sanitized)
    except ValueError:
        return None
    return sanitized


def read_ips_from_csv(path: str, console: Console) -> list[str]:
    """Read IP addresses from a CSV file (one per line)."""
    ips: list[str] = []
    invalid_count = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                ip = normalize_ip(raw_line)
                if ip:
                    ips.append(ip)
                else:
                    invalid_count += 1
    except OSError as e:
        console.print(f"[bold red]Error:[/] Could not read CSV file '{path}': {e}")
        return []
    if invalid_count:
        console.print(
            f"[yellow]Warning:[/] Skipped {invalid_count} "
            f"entr{'y' if invalid_count == 1 else 'ies'} "
            "that were not valid IP addresses."
        )
    return ips


def read_ips_from_stdin(console: Console) -> list[str]:
    """Read IP addresses from stdin (one per line, or comma/semicolon-separated)."""
    ips: list[str] = []
    invalid_count = 0
    for raw_line in sys.stdin:
        for chunk in re.split(r"[;,]", raw_line):
            chunk = chunk.strip()
            if not chunk:
                continue
            ip = normalize_ip(chunk)
            if ip:
                ips.append(ip)
            else:
                invalid_count += 1
    if invalid_count:
        console.print(
            f"[yellow]Warning:[/] Skipped {invalid_count} "
            f"entr{'y' if invalid_count == 1 else 'ies'} "
            "from stdin that were not valid IP addresses."
        )
    return ips


def get_ip_list_from_prompt(console: Console) -> list[str]:
    """Prompt the user for IP addresses separated by commas or semicolons."""
    ip_input = Prompt.ask(
        "[bold cyan]Enter IPs[/] [dim](comma/semicolon-separated, empty to exit)[/]",
        default="",
        console=console,
    ).strip()
    if not ip_input:
        return []
    ip_list = re.split(r"[;,]", ip_input)
    sanitized: list[str] = []
    for raw_ip in ip_list:
        ip = normalize_ip(raw_ip)
        if ip:
            sanitized.append(ip)
    if len(sanitized) != len([ip for ip in ip_list if ip.strip()]):
        console.print(
            "[yellow]Warning:[/] One or more entries were ignored because they are not valid IPs."
        )
    return sanitized


# ---------------------------------------------------------------------------
# API interaction
# ---------------------------------------------------------------------------


def build_error_result(ip: str, message: str) -> dict:
    """Return a uniform error payload for downstream display."""
    return {
        "ipAddress": ip,
        "abuseConfidenceScore": "ERR",
        "totalReports": "-",
        "domain": message,
        "countryCode": "-",
        "usageType": "-",
        "isTor": "-",
        "isp": "-",
        "lastReportedAt": "-",
        "numDistinctUsers": "-",
    }


# Shared mutable state for rate-limit info (updated from worker threads).
_rate_limit_info: dict[str, str] = {}
_rate_limit_lock = __import__("threading").Lock()


def check_ip(
    session: requests.Session,
    api_key: str,
    ip: str,
    *,
    max_age_days: int = 90,
) -> dict | None:
    """Query a single IP address via the AbuseIPDB API."""
    ip = normalize_ip(ip)
    if not ip:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}

    try:
        resp = session.get(
            url,
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            timeout=10,
        )
        # Capture rate-limit headers from the most recent response
        with _rate_limit_lock:
            for hdr in ("X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"):
                val = resp.headers.get(hdr)
                if val is not None:
                    _rate_limit_info[hdr] = val
        resp.raise_for_status()
        return resp.json().get("data", {})
    except requests.exceptions.HTTPError as http_err:
        return build_error_result(ip, f"HTTP error: {http_err}")
    except requests.exceptions.ConnectionError as ce:
        return build_error_result(ip, f"Connection error: {ce}")
    except requests.exceptions.Timeout:
        return build_error_result(ip, "Request timeout")
    except requests.exceptions.RequestException as err:
        return build_error_result(ip, f"Unexpected error: {err}")


def fetch_results(
    ip_list: list[str],
    api_key: str,
    max_age_days: int = 90,
    console: Console | None = None,
) -> list[dict]:
    """Fetch results for a list of IPs concurrently with a Rich progress bar."""
    c = console or Console()
    total = len(ip_list)
    results_list: list[dict | None] = [None] * total

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=c,
    ) as progress:
        task = progress.add_task("Querying AbuseIPDB…", total=total)

        with requests.Session() as session:
            with ThreadPoolExecutor(max_workers=10) as executor:
                worker = partial(
                    check_ip, session, api_key, max_age_days=max_age_days
                )
                future_to_idx = {
                    executor.submit(worker, ip): idx
                    for idx, ip in enumerate(ip_list)
                }
                for future in as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    data = future.result()
                    if data:
                        results_list[idx] = data
                    progress.update(task, advance=1)

    return [r for r in results_list if r]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def print_table(ip_results: list[dict], headers: list[str], console: Console) -> None:
    """Print results as a Rich-formatted table with color-coded risk levels."""
    table = Table(
        title="AbuseIPDB Results",
        box=box.ROUNDED,
        header_style="bold cyan",
        show_lines=True,
        title_style="bold white",
    )
    for h in headers:
        table.add_column(h)

    for result in ip_results:
        score = result.get("abuseConfidenceScore", "N/A")
        if isinstance(score, int):
            if score >= 75:
                style = "bold red"
            elif score >= 50:
                style = "yellow"
            elif score > 0:
                style = "white"
            else:
                style = "bold green"
        else:
            style = "dim"

        row = [str(result.get(h, "N/A")) for h in headers]
        table.add_row(*row, style=style)

    console.print()
    console.print(table)


def write_csv(path: str, rows: list[dict], headers: list[str], console: Console) -> None:
    """Write results to a CSV file."""
    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            for r in rows:
                writer.writerow({k: r.get(k, "N/A") for k in headers})
        console.print(f"[green]Success:[/] Wrote {len(rows)} rows to '{path}'.")
    except OSError as e:
        console.print(f"[bold red]Error:[/] Failed to write CSV '{path}': {e}")


def print_summary(rows: list[dict], console: Console) -> None:
    """Print a summary panel with risk-level statistics."""
    total = len(rows)
    if total == 0:
        console.print("[dim]No results to summarize.[/]")
        return

    scores: list[int] = []
    for r in rows:
        try:
            scores.append(int(r.get("abuseConfidenceScore", 0)))
        except (ValueError, TypeError):
            pass

    high_risk = sum(1 for s in scores if s >= 75)
    medium_risk = sum(1 for s in scores if 50 <= s < 75)
    low_risk = sum(1 for s in scores if 0 < s < 50)
    clean = sum(1 for s in scores if s == 0)
    errors = total - len(scores)

    parts = [
        f"[bold]Total:[/] {total}",
        f"[bold red]High (≥75):[/] {high_risk}",
        f"[bold yellow]Medium (50-74):[/] {medium_risk}",
        f"[white]Low (1-49):[/] {low_risk}",
        f"[bold green]Clean (0):[/] {clean}",
    ]
    if errors:
        parts.append(f"[dim]Errors:[/] {errors}")

    console.print(
        Panel(
            "  ".join(parts),
            title="Summary",
            border_style="blue",
            expand=False,
        )
    )


def print_rate_limit(console: Console) -> None:
    """Display API rate-limit information if available."""
    info = _rate_limit_info.copy()
    if not info:
        return
    limit = info.get("X-RateLimit-Limit", "?")
    remaining = info.get("X-RateLimit-Remaining", "?")
    retry = info.get("Retry-After")

    try:
        remaining_int = int(remaining)
        limit_int = int(limit)
        pct = remaining_int / limit_int * 100 if limit_int else 0
        if pct <= 10:
            color = "bold red"
        elif pct <= 30:
            color = "yellow"
        else:
            color = "green"
    except (ValueError, TypeError):
        color = "dim"

    parts = [f"[{color}]{remaining}[/]/{limit} requests remaining"]
    if retry:
        parts.append(f"  [dim](resets in {retry}s)[/]")
    console.print(
        Panel("".join(parts), title="API Rate Limit", border_style="dim", expand=False)
    )


def sort_results(rows: list[dict], sort_key: str | None) -> list[dict]:
    """Sort result rows by the given key."""
    if not sort_key:
        return rows

    key_map = {
        "score": "abuseConfidenceScore",
        "reports": "totalReports",
        "country": "countryCode",
        "ip": "ipAddress",
    }
    field = key_map.get(sort_key)
    if not field:
        return rows

    def sort_val(row: dict):
        v = row.get(field, "")
        if field in ("abuseConfidenceScore", "totalReports"):
            try:
                return int(v)
            except (ValueError, TypeError):
                return -1
        return str(v)

    reverse = sort_key in ("score", "reports")
    return sorted(rows, key=sort_val, reverse=reverse)


def export_html(path: str, rows: list[dict], headers: list[str], console: Console) -> None:
    """Generate a self-contained HTML report file."""
    e = html_mod.escape

    style = """
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
             margin: 2rem; background: #0d1117; color: #c9d1d9; }
      h1 { color: #58a6ff; }
      .meta { color: #8b949e; margin-bottom: 1rem; }
      table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
      th { background: #161b22; color: #58a6ff; text-align: left;
           padding: 10px 12px; border: 1px solid #30363d; }
      td { padding: 8px 12px; border: 1px solid #30363d; }
      tr:nth-child(even) { background: #161b22; }
      .high { color: #f85149; font-weight: bold; }
      .medium { color: #d29922; }
      .low { color: #c9d1d9; }
      .clean { color: #3fb950; font-weight: bold; }
      .error { color: #8b949e; font-style: italic; }
      .summary { margin-top: 1.5rem; padding: 1rem; border: 1px solid #30363d;
                  border-radius: 6px; background: #161b22; }
      .summary span { margin-right: 1.5rem; }
    </style>"""

    # Build summary stats
    scores: list[int] = []
    for r in rows:
        try:
            scores.append(int(r.get("abuseConfidenceScore", 0)))
        except (ValueError, TypeError):
            pass
    total = len(rows)
    high = sum(1 for s in scores if s >= 75)
    medium = sum(1 for s in scores if 50 <= s < 75)
    low = sum(1 for s in scores if 0 < s < 50)
    clean = sum(1 for s in scores if s == 0)

    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='en'><head><meta charset='utf-8'>",
        f"<title>AbuseIPDB Report</title>{style}</head><body>",
        "<h1>AbuseIPDB Quick Check Report</h1>",
        f"<p class='meta'>Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} "
        f"&mdash; {total} IPs checked &mdash; v{__version__}</p>",
        "<div class='summary'>",
        f"<span><strong>Total:</strong> {total}</span>",
        f"<span class='high'>High (≥75): {high}</span>",
        f"<span class='medium'>Medium (50-74): {medium}</span>",
        f"<span class='low'>Low (1-49): {low}</span>",
        f"<span class='clean'>Clean (0): {clean}</span>",
        "</div>",
        "<table><thead><tr>",
    ]
    for h in headers:
        html_parts.append(f"<th>{e(h)}</th>")
    html_parts.append("</tr></thead><tbody>")

    for row in rows:
        score = row.get("abuseConfidenceScore", "N/A")
        try:
            s = int(score)
            if s >= 75:
                cls = "high"
            elif s >= 50:
                cls = "medium"
            elif s > 0:
                cls = "low"
            else:
                cls = "clean"
        except (ValueError, TypeError):
            cls = "error"
        html_parts.append(f"<tr class='{cls}'>")
        for h in headers:
            html_parts.append(f"<td>{e(str(row.get(h, 'N/A')))}</td>")
        html_parts.append("</tr>")

    html_parts.append("</tbody></table></body></html>")

    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))
        console.print(f"[green]Success:[/] HTML report written to '{path}'.")
    except OSError as exc:
        console.print(f"[bold red]Error:[/] Failed to write HTML '{path}': {exc}")


def output_results(
    rows: list[dict],
    args: argparse.Namespace,
    headers: list[str],
    console: Console,
) -> None:
    """Route results to the appropriate output (JSON / CSV / Rich table)."""
    if args.json_output:
        filtered = [{k: r.get(k, "N/A") for k in headers} for r in rows]
        print(json.dumps(filtered, indent=2, default=str))
    elif args.output_file:
        write_csv(args.output_file, rows, headers, console)
    else:
        print_table(rows, headers, console)
        print_summary(rows, console)
    # HTML export (can be combined with any other output)
    if args.export:
        export_html(args.export, rows, headers, console)
    # Always show rate-limit info (unless JSON mode)
    if not args.json_output:
        print_rate_limit(console)


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def apply_threshold(rows: list[dict], threshold: int | None) -> list[dict]:
    """Keep only rows with abuseConfidenceScore >= *threshold*."""
    if threshold is None:
        return rows

    def meets(val: str | int | None) -> bool:
        try:
            return int(val) >= threshold
        except (ValueError, TypeError):
            return False

    return [r for r in rows if meets(r.get("abuseConfidenceScore"))]


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


def print_banner(console: Console) -> None:
    """Display a startup banner."""
    title = Text()
    title.append("AbuseIPDB", style="bold cyan")
    title.append(" Quick Check Tool", style="bold white")
    console.print(
        Panel(
            title,
            subtitle=f"v{__version__}",
            border_style="blue",
            expand=False,
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    args = parse_args()

    console = Console(
        no_color=args.no_color,
        force_terminal=None if not args.no_color else False,
    )

    # Backward compatibility: -x → -t 100
    if args.exclude and args.threshold is None:
        args.threshold = 100

    headers = get_headers(args.verbose)

    # Validate positional IP early (before prompting for API key)
    if args.ip and args.ip != "-":
        validated_ip = normalize_ip(args.ip)
        if not validated_ip:
            console.print(
                f"[bold red]Error:[/] '{args.ip}' is not a valid IP address."
            )
            sys.exit(1)

    # Banner (skip for JSON or no-color modes)
    if not args.json_output and not args.no_color:
        print_banner(console)

    # API key
    api_key = resolve_api_key(console, clear_cache=args.clear_key)

    # --- Positional single-IP lookup ---
    if args.ip and args.ip != "-":
        rows = fetch_results([validated_ip], api_key, max_age_days=args.days, console=console)
        rows = apply_threshold(rows, args.threshold)
        rows = sort_results(rows, args.sort)
        output_results(rows, args, headers, console)
        return

    # --- Stdin pipe mode: `command | abuseipdb_cli.py -` ---
    if args.ip == "-" or (not args.ip and not args.input_file and not sys.stdin.isatty()):
        ip_list = read_ips_from_stdin(console)
        if not ip_list:
            console.print("[yellow]Warning:[/] No valid IPs received from stdin.")
            sys.exit(0)
        rows = fetch_results(ip_list, api_key, max_age_days=args.days, console=console)
        rows = apply_threshold(rows, args.threshold)
        rows = sort_results(rows, args.sort)
        output_results(rows, args, headers, console)
        return

    # --- Batch mode: input file ---
    if args.input_file:
        if not os.path.isfile(args.input_file):
            console.print(
                f"[bold red]Error:[/] Input file not found: {args.input_file}"
            )
            sys.exit(1)
        ip_list = read_ips_from_csv(args.input_file, console)
        if not ip_list:
            console.print("[yellow]Warning:[/] No IPs found in input file. Exiting…")
            sys.exit(0)

        rows = fetch_results(
            ip_list, api_key, max_age_days=args.days, console=console
        )
        rows = apply_threshold(rows, args.threshold)
        rows = sort_results(rows, args.sort)
        output_results(rows, args, headers, console)
        return

    # --- Interactive mode ---
    while True:
        ip_list = get_ip_list_from_prompt(console)
        if not ip_list:
            console.print("[dim]Exiting… Goodbye![/]")
            break
        rows = fetch_results(
            ip_list, api_key, max_age_days=args.days, console=console
        )
        rows = apply_threshold(rows, args.threshold)
        rows = sort_results(rows, args.sort)
        output_results(rows, args, headers, console)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProcess interrupted. Exiting…")
        sys.exit(0)
