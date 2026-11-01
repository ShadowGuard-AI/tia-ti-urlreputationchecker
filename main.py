#!/usr/bin/env python3

import argparse
import base64
import logging
import requests
import json
import re
import os
import sys
import time
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define API keys (ideally these would be read from environment variables or a config file)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
URLSCANIO_API_KEY = os.environ.get("URLSCANIO_API_KEY")

# Outcomes that mean a check was actually performed and answered.
COMPLETED_OUTCOMES = ("ok", "unknown", "no_results")


def setup_argparse():
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Checks the reputation of a URL against various blacklists and services.")
    parser.add_argument("url", help="The URL to check.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-o", "--output", help="Output file to save the results (JSON format).")
    parser.add_argument("--vt", action="store_true", help="Check URL against VirusTotal.")
    parser.add_argument("--urlscan", action="store_true", help="Look the URL up on URLScan.io (search only, nothing is submitted).")
    parser.add_argument("--urlscan-submit", action="store_true", help="Submit the URL to URLScan.io as a PUBLIC scan and wait for the result. A public submission is visible to anyone and makes urlscan fetch the target URL. Off by default; without this flag no submission is made.")
    parser.add_argument("--blacklist", action="store_true", help="Check against the bundled sample local blacklist (example data only, not a real threat feed).")
    parser.add_argument("--timeout", type=int, default=30, help="Timeout in seconds for each service request (default: 30).")
    parser.add_argument("--urlscan-wait", type=int, default=60, help="Maximum seconds to wait for a submitted urlscan result before giving up (default: 60).")
    return parser


def is_valid_url(url):
    """
    Validates if the provided URL is syntactically correct.
    """
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url) is not None


def virustotal_url_id(url):
    """The VirusTotal v3 identifier for a URL: base64 urlsafe, no padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def check_virustotal(url, timeout=30):
    """
    Checks the URL against VirusTotal.

    Returns:
        tuple: (outcome, payload). A 404 is "unknown" (the URL is unknown
        to VirusTotal), distinct from a failed lookup ("error").
    """
    if not VIRUSTOTAL_API_KEY:
        logging.error("VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable.")
        return "not_configured", None

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{virustotal_url_id(url)}",
            headers=headers, timeout=timeout)
    except requests.exceptions.RequestException as e:
        logging.error(f"Request to VirusTotal failed: {e}")
        return "error", None

    if response.status_code == 404:
        logging.info(f"URL unknown to VirusTotal: {url}")
        return "unknown", None
    if response.status_code != 200:
        logging.error(f"VirusTotal returned HTTP {response.status_code}.")
        return "error", None
    try:
        return "ok", response.json()
    except ValueError as e:
        logging.error(f"Failed to decode JSON response from VirusTotal: {e}")
        return "error", None


def check_urlscanio_search(url, timeout=30):
    """
    Looks the URL up in existing urlscan.io results. This performs no
    submission: urlscan is not asked to fetch the target.
    """
    if not URLSCANIO_API_KEY:
        logging.error("URLScan.io API key not found. Please set the URLSCANIO_API_KEY environment variable.")
        return "not_configured", None

    headers = {
        "API-Key": URLSCANIO_API_KEY,
        "Content-Type": "application/json"
    }
    try:
        response = requests.get(
            "https://urlscan.io/api/v1/search/",
            headers=headers, params={"q": f'page.url:"{url}"'}, timeout=timeout)
    except requests.exceptions.RequestException as e:
        logging.error(f"Request to URLScan.io search failed: {e}")
        return "error", None

    if response.status_code != 200:
        logging.error(f"URLScan.io search returned HTTP {response.status_code}.")
        return "error", None
    try:
        payload = response.json()
    except ValueError as e:
        logging.error(f"Failed to decode JSON response from URLScan.io search: {e}")
        return "error", None
    if not payload.get("results"):
        logging.info(f"No existing urlscan.io results for: {url}")
        return "no_results", payload
    return "ok", payload


def check_urlscanio_submit(url, timeout=30, wait_seconds=60, poll_interval=5):
    """
    Submits the URL to URLScan.io as a PUBLIC scan (see --urlscan-submit)
    and polls the result endpoint until the scan completes or the wait
    deadline passes.
    """
    if not URLSCANIO_API_KEY:
        logging.error("URLScan.io API key not found. Please set the URLSCANIO_API_KEY environment variable.")
        return "not_configured", None

    headers = {
        "API-Key": URLSCANIO_API_KEY,
        "Content-Type": "application/json"
    }
    data = {"url": url, "visibility": "public"}  # Public, and disclosed as public by the flag that enables this path.

    try:
        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data, timeout=timeout)
    except requests.exceptions.RequestException as e:
        logging.error(f"Request to URLScan.io failed: {e}")
        return "error", None

    if response.status_code not in (200, 201):
        logging.error(f"URLScan.io submission returned HTTP {response.status_code}.")
        return "error", None
    try:
        scan_result = response.json()
    except ValueError as e:
        logging.error(f"Failed to decode JSON response from URLScan.io: {e}")
        return "error", None

    scan_id = scan_result.get("uuid")
    if not scan_id:
        result_value = scan_result.get("result") or ""
        scan_id = result_value.rstrip("/").split("/")[-1]
    if not scan_id:
        logging.error("URLScan.io submission response carried no scan ID.")
        return "error", None

    result_url = f"https://urlscan.io/api/v1/result/{scan_id}"
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            result_response = requests.get(result_url, headers=headers, timeout=timeout)
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to retrieve scan results from URLScan.io: {e}")
            return "error", None
        if result_response.status_code == 200:
            try:
                return "ok", result_response.json()
            except ValueError as e:
                logging.error(f"Failed to decode JSON response from URLScan.io for result: {e}")
                return "error", None
        if result_response.status_code == 404 and time.monotonic() < deadline:
            logging.info("urlscan.io result is still pending; waiting before retrying.")
            time.sleep(poll_interval)
            continue
        logging.error(
            f"URLScan.io result fetch returned HTTP {result_response.status_code} after waiting up to {wait_seconds} seconds."
        )
        return "error", None


# Bundled sample local blacklist: example data only, not a real threat feed.
# Entries are hostnames and matching is host based (exact host or a
# subdomain of the entry), never a substring search over the whole URL.
SAMPLE_BLACKLIST_HOSTS = [
    "badsite.net",
    "malicious.example.com",
]


def check_blacklist(url):
    """
    Checks the URL host against the bundled sample local blacklist.
    Returns True only when the parsed hostname equals a listed host or
    is a subdomain of one. Loopback and lookalike names do not match.
    """
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    if not host:
        return False
    for listed in SAMPLE_BLACKLIST_HOSTS:
        if host == listed or host.endswith("." + listed):
            return True
    return False


def main():
    """
    Main function to drive the URL reputation checker.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    if not is_valid_url(url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    if not (args.vt or args.urlscan or args.urlscan_submit or args.blacklist):
        parser.error("No check selected: pass at least one of --vt, --urlscan, --urlscan-submit, or --blacklist.")

    results = {
        "url": url,
        "virustotal": None,
        "urlscanio": None,
        "blacklist": None,
        "check_status": {}
    }
    completed = 0

    if args.vt:
        logging.info(f"Checking URL against VirusTotal: {url}")
        outcome, payload = check_virustotal(url, timeout=args.timeout)
        results["virustotal"] = payload
        results["check_status"]["virustotal"] = outcome
        if outcome in COMPLETED_OUTCOMES:
            completed += 1

    if args.urlscan_submit:
        logging.info(f"Submitting URL to URLScan.io as a public scan: {url}")
        outcome, payload = check_urlscanio_submit(
            url, timeout=args.timeout, wait_seconds=args.urlscan_wait)
        results["urlscanio"] = payload
        results["check_status"]["urlscanio"] = outcome
        if outcome in COMPLETED_OUTCOMES:
            completed += 1
    elif args.urlscan:
        logging.info(f"Looking URL up on URLScan.io (no submission): {url}")
        outcome, payload = check_urlscanio_search(url, timeout=args.timeout)
        results["urlscanio"] = payload
        results["check_status"]["urlscanio"] = outcome
        if outcome in COMPLETED_OUTCOMES:
            completed += 1

    if args.blacklist:
        logging.info(f"Checking URL against sample local blacklist: {url}")
        results["blacklist"] = {
            "listed": check_blacklist(url),
            "source": "Bundled sample local blacklist (example data only, not a real threat feed)"
        }
        results["check_status"]["blacklist"] = "ok"
        completed += 1

    if completed == 0:
        # Every selected check failed or was not configured: no verdict
        # was earned, so no results JSON is printed.
        print(f"No checks could be completed for {url}. Check status: {json.dumps(results['check_status'])}")
        sys.exit(1)

    # Output results
    if args.output:
        try:
            with open(args.output, "w") as f:
                json.dump(results, f, indent=4)
            logging.info(f"Results saved to {args.output}")
        except Exception as e:
            logging.error(f"Failed to write results to file: {e}")
            sys.exit(1)
    else:
        print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()

"""
Usage Examples:

1.  Basic usage:  Look a URL up on VirusTotal and print the results to the console
    (at least one check must be selected):
    ```bash
    python tia-ti-URLReputationChecker.py https://www.google.com --vt
    ```

2.  Check a URL against VirusTotal and look it up on URLScan.io, then print to console.
    The urlscan lookup submits nothing:
    ```bash
    python tia-ti-URLReputationChecker.py https://www.example.com --vt --urlscan
    ```

3.  Submit a URL to URLScan.io as a PUBLIC scan (visible to anyone, and urlscan
    fetches the target), wait for the result, and save all results to a file:
    ```bash
    python tia-ti-URLReputationChecker.py https://www.example.com --vt --urlscan-submit -o results.json
    ```

4.  Enable verbose logging:
    ```bash
    python tia-ti-URLReputationChecker.py https://www.example.com --vt -v
    ```

5. Check against the bundled sample local blacklist (example data only)
    ```bash
    python tia-ti-URLReputationChecker.py https://malicious.example.com/ --blacklist
    ```
"""
