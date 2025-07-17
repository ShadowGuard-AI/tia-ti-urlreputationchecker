#!/usr/bin/env python3

import argparse
import logging
import requests
import json
from bs4 import BeautifulSoup
from dateutil import parser
import re
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define API keys (ideally these would be read from environment variables or a config file)
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
URLSCANIO_API_KEY = os.environ.get("URLSCANIO_API_KEY")

def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    """
    parser = argparse.ArgumentParser(description="Checks the reputation of a URL against various blacklists and services.")
    parser.add_argument("url", help="The URL to check.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("-o", "--output", help="Output file to save the results (JSON format).")
    parser.add_argument("--vt", action="store_true", help="Check URL against VirusTotal.")
    parser.add_argument("--urlscan", action="store_true", help="Check URL against URLScan.io.")
    parser.add_argument("--blacklist", action="store_true", help="Check against local blacklist (example)")
    return parser.parse_args()

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

def check_virustotal(url):
    """
    Checks the URL against VirusTotal.
    """
    if not VIRUSTOTAL_API_KEY:
        logging.error("VirusTotal API key not found. Please set the VIRUSTOTAL_API_KEY environment variable.")
        return None

    try:
        url_id = requests.utils.quote(url) # URL encode to be safe.
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        json_response = response.json()

        if response.status_code == 200:
            #logging.debug(f"VirusTotal response: {json_response}") #too noisy even on debug
            return json_response
        else:
            logging.error(f"Error from VirusTotal API: {json_response}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Request to VirusTotal failed: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode JSON response from VirusTotal: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking VirusTotal: {e}")
        return None


def check_urlscanio(url):
    """
    Checks the URL against URLScan.io.
    """
    if not URLSCANIO_API_KEY:
        logging.error("URLScan.io API key not found. Please set the URLSCANIO_API_KEY environment variable.")
        return None

    try:
        headers = {
            "API-Key": URLSCANIO_API_KEY,
            "Content-Type": "application/json"
        }
        data = {"url": url, "visibility": "public"} # Public so we can fetch results later

        response = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
        response.raise_for_status()

        scan_result = response.json()

        if response.status_code == 200:
            # Poll URLScan.io for results
            try:
                scan_id = scan_result["result"].split("/")[-1]
                result_url = f"https://urlscan.io/api/v1/result/{scan_id}"
                result_response = requests.get(result_url, headers=headers)
                result_response.raise_for_status()
                result_json = result_response.json()
                return result_json
            except requests.exceptions.RequestException as e:
                logging.error(f"Failed to retrieve scan results from URLScan.io: {e}")
                return None
            except json.JSONDecodeError as e:
                logging.error(f"Failed to decode JSON response from URLScan.io for result: {e}")
                return None
            except Exception as e:
                logging.error(f"An unexpected error occurred while retrieving URLScan.io results: {e}")
                return None
        else:
            logging.error(f"Error from URLScan.io API: {scan_result}")
            return None

    except requests.exceptions.RequestException as e:
        logging.error(f"Request to URLScan.io failed: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Failed to decode JSON response from URLScan.io: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking URLScan.io: {e}")
        return None


def check_blacklist(url):
    """
    Checks the URL against a local blacklist (example).
    """
    # This is a placeholder for a real blacklist implementation.
    # In a real-world scenario, you might load the blacklist from a file
    # or a database.
    blacklist = [
        "example.com/malicious",
        "badsite.net",
        "127.0.0.1" #added IP address to demonstrate that works too
    ]
    
    if url in blacklist:
        return True
    
    for blacklisted_url in blacklist:
        if blacklisted_url in url:
            return True # Return immediately if found
        
    return False


def main():
    """
    Main function to drive the URL reputation checker.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    if not is_valid_url(url):
        logging.error("Invalid URL provided.")
        sys.exit(1)

    results = {
        "url": url,
        "virustotal": None,
        "urlscanio": None,
        "blacklist": False
    }

    if args.vt:
        logging.info(f"Checking URL against VirusTotal: {url}")
        results["virustotal"] = check_virustotal(url)

    if args.urlscan:
        logging.info(f"Checking URL against URLScan.io: {url}")
        results["urlscanio"] = check_urlscanio(url)

    if args.blacklist:
        logging.info(f"Checking URL against local blacklist: {url}")
        results["blacklist"] = check_blacklist(url)

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

1.  Basic usage:  Check a URL and print the results to the console:
    ```bash
    python tia-ti-URLReputationChecker.py https://www.google.com
    ```

2.  Check a URL against VirusTotal and URLScan.io, then print to console:
    ```bash
    python tia-ti-URLReputationChecker.py https://www.example.com --vt --urlscan
    ```

3.  Check a URL against VirusTotal and URLScan.io, then save the results to a file named "results.json":
    ```bash
    python tia-ti-URLReputationChecker.py https://www.example.com --vt --urlscan -o results.json
    ```

4.  Enable verbose logging:
    ```bash
    python tia-ti-URLReputationChecker.py https://www.example.com -v
    ```

5. Check against local blacklist
    ```bash
    python tia-ti-URLReputationChecker.py https://www.example.com/malicious --blacklist
    ```

Offensive Tool considerations (Note:  This script is designed for defensive threat intelligence. Using the information it gathers for offensive purposes without authorization is illegal and unethical.)

*   The gathered information, especially from VirusTotal and URLScan.io, could potentially reveal information about a target's infrastructure and security posture if they have scanned the URL previously.  This information should only be used with explicit permission and for defensive purposes.

* The blacklist option allows a threat actor to maintain a list of targets or known C2 domains.

* Gathering information about URL redirects and associated network traffic can expose potential vulnerabilities.
"""