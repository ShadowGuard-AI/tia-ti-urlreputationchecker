# tia-ti-URLReputationChecker
Checks the reputation of a URL against various blacklists and services (e.g., VirusTotal, URLScan.io) providing a risk assessment based on aggregated reputation data. - Focused on Aggregates threat intelligence feeds from various open sources (e.g., malware trackers, vulnerability databases, pastebins) to provide a consolidated view of potential threats. Includes parsing and basic filtering capabilities. 

## Install
`git clone https://github.com/ShadowGuardAI/tia-ti-urlreputationchecker`

## Usage
`./tia-ti-urlreputationchecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose logging.
- `-o`: No description provided
- `--vt`: Check URL against VirusTotal.
- `--urlscan`: Look the URL up in existing URLScan.io results. This submits nothing: urlscan is not asked to fetch the target.
- `--urlscan-submit`: Submit the URL to URLScan.io as a PUBLIC scan and wait for the result. A public submission is visible to anyone and makes urlscan fetch the target URL. Off by default.
- `--blacklist`: Check against the bundled sample local blacklist (example data only, not a real threat feed).
- `--timeout`: Timeout in seconds for each service request (default: 30).
- `--urlscan-wait`: Maximum seconds to wait for a submitted urlscan result (default: 60).

## Notes
At least one check must be selected; a run with no check selected is a usage error and exits non-zero, and a run where every selected check failed prints no results verdict and exits non-zero. Each check outcome is reported under `check_status` (ok, unknown, no_results, error, or not_configured). A VirusTotal 404 means the URL is unknown to VirusTotal and is reported as unknown, distinct from a failure. The VirusTotal identifier is the base64 urlsafe encoding of the URL without padding, as the v3 API defines. The local blacklist is bundled sample data, marked as sample data in the output; matching is by hostname (exact host or subdomain) and loopback addresses are not listed.

## License
Copyright (c) ShadowGuardAI
