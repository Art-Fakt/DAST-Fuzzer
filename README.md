# DAST-Fuzzer

`DAST-Fuzzer.sh` is an automated tool for performing Dynamic Application Security Testing (DAST) on domains or subdomains. It integrates multiple tools to crawl, collect, filter, and analyze URLs and Javascript to detect potential secrets in js and vulnerabilities.

## Features

- **URL Collection**: Uses `gau`, `Katana` and `waybackurls` to gather URLs associated with a domain or list of subdomains.
- **URL Filtering**: Filters URLs with query parameters to focus on relevant targets.
- **Live URL Checking**: Uses `httpx` to identify accessible URLs.
- **Vulnerability Scanning**: Use `--nuclei` option to runs DAST scans with `nuclei` to detect potential vulnerabilities.
- **JavaScript Analysis**: With the `-js` option, extracts and analyzes JavaScript files for secrets, API keys, and sensitive information using `SecretFinder.py`.
- **Reporting**: Generates files containing filtered results and detected vulnerabilities.

## Prerequisites

Ensure the following tools are installed on your system before using this script:

- [gau](https://github.com/lc/gau)
- [waybackurls](https://github.com/tomnomnom/waybackurls)
- [httpx](https://github.com/projectdiscovery/httpx)
- [nuclei](https://github.com/projectdiscovery/nuclei)
- [uro](https://github.com/s0md3v/uro)
- [subjs](https://github.com/lc/subjs) *(required for JavaScript analysis)*

## Installation

Clone this repository and make sure the script is executable:

```bash
git clone https://github.com/Art-Fakt/DAST-Fuzzer
chmod +x ./dast-fuzzer.sh
```

## Usage
```bash
./dast-fuzzer.sh                    # Crawling uniquement
./dast-fuzzer.sh -js                # Crawling + analyse JS
./dast-fuzzer.sh --nuclei           # Crawling + scan Nuclei DAST  
./dast-fuzzer.sh -js --nuclei       # Crawling + analyse JS + scan Nuclei DAST
```