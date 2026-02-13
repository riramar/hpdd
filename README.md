# Header Parsing Discrepancy Detector (hpdd)

## Overview

**hpdd.py** is a tool for detecting HTTP header parsing discrepancies across different proxies in a chain. It automates the process of testing various header mutations and transformations, comparing responses to identify inconsistencies that may indicate security issues such as HTTP request smuggling.

## Research Credits
This tool is based on and inspired by the following research:
- [Practical HTTP Header Smuggling (Intruder.io)](https://www.intruder.io/research/practical-http-header-smuggling)
- [Black Hat Europe 2021: Practical HTTP Header Smuggling – Sneaking Past Reverse Proxies to Attack AWS and Beyond](https://blackhat.com/eu-21/briefings/schedule/#practical-http-header-smuggling-sneaking-past-reverse-proxies-to-attack-aws-and-beyond-243631633367882)
- [YouTube: Practical HTTP Header Smuggling (Daniel Thatcher, Black Hat EU 2021)](https://www.youtube.com/watch?v=RAtpG6OYYNM)

## Installation

```bash
pipx install git+https://github.com/riramar/hpdd
```

## Features
- Tests for header parsing discrepancies using a variety of header mutations and transformations
- Supports custom test configurations and mutation sets
- Compares responses for valid and invalid header values
- Handles rate limiting (HTTP 429) automatically
- Provides detailed output for each test case

## Help
```
$ hpdd -h
usage: hpdd [-h] [-n CONNECTION_HEADER] [-s] [-t TIMEOUT] [-u USER_AGENT] [-q] [-m METHOD] [-c CONFIG_FILE] [-st] [-sm] [-e DEVIATION] [-d] [-k] [-so] url

Detect header parsing discrepancies across proxy chains

positional arguments:
  url                   Target URL to test.

options:
  -h, --help            show this help message and exit
  -n, --connection_header CONNECTION_HEADER
                        Value for Connection header (default: close).
  -s, --upgrade-https   Upgrade URL to https if the same subdomain accepts https requests.
  -t, --timeout TIMEOUT
                        Request timeout in seconds (default: 10).
  -u, --user-agent USER_AGENT
                        User-Agent string (default: Chrome 138).
  -q, --quit-on-first   Exit immediately when the first discrepancy is found (default: false).
  -m, --method METHOD   HTTP method to use for all requests, overriding per-header configuration (e.g., GET, POST, PUT).
  -c, --config-file CONFIG_FILE
                        Path to Python configuration file containing required test_configurations, test_transformations and test_mutations variables.
  -st, --skip-transformations
                        Skip transformation tests (cannot be used with --skip-mutations).
  -sm, --skip-mutations
                        Skip mutation tests (cannot be used with --skip-transformations).
  -e, --deviation DEVIATION
                        Allowed deviation percentage for response body/headers length comparisons (default: 20).
  -d, --debug           Print raw HTTP request for debugging (default: false).
  -k, --confirm         Confirm discrepancies by retesting the same requests before reporting (default: false).
  -so, --skip-timeout   Skip tests when timeout occurs, treating timeouts the same as failed requests (default: false).

Example usage:
  hpdd https://example.com
  hpdd https://example.com -t 15
  hpdd https://example.com -u "Custom-Agent/1.0"
  hpdd https://example.com -q
  hpdd https://example.com -m POST
  hpdd https://example.com -c config.py
  hpdd https://example.com -st
  hpdd https://example.com -sm
  hpdd https://example.com --timeout 15 --quit-on-first
```

## How It Works
- Sends HTTP requests with various header mutations and transformations (e.g., hyphen to underscore, case swap, Unicode mapping)
- Compares the responses for valid and invalid header values
- Identifies discrepancies in status code, body length, header length, etc.
- Highlights potential parsing differences between proxies or servers

## Disclaimer
This tool is intended for research and authorized testing only. Do not use against systems without permission.

## License
MIT
