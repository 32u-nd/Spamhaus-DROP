# 32u-nd/Spamhaus-DROP

**32u-nd/Spamhaus-DROP** is a Python script designed to fetch ASN (Autonomous System Number) and IP block data from the **Spamhaus** and **RIPEstat** APIs, consolidate overlapping IPv4 and IPv6 ranges, and output the results as a JSON file. This script is primarily useful for identifying and managing potentially malicious IP ranges.

## Features
- Fetches ASN and IP block data from **Spamhaus DROP lists** and **RIPEstat API**.
- Consolidates overlapping or adjacent IPv4 and IPv6 IP ranges into broader CIDR blocks.
- Handles invalid IPs gracefully by logging errors without halting execution.
- Outputs the resulting IP ranges in a clean JSON format.

## Requirements
To run this script, you need the following Python libraries:
- `requests` (for making HTTP requests)
- `ipaddress` (for handling and manipulating IP addresses)
- `json` (for JSON encoding/decoding)

You can install the required dependencies using `pip`:

```bash
pip install requests
