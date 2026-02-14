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
```

## Gist
The output is available as a [Gist](https://gist.github.com/32u-nd/2d9c1ca5edfce44d45606d1b4ee18a62).
You can consume the output directly from the [raw Gist](https://gist.githubusercontent.com/32u-nd/2d9c1ca5edfce44d45606d1b4ee18a62/raw/spamhaus_ripe.json), which can be integrated into your firewall application or other network security tools. The Gist is updated around 0605h and 1805h CET. However, this is not guaranteed.

I use it in OPNsense (a popular open-source firewall): go to *Firewall* -- *Aliases* and select *URL Table in JSON format (IPs)*. The *Path Expression* to extract the IPv4 CIDR data is: ```.[].v4[]```. IPv6 is accordingly.
