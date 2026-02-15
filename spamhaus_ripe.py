# This file is part of the repository 32u-nd/Spamhaus-DROP.
#
# 32u-nd/Spamhaus-DROP is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# 32u-nd/Spamhaus-DROP is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with 32u-nd/Spamhaus-DROP. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (C) 2026 32u-nd

"""
This script fetches ASN and IP block data from Spamhaus and RIPEstat API, consolidates overlapping IPv4 and IPv6 ranges, and outputs the result as a JSON file.
It handles invalid IPs gracefully, logging errors without halting execution.
The script is useful for identifying and managing potentially malicious IP ranges.
"""

import json
import requests
import ipaddress
from datetime import datetime

# Constants for URLs
SPAMHAUS_URLS = {
    "asn": "https://www.spamhaus.org/drop/asndrop.json",
    "drop_v4": "https://www.spamhaus.org/drop/drop_v4.json",
    "drop_v6": "https://www.spamhaus.org/drop/drop_v6.json",
}

RIPESTAT_URL = (
    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
)


def fetch_spamhaus_list(url, session):
    """Fetch a list from Spamhaus."""
    try:
        response = session.get(url)
        response.raise_for_status()
        return [
            entry.get("asn", entry.get("cidr"))
            for entry in map(json.loads, response.text.splitlines())
        ]
    except requests.RequestException as e:
        print(f"Failed to retrieve list from {url}: {e}")
        return []


def fetch_asn_ip_ranges(asn_list, session):
    """Convert ASN to IP ranges using the RIPEstat API."""
    ip_ranges = set()
    for asn in asn_list:
        try:
            response = session.get(RIPESTAT_URL.format(asn=asn))
            response.raise_for_status()
            data = response.json()
            prefixes = data.get("data", {}).get("prefixes", [])
            ip_ranges.update(prefix["prefix"] for prefix in prefixes)
        except requests.RequestException as e:
            print(f"Failed to retrieve IP ranges for ASN {asn}: {e}")
    return list(ip_ranges)


def consolidate_ip_ranges(ip_ranges):
    """Consolidate overlapping or adjacent IP ranges into broader CIDR blocks."""
    ipv4_ranges = []
    ipv6_ranges = []

    for ip in ip_ranges:
        try:
            # Try to create an ip_network object
            network = ipaddress.ip_network(ip)
            if network.version == 4:
                ipv4_ranges.append(network)
            elif network.version == 6:
                ipv6_ranges.append(network)
        except ValueError as e:
            # Catch ValueError and print a message for invalid IP addresses
            print(f"Skipping invalid IP address or CIDR: {ip}. Error: {e}")

    return [
        [str(net) for net in ipaddress.collapse_addresses(ipv4_ranges)],
        [str(net) for net in ipaddress.collapse_addresses(ipv6_ranges)],
    ]


def get_current_timestamp():
    """Return the current timestamp."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def main():
    """main loop"""

    start_time = datetime.now()
    print(f"Start Time: {get_current_timestamp()}")

    with requests.Session() as session:
        # Fetch lists from Spamhaus
        drop4 = fetch_spamhaus_list(SPAMHAUS_URLS["drop_v4"], session)
        drop6 = fetch_spamhaus_list(SPAMHAUS_URLS["drop_v6"], session)
        asn_drop = fetch_spamhaus_list(SPAMHAUS_URLS["asn"], session)

        print(f"Spamhaus DROP v4: {len(drop4)} entries")
        print(f"Spamhaus DROP v6: {len(drop6)} entries")
        print(f"Spamhaus ASN-DROP: {len(asn_drop)} entries")

        # Fetch corresponding IP ranges from ASN
        ip_ranges = fetch_asn_ip_ranges(asn_drop, session)
        print(f"Fetched {len(ip_ranges)} unique IP ranges")

        # Consolidate the IP ranges
        consolidated_ipv4, consolidated_ipv6 = consolidate_ip_ranges(
            ip_ranges + drop4 + drop6
        )
        print(
            f"Consolidated to {len(consolidated_ipv4)} IPv4 ranges and {len(consolidated_ipv6)} IPv6 ranges"
        )

        # Save the result to a JSON file
        output_data = [
            {
                "comment": "Converted the Spamhaus DROP lists into a consolidated list of IP ranges using the RIPEstat API.",
                "timestamp": get_current_timestamp(),
                "ASN-DROP": f"{len(asn_drop)} entries, converted to {len(ip_ranges)} unique IP ranges",
                "DROP v4": f"{len(drop4)} entries",
                "DROP v6": f"{len(drop6)} entries",
                "consolidated v4": f"{len(consolidated_ipv4)} IPv4 ranges",
                "consolidated v6": f"{len(consolidated_ipv6)} IPv6 ranges",
                "v4": consolidated_ipv4,
                "v6": consolidated_ipv6,
            }
        ]
        with open("spamhaus_ripe.json", "w") as file:
            json.dump(output_data, file, indent=2)

    end_time = datetime.now()
    print(f"End Time: {get_current_timestamp()}")
    print(
        f"Execution time: {round((end_time - start_time).total_seconds(), 1)} seconds"
    )


if __name__ == "__main__":
    main()
