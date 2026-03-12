"""
spamhaus_ripe.py

Fetches ASN and IP block data from the Spamhaus DROP lists and the RIPEstat API,
consolidates all overlapping/adjacent IPv4 and IPv6 ranges across all ASNs, and
writes a single flat JSON object to spamhaus_ripe.json.

ASNs are used only as an intermediate step to resolve IP prefixes via RIPEstat.
They do not appear in the output.

Data sources:
  - Spamhaus ASN-DROP:  https://www.spamhaus.org/drop/asndrop.json  (NDJSON)
  - Spamhaus DROP (v4): https://www.spamhaus.org/drop/drop_v4.json  (NDJSON)
  - Spamhaus DROP (v6): https://www.spamhaus.org/drop/drop_v6.json  (NDJSON)
  - RIPEstat API:       https://stat.ripe.net/data/announced-prefixes/data.json

Note: All Spamhaus endpoints return NDJSON (one JSON object per line), not a
JSON array. The last line is always a metadata record and is ignored.

Output format (spamhaus_ripe.json):
{
  "v4": ["1.2.3.0/24", ...],
  "v6": ["2001:db8::/32", ...]
}
"""

import ipaddress
import json
import logging
import sys
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SPAMHAUS_ASN_DROP_URL = "https://www.spamhaus.org/drop/asndrop.json"
SPAMHAUS_DROP_V4_URL = "https://www.spamhaus.org/drop/drop_v4.json"
SPAMHAUS_DROP_V6_URL = "https://www.spamhaus.org/drop/drop_v6.json"
RIPESTAT_URL = "https://stat.ripe.net/data/announced-prefixes/data.json"

OUTPUT_FILE = "spamhaus_ripe.json"
REQUEST_TIMEOUT = 30  # seconds per HTTP request
RIPE_MAX_RETRIES = 2  # retries for RIPEstat lookups

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def fetch_text(url: str, retries: int = 0) -> str | None:
    """Fetch *url* and return the raw response text. Returns None on error."""
    for attempt in range(retries + 1):
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as exc:
            log.warning(
                "Request failed (attempt %d/%d): %s — %s",
                attempt + 1,
                retries + 1,
                url,
                exc,
            )
    return None


def fetch_json(
    url: str, params: dict | None = None, retries: int = 0
) -> dict | list | None:
    """Fetch *url* with optional query *params* and return parsed JSON. Returns None on error."""
    for attempt in range(retries + 1):
        try:
            response = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as exc:
            log.warning(
                "Request failed (attempt %d/%d): %s — %s",
                attempt + 1,
                retries + 1,
                url,
                exc,
            )
        except json.JSONDecodeError as exc:
            log.warning("JSON decode error for %s: %s", url, exc)
            return None
    return None


def parse_ndjson(text: str) -> list[dict]:
    """
    Parse a Newline-Delimited JSON (NDJSON) response into a list of dicts.
    Lines that cannot be parsed or that represent metadata records are skipped.
    """
    records: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            log.warning("Skipping unparseable NDJSON line: %.80s", line)
            continue
        # Skip the trailing metadata record present in all Spamhaus DROP files
        if obj.get("type") == "metadata":
            continue
        records.append(obj)
    return records


# ---------------------------------------------------------------------------
# Spamhaus helpers
# ---------------------------------------------------------------------------


def fetch_spamhaus_asns() -> list[int]:
    """Return a sorted list of unique ASNs from the Spamhaus ASN-DROP list."""
    text = fetch_text(SPAMHAUS_ASN_DROP_URL)
    if not text:
        log.error("Failed to fetch Spamhaus ASN-DROP list.")
        return []

    asns: set[int] = set()
    for record in parse_ndjson(text):
        asn = record.get("asn")
        if asn is not None:
            try:
                asns.add(int(asn))
            except (ValueError, TypeError):
                log.warning("Unreadable ASN value, skipping: %s", asn)

    log.info("Fetched %d unique ASNs from Spamhaus ASN-DROP.", len(asns))
    return sorted(asns)


def fetch_spamhaus_prefixes() -> tuple[list[str], list[str]]:
    """
    Return (v4_prefixes, v6_prefixes) from the Spamhaus DROP v4/v6 lists.
    Invalid entries are skipped with a warning.
    """
    v4: list[str] = []
    v6: list[str] = []

    for url, container, label in [
        (SPAMHAUS_DROP_V4_URL, v4, "DROP-v4"),
        (SPAMHAUS_DROP_V6_URL, v6, "DROP-v6"),
    ]:
        text = fetch_text(url)
        if not text:
            log.error("Failed to fetch Spamhaus %s list.", label)
            continue
        for record in parse_ndjson(text):
            cidr = record.get("cidr")
            if not cidr:
                continue
            try:
                ipaddress.ip_network(cidr, strict=False)
                container.append(cidr)
            except ValueError:
                log.warning("Invalid CIDR in %s, skipping: %s", label, cidr)

        log.info("Fetched %d prefixes from Spamhaus %s.", len(container), label)

    return v4, v6


# ---------------------------------------------------------------------------
# RIPEstat helper
# ---------------------------------------------------------------------------


def fetch_ripe_prefixes(asn: int) -> tuple[list[str], list[str]]:
    """
    Query RIPEstat for all prefixes announced by *asn*.
    Returns (v4_prefixes, v6_prefixes).
    """
    data = fetch_json(
        RIPESTAT_URL, params={"resource": f"AS{asn}"}, retries=RIPE_MAX_RETRIES
    )
    if not data:
        log.warning("No RIPEstat data for AS%d.", asn)
        return [], []

    v4: list[str] = []
    v6: list[str] = []

    for entry in data.get("data", {}).get("prefixes", []):  # type: ignore
        cidr = entry.get("prefix")
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            (v4 if network.version == 4 else v6).append(cidr)
        except ValueError:
            log.warning(
                "Invalid prefix from RIPEstat for AS%d, skipping: %s", asn, cidr
            )

    return v4, v6


# ---------------------------------------------------------------------------
# IP consolidation
# ---------------------------------------------------------------------------


def consolidate(cidrs: list[str]) -> list[str]:
    """
    Collapse a list of CIDR strings into the minimal set of non-overlapping
    supernets using Python's ipaddress.collapse_addresses().
    """
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            log.warning("Skipping invalid CIDR during consolidation: %s", cidr)

    return [str(n) for n in ipaddress.collapse_addresses(networks)]  # type: ignore


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    log.info(
        "Starting Spamhaus DROP fetch — %s UTC",
        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
    )

    # Step 1: Collect all ASNs from Spamhaus ASN-DROP
    asns = fetch_spamhaus_asns()
    if not asns:
        log.error("No ASNs retrieved — aborting.")
        sys.exit(1)

    # Step 2: Collect standalone Spamhaus DROP prefixes (v4 + v6)
    all_v4, all_v6 = fetch_spamhaus_prefixes()

    # Step 3: Resolve each ASN to its announced prefixes via RIPEstat and accumulate
    for asn in asns:
        log.info("Processing AS%d …", asn)
        ripe_v4, ripe_v6 = fetch_ripe_prefixes(asn)
        all_v4.extend(ripe_v4)
        all_v6.extend(ripe_v6)

    # Step 4: Consolidate everything into a minimal flat list per IP version
    log.info(
        "Consolidating %d raw IPv4 and %d raw IPv6 prefixes …", len(all_v4), len(all_v6)
    )
    result = {
        "v4": consolidate(all_v4),
        "v6": consolidate(all_v6),
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    log.info(
        "Done. Wrote %d IPv4 and %d IPv6 prefixes to %s.",
        len(result["v4"]),
        len(result["v6"]),
        OUTPUT_FILE,
    )


if __name__ == "__main__":
    main()
