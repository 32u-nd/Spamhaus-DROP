# Spamhaus DROP — Consolidated IP Blocklist

![Update Spamhaus DROP JSON](https://github.com/32u-nd/Spamhaus-DROP/actions/workflows/update-blocklist.yml/badge.svg)

A Python script and GitHub Actions workflow that fetches ASN and IP block data from the **Spamhaus DROP lists** and the **RIPEstat API**, consolidates all overlapping IPv4 and IPv6 ranges, and commits the result as a flat JSON file to this repository.
The JSON is updated automatically **twice a day** (06:05 UTC and 18:05 UTC) via GitHub Actions. Depending on platform load, execution may be delayed slightly.

---

## Stable JSON URL

The output file lives directly in this repository and is always available at a permanent raw URL:

```
https://raw.githubusercontent.com/32u-nd/Spamhaus-DROP/main/spamhaus_ripe.json
```

No Gist, no third-party hosting — the URL never changes.

---

## Output Format

```json
{
  "v4": ["1.2.3.0/24", "5.6.7.0/22"],
  "v6": ["2001:db8::/32"]
}
```

A single object with two keys:

| Key  | Type             | Description                                      |
|------|------------------|--------------------------------------------------|
| `v4` | array of strings | Consolidated IPv4 CIDR blocks                    |
| `v6` | array of strings | Consolidated IPv6 CIDR blocks                    |

Overlapping or adjacent CIDR blocks are collapsed into the smallest possible set of supernets using Python's built-in `ipaddress.collapse_addresses()`.

---

## How It Works

`spamhaus_ripe.py` runs through four steps:

1. **Fetch ASNs** — Downloads the [Spamhaus ASN-DROP list](https://www.spamhaus.org/drop/asndrop.json) and extracts all listed Autonomous System Numbers. ASNs serve only as intermediate lookup keys and do not appear in the output.

2. **Fetch standalone prefixes** — Downloads the [Spamhaus DROP (v4)](https://www.spamhaus.org/drop/drop_v4.json) and [DROP (v6)](https://www.spamhaus.org/drop/drop_v6.json) lists, which contain IP ranges not tied to a specific ASN.

3. **Resolve ASNs via RIPEstat** — For each ASN, queries the [RIPEstat announced-prefixes API](https://stat.ripe.net/data/announced-prefixes/data.json) to retrieve all currently routed prefixes. Lookups are retried up to **2 times** on transient errors.

4. **Consolidate & write** — All collected prefixes (Spamhaus standalone + RIPEstat) are merged into a single pool per IP version, collapsed into a minimal non-overlapping set, and written to `spamhaus_ripe.json`.

Invalid CIDR strings are skipped with a warning and never halt execution.

---

## GitHub Actions Workflow

The workflow file is located at `.github/workflows/update-blocklist.yml`.

```
Triggers:
  - Scheduled: 06:05 UTC and 18:05 UTC daily
  - Manual:    workflow_dispatch (GitHub UI → Actions → Run workflow)

Steps:
  1. Check out the repository
  2. Set up Python 3.12
  3. Install dependencies (requests)
  4. Run spamhaus_ripe.py → produces spamhaus_ripe.json
  5. Commit and push the updated JSON (only if the content changed)
```

Each bot commit includes a UTC timestamp so you can trace exactly when an update was generated.

---

## OPNsense Integration

In OPNsense go to **Firewall → Aliases** and create a new alias:

| Setting | Value |
|---------|-------|
| Type | URL Table in JSON format (IPs) |
| URL | `https://raw.githubusercontent.com/32u-nd/Spamhaus-DROP/main/spamhaus_ripe.json` |
| Path Expression (IPv4) | `.v4[]` |
| Path Expression (IPv6) | `.v6[]` |

---

## Requirements

Python 3.10+ and the `requests` library:

```bash
pip install requests
```

`ipaddress` and `json` are part of the Python standard library — no additional dependencies required.

---

## License

[MIT](LICENSE)
