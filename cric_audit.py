#!/usr/bin/env python3
"""
CRIC Audit Workflow - Combined Script

This script combines the full audit workflow:
1. Fetch CRIC data from WLCG and produce cric.json
2. Run audit to compare against ESNet RIB and produce output.txt
3. Extract "not in cric" entries and run WHOIS lookups
4. Generate the final report without intermediate files

Usage: python cric_audit.py [output_file]
"""

import json
import os
import re
import socket
import ssl
import sys
import time
from urllib.request import urlopen

import pytricia
from ipwhois import IPWhois
from ipwhois.exceptions import ASNRegistryError, HostLookupError, HTTPLookupError

# ============================================================================
# Step 1: Fetch CRIC data
# ============================================================================

CRIC_URL = "https://wlcg-cric.cern.ch/api/core/rcsite/query/?json"


def fetch_cric_data(url: str = CRIC_URL) -> dict:
    """Fetch CRIC data from WLCG API and save to cric.json"""
    print(f"Fetching CRIC data from {url}...")
    # Create SSL context that doesn't verify certificates (handles self-signed certs)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urlopen(url, context=ctx) as response:
        data = json.load(response)
    with open("cric.json", "w") as f:
        json.dump(data, f, indent=2)
    print(f"Fetched {len(data)} sites from CRIC")
    return data


def build_cric_prefix_tree(cric_data: dict) -> pytricia.PyTricia:
    """Build a PyTricia tree of CRIC prefixes"""
    cric = pytricia.PyTricia(128)
    for rcsite in cric_data:
        if cric_data[rcsite].get("netroutes"):
            for netsite in cric_data[rcsite]["netroutes"]:
                if cric_data[rcsite]["netroutes"][netsite].get("lhcone_bandwidth_limit", -1) >= 0:
                    for af in ["ipv4", "ipv6"]:
                        networks = cric_data[rcsite]["netroutes"][netsite].get("networks", {})
                        if af in networks:
                            for prefix in networks[af]:
                                pfx_attributes = {
                                    "asn": cric_data[rcsite]["netroutes"][netsite]["asn"],
                                    "netsite": netsite,
                                    "rcsite": rcsite,
                                }
                                cric[prefix] = pfx_attributes
    return cric


# ============================================================================
# Step 2: Load ESNet RIB data
# ============================================================================

def load_rib_files() -> pytricia.PyTricia:
    """Load ESNet RIB data from JSON files"""
    esnetrib = pytricia.PyTricia(128)
    rib_files = [
        "lhcone.ipv4.nren.json",
        "lhcone.ipv4.sites.json",
        "lhcone.ipv6.nren.json",
        "lhcone.ipv6.sites.json",
    ]

    for file in rib_files:
        if not os.path.exists(file):
            print(f"Warning: RIB file '{file}' not found. Skipping.")
            continue
        with open(file) as rib_file:
            rib = json.load(rib_file)
        for router in rib.get("routes", {}).get("routeDistinguishers", {}):
            for prefix in rib["routes"]["routeDistinguishers"][router]:
                for route in rib["routes"]["routeDistinguishers"][router][prefix]:
                    pfx_attributes = {"as-path": route["path"]}
                    esnetrib[prefix] = pfx_attributes
    return esnetrib


# ============================================================================
# Step 3: Audit and generate "not in cric" entries
# ============================================================================

def run_audit(cric: pytricia.PyTricia, esnetrib: pytricia.PyTricia) -> list:
    """Run audit comparing ESNet RIB against CRIC, return entries not in CRIC"""
    results = []
    for pfx in esnetrib:
        if pfx not in cric:
            results.append({
                "prefix": pfx,
                "as_path": esnetrib[pfx]["as-path"],
                "not_in_cric": True,
            })
    return results


# ============================================================================
# Step 4: WHOIS lookups
# ============================================================================

def clean_ip_address(prefix: str) -> str:
    """Strip CIDR netmask from prefix"""
    if "/" in prefix:
        return prefix.split("/")[0]
    return prefix


def query_whois_server(host: str, query: str, port: int = 43, timeout: int = 10) -> str:
    """Query a WHOIS server directly"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(f"{query}\r\n".encode("utf-8"))
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        sock.close()
        return response.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def lookup_asn_description(ip_address: str) -> str:
    """Perform WHOIS/RDAP lookup to get ASN description with fallback to direct WHOIS queries"""
    # First try RDAP (preferred)
    try:
        obj = IPWhois(ip_address)
        results = obj.lookup_rdap(depth=1)

        netname = results.get("asn_description")
        # Check if asn_description is "NA" which means it's not a real name
        if not netname or netname == "NA":
            netname = results.get("network", {}).get("name")
        # Also check for "NA" in the network name and try to get more info
        if netname and netname != "NA":
            # If network name looks generic, try to get org info from entities
            if netname in ("NA", "N/A", "UNKNOWN"):
                netname = None
            else:
                return netname

        if not netname:
            netname = "Not Found (No organization name in RDAP)"
        return netname
    except HTTPLookupError:
        # RDAP failed, try direct WHOIS as fallback
        pass
    except (ASNRegistryError, HostLookupError):
        pass
    except Exception:
        pass

    # Fallback: Query WHOIS servers directly based on IP registry
    # APNIC (Asia-Pacific), ARIN (North America), RIPE (Europe), LACNIC (Latin America), AFRINIC (Africa)
    # Determine the RIR based on IP prefix
    rir_whois_servers = {
        "apnic": "whois.apnic.net",
        "arin": "whois.arin.net",
        "ripe": "whois.ripe.net",
        "lacnic": "whois.lacnic.net",
        "afrinic": "whois.afrinic.net",
    }

    try:
        # Try APNIC first (covers most of the problematic cases like Korean IPs)
        response = query_whois_server("whois.apnic.net", ip_address)
        if response:
            # Parse KREONet/KISTI specific response
            for line in response.split("\n"):
                line = line.strip()
                if line.startswith("netname:") or line.startswith("descr:"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
            # Return first meaningful line with organization info
            for line in response.split("\n"):
                if "KISTI" in line or "KREONet" in line or "KISA" in line:
                    return line.strip()
    except Exception:
        pass

    # Try ARIN if APNIC failed (for US IPs)
    try:
        response = query_whois_server("whois.arin.net", ip_address)
        if response:
            for line in response.split("\n"):
                line = line.strip()
                if line.startswith("OrgName:") or line.startswith("NetName:"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except Exception:
        pass

    # Try RIPE if still no result (for European IPs)
    try:
        response = query_whois_server("whois.ripe.net", ip_address)
        if response:
            for line in response.split("\n"):
                line = line.strip()
                if line.startswith("netname:") or line.startswith("descr:"):
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        return parts[1].strip()
    except Exception:
        pass

    return "Lookup Failed (Direct WHOIS also failed)"


def perform_whois_lookups(entries: list) -> list:
    """Perform WHOIS lookups on unique prefixes"""
    unique_ips = set()
    for entry in entries:
        ip_addr = clean_ip_address(entry["prefix"])
        unique_ips.add(ip_addr)

    print(f"\nFound {len(unique_ips)} unique IP addresses. Starting WHOIS lookups...")

    ip_cache = {}
    for i, ip_address in enumerate(unique_ips, 1):
        print(f"-> Querying {i}/{len(unique_ips)}: {ip_address}...", end=" ", flush=True)
        netname = lookup_asn_description(ip_address)
        ip_cache[ip_address] = netname
        print(f"{netname}")
        time.sleep(0.5)  # Be polite to WHOIS servers

    # Update entries with netname
    for entry in entries:
        ip_addr = clean_ip_address(entry["prefix"])
        entry["netname"] = ip_cache.get(ip_addr, "Error: Cache Miss")

    return entries


# ============================================================================
# Step 5: Output report
# ============================================================================

def generate_report(entries: list, output_file: str) -> None:
    """Generate the final report in tabular format"""
    # Sort by AS number for cleaner output
    entries.sort(key=lambda x: (int(x["as_path"].split()[-1]) if x["as_path"].split() else 0, x["prefix"]))

    with open(output_file, "w") as f:
        f.write("=" * 66 + "\n")
        f.write("Final Processed Results from ESNet RIB (not in CRIC)\n")
        f.write("=" * 66 + "\n")
        f.write(f"{'AS Number':<10} | {'Prefix':<25} | {'Organization/NetName'}\n")
        f.write("-" * 10 + "-+-" + "-" * 25 + "-+-" + "-" * 40 + "\n")

        for entry in entries:
            as_number = entry["as_path"].split()[-1] if entry["as_path"].split() else "N/A"
            f.write(
                f"{as_number:<10} | {entry['prefix']:<25} | {entry['netname']}\n"
            )
        f.write("=" * 66 + "\n")

    print(f"\nReport written to {output_file}")


# ============================================================================
# Main workflow
# ============================================================================

def main():
    output_file = sys.argv[1] if len(sys.argv) > 1 else "cric_audit_report.txt"

    print("=" * 60)
    print("CRIC Audit Workflow")
    print("=" * 60)

    # Step 1: Fetch CRIC data
    cric_data = fetch_cric_data()

    # Step 2: Build CRIC prefix tree
    print("Building CRIC prefix tree...")
    cric = build_cric_prefix_tree(cric_data)
    print(f"CRIC contains {len(cric)} prefixes")

    # Step 3: Load ESNet RIB
    print("Loading ESNet RIB data...")
    esnetrib = load_rib_files()
    print(f"ESNet RIB contains {len(esnetrib)} prefixes")

    # Step 4: Run audit
    print("Running audit (comparing ESNet RIB vs CRIC)...")
    not_in_cric = run_audit(cric, esnetrib)
    print(f"Found {len(not_in_cric)} prefixes in ESNet RIB not in CRIC")

    # Step 5: Perform WHOIS lookups
    print("Performing WHOIS lookups...")
    with_whois = perform_whois_lookups(not_in_cric)

    # Step 6: Generate report
    generate_report(with_whois, output_file)

    print("\nWorkflow complete!")


if __name__ == "__main__":
    main()
