#!/usr/bin/env python3
import argparse
import glob
import json
import os
import time
import urllib.request
import urllib.error

import csv

"""
Identify devices from captured feature/alert CSVs using OUI manufacturer lookup.

Usage:
    python tools/identify_devices.py --data_dir training/data

Looks up each unique MAC's manufacturer via macvendors.com API,
shows traffic stats and heuristic classification, and caches results
to avoid repeat lookups.
"""


OUI_DEVICE_MAP = {
    # Routers / network infrastructure
    "NETGEAR":              "router",
    "Ruckus Wireless":      "router",
    "Arcadyan Corporation": "router",
    "Commscope":            "router",
    "Vantiva USA LLC":      "router",
    "WNC Corporation":      "router",
    "Epigram, Inc":         "router",
    "TP-Link":              "router",
    "Ubiquiti":             "router",
    "Sagemcom":             "router",

    # Smart home / IoT
    "Sonos, Inc.":          "smart_home",
    "Nest Labs Inc.":       "smart_home",
    "ecobee inc":           "smart_home",
    "GE Lighting":          "smart_home",
    "Tuya Smart Inc.":      "smart_home",
    "Espressif Inc.":       "smart_home",
    "Smart Innovation LLC": "smart_home",
    "Vizio, Inc":           "smart_home",
    "iRobot Corporation":   "smart_home",
    "Ring LLC":             "smart_home",
    "SimpliSafe":           "smart_home",
    "Blink by Amazon":      "smart_home",
    "SAMJIN":               "smart_home",
    "AMPAK Technology":     "smart_home",

    # Phones
    "Samsung":              "phone",
    "Google, Inc.":         "phone",
    "LG Innotek":           "phone",
    "Huawei":               "phone",
    "Xiaomi":               "phone",
    "OnePlus":              "phone",
    "Motorola":             "phone",
    "OPPO":                 "phone",
    "Nokia Solutions and Networks GmbH & Co. KG":   "phone",

    # Laptops / computers
    "Dell Inc.":            "cpu",
    "Lenovo":               "cpu",
    "Intel":                "cpu",
    "AzureWave Technology Inc.": "cpu",
    "ASUSTek":              "cpu",
    "Apple, Inc.":          "cpu",

    # Printers
    "LEXMARK INTERNATIONAL, INC.": "printer",

    # Game consoles
    "Nintendo Co., Ltd.":  "game_console",

    # Other
    "Tesla,Inc.":           "iot_sensor",
    "Visteon":              "iot_sensor",
}


def lookup_oui(mac, cache, cache_path):
    oui = mac[:8].upper()
    if oui in cache:
        return cache[oui]

    try:
        url = f"https://api.macvendors.com/{oui}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CYD-Sniffer/1.0")
        with urllib.request.urlopen(req, timeout=5) as resp:
            vendor = resp.read().decode().strip()
    except urllib.error.HTTPError:
        vendor = "Unknown"
    except Exception:
        vendor = "Lookup failed"

    cache[oui] = vendor
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=2)
    time.sleep(1.1)
    return vendor


def oui_device_type(mac, cache):
    prefix = mac[:8].upper()
    vendor = cache.get(prefix, "Unknown")

    for keyword in OUI_DEVICE_MAP:
        if keyword.lower() in vendor.lower():
            return OUI_DEVICE_MAP[keyword]

    if vendor == "Unknown":
        return "phone"

    return None


def load_csvs(data_dir, prefix):
    pattern = os.path.join(data_dir, f"{prefix}_*.csv")
    files = sorted(glob.glob(pattern))
    rows = []
    for fpath in files:
        with open(fpath, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description="Identify devices from sniffer data")
    parser.add_argument("--data_dir", required=True, help="Directory with feat_*.csv and alert_*.csv")
    parser.add_argument("--no-lookup", action="store_true", help="Skip API lookup, use cache only")
    args = parser.parse_args()

    cache_path = os.path.join(args.data_dir, "oui_cache.json")
    cache = {}
    if os.path.exists(cache_path):
        with open(cache_path) as f:
            cache = json.load(f)

    feat_rows = load_csvs(args.data_dir, "feat")
    alert_rows = load_csvs(args.data_dir, "alert")

    if not feat_rows:
        print(f"No feat_*.csv files found in {args.data_dir}")
        return

    # aggregate per device
    devices = {}
    for row in feat_rows:
        mac = row.get("src_mac", "").strip()
        if not mac:
            continue
        if mac not in devices:
            devices[mac] = {
                "ssid": "",
                "security": "",
                "pkt_count": 0,
                "avg_rssi": 0.0,
                "pkt_rate": 0.0,
                "avg_pkt_size": 0.0,
                "beacon_rate": 0.0,
                "probe_req_rate": 0.0,
                "mgmt_ratio": 0.0,
                "data_ratio": 0.0,
                "retry_ratio": 0.0,
                "unique_dst_count": 0,
                "samples": 0,
                "alerts": set(),
            }

        d = devices[mac]
        d["samples"] += 1
        d["pkt_count"] = max(d["pkt_count"], int(float(row.get("pkt_count", 0))))
        d["pkt_rate"] = max(d["pkt_rate"], float(row.get("pkt_rate", 0)))
        d["avg_pkt_size"] += float(row.get("avg_pkt_size", 0))
        d["beacon_rate"] = max(d["beacon_rate"], float(row.get("beacon_rate", 0)))
        d["probe_req_rate"] = max(d["probe_req_rate"], float(row.get("probe_req_rate", 0)))
        d["unique_dst_count"] = max(d["unique_dst_count"], int(float(row.get("unique_dst_count", 0))))
        d["avg_rssi"] += float(row.get("avg_rssi", 0))
        d["mgmt_ratio"] += float(row.get("mgmt_ratio", 0))
        d["data_ratio"] += float(row.get("data_ratio", 0))
        d["retry_ratio"] += float(row.get("retry_ratio", 0))

        ssid = row.get("ssid", "").strip()
        if ssid and not d["ssid"]:
            d["ssid"] = ssid
        sec = row.get("security", "").strip()
        if sec and not d["security"]:
            d["security"] = sec

    # average the accumulated fields
    for d in devices.values():
        n = d["samples"]
        if n > 0:
            d["avg_rssi"] /= n
            d["mgmt_ratio"] /= n
            d["avg_pkt_size"] /= n
            d["data_ratio"] /= n
            d["retry_ratio"] /= n

    # incorporate alerts
    for row in alert_rows:
        mac = row.get("src_mac", "").strip()
        alert = row.get("alert", "").strip()
        if mac in devices and alert:
            devices[mac]["alerts"].add(alert)

    # look up manufacturers
    unique_ouis = set(mac[:8].upper() for mac in devices)
    print(f"Found {len(devices)} unique devices ({len(unique_ouis)} unique OUIs)")

    if not args.no_lookup:
        uncached = [oui for oui in unique_ouis if oui not in cache]
        if uncached:
            print(f"Looking up {len(uncached)} new OUIs (1 req/sec)...")
            for i, oui in enumerate(sorted(uncached)):
                dummy_mac = oui + ":00:00:00"
                vendor = lookup_oui(dummy_mac, cache, cache_path)
                print(f"  [{i+1}/{len(uncached)}] {oui} = {vendor}")
    else:
        print("Skipping API lookup (--no-lookup)")

    # classify and display
    print("\n" + "=" * 110)
    print(f"{'MAC':<18} {'Vendor':<22} {'SSID':<16} {'Sec':<6} {'Pkts':>6} {'Rate':>6} {'Type':<12} {'Alerts'}")
    print("=" * 110)

    for mac in sorted(devices, key=lambda m: devices[m]["pkt_count"], reverse=True):
        d = devices[mac]
        oui = mac[:8].upper()
        vendor = cache.get(oui, "Unknown")

        # OUI-based classification
        dev_type = "unknown"
        vendor_lower = vendor.lower()

        dev_type = oui_device_type(mac, cache) or "unknown"

        # Strong heuristic overrides
        if d["beacon_rate"] > 0.5 and d["probe_req_rate"] < 0.1:
            dev_type = "router"
        elif d["beacon_rate"] > 0.5 and d["probe_req_rate"] >= 0.1:
            dev_type = "smart_home"
        elif d.get("avg_pkt_size", 0) > 300 and d["data_ratio"] > 0.5 and d["pkt_rate"] > 10:
            dev_type = "cpu"
        elif dev_type == "unknown":
            if d["probe_req_rate"] > 1.0 and d["data_ratio"] < 0.3:
                dev_type = "phone"
            elif d["probe_req_rate"] > 0.1 and d["data_ratio"] > 0.3:
                dev_type = "cpu"
            elif d["probe_req_rate"] > 0.1 and d["data_ratio"] < 0.3 and d.get("avg_pkt_size", 0) < 200:
                dev_type = "phone"
            elif d["pkt_count"] < 50 and d["mgmt_ratio"] > 0.5:
                dev_type = "iot_sensor"
            elif d.get("avg_pkt_size", 0) < 200 and d["pkt_rate"] < 5:
                dev_type = "smart_home"

        ssid = d["ssid"][:14] if d["ssid"] else ""
        sec = d["security"][:5] if d["security"] else ""
        alerts = ", ".join(sorted(d["alerts"])) if d["alerts"] else ""

        print(f"{mac:<18} {vendor:<22} {ssid:<16} {sec:<6} {d['pkt_count']:>6} {d['pkt_rate']:>6.1f} {dev_type:<12} {alerts}")

    # summary
    alert_devices = [m for m, d in devices.items() if d["alerts"]]
    routers = [m for m, d in devices.items() if d["beacon_rate"] > 0.5]
    print(f"\nSummary: {len(routers)} routers/APs, {len(alert_devices)} devices with alerts, {len(devices)} total")

    if alert_devices:
        print("\nDevices with alerts:")
        for mac in alert_devices:
            d = devices[mac]
            vendor = cache.get(mac[:8].upper(), "Unknown")
            print(f"  {mac} ({vendor}) — {', '.join(sorted(d['alerts']))}")


if __name__ == "__main__":
    main()
