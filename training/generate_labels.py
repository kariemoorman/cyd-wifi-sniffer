#!/usr/bin/env python3
import argparse
import glob
import json
import os

import pandas as pd

from training.labels import FEATURE_COLS, OUI_DEVICE_MAP

"""
CYD Network Sniffer — Label Generation

Reads feature CSVs and alert CSVs collected from the ESP32 sniffer,
applies heuristic classification rules (matching firmware thresholds),
and generates a labels.csv for training.

Usage:
    python training/generate_labels.py --data_dir training/data
    (or `make labels`)

The data_dir should contain:
    - feat_*.csv files from the sniffer
    - alert_*.csv files (optional, improves anomaly labeling)

Output:
    data_dir/labels.csv — one row per unique device with suggested labels.
    Review and edit before training.
"""

def load_oui_cache(data_dir: str) -> dict:
    path = os.path.join(data_dir, "oui_cache.json")
    if os.path.exists(path):
        with open(path) as f:
            cache = json.load(f)
        print(f"  Loaded OUI cache: {len(cache)} entries")
        return cache
    print("  No oui_cache.json found, skipping OUI lookup")
    return {}


def oui_device_type(mac, oui_cache):
    """Look up device type from OUI manufacturer."""
    prefix = mac[:8].upper()
    manufacturer = oui_cache.get(prefix, "Unknown")

    for keyword, dev_type in OUI_DEVICE_MAP.items():
        if keyword.lower() in manufacturer.lower():
            return dev_type

    # Randomized MAC (unknown OUI) = almost certainly phone/tablet
    if manufacturer == "Unknown":
        return "phone"

    return None


def load_features(data_dir: str) -> pd.DataFrame:
    pattern = os.path.join(data_dir, "feat_*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No feature files found matching {pattern}")

    dfs = []
    for f in files:
        df = pd.read_csv(f)
        dfs.append(df)
        print(f"  Loaded {f}: {len(df)} rows")

    combined = pd.concat(dfs, ignore_index=True)
    print(f"Total feature rows: {len(combined)}")
    return combined


def load_alerts(data_dir: str) -> dict:
    pattern = os.path.join(data_dir, "alert_*.csv")
    files = sorted(glob.glob(pattern))
    alerts = {}
    for f in files:
        try:
            df = pd.read_csv(f)
            for _, row in df.iterrows():
                mac = str(row.get("src_mac", "")).strip()
                alert = str(row.get("alert", "")).strip()
                if mac and alert:
                    alerts.setdefault(mac, set()).add(alert)
        except Exception:
            pass
    if alerts:
        print(f"  Loaded alerts for {len(alerts)} devices from {len(files)} alert files")
    return alerts


def classify_device(row, oui_cache):
    anomaly = "normal"
    packet_class = "normal"
    protocol = "unknown"
    device_type = "unknown"
    route_action = "allow"

    pkt_rate = row.get("pkt_rate", 0)
    probe_req_rate = row.get("probe_req_rate", 0)
    retry_ratio = row.get("retry_ratio", 0)
    beacon_rate = row.get("beacon_rate", 0)
    mgmt_ratio = row.get("mgmt_ratio", 0)
    data_ratio = row.get("data_ratio", 0)
    ctrl_ratio = row.get("ctrl_ratio", 0)
    pkt_count = row.get("pkt_count", 0)
    unique_dst_count = row.get("unique_dst_count", 0)
    avg_pkt_size = row.get("avg_pkt_size", 0)

    # Device type: OUI first, heuristic as fallback
    oui_type = oui_device_type(row["src_mac"], oui_cache)
    if oui_type:
        device_type = oui_type

    # Strong heuristic overrides (even over OUI)
    if beacon_rate > 0.5 and probe_req_rate < 0.1:
        device_type = "router"
    elif beacon_rate > 0.5 and probe_req_rate >= 0.1:
        device_type = "smart_home"
    elif avg_pkt_size > 300 and data_ratio > 0.5 and pkt_rate > 10:
        device_type = "cpu"
    elif device_type == "unknown":
        # Only apply weak heuristics if OUI didn't classify
        if probe_req_rate > 1.0 and data_ratio < 0.3:
            device_type = "phone"
        elif probe_req_rate > 0.1 and data_ratio > 0.3:
            device_type = "cpu"
        elif probe_req_rate > 0.1 and data_ratio < 0.3 and avg_pkt_size < 200:
            device_type = "phone"
        elif pkt_count < 50 and mgmt_ratio > 0.5:
            device_type = "iot_sensor"
        elif avg_pkt_size < 200 and pkt_rate < 5:
            device_type = "smart_home"

    is_infra = device_type in ("router", "smart_home")

    if probe_req_rate > 5.0:
        anomaly = "anomalous"
        packet_class = "suspicious"
        route_action = "throttle"
    elif retry_ratio > 0.5 and pkt_rate > 5.0:
        anomaly = "anomalous"
        packet_class = "suspicious"
        route_action = "throttle"
    elif unique_dst_count > 20 and not is_infra and pkt_rate > 1.0:
        anomaly = "anomalous"
        packet_class = "suspicious"
        route_action = "throttle"
    elif pkt_rate > 200.0 and data_ratio > 0.8 and not is_infra:
        anomaly = "anomalous"
        packet_class = "malicious"
        route_action = "block"

    if beacon_rate > 0.5:
        protocol = "wifi_mgmt"
    elif mgmt_ratio > 0.7:
        protocol = "wifi_mgmt"
    elif data_ratio > 0.7:
        protocol = "wifi_data"
    elif ctrl_ratio > 0.7:
        protocol = "wifi_ctrl"

    return anomaly, packet_class, protocol, device_type, route_action


def generate_labels(features: pd.DataFrame, output_path: str, data_dir: str):
    alert_map = load_alerts(data_dir)
    oui_cache = load_oui_cache(data_dir)

    agg = features.groupby("src_mac").agg({
        "pkt_count": "max",
        "avg_pkt_size": "mean",
        "std_pkt_size": "mean",
        "avg_rssi": "mean",
        "pkt_rate": "max",
        "mgmt_ratio": "mean",
        "data_ratio": "mean",
        "ctrl_ratio": "mean",
        "unique_dst_count": "max",
        "beacon_rate": "max",
        "probe_req_rate": "max",
        "retry_ratio": "mean",
    }).reset_index()

    rows = []
    anomaly_count = 0
    for _, row in agg.iterrows():
        anomaly, pkt_class, protocol, dev_type, action = classify_device(row, oui_cache)

        mac = row["src_mac"]
        is_infra = dev_type in ("router", "smart_home")
        if mac in alert_map:
            alerts = alert_map[mac]
            infra_only = alerts <= {"FLOOD", "MANY_DSTS"}
            if not (is_infra and infra_only):
                anomaly = "anomalous"
                if "FLOOD" in alerts:
                    pkt_class = "malicious"
                    action = "block"
                elif pkt_class == "normal":
                    pkt_class = "suspicious"
                    action = "throttle"

        if anomaly == "anomalous":
            anomaly_count += 1
        rows.append({
            "src_mac": mac,
            "anomaly": anomaly,
            "packet_class": pkt_class,
            "protocol": protocol,
            "device_type": dev_type,
            "route_action": action,
        })

    template = pd.DataFrame(rows)
    template.to_csv(output_path, index=False)
    print(f"\nLabel file saved: {output_path}")
    print(f"  {len(rows)} unique devices")
    print(f"  {anomaly_count} flagged as anomalous")
    print(f"  {len(rows) - anomaly_count} classified as normal")
    print("  Review and adjust labels, then run train_model.py.")


def main():
    parser = argparse.ArgumentParser(description="Generate training labels from sniffer data")
    parser.add_argument("--data_dir", required=True, help="Directory with feat_*.csv and alert_*.csv files")
    args = parser.parse_args()

    print("Loading feature data...")
    features = load_features(args.data_dir)

    print("\nFeature summary:")
    for col in FEATURE_COLS:
        if col in features.columns:
            print(f"  {col}: min={features[col].min():.2f}, max={features[col].max():.2f}, mean={features[col].mean():.2f}")

    output_path = os.path.join(args.data_dir, "labels.csv")
    generate_labels(features, output_path, args.data_dir)


if __name__ == "__main__":
    main()