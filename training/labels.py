# Feature columns produced by the ESP32 feature extractor.
FEATURE_COLS = [
    "pkt_count",
    "avg_pkt_size",
    "std_pkt_size",
    "avg_rssi",
    "pkt_rate",
    "mgmt_ratio",
    "data_ratio",
    "ctrl_ratio",
    "unique_dst_count",
    "beacon_rate",
    "probe_req_rate",
    "retry_ratio",
]

# 802.11 frame type / management-subtype decoders for the raw `frame_type`
# and `frame_subtype` columns in sniff_*.csv. Mirror the FrameType /
# MgmtSubtype enums in src/packet_parser.h — keep the two in sync.
# Note: `frame_subtype` is only a management subtype when frame_type == 0;
# the same value means something different for control/data frames.
FRAME_TYPES = {
    0: "MGMT",
    1: "CTRL",
    2: "DATA",
}

MGMT_SUBTYPES = {
    0: "ASSOC_REQ",
    1: "ASSOC_RESP",
    2: "REASSOC_REQ",
    3: "REASSOC_RESP",
    4: "PROBE_REQ",
    5: "PROBE_RESP",
    6: "TIMING_AD",
    8: "BEACON",
    9: "ATIM",
    10: "DISASSOC",
    11: "AUTH",
    12: "DEAUTH",
    13: "ACTION",
}

# Output head classes
# DEVICE_TYPE_LABELS in src/label_mappings.h must match DEVICE_CLASSES
ANOMALY_CLASSES = ["normal", "anomalous"]

PACKET_CLASSES = ["normal", "suspicious", "malicious", "unknown"]

PROTOCOL_CLASSES = [
    "wifi_mgmt",
    "wifi_data",
    "wifi_ctrl",
    "dhcp",
    "dns",
    "http",
    "https",
    "mqtt",
    "unknown",
]

DEVICE_CLASSES = [
    "router",
    "phone",
    "cpu",
    "iot_sensor",
    "smart_home",
    "camera",
    "printer",
    "game_console",
    "unknown",
    "flock",
]

ROUTE_ACTIONS = ["allow", "throttle", "block"]

OUTPUT_NAMES = [
    "anomaly",
    "packet_class",
    "protocol",
    "device_type",
    "route_action",
]

LABEL_CLASSES = {
    "anomaly": ANOMALY_CLASSES,
    "packet_class": PACKET_CLASSES,
    "protocol": PROTOCOL_CLASSES,
    "device_type": DEVICE_CLASSES,
    "route_action": ROUTE_ACTIONS,
}

# OUI manufacturer keyword → device_type. Used by generate_labels.py for
# training-label heuristics, identify_devices.py for post-hoc analysis, and
# tools/generate_oui_table.py to emit the on-device lookup table.
OUI_DEVICE_MAP = {
    # Routers / network infrastructure
    "NETGEAR": "router",
    "Ruckus Wireless": "router",
    "Arcadyan Corporation": "router",
    "Commscope": "router",
    "Vantiva USA LLC": "router",
    "WNC Corporation": "router",
    "Epigram, Inc": "router",
    "TP-Link": "router",
    "Ubiquiti": "router",
    "Sagemcom": "router",
    "Cisco Meraki": "router",
    # camera
    "Blink by Amazon": "camera",
    "Ring LLC": "camera",
    "Wyze Labs Inc": "camera",
    # Smart home / IoT
    "Sonos, Inc.": "smart_home",
    "Nest Labs Inc.": "smart_home",
    "ecobee inc": "smart_home",
    "GE Lighting": "smart_home",
    "Tuya Smart Inc.": "smart_home",
    "Espressif Inc.": "smart_home",
    "Smart Innovation LLC": "smart_home",
    "Vizio, Inc": "smart_home",
    "iRobot Corporation": "smart_home",
    "SimpliSafe": "smart_home",
    "SAMJIN": "smart_home",
    "AMPAK Technology": "smart_home",
    # Phones
    "Samsung": "phone",
    "Google, Inc.": "phone",
    "LG Innotek": "phone",
    "Huawei": "phone",
    "Xiaomi": "phone",
    "OnePlus": "phone",
    "Motorola": "phone",
    "OPPO": "phone",
    "Nokia Solutions and Networks GmbH & Co. KG": "phone",
    # Laptops / computers
    "Dell Inc.": "cpu",
    "Lenovo": "cpu",
    "Intel": "cpu",
    "AzureWave Technology Inc.": "cpu",
    "ASUSTek": "cpu",
    "Apple, Inc.": "cpu",
    # Printers
    "LEXMARK INTERNATIONAL, INC.": "printer",
    # Game consoles
    "Nintendo Co., Ltd.": "game_console",
    # Other
    "Tesla, Inc.": "iot_sensor",
    "Visteon": "iot_sensor",
    # Flock Safety (cameras, batteries, WiFi APs)
    "Liteon Technology Corp": "flock",
    "Flock Safety": "flock",
    "Silicon Laboratories": "flock",
    "ShotSpotter, Inc.": "flock",
    "Universal Global Scientific Industrial., Ltd": "flock",
}
