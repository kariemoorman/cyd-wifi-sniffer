#pragma once

static const char* ANOMALY_LABELS[] = {
    "normal",
    "anomalous",
};
static const int ANOMALY_COUNT = 2;

static const char* PACKET_CLASS_LABELS[] = {
    "normal",
    "suspicious",
    "malicious",
    "unknown",
};
static const int PACKET_CLASS_COUNT = 4;

static const char* PROTOCOL_LABELS[] = {
    "wifi_mgmt",
    "wifi_data",
    "wifi_ctrl",
    "dhcp",
    "dns",
    "http",
    "https",
    "mqtt",
    "unknown",
};
static const int PROTOCOL_COUNT = 9;

static const char* DEVICE_TYPE_LABELS[] = {
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
};
static const int DEVICE_TYPE_COUNT = 10;

static const char* ROUTE_ACTION_LABELS[] = {
    "allow",
    "throttle",
    "block",
};
static const int ROUTE_ACTION_COUNT = 3;

static const int N_FEATURES = 12;