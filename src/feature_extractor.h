#pragma once

#include <cstdint>
#include <cmath>
#include "config.h"
#include "ring_buffer.h"
#include "packet_parser.h"

struct MLPrediction {
    uint8_t anomaly;
    uint8_t packet_class;
    uint8_t protocol;
    uint8_t device_type;
    uint8_t route_action;
    float   anomaly_score;
    bool    valid;
};

struct DeviceStats {
    uint8_t      mac[6];
    bool         active;
    char         ssid[33];
    SecurityType security;
    MLPrediction ml;

    uint32_t pkt_count;
    uint32_t total_pkt_size;
    uint64_t sum_pkt_size_sq;
    int32_t  total_rssi;
    int64_t  first_seen_us;
    int64_t  last_seen_us;

    uint32_t mgmt_count;
    uint32_t data_count;
    uint32_t ctrl_count;
    uint32_t beacon_count;
    uint32_t probe_req_count;
    uint32_t retry_count;

    uint8_t  unique_dsts[32][6];
    uint8_t  unique_dst_count;

    float avg_pkt_size() const {
        return pkt_count ? (float)total_pkt_size / pkt_count : 0;
    }

    float std_pkt_size() const {
        if (pkt_count < 2) return 0;
        float mean = avg_pkt_size();
        float variance = (float)sum_pkt_size_sq / pkt_count - mean * mean;
        return variance > 0 ? sqrtf(variance) : 0;
    }

    float avg_rssi() const {
        return pkt_count ? (float)total_rssi / pkt_count : 0;
    }

    float pkt_rate() const {
        int64_t dur = last_seen_us - first_seen_us;
        return dur > 0 ? (float)pkt_count / ((float)dur / 1000000.0f) : 0;
    }

    float mgmt_ratio() const { return pkt_count ? (float)mgmt_count / pkt_count : 0; }
    float data_ratio() const { return pkt_count ? (float)data_count / pkt_count : 0; }
    float ctrl_ratio() const { return pkt_count ? (float)ctrl_count / pkt_count : 0; }
    float retry_ratio() const { return pkt_count ? (float)retry_count / pkt_count : 0; }

    float beacon_rate() const {
        int64_t dur = last_seen_us - first_seen_us;
        return dur > 0 ? (float)beacon_count / ((float)dur / 1000000.0f) : 0;
    }

    float probe_req_rate() const {
        int64_t dur = last_seen_us - first_seen_us;
        return dur > 0 ? (float)probe_req_count / ((float)dur / 1000000.0f) : 0;
    }
};

class FeatureExtractor {
public:
    void process_packet(const PacketInfo& pkt);
    void reset();

    DeviceStats* get_device(const uint8_t mac[6]);
    DeviceStats* get_devices() { return devices_; }
    int device_count() const { return device_count_; }
    uint32_t total_packets() const { return total_packets_; }

    void sort_by_packets();

private:
    DeviceStats devices_[MAX_DEVICES];
    int device_count_ = 0;
    uint32_t total_packets_ = 0;

    DeviceStats* find_or_create(const uint8_t mac[6]);
    void add_unique_dst(DeviceStats* dev, const uint8_t mac[6]);
};
