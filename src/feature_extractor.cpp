#include "feature_extractor.h"
#include "packet_parser.h"
#include <cstring>
#include <algorithm>

void FeatureExtractor::process_packet(const PacketInfo& pkt) {
    total_packets_++;

    DeviceStats* dev = find_or_create(pkt.src_mac);
    if (!dev) return;

    dev->pkt_count++;
    dev->total_pkt_size += pkt.pkt_len;
    dev->sum_pkt_size_sq += (uint64_t)pkt.pkt_len * pkt.pkt_len;
    dev->total_rssi += pkt.rssi;
    dev->last_seen_us = pkt.timestamp_us;
    if (dev->first_seen_us == 0) {
        dev->first_seen_us = pkt.timestamp_us;
    }

    switch (pkt.frame_type) {
        case FRAME_MGMT: dev->mgmt_count++; break;
        case FRAME_DATA: dev->data_count++; break;
        case FRAME_CTRL: dev->ctrl_count++; break;
    }

    if (pkt.frame_type == FRAME_MGMT) {
        if (pkt.frame_subtype == MGMT_BEACON) dev->beacon_count++;
        if (pkt.frame_subtype == MGMT_PROBE_REQ) dev->probe_req_count++;
    }

    if (pkt.retry) dev->retry_count++;

    if (pkt.ssid[0] != '\0' && dev->ssid[0] == '\0') {
        memcpy(dev->ssid, pkt.ssid, 33);
    }

    if (dev->security == SEC_UNKNOWN && pkt.frame_type == FRAME_MGMT &&
        (pkt.frame_subtype == MGMT_BEACON || pkt.frame_subtype == MGMT_PROBE_RESP)) {
        dev->security = parse_security(pkt.raw, pkt.capture_len);
    }

    add_unique_dst(dev, pkt.dst_mac);
}

void FeatureExtractor::reset() {
    memset(devices_, 0, sizeof(devices_));
    device_count_ = 0;
    total_packets_ = 0;
}

DeviceStats* FeatureExtractor::get_device(const uint8_t mac[6]) {
    for (int i = 0; i < device_count_; i++) {
        if (mac_equals(devices_[i].mac, mac)) {
            return &devices_[i];
        }
    }
    return nullptr;
}

void FeatureExtractor::sort_by_packets() {
    std::sort(devices_, devices_ + device_count_,
              [](const DeviceStats& a, const DeviceStats& b) {
                  return a.pkt_count > b.pkt_count;
              });
}

DeviceStats* FeatureExtractor::find_or_create(const uint8_t mac[6]) {
    static const uint8_t zero_mac[6] = {0};
    if (mac_equals(mac, zero_mac)) return nullptr;

    for (int i = 0; i < device_count_; i++) {
        if (mac_equals(devices_[i].mac, mac)) {
            return &devices_[i];
        }
    }

    if (device_count_ >= MAX_DEVICES) {
        // evict device with fewest packets
        int min_idx = 0;
        for (int i = 1; i < device_count_; i++) {
            if (devices_[i].pkt_count < devices_[min_idx].pkt_count) {
                min_idx = i;
            }
        }
        memset(&devices_[min_idx], 0, sizeof(DeviceStats));
        memcpy(devices_[min_idx].mac, mac, 6);
        devices_[min_idx].active = true;
        devices_[min_idx].oui_device_type = oui_lookup(mac);
        return &devices_[min_idx];
    }

    DeviceStats* dev = &devices_[device_count_++];
    memset(dev, 0, sizeof(DeviceStats));
    memcpy(dev->mac, mac, 6);
    dev->active = true;
    dev->oui_device_type = oui_lookup(mac);
    return dev;
}

void FeatureExtractor::add_unique_dst(DeviceStats* dev, const uint8_t mac[6]) {
    if (mac_is_broadcast(mac)) return;
    if (dev->unique_dst_count >= 32) return;

    for (int i = 0; i < dev->unique_dst_count; i++) {
        if (mac_equals(dev->unique_dsts[i], mac)) return;
    }

    memcpy(dev->unique_dsts[dev->unique_dst_count], mac, 6);
    dev->unique_dst_count++;
}
