#pragma once

#include <cstdint>
#include <atomic>
#include "config.h"

struct PacketInfo {
    int64_t  timestamp_us;
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  frame_type;
    uint8_t  frame_subtype;
    uint16_t duration;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  bssid[6];
    uint16_t seq_num;
    uint16_t pkt_len;
    uint8_t  rate;
    bool     retry;
    char     ssid[33];
    uint16_t capture_len;
    uint8_t  raw[MAX_CAPTURE_LEN];
};

class RingBuffer {
public:
    bool push(const PacketInfo& pkt) {
        uint32_t next = (write_idx_.load(std::memory_order_relaxed) + 1) % RING_BUFFER_SIZE;
        if (next == read_idx_.load(std::memory_order_acquire)) {
            drops_++;
            return false;
        }
        buffer_[write_idx_.load(std::memory_order_relaxed)] = pkt;
        write_idx_.store(next, std::memory_order_release);
        return true;
    }

    bool pop(PacketInfo& pkt) {
        uint32_t r = read_idx_.load(std::memory_order_relaxed);
        if (r == write_idx_.load(std::memory_order_acquire)) {
            return false;
        }
        pkt = buffer_[r];
        read_idx_.store((r + 1) % RING_BUFFER_SIZE, std::memory_order_release);
        return true;
    }

    uint32_t available() const {
        uint32_t w = write_idx_.load(std::memory_order_acquire);
        uint32_t r = read_idx_.load(std::memory_order_acquire);
        return (w >= r) ? (w - r) : (RING_BUFFER_SIZE - r + w);
    }

    uint32_t drops() const { return drops_; }

private:
    PacketInfo buffer_[RING_BUFFER_SIZE];
    std::atomic<uint32_t> write_idx_{0};
    std::atomic<uint32_t> read_idx_{0};
    uint32_t drops_ = 0;
};
