#include "wifi_sniffer.h"
#include "packet_parser.h"
#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_timer.h>
#include <cstring>

static RingBuffer* g_ring = nullptr;
static bool g_running = false;
static int g_channel = 6;
static bool g_auto_hop = false;
static uint32_t g_last_hop_ms = 0;

struct ieee80211_hdr {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  addr1[6]; // destination
    uint8_t  addr2[6]; // source
    uint8_t  addr3[6]; // bssid
    uint16_t seq_ctrl;
} __attribute__((packed));

// static void IRAM_ATTR promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
//     if (!g_ring) return;

//     auto* pkt = (wifi_promiscuous_pkt_t*)buf;
//     auto* rx  = &pkt->rx_ctrl;

//     if (rx->sig_len < sizeof(ieee80211_hdr)) return;

//     auto* hdr = (ieee80211_hdr*)pkt->payload;

//     PacketInfo info{};
//     info.timestamp_us  = esp_timer_get_time();
//     info.rssi          = rx->rssi;
//     info.channel       = rx->channel;
//     info.frame_type    = (hdr->frame_control & 0x0C) >> 2;
//     info.frame_subtype = (hdr->frame_control & 0xF0) >> 4;
//     info.duration      = hdr->duration;
//     info.pkt_len       = rx->sig_len;
//     info.rate          = rx->rate;
//     info.seq_num       = hdr->seq_ctrl >> 4;
//     info.retry         = (hdr->frame_control & 0x0800) != 0;

//     memcpy(info.src_mac, hdr->addr2, 6);
//     memcpy(info.dst_mac, hdr->addr1, 6);
//     memcpy(info.bssid,   hdr->addr3, 6);

//     info.capture_len = (rx->sig_len > MAX_CAPTURE_LEN) ? MAX_CAPTURE_LEN : rx->sig_len;
//     memcpy(info.raw, pkt->payload, info.capture_len);

//     info.ssid[0] = '\0';
//     if (info.frame_type == 0) {
//         uint8_t sub = info.frame_subtype;
//         if (sub == 0 || sub == 4 || sub == 5 || sub == 8) {
//             int body_offset = sizeof(ieee80211_hdr);
//             if (sub == 8 || sub == 5) body_offset += 12;
//             else if (sub == 0) body_offset += 4;

//             const uint8_t* payload = pkt->payload;
//             int total_len = rx->sig_len;
//             int pos = body_offset;
//             while (pos + 2 <= total_len) {
//                 uint8_t tag_id  = payload[pos];
//                 uint8_t tag_len = payload[pos + 1];
//                 if (pos + 2 + tag_len > total_len) break;
//                 if (tag_id == 0 && tag_len > 0 && tag_len <= 32) {
//                     memcpy(info.ssid, &payload[pos + 2], tag_len);
//                     info.ssid[tag_len] = '\0';
//                     break;
//                 }
//                 if (tag_id == 0) break;
//                 pos += 2 + tag_len;
//             }
//         }
//     }

//     g_ring->push(info);
// }


static void IRAM_ATTR promisc_cb(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!g_ring) return;

    auto* pkt = (wifi_promiscuous_pkt_t*)buf;
    auto* rx  = &pkt->rx_ctrl;

    if (rx->sig_len < 10) return;  // absolute minimum (ACK frame)

    auto* raw = pkt->payload;
    uint8_t frame_type = (raw[0] & 0x0C) >> 2;

    PacketInfo info{};
    info.timestamp_us  = esp_timer_get_time();
    info.rssi          = rx->rssi;
    info.channel       = rx->channel;
    info.frame_type    = frame_type;
    info.frame_subtype = (raw[0] & 0xF0) >> 4;
    info.pkt_len       = rx->sig_len;
    info.retry         = (raw[1] & 0x08) != 0;

    if (frame_type == FRAME_CTRL) {
        // Control frames have minimal headers
        // ACK/CTS: only addr1 (10 bytes), RTS: addr1+addr2 (16 bytes)
        memcpy(info.dst_mac, &raw[4], 6);
        if (rx->sig_len >= 16) {
            memcpy(info.src_mac, &raw[10], 6);
        }
        info.duration = raw[2] | (raw[3] << 8);
        info.rate = rx->rate;
        info.seq_num = 0;
        memset(info.bssid, 0, 6);
        info.ssid[0] = '\0';
        info.capture_len = (rx->sig_len > MAX_CAPTURE_LEN) ? MAX_CAPTURE_LEN : rx->sig_len;
        memcpy(info.raw, raw, info.capture_len);
        g_ring->push(info);
        return;
    }

    // MGMT and DATA frames need full header
    if (rx->sig_len < sizeof(ieee80211_hdr)) return;

    auto* hdr = (ieee80211_hdr*)raw;
    info.duration = hdr->duration;
    info.rate     = rx->rate;
    info.seq_num  = hdr->seq_ctrl >> 4;

    memcpy(info.src_mac, hdr->addr2, 6);
    memcpy(info.dst_mac, hdr->addr1, 6);
    memcpy(info.bssid,   hdr->addr3, 6);

    info.capture_len = (rx->sig_len > MAX_CAPTURE_LEN) ? MAX_CAPTURE_LEN : rx->sig_len;
    memcpy(info.raw, raw, info.capture_len);

    info.ssid[0] = '\0';
    if (info.frame_type == 0) {
        uint8_t sub = info.frame_subtype;
        if (sub == 0 || sub == 4 || sub == 5 || sub == 8) {
            int body_offset = sizeof(ieee80211_hdr);
            if (sub == 8 || sub == 5) body_offset += 12;
            else if (sub == 0) body_offset += 4;

            int total_len = rx->sig_len;
            int pos = body_offset;
            while (pos + 2 <= total_len) {
                uint8_t tag_id  = raw[pos];
                uint8_t tag_len = raw[pos + 1];
                if (pos + 2 + tag_len > total_len) break;
                if (tag_id == 0 && tag_len > 0 && tag_len <= 32) {
                    memcpy(info.ssid, &raw[pos + 2], tag_len);
                    info.ssid[tag_len] = '\0';
                    break;
                }
                if (tag_id == 0) break;
                pos += 2 + tag_len;
            }
        }
    }

    g_ring->push(info);
}

void sniffer_init(RingBuffer* rb) {
    g_ring = rb;

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();
}

void sniffer_start() {
    if (g_running) return;

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT // beacons, probes, assoc
                     | WIFI_PROMIS_FILTER_MASK_DATA // data frames
                     | WIFI_PROMIS_FILTER_MASK_CTRL // ACK, RTS/CTS, etc.
    };
    esp_wifi_set_promiscuous_filter(&filt);

    esp_wifi_set_promiscuous_rx_cb(promisc_cb);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
    g_running = true;
}

void sniffer_stop() {
    if (!g_running) return;

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    g_running = false;
}

void sniffer_set_channel(int channel) {
    if (channel < 1) channel = 1;
    if (channel > MAX_CHANNELS) channel = MAX_CHANNELS;
    g_channel = channel;
    if (g_running) {
        esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
    }
}

int sniffer_get_channel() {
    return g_channel;
}

bool sniffer_is_running() {
    return g_running;
}

void sniffer_set_auto_hop(bool enabled) {
    g_auto_hop = enabled;
    g_last_hop_ms = millis();
}

bool sniffer_is_auto_hop() {
    return g_auto_hop;
}

void sniffer_tick() {
    if (!g_auto_hop || !g_running) return;

    uint32_t now = millis();
    if (now - g_last_hop_ms >= CHANNEL_HOP_MS) {
        g_channel++;
        if (g_channel > MAX_CHANNELS) g_channel = 1;
        esp_wifi_set_channel(g_channel, WIFI_SECOND_CHAN_NONE);
        g_last_hop_ms = now;
    }
}
