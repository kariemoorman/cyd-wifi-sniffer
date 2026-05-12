#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include "config.h"
#include "ring_buffer.h"

enum FrameType : uint8_t {
    FRAME_MGMT = 0,
    FRAME_CTRL = 1,
    FRAME_DATA = 2,
};

enum MgmtSubtype : uint8_t {
    MGMT_ASSOC_REQ    = 0,
    MGMT_ASSOC_RESP   = 1,
    MGMT_PROBE_REQ    = 4,
    MGMT_PROBE_RESP   = 5,
    MGMT_BEACON       = 8,
    MGMT_DISASSOC     = 10,
    MGMT_AUTH          = 11,
    MGMT_DEAUTH       = 12,
};

inline const char* frame_type_str(uint8_t type) {
    switch (type) {
        case FRAME_MGMT: return "MGMT";
        case FRAME_CTRL: return "CTRL";
        case FRAME_DATA: return "DATA";
        default:         return "UNKN";
    }
}

inline const char* mgmt_subtype_str(uint8_t subtype) {
    switch (subtype) {
        case MGMT_BEACON:     return "BEACON";
        case MGMT_PROBE_REQ:  return "PROBE_REQ";
        case MGMT_PROBE_RESP: return "PROBE_RESP";
        case MGMT_AUTH:       return "AUTH";
        case MGMT_DEAUTH:     return "DEAUTH";
        case MGMT_ASSOC_REQ:  return "ASSOC_REQ";
        case MGMT_ASSOC_RESP: return "ASSOC_RESP";
        case MGMT_DISASSOC:   return "DISASSOC";
        default:              return "OTHER";
    }
}

enum SecurityType : uint8_t {
    SEC_UNKNOWN = 0,
    SEC_OPEN,
    SEC_WEP,
    SEC_WPA,
    SEC_WPA2,
    SEC_WPA3,
    SEC_WPA2_WPA3,
};

inline const char* security_str(SecurityType s) {
    switch (s) {
        case SEC_OPEN:      return "OPEN";
        case SEC_WEP:       return "WEP";
        case SEC_WPA:       return "WPA";
        case SEC_WPA2:      return "WPA2";
        case SEC_WPA3:      return "WPA3";
        case SEC_WPA2_WPA3: return "W2/3";
        default:            return "";
    }
}

inline SecurityType parse_security(const uint8_t* frame, uint16_t len) {
    if (len < 38) return SEC_UNKNOWN;

    uint16_t capability = frame[34] | (frame[35] << 8);
    bool privacy = (capability & 0x0010) != 0;

    int pos = 36;
    bool has_rsn = false;
    bool has_wpa = false;
    bool has_psk = false;
    bool has_sae = false;

    while (pos + 2 <= len) {
        uint8_t tag_id  = frame[pos];
        uint8_t tag_len = frame[pos + 1];
        if (pos + 2 + tag_len > len) break;

        if (tag_id == 48 && tag_len >= 10) {
            has_rsn = true;
            int off = pos + 2 + 2 + 4;
            if (off + 2 > pos + 2 + tag_len) { pos += 2 + tag_len; continue; }
            uint16_t pw_count = frame[off] | (frame[off + 1] << 8);
            off += 2 + pw_count * 4;
            if (off + 2 > pos + 2 + tag_len) { pos += 2 + tag_len; continue; }
            uint16_t akm_count = frame[off] | (frame[off + 1] << 8);
            off += 2;
            for (int i = 0; i < akm_count && off + 4 <= pos + 2 + tag_len; i++) {
                uint8_t akm_type = frame[off + 3];
                if (akm_type == 2) has_psk = true;
                if (akm_type == 8) has_sae = true;
                off += 4;
            }
        }

        if (tag_id == 221 && tag_len >= 4) {
            if (frame[pos+2] == 0x00 && frame[pos+3] == 0x50 &&
                frame[pos+4] == 0xF2 && frame[pos+5] == 0x01) {
                has_wpa = true;
            }
        }

        pos += 2 + tag_len;
    }

    if (has_rsn) {
        if (has_psk && has_sae) return SEC_WPA2_WPA3;
        if (has_sae) return SEC_WPA3;
        return SEC_WPA2;
    }
    if (has_wpa) return SEC_WPA;
    if (privacy) return SEC_WEP;
    return SEC_OPEN;
}

inline void mac_to_str(const uint8_t mac[6], char* out) {
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

inline bool mac_equals(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

inline bool mac_is_broadcast(const uint8_t mac[6]) {
    return mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
           mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF;
}
