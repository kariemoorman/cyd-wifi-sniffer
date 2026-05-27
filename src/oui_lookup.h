#pragma once

#include <cstdint>
#include "oui_table.h"

static constexpr uint8_t OUI_DEVICE_TYPE_NONE = 0xFF;

// Returns the DEVICE_TYPE_LABELS index for `mac`'s OUI, or
// OUI_DEVICE_TYPE_NONE when there is no match.
inline uint8_t oui_lookup(const uint8_t mac[6]) {
    // Randomized (locally-administered) MACs carry no vendor signal.
    if (mac[0] & 0x02) return OUI_DEVICE_TYPE_NONE;

    uint32_t key = ((uint32_t)mac[0] << 16) | ((uint32_t)mac[1] << 8) | mac[2];
    int lo = 0, hi = OUI_TABLE_LEN - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        uint32_t v = OUI_TABLE[mid].oui;
        if (v == key) return OUI_TABLE[mid].device_type;
        if (v < key)  lo = mid + 1;
        else          hi = mid - 1;
    }
    return OUI_DEVICE_TYPE_NONE;
}
