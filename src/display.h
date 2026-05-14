#pragma once

#include <TFT_eSPI.h>
#include "feature_extractor.h"
#include "sd_logger.h"

enum Screen : uint8_t {
    SCREEN_SSID = 0,
    SCREEN_MAC,
    SCREEN_STATS,
    SCREEN_ALERTS,
    SCREEN_ML,
    SCREEN_LOG,
    SCREEN_COUNT
};


static constexpr int HIST_LEN = 30;  // 30 time slots

struct FrameHistory {
    uint32_t mgmt[HIST_LEN] = {};
    uint32_t data[HIST_LEN] = {};
    uint32_t ctrl[HIST_LEN] = {};
    int head = 0;

    void push(uint32_t m, uint32_t d, uint32_t c) {
        mgmt[head] = m;
        data[head] = d;
        ctrl[head] = c;
        head = (head + 1) % HIST_LEN;
    }

    // read i-th oldest sample (0 = oldest)
    uint32_t get_mgmt(int i) const { return mgmt[(head + i) % HIST_LEN]; }
    uint32_t get_data(int i) const { return data[(head + i) % HIST_LEN]; }
    uint32_t get_ctrl(int i) const { return ctrl[(head + i) % HIST_LEN]; }
};


class Display {
public:
    void init();
    void set_brightness(uint8_t level);
    void draw(FeatureExtractor& fe, SDLogger& logger,
              int channel, bool running, bool auto_hop, uint32_t total_pkts);
    void set_screen(Screen s) { screen_ = s; }
    Screen get_screen() const { return screen_; }
    void next_screen();
    void prev_screen();
    void set_ml_loaded(bool on) { ml_loaded_ = on; }
    bool get_ml_loaded() const { return ml_loaded_; }

    TFT_eSPI& tft() { return tft_; }

private:
    TFT_eSPI tft_;
    Screen screen_ = SCREEN_SSID;
    uint32_t last_draw_ms_ = 0;
    int prev_live_count_ = 0;
    int prev_alert_count_ = 0;
    int prev_ml_count_ = 0;
    bool ml_loaded_ = false;

    FrameHistory frame_hist_;
    uint32_t prev_mgmt_ = 0;
    uint32_t prev_data_ = 0;
    uint32_t prev_ctrl_ = 0;

    void draw_status_bar(int channel, bool running, bool auto_hop, uint32_t total_pkts, int device_count);
    void draw_nav_arrows();
    void draw_buttons(bool running, bool logging, bool auto_hop);
    void draw_device_list(FeatureExtractor& fe, bool show_ssid);
    void draw_stats(FeatureExtractor& fe, uint32_t total_pkts);
    void draw_alerts(FeatureExtractor& fe);
    void draw_ml(FeatureExtractor& fe);
    void draw_log(SDLogger& logger);
};
