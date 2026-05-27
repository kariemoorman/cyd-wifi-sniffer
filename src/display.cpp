#include "display.h"
#include "packet_parser.h"
#include "label_mappings.h"
#include "config.h"
#include <Arduino.h>

#define C_BG        TFT_BLACK
#define C_TEXT      TFT_WHITE
#define C_HEADER    0x1A3A
#define C_BTN       0x2945
#define C_BTN_ACT   0x04A0
#define C_ACCENT    TFT_CYAN
#define C_WARN      TFT_YELLOW
#define C_GOOD      TFT_GREEN
#define C_BAD       TFT_RED

// Font sizes for 480x320 display
#define F_SMALL  2  // 16px
#define F_MEDIUM 4  // 26px
#define F_LARGE  4  // 26px

void Display::init() {
    tft_.init();
    tft_.setRotation(1);
    tft_.fillScreen(C_BG);
    tft_.setTextColor(C_TEXT, C_BG);
    tft_.setTextSize(1);

    ledcSetup(0, 5000, 8);
    ledcAttachPin(PIN_TFT_BL, 0);
    set_brightness(200);
}

void Display::set_brightness(uint8_t level) {
    ledcWrite(0, level);
}

void Display::draw(FeatureExtractor& fe, SDLogger& logger,
                   int channel, bool running, bool auto_hop, uint32_t total_pkts) {
    uint32_t now = millis();
    if (now - last_draw_ms_ < DISPLAY_REFRESH_MS) return;
    last_draw_ms_ = now;

    draw_status_bar(channel, running, auto_hop, total_pkts, fe.device_count());
    draw_buttons(running, logger.is_logging(), auto_hop);

    switch (screen_) {
        case SCREEN_SSID:   draw_device_list(fe, true); break;
        case SCREEN_MAC:    draw_device_list(fe, false); break;
        case SCREEN_STATS:  draw_stats(fe, total_pkts); break;
        case SCREEN_ALERTS: draw_alerts(fe); break;
        case SCREEN_ML:     draw_ml(fe); break;
        case SCREEN_LOG:    draw_log(logger); break;
        default: break;
    }

    draw_nav_arrows();
}

void Display::next_screen() {
    do {
        screen_ = (Screen)((screen_ + 1) % SCREEN_COUNT);
    } while (screen_ == SCREEN_ML && !ml_loaded_);
    tft_.fillRect(0, LIST_AREA_Y, SCREEN_W, LIST_AREA_H, C_BG);
    tft_.fillRect(0, SCREEN_H - BUTTON_BAR_H, SCREEN_W, BUTTON_BAR_H, C_BG);
    prev_live_count_ = 0;
    prev_alert_count_ = 0;
    prev_ml_count_ = 0;
}

void Display::prev_screen() {
    do {
        screen_ = (Screen)((screen_ + SCREEN_COUNT - 1) % SCREEN_COUNT);
    } while (screen_ == SCREEN_ML && !ml_loaded_);
    tft_.fillRect(0, LIST_AREA_Y, SCREEN_W, LIST_AREA_H, C_BG);
    tft_.fillRect(0, SCREEN_H - BUTTON_BAR_H, SCREEN_W, BUTTON_BAR_H, C_BG);
    prev_live_count_ = 0;
    prev_alert_count_ = 0;
    prev_ml_count_ = 0;
}

void Display::draw_status_bar(int channel, bool running, bool auto_hop, uint32_t total_pkts, int device_count) {
    tft_.fillRect(0, 0, SCREEN_W, STATUS_BAR_H, C_HEADER);
    tft_.setTextDatum(TL_DATUM);
    tft_.setTextColor(C_ACCENT, C_HEADER);

    String ch_str = "CH:" + String(channel);
    if (auto_hop) ch_str += "*";
    tft_.drawString(ch_str, 6, 3, F_SMALL);
    tft_.drawString("PKT:" + String(total_pkts), 110, 3, F_SMALL);
    tft_.drawString("DEV:" + String(device_count), 260, 3, F_SMALL);

    if (ml_loaded_) {
        tft_.setTextColor(TFT_MAGENTA, C_HEADER);
        tft_.drawString("ML", 370, 3, F_SMALL);
    }

    tft_.setTextDatum(TR_DATUM);
    if (running) {
        tft_.setTextColor(C_GOOD, C_HEADER);
        tft_.drawString("LIVE", SCREEN_W - 6, 3, F_SMALL);
    } else {
        tft_.setTextColor(C_BAD, C_HEADER);
        tft_.drawString("STOP", SCREEN_W - 6, 3, F_SMALL);
    }
}

void Display::draw_buttons(bool running, bool logging, bool auto_hop) {
    int y = SCREEN_H - BUTTON_BAR_H;
    int bw = SCREEN_W / 4;

    tft_.setTextDatum(MC_DATUM);

    // CH-
    tft_.fillRect(0, y, bw - 2, BUTTON_BAR_H, C_BTN);
    tft_.setTextColor(C_TEXT, C_BTN);
    tft_.drawString("CH-", bw / 2, y + BUTTON_BAR_H / 2, F_MEDIUM);

    // CH+ / AUTO
    uint16_t hop_col = auto_hop ? C_ACCENT : C_BTN;
    tft_.fillRect(bw, y, bw - 2, BUTTON_BAR_H, hop_col);
    tft_.setTextColor(auto_hop ? TFT_BLACK : C_TEXT, hop_col);
    tft_.drawString(auto_hop ? "AUTO" : "CH+", bw + bw / 2, y + BUTTON_BAR_H / 2, F_MEDIUM);

    // START/STOP
    uint16_t col = running ? C_BAD : C_BTN_ACT;
    tft_.fillRect(bw * 2, y, bw - 2, BUTTON_BAR_H, col);
    tft_.setTextColor(C_TEXT, col);
    tft_.drawString(running ? "STOP" : "START", bw * 2 + bw / 2, y + BUTTON_BAR_H / 2, F_MEDIUM);

    // LOG
    uint16_t lcol = logging ? C_WARN : C_BTN;
    tft_.fillRect(bw * 3, y, bw, BUTTON_BAR_H, lcol);
    tft_.setTextColor(C_TEXT, lcol);
    tft_.drawString("LOG", bw * 3 + bw / 2, y + BUTTON_BAR_H / 2, F_MEDIUM);
}

void Display::draw_nav_arrows() {
}

void Display::draw_device_list(FeatureExtractor& fe, bool show_ssid) {
    fe.sort_by_packets();

    int max_rows = LIST_AREA_H / LIST_ROW_H;
    int count = min(fe.device_count(), max_rows);

    if (count == 0) {
        if (prev_live_count_ != 0) {
            tft_.fillRect(0, LIST_AREA_Y, SCREEN_W, LIST_AREA_H, C_BG);
            prev_live_count_ = 0;
        }
        tft_.setTextColor(C_TEXT, C_BG);
        tft_.setTextDatum(MC_DATUM);
        tft_.setTextPadding(300);
        tft_.drawString("Waiting for packets...", SCREEN_W / 2, SCREEN_H / 2, F_MEDIUM);
        tft_.setTextPadding(0);
        return;
    }

    if (prev_live_count_ == 0) {
        tft_.fillRect(0, LIST_AREA_Y, SCREEN_W, LIST_AREA_H, C_BG);
    }

    tft_.setTextDatum(TL_DATUM);

    for (int i = 0; i < count; i++) {
        DeviceStats* dev = &fe.get_devices()[i];
        int y = LIST_AREA_Y + i * LIST_ROW_H + 2;

        tft_.setTextColor(C_ACCENT, C_BG);
        tft_.setTextPadding(145);
        if (show_ssid && dev->ssid[0] != '\0') {
            tft_.drawString(dev->ssid, 6, y, F_SMALL);
        } else {
            char mac_str[18];
            mac_to_str(dev->mac, mac_str);
            tft_.drawString(mac_str, 6, y, F_SMALL);
        }

        if (dev->security != SEC_UNKNOWN) {
            tft_.setTextColor(C_WARN, C_BG);
            tft_.setTextPadding(55);
            tft_.drawString(security_str(dev->security), 155, y, F_SMALL);
        } else {
            tft_.setTextPadding(55);
            tft_.setTextColor(C_BG, C_BG);
            tft_.drawString("", 155, y, F_SMALL);
        }

        tft_.setTextColor(C_TEXT, C_BG);
        char info[32];
        snprintf(info, sizeof(info), "%ddB  %u", (int)dev->avg_rssi(), dev->pkt_count);
        tft_.setTextPadding(180);
        tft_.drawString(info, 220, y, F_SMALL);
        tft_.setTextPadding(0);

        int bar_w = map(constrain((int)dev->avg_rssi(), -90, -20), -90, -20, 0, 60);
        uint16_t bar_color = bar_w > 35 ? C_GOOD : (bar_w > 18 ? C_WARN : C_BAD);
        tft_.fillRect(395, y + 2, bar_w, LIST_ROW_H - 6, bar_color);
        if (bar_w < 60)
            tft_.fillRect(395 + bar_w, y + 2, 60 - bar_w, LIST_ROW_H - 6, C_BG);
    }

    if (count < prev_live_count_) {
        int clear_y = LIST_AREA_Y + count * LIST_ROW_H;
        tft_.fillRect(0, clear_y, SCREEN_W, (prev_live_count_ - count) * LIST_ROW_H, C_BG);
    }
    prev_live_count_ = count;
}

void Display::draw_stats(FeatureExtractor& fe, uint32_t total_pkts) {
    tft_.setTextDatum(TL_DATUM);
    tft_.setTextPadding(300);

    uint32_t mgmt = 0, data = 0, ctrl = 0;
    for (int i = 0; i < fe.device_count(); i++) {
        DeviceStats* d = &fe.get_devices()[i];
        mgmt += d->mgmt_count;
        data += d->data_count;
        ctrl += d->ctrl_count;
    }

    // Push deltas into history
    uint32_t new_mgmt = mgmt - prev_mgmt_;
    uint32_t new_data = data - prev_data_;
    uint32_t new_ctrl = ctrl - prev_ctrl_;

    // Skip the first-frame spike
    if (prev_mgmt_ == 0 && prev_data_ == 0 && prev_ctrl_ == 0) {
        new_mgmt = new_data = new_ctrl = 0;
    }

    prev_mgmt_ = mgmt;
    prev_data_ = data;
    prev_ctrl_ = ctrl;
    frame_hist_.push(new_mgmt, new_data, new_ctrl);

    int y = LIST_AREA_Y + 10;
    tft_.setTextColor(TFT_MAGENTA, C_BG);
    tft_.drawString("Frame Types:", 10, y, F_MEDIUM);    y += 34;

    tft_.setTextColor(C_GOOD, C_BG);
    tft_.drawString("MGMT: " + String(mgmt), 10, y, F_SMALL);
    tft_.setTextColor(C_WARN, C_BG);
    tft_.drawString("Devices: " + String(fe.device_count()), 250, y, F_SMALL);
    y += 26;

    tft_.setTextColor(C_ACCENT, C_BG);
    tft_.drawString("DATA: " + String(data), 10, y, F_SMALL);
    tft_.setTextColor(C_WARN, C_BG);
    tft_.drawString("Total Frames: " + String(total_pkts), 250, y, F_SMALL);
    y += 26;

    tft_.setTextColor(C_TEXT, C_BG);
    tft_.drawString("CTRL: " + String(ctrl), 10, y, F_SMALL);
    y += 26;

    // Stacked bar graph
    int graph_y = LIST_AREA_Y + 160;
    int graph_h = 80;
    int bar_w = (SCREEN_W - 20) / HIST_LEN;
    int base_x = 10;

    uint32_t max_val = 1;
    for (int i = 0; i < HIST_LEN; i++) {
        uint32_t total = frame_hist_.get_mgmt(i) + frame_hist_.get_data(i) + frame_hist_.get_ctrl(i);
        if (total > max_val) max_val = total;
    }

    tft_.fillRect(base_x, graph_y, SCREEN_W - base_x - 10, graph_h, C_BG);

    for (int i = 0; i < HIST_LEN; i++) {
        int x = base_x + i * bar_w;
        uint32_t m = frame_hist_.get_mgmt(i);
        uint32_t d = frame_hist_.get_data(i);
        uint32_t c = frame_hist_.get_ctrl(i);

        int h_m = (m * graph_h) / max_val;
        int h_d = (d * graph_h) / max_val;
        int h_c = (c * graph_h) / max_val;

        // Clamp so bars never exceed graph area
        int total_h = h_m + h_d + h_c;
        if (total_h > graph_h) {
            h_m = h_m * graph_h / total_h;
            h_d = h_d * graph_h / total_h;
            h_c = graph_h - h_m - h_d;
        }

        int bottom = graph_y + graph_h;

        int y_ctrl = bottom - h_c;
        int y_data = y_ctrl - h_d;
        int y_mgmt = y_data - h_m;

        if (y_mgmt < graph_y) y_mgmt = graph_y;
        if (y_data < graph_y) y_data = graph_y;
        if (y_ctrl < graph_y) y_ctrl = graph_y;

        if (h_c > 0) tft_.fillRect(x, y_ctrl, bar_w - 1, h_c, C_WARN);
        if (h_d > 0) tft_.fillRect(x, y_data, bar_w - 1, h_d, C_ACCENT);
        if (h_m > 0) tft_.fillRect(x, y_mgmt, bar_w - 1, h_m, C_GOOD);
    }

    tft_.setTextPadding(0);
}

void Display::draw_alerts(FeatureExtractor& fe) {
    tft_.setTextDatum(TL_DATUM);

    int y = LIST_AREA_Y + 10;
    tft_.setTextColor(TFT_MAGENTA, C_BG);
    tft_.setTextPadding(300);
    tft_.drawString("Anomaly Detection", 10, y, F_MEDIUM);
    y += 32;

    int alert_count = 0;
    int max_rows = (LIST_AREA_H - 40) / LIST_ROW_H;

    for (int i = 0; i < fe.device_count() && alert_count < max_rows; i++) {
        DeviceStats* dev = &fe.get_devices()[i];
        if (dev->pkt_count < 10 || dev->pkt_rate() < 1.0f) continue;

        const char* reason = nullptr;

        if (dev->probe_req_rate() > 5.0f) {
            reason = "HIGH PROBE";
        } else if (dev->retry_ratio() > 0.5f && dev->pkt_rate() > 5.0f) {
            reason = "HIGH RETRY";
        } else if (dev->unique_dst_count > 20 && dev->pkt_rate() > 1.0f) {
            reason = "MANY DSTS";
        } else if (dev->pkt_rate() > 200.0f && dev->data_ratio() > 0.8f) {
            reason = "FLOOD";
        }

        if (reason) {
            char mac_str[18];
            mac_to_str(dev->mac, mac_str);

            tft_.fillCircle(16, y + 8, 5, C_BAD);

            tft_.setTextColor(C_ACCENT, C_BG);
            tft_.setTextPadding(200);
            tft_.drawString(mac_str, 28, y, F_SMALL);

            tft_.setTextColor(C_WARN, C_BG);
            tft_.setTextPadding(140);
            tft_.drawString(reason, 240, y, F_SMALL);

            char detail[32];
            snprintf(detail, sizeof(detail), "%u pkts %.0fp/s", dev->pkt_count, dev->pkt_rate());
            tft_.setTextColor(C_TEXT, C_BG);
            tft_.setTextPadding(120);
            tft_.drawString(detail, 360, y, F_SMALL);

            y += LIST_ROW_H;
            alert_count++;
        }
    }

    tft_.setTextPadding(0);

    if (alert_count == 0) {
        if (prev_alert_count_ > 0) {
            int clear_y = LIST_AREA_Y + 38;
            tft_.fillRect(0, clear_y, SCREEN_W, LIST_AREA_H - 38, C_BG);
        }
        tft_.setTextPadding(300);
        tft_.setTextColor(C_GOOD, C_BG);
        tft_.drawString("No anomalies detected", 10, y + 20, F_SMALL);
        tft_.setTextPadding(0);
    } else if (alert_count < prev_alert_count_) {
        tft_.fillRect(0, y, SCREEN_W, (prev_alert_count_ - alert_count) * LIST_ROW_H, C_BG);
    } else if (prev_alert_count_ == 0 && alert_count > 0) {
        int msg_y = LIST_AREA_Y + 38;
        tft_.fillRect(0, msg_y, SCREEN_W, 80, C_BG);
    }
    prev_alert_count_ = alert_count;
}

void Display::draw_ml(FeatureExtractor& fe) {
    tft_.setTextDatum(TL_DATUM);

    int y = LIST_AREA_Y + 10;
    tft_.setTextColor(TFT_MAGENTA, C_BG);
    tft_.setTextPadding(300);
    tft_.drawString("ML Classification", 10, y, F_MEDIUM);
    y += 32;

    if (!ml_loaded_) {
        if (prev_ml_count_ > 0) {
            int clear_y = LIST_AREA_Y + 38;
            tft_.fillRect(0, clear_y, SCREEN_W, LIST_AREA_H - 38, C_BG);
            prev_ml_count_ = 0;
        }
        tft_.setTextPadding(300);
        tft_.setTextColor(C_BAD, C_BG);
        tft_.drawString("ML model not loaded", 10, y + 20, F_SMALL);
        tft_.setTextPadding(0);
        return;
    }

    fe.sort_by_packets();
    int ml_count = 0;
    int max_rows = (LIST_AREA_H - 40) / LIST_ROW_H;

    for (int i = 0; i < fe.device_count() && ml_count < max_rows; i++) {
        DeviceStats* dev = &fe.get_devices()[i];
        if (!dev->ml.valid) continue;

        char mac_str[18];
        mac_to_str(dev->mac, mac_str);

        uint16_t dot_color = dev->ml.anomaly == 1 ? C_BAD : C_GOOD;
        tft_.fillCircle(16, y + 8, 5, dot_color);

        tft_.setTextColor(C_ACCENT, C_BG);
        tft_.setTextPadding(150);
        tft_.drawString(mac_str, 24, y, F_SMALL);

        tft_.setTextColor(C_WARN, C_BG);
        tft_.setTextPadding(92);
        uint8_t dtype = (dev->oui_device_type != OUI_DEVICE_TYPE_NONE)
            ? dev->oui_device_type
            : dev->ml.device_type;
        tft_.drawString(DEVICE_TYPE_LABELS[dtype], 168, y, F_SMALL);

        uint16_t cls_col = dev->ml.packet_class >= 2 ? C_BAD :
                           dev->ml.packet_class == 1 ? C_WARN : C_TEXT;
        tft_.setTextColor(cls_col, C_BG);
        tft_.setTextPadding(75);
        tft_.drawString(PACKET_CLASS_LABELS[dev->ml.packet_class], 262, y, F_SMALL);

        uint16_t act_col = dev->ml.route_action == 2 ? C_BAD :
                           dev->ml.route_action == 1 ? C_WARN : C_GOOD;
        tft_.setTextColor(act_col, C_BG);
        tft_.setTextPadding(55);
        tft_.drawString(ROUTE_ACTION_LABELS[dev->ml.route_action], 342, y, F_SMALL);

        char score[16];
        float threat = fmaxf(dev->ml.anomaly_score, dev->ml.packet_class_score);
        snprintf(score, sizeof(score), "%.2f", threat);
        bool is_threat = (dev->ml.anomaly == 1) || (dev->ml.packet_class == 2);
        tft_.setTextColor(is_threat ? C_BAD : C_TEXT, C_BG);
        tft_.setTextPadding(80);
        tft_.drawString(score, 400, y, F_SMALL);

        y += LIST_ROW_H;
        ml_count++;
    }

    tft_.setTextPadding(0);

    if (ml_count == 0) {
        if (prev_ml_count_ > 0) {
            int clear_y = LIST_AREA_Y + 38;
            tft_.fillRect(0, clear_y, SCREEN_W, LIST_AREA_H - 38, C_BG);
        }
        tft_.setTextPadding(300);
        tft_.setTextColor(C_TEXT, C_BG);
        tft_.drawString("No ML predictions yet", 10, y + 20, F_SMALL);
        tft_.drawString("(need 5+ packets per device)", 10, y + 46, F_SMALL);
        tft_.setTextPadding(0);
    } else if (ml_count < prev_ml_count_) {
        tft_.fillRect(0, y, SCREEN_W, (prev_ml_count_ - ml_count) * LIST_ROW_H, C_BG);
    } else if (prev_ml_count_ == 0 && ml_count > 0) {
        int msg_y = LIST_AREA_Y + 38;
        tft_.fillRect(0, msg_y, SCREEN_W, 80, C_BG);
    }
    prev_ml_count_ = ml_count;
}

void Display::draw_log(SDLogger& logger) {
    tft_.setTextDatum(TL_DATUM);
    tft_.setTextPadding(350);

    int y = LIST_AREA_Y + 10;

    tft_.setTextColor(TFT_MAGENTA, C_BG);
    tft_.drawString("SD Card Logger", 10, y, F_MEDIUM); y += 36;

    if (logger.is_ready()) {
        tft_.setTextColor(C_GOOD, C_BG);
        tft_.drawString("SD: Ready", 10, y, F_SMALL); y += 28;

        tft_.setTextColor(C_TEXT, C_BG);
        tft_.drawString("File: " + String(logger.filename()), 10, y, F_SMALL); y += 26;
        tft_.drawString("Logged: " + String(logger.packets_logged()) + " pkts", 10, y, F_SMALL); y += 26;

        tft_.setTextColor(logger.is_logging() ? C_GOOD : C_WARN, C_BG);
        tft_.drawString(logger.is_logging() ? "Status: RECORDING" : "Status: PAUSED", 10, y, F_SMALL);
    } else {
        tft_.setTextColor(C_BAD, C_BG);
        tft_.drawString("SD: Not found", 10, y, F_SMALL); y += 28;
        tft_.setTextColor(C_TEXT, C_BG);
        tft_.drawString("Insert SD card and reset", 10, y, F_SMALL);
    }

    tft_.setTextPadding(0);
}
