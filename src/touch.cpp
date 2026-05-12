#include "touch.h"
#include "config.h"
#include <Arduino.h>

void TouchInput::init(TFT_eSPI* tft) {
    tft_ = tft;
    uint16_t calData[5] = {300, 3600, 300, 3600, 1};
    tft_->setTouch(calData);
}

TouchEvent TouchInput::poll() {
    TouchEvent evt = {BTN_NONE, SWIPE_NONE};
    if (!tft_) return evt;

    uint32_t now = millis();
    if (now - last_event_ms_ < 200) return evt;

    uint16_t tx, ty;
    bool pressed = tft_->getTouch(&tx, &ty);

    if (pressed && !was_pressed_) {
        start_x_ = SCREEN_W - tx;
        start_y_ = ty;
        was_pressed_ = true;
        press_start_ms_ = now;
    } else if (!pressed && was_pressed_) {
        was_pressed_ = false;
        last_event_ms_ = now;
        uint32_t hold_ms = now - press_start_ms_;

        // nav buttons on left/right edges of list area
        if (start_y_ > STATUS_BAR_H && start_y_ < (SCREEN_H - BUTTON_BAR_H)) {
            if (start_x_ < NAV_BTN_W) {
                evt.button = BTN_NAV_LEFT;
                return evt;
            } else if (start_x_ >= (SCREEN_W - NAV_BTN_W)) {
                evt.button = BTN_NAV_RIGHT;
                return evt;
            }
        }

        // bottom button bar
        if (start_y_ >= (SCREEN_H - BUTTON_BAR_H)) {
            int bw = SCREEN_W / 4;
            int btn_idx = start_x_ / bw;
            if (btn_idx == BTN_START_STOP && hold_ms >= 2000) {
                evt.button = BTN_RESET;
            } else if (btn_idx == BTN_LOG && hold_ms >= 2000) {
                evt.button = BTN_ML_TOGGLE;
            } else if (btn_idx >= 0 && btn_idx <= 3) {
                evt.button = (TouchButton)btn_idx;
            }
        }
    }

    return evt;
}
