#pragma once

#include <cstdint>
#include <TFT_eSPI.h>

enum TouchButton : int8_t {
    BTN_NONE = -1,
    BTN_CH_DOWN = 0,
    BTN_CH_UP = 1,
    BTN_START_STOP = 2,
    BTN_LOG = 3,
    BTN_NAV_LEFT = 4,
    BTN_NAV_RIGHT = 5,
    BTN_RESET = 6,
    BTN_ML_TOGGLE = 7,
};

enum SwipeDir : int8_t {
    SWIPE_NONE = 0,
    SWIPE_LEFT = -1,
    SWIPE_RIGHT = 1,
};

struct TouchEvent {
    TouchButton button;
    SwipeDir swipe;
};

class TouchInput {
public:
    void init(TFT_eSPI* tft);
    TouchEvent poll();

private:
    TFT_eSPI* tft_ = nullptr;
    bool was_pressed_ = false;
    int16_t start_x_ = 0;
    int16_t start_y_ = 0;
    uint32_t last_event_ms_ = 0;
    uint32_t press_start_ms_ = 0;
};
