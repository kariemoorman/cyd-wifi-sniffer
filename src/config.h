#pragma once

#include <cstdint>

// --- Display (ST7796 on HSPI) ---
constexpr int PIN_TFT_BL       = 27;

// --- Touch (XPT2046 on shared HSPI) ---
constexpr int PIN_TOUCH_CS     = 33;
constexpr int PIN_TOUCH_IRQ    = 36;

// --- SD Card (VSPI) ---
constexpr int PIN_SD_CS        = 5;
constexpr int PIN_SD_MOSI      = 23;
constexpr int PIN_SD_MISO      = 19;
constexpr int PIN_SD_SCK       = 18;

// --- Sniffer ---
constexpr int MAX_CAPTURE_LEN      = 256;
constexpr int RING_BUFFER_SIZE     = 128;
constexpr int MAX_DEVICES          = 96;
constexpr int FEATURE_WINDOW_SEC   = 10;
constexpr int SD_FLUSH_INTERVAL_MS = 5000;
constexpr int SD_FLUSH_PKT_COUNT   = 100;
constexpr int DEFAULT_CHANNEL      = 1;
constexpr int DISPLAY_REFRESH_MS   = 500;
constexpr int MAX_CHANNELS         = 13;
constexpr int CHANNEL_HOP_MS       = 2000;
constexpr int ML_PREDICT_MS        = 10000;
constexpr bool ML_MODE_DEFAULT     = true;

// --- Display layout (480x320 landscape) ---
constexpr int SCREEN_W             = 480;
constexpr int SCREEN_H             = 320;
constexpr int STATUS_BAR_H         = 24;
constexpr int BUTTON_BAR_H         = 48;
constexpr int LIST_AREA_Y          = STATUS_BAR_H;
constexpr int LIST_AREA_H          = SCREEN_H - STATUS_BAR_H - BUTTON_BAR_H;
constexpr int LIST_ROW_H           = 24;
constexpr int NAV_BTN_W            = 30;
