#include <Arduino.h>
#include "config.h"
#include "ring_buffer.h"
#include "wifi_sniffer.h"
#include "packet_parser.h"
#include "feature_extractor.h"
#include "sd_logger.h"
#include "display.h"
#include "touch.h"
#include "ml_inference.h"

static RingBuffer ring_buffer;
static FeatureExtractor features;
static SDLogger sd_logger;
static Display display;
static TouchInput touch;
static MLInference ml;

static uint32_t last_feature_log_ms = 0;
static uint32_t last_ml_ms = 0;

void setup() {
    Serial.begin(115200);
    Serial.println("\n=== CYD Network Sniffer ===");

    display.init();
    display.tft().setTextDatum(MC_DATUM);
    display.tft().setTextColor(TFT_CYAN, TFT_BLACK);
    display.tft().drawString("CYD Network Sniffer", SCREEN_W / 2, SCREEN_H / 2 - 20, 4);
    display.tft().drawString("Initializing...", SCREEN_W / 2, SCREEN_H / 2 + 20, 2);

    touch.init(&display.tft());
    sd_logger.init();

    if (ml.init()) {
        display.set_ml_loaded(true);
    }

    sniffer_init(&ring_buffer);
    sniffer_set_channel(DEFAULT_CHANNEL);
    sniffer_start();

    delay(1500);
    display.tft().fillScreen(TFT_BLACK);

    Serial.println("Ready. Sniffing on channel " + String(DEFAULT_CHANNEL));
}

void loop() {
    PacketInfo pkt;
    int processed = 0;
    while (ring_buffer.pop(pkt) && processed < 64) {
        features.process_packet(pkt);
        sd_logger.log_packet(pkt);
        processed++;
    }

    uint32_t now = millis();
    if (sd_logger.is_logging() &&
        (now - last_feature_log_ms) >= (FEATURE_WINDOW_SEC * 1000)) {
        sd_logger.log_features(features);
        sd_logger.log_anomalies(features);
        last_feature_log_ms = now;
    }

    if (ml.is_loaded() && (now - last_ml_ms) >= ML_PREDICT_MS) {
        ml.predict_all(features);
        if (sd_logger.is_logging()) {
            sd_logger.log_ml_predictions(features);
        }
        last_ml_ms = now;
    }

    sniffer_tick();

    TouchEvent evt = touch.poll();

    if (evt.button != BTN_NONE) {
        switch (evt.button) {
            case BTN_CH_DOWN:
                if (sniffer_is_auto_hop()) {
                    sniffer_set_auto_hop(false);
                    sniffer_set_channel(MAX_CHANNELS);
                } else if (sniffer_get_channel() <= 1) {
                    sniffer_set_auto_hop(true);
                } else {
                    sniffer_set_channel(sniffer_get_channel() - 1);
                }
                Serial.println(sniffer_is_auto_hop() ? "AUTO" : "Channel: " + String(sniffer_get_channel()));
                break;
            case BTN_CH_UP:
                if (sniffer_is_auto_hop()) {
                    sniffer_set_auto_hop(false);
                    sniffer_set_channel(1);
                } else if (sniffer_get_channel() >= MAX_CHANNELS) {
                    sniffer_set_auto_hop(true);
                } else {
                    sniffer_set_channel(sniffer_get_channel() + 1);
                }
                Serial.println(sniffer_is_auto_hop() ? "AUTO" : "Channel: " + String(sniffer_get_channel()));
                break;
            case BTN_START_STOP:
                if (sniffer_is_running()) {
                    sniffer_stop();
                    Serial.println("Sniffer stopped");
                } else {
                    sniffer_start();
                    Serial.println("Sniffer started");
                }
                break;
            case BTN_LOG:
                if (sd_logger.is_ready()) {
                    sd_logger.set_logging(!sd_logger.is_logging());
                    Serial.println(sd_logger.is_logging() ? "Logging ON" : "Logging OFF");
                }
                break;
            case BTN_NAV_LEFT:
                display.prev_screen();
                Serial.println("Screen: prev");
                break;
            case BTN_NAV_RIGHT:
                display.next_screen();
                Serial.println("Screen: next");
                break;
            case BTN_RESET:
                features.reset();
                Serial.println("Devices cleared");
                break;
            case BTN_ML_TOGGLE:
                break;
            default:
                break;
        }
    }
    
    display.draw(features, sd_logger,
                 sniffer_get_channel(), sniffer_is_running(),
                 sniffer_is_auto_hop(), features.total_packets());
}
