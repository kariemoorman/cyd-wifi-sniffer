#pragma once

#include <SPI.h>
#include <SD.h>
#include "ring_buffer.h"
#include "feature_extractor.h"

struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} __attribute__((packed));

struct pcap_pkthdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
} __attribute__((packed));

class SDLogger {
public:
    bool init();
    void log_packet(const PacketInfo& pkt);
    void log_features(FeatureExtractor& fe);
    void log_anomalies(FeatureExtractor& fe);
    void log_ml_predictions(FeatureExtractor& fe);
    void flush();
    void close();

    bool is_ready() const { return ready_; }
    bool is_logging() const { return logging_; }
    void set_logging(bool on) { logging_ = on; }
    uint32_t packets_logged() const { return packets_logged_; }
    const char* filename() const { return pkt_filename_; }

private:
    SPIClass sd_spi_{VSPI};
    File pkt_file_;
    File feat_file_;
    File pcap_file_;
    File alert_file_;
    File ml_file_;
    char pkt_filename_[32];
    char feat_filename_[32];
    char pcap_filename_[32];
    char alert_filename_[32];
    char ml_filename_[32];
    bool ready_ = false;
    bool logging_ = false;
    uint32_t packets_logged_ = 0;
    uint32_t pending_writes_ = 0;
    uint32_t last_flush_ms_ = 0;

    void generate_filenames();
};
