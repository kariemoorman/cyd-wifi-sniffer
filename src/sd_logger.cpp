#include "sd_logger.h"
#include "packet_parser.h"
#include "label_mappings.h"
#include "config.h"
#include <Arduino.h>

bool SDLogger::init() {
    sd_spi_.begin(PIN_SD_SCK, PIN_SD_MISO, PIN_SD_MOSI, PIN_SD_CS);

    if (!SD.begin(PIN_SD_CS, sd_spi_)) {
        Serial.println("SD card init failed");
        ready_ = false;
        return false;
    }

    Serial.printf("SD card: %lluMB\n", SD.cardSize() / (1024 * 1024));

    generate_filenames();

    pkt_file_ = SD.open(pkt_filename_, FILE_WRITE);
    if (!pkt_file_) {
        Serial.println("Failed to create packet log");
        ready_ = false;
        return false;
    }
    pkt_file_.println("timestamp,channel,src_mac,dst_mac,bssid,frame_type,frame_subtype,rssi,pkt_len,rate,seq_num,retry,ssid");

    feat_file_ = SD.open(feat_filename_, FILE_WRITE);
    if (feat_file_) {
        feat_file_.println("timestamp,src_mac,oui,ssid,security,pkt_count,avg_pkt_size,std_pkt_size,avg_rssi,"
                           "pkt_rate,mgmt_ratio,data_ratio,ctrl_ratio,unique_dst_count,"
                           "beacon_rate,probe_req_rate,retry_ratio");
    }

    pcap_file_ = SD.open(pcap_filename_, FILE_WRITE);
    if (pcap_file_) {
        pcap_file_header ghdr{};
        ghdr.magic = 0xa1b2c3d4;
        ghdr.version_major = 2;
        ghdr.version_minor = 4;
        ghdr.snaplen = MAX_CAPTURE_LEN;
        ghdr.linktype = 105;
        pcap_file_.write((uint8_t*)&ghdr, sizeof(ghdr));
        pcap_file_.flush();
    }

    alert_file_ = SD.open(alert_filename_, FILE_WRITE);
    if (alert_file_) {
        alert_file_.println("timestamp,src_mac,ssid,security,alert,pkt_count,pkt_rate,avg_rssi,probe_req_rate,retry_ratio,unique_dst_count,data_ratio");
    }

    ml_file_ = SD.open(ml_filename_, FILE_WRITE);
    if (ml_file_) {
        ml_file_.println("timestamp,src_mac,anomaly,packet_class,protocol,device_type,route_action,anomaly_score,packet_class_score");
    }

    ready_ = true;
    Serial.printf("Logging to: %s, %s\n", pkt_filename_, pcap_filename_);
    return true;
}

void SDLogger::log_packet(const PacketInfo& pkt) {
    if (!ready_ || !logging_) return;

    char src[18], dst[18], bss[18];
    mac_to_str(pkt.src_mac, src);
    mac_to_str(pkt.dst_mac, dst);
    mac_to_str(pkt.bssid, bss);

    pkt_file_.printf("%lld,%u,%s,%s,%s,%u,%u,%d,%u,%u,%u,%u,%s\n",
                     pkt.timestamp_us, pkt.channel,
                     src, dst, bss,
                     pkt.frame_type, pkt.frame_subtype,
                     pkt.rssi, pkt.pkt_len, pkt.rate,
                     pkt.seq_num, pkt.retry ? 1 : 0,
                     pkt.ssid);

    if (pcap_file_ && pkt.capture_len > 0) {
        pcap_pkthdr phdr{};
        phdr.ts_sec  = (uint32_t)(pkt.timestamp_us / 1000000);
        phdr.ts_usec = (uint32_t)(pkt.timestamp_us % 1000000);
        phdr.caplen  = pkt.capture_len;
        phdr.len     = pkt.pkt_len;
        pcap_file_.write((uint8_t*)&phdr, sizeof(phdr));
        pcap_file_.write(pkt.raw, pkt.capture_len);
    }

    packets_logged_++;
    pending_writes_++;

    uint32_t now = millis();
    if (pending_writes_ >= SD_FLUSH_PKT_COUNT ||
        (now - last_flush_ms_) >= SD_FLUSH_INTERVAL_MS) {
        flush();
    }
}

void SDLogger::log_features(FeatureExtractor& fe) {
    if (!ready_ || !logging_ || !feat_file_) return;

    int64_t now = esp_timer_get_time();
    char mac_str[18];

    for (int i = 0; i < fe.device_count(); i++) {
        DeviceStats* dev = &fe.get_devices()[i];
        if (dev->pkt_count == 0) continue;

        mac_to_str(dev->mac, mac_str);
        char oui[9];
        snprintf(oui, sizeof(oui), "%02X%02X%02X", dev->mac[0], dev->mac[1], dev->mac[2]);

        feat_file_.printf("%lld,%s,%s,%s,%s,%u,%.1f,%.1f,%.1f,%.2f,%.3f,%.3f,%.3f,%u,%.2f,%.2f,%.3f\n",
                          now, mac_str, oui, dev->ssid, security_str(dev->security),
                          dev->pkt_count, dev->avg_pkt_size(), dev->std_pkt_size(),
                          dev->avg_rssi(), dev->pkt_rate(),
                          dev->mgmt_ratio(), dev->data_ratio(), dev->ctrl_ratio(),
                          dev->unique_dst_count,
                          dev->beacon_rate(), dev->probe_req_rate(), dev->retry_ratio());
    }

    feat_file_.flush();
}

void SDLogger::log_anomalies(FeatureExtractor& fe) {
    if (!ready_ || !logging_ || !alert_file_) return;

    int64_t now = esp_timer_get_time();
    char mac_str[18];

    for (int i = 0; i < fe.device_count(); i++) {
        DeviceStats* dev = &fe.get_devices()[i];
        if (dev->pkt_count < 10) continue;

        if (dev->pkt_count < 10 || dev->pkt_rate() < 1.0f) continue;

        const char* reason = nullptr;
        if (dev->probe_req_rate() > 5.0f)
            reason = "HIGH_PROBE";
        else if (dev->retry_ratio() > 0.5f && dev->pkt_rate() > 5.0f)
            reason = "HIGH_RETRY";
        else if (dev->unique_dst_count > 20 && dev->pkt_rate() > 1.0f)
            reason = "MANY_DSTS";
        else if (dev->pkt_rate() > 200.0f && dev->data_ratio() > 0.8f)
            reason = "FLOOD";

        if (reason) {
            mac_to_str(dev->mac, mac_str);
            alert_file_.printf("%lld,%s,%s,%s,%s,%u,%.2f,%.1f,%.2f,%.3f,%u,%.3f\n",
                               now, mac_str, dev->ssid, security_str(dev->security),
                               reason, dev->pkt_count, dev->pkt_rate(),
                               dev->avg_rssi(), dev->probe_req_rate(),
                               dev->retry_ratio(), dev->unique_dst_count,
                               dev->data_ratio());
        }
    }

    alert_file_.flush();
}

void SDLogger::log_ml_predictions(FeatureExtractor& fe) {
    if (!ready_ || !logging_ || !ml_file_) return;

    int64_t now = esp_timer_get_time();
    char mac_str[18];

    for (int i = 0; i < fe.device_count(); i++) {
        DeviceStats* dev = &fe.get_devices()[i];
        if (!dev->ml.valid) continue;

        mac_to_str(dev->mac, mac_str);
        ml_file_.printf("%lld,%s,%s,%s,%s,%s,%s,%.4f,%.4f\n",
                now, mac_str,
                ANOMALY_LABELS[dev->ml.anomaly],
                PACKET_CLASS_LABELS[dev->ml.packet_class],
                PROTOCOL_LABELS[dev->ml.protocol],
                DEVICE_TYPE_LABELS[dev->ml.device_type],
                ROUTE_ACTION_LABELS[dev->ml.route_action],
                dev->ml.anomaly_score,
                dev->ml.packet_class_score);
    }

    ml_file_.flush();
}

void SDLogger::flush() {
    if (!ready_) return;
    pkt_file_.flush();
    if (pcap_file_) pcap_file_.flush();
    pending_writes_ = 0;
    last_flush_ms_ = millis();
}

void SDLogger::close() {
    if (pkt_file_) { pkt_file_.flush(); pkt_file_.close(); }
    if (feat_file_) { feat_file_.flush(); feat_file_.close(); }
    if (pcap_file_) { pcap_file_.flush(); pcap_file_.close(); }
    if (alert_file_) { alert_file_.flush(); alert_file_.close(); }
    if (ml_file_) { ml_file_.flush(); ml_file_.close(); }
    logging_ = false;
}

void SDLogger::generate_filenames() {
    uint32_t session = 0;
    File f = SD.open("/session_id.txt", FILE_READ);
    if (f) {
        session = f.parseInt();
        f.close();
    }
    session++;
    f = SD.open("/session_id.txt", FILE_WRITE);
    if (f) {
        f.print(session);
        f.close();
    }
    snprintf(pkt_filename_, sizeof(pkt_filename_), "/sniff_%u.csv", session);
    snprintf(feat_filename_, sizeof(feat_filename_), "/feat_%u.csv", session);
    snprintf(pcap_filename_, sizeof(pcap_filename_), "/cap_%u.pcap", session);
    snprintf(alert_filename_, sizeof(alert_filename_), "/alert_%u.csv", session);
    snprintf(ml_filename_, sizeof(ml_filename_), "/ml_%u.csv", session);
}
