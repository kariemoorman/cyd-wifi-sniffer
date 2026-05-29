
<p align='center'><img src='assets/image.png' width='30%'></p>

<h1 align='center'>cyd-wifi-sniffer</h1>

<p align='center'>WiFi packet sniffer and network traffic classifier for the ESP32-3248S035 (CYD) board.
Captures 802.11 frames in promiscuous mode, extracts features, classifies and displays live traffic on the built-in touchscreen, and logs data to microSD.</p>

---

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Data](#data)
- [ML Model Training](#ml-model-training)

---

## Prerequisites

### Software
- Python>=3.12
- PlatformIO (e.g., `brew install platformio`)

### Hardware
<p align='left'><img src='assets/front.png' width='35%'><img src='assets/back.png' width='35%'></p>

- **Board:** ESP32-3248S035 ("Cheap Yellow Display")
- **Display:** 3.5" ST7796 TFT, 480x320
- **Touch:** XPT2046 resistive touchscreen
- **Storage:** microSD card slot
- **USB:** USB-C with CH340 serial chip

---

## Installation

### Clone Repository

```bash
git clone https://github.com/kariemoorman/cyd-wifi-sniffer.git
```

### Build Firmware

```bash
cd cyd-wifi-sniffer
pio run -e cyd-sniffer
```

First build takes a few minutes (downloads the ESP32 toolchain), confirming no issues.


### Build & Flash Firmware

Verify the CYD is detected - plug in the CYD via USB-C, then run:

```bash
ls /dev/cu.*
```

You should see output similar to the following:

```bash
/dev/cu.Bluetooth-Incoming-Port
/dev/cu.usbserial-XXXXX
```

<details><summary><b>Troubleshooting</b></summary>
   
The `/dev/cu.usbserial-XXXXX` entry is your CYD. If it doesn't appear:

- Try a different USB-C cable (some are charge-only, no data)
- Try a different USB port
- Confirm any driver is installed if needed (e.g., `wch-ch34x-usb-serial-driver`)
- Check `System Settings > Privacy & Security` for blocked drivers

</details>

Then flash your device with the new firmware:
(Replace `XXXXX` with your actual device ID from the `ls /dev/cu.*` step)

```bash
pio run -e cyd-sniffer -t upload --upload-port /dev/cu.usbserial-XXXXX
```


### Monitor Serial Output

```bash
pio device monitor -b 115200
```

Press `reset` button on the back of the CYD device.

---

## Usage

### Display Screens

There are 6 screens. Tap the left/right edges of the screen to switch:

| No. | Screen | Description |
|----|--------|-------------|
| 1 | **SSID** | Device list showing network names (SSIDs), security type, signal strength |
| 2 | **MAC** | Device list showing MAC addresses, security type, signal strength |
| 3 | **Stats** | Frame type breakdown (MGMT/DATA/CTRL), device and packet counts |
| 4 | **Alerts** | Anomaly detection using heuristic rules |
| 5 | **ML** | ML classification of network traffic |
| 6 | **Log** | SD card status, filename, packets logged |

### Reading the Device List (SSID / MAC Screens)

Each row represents a detected WiFi device, sorted by packet count, e.g.,

```
MyNetwork    WPA2    -45dB  1523  ████████
AA:BB:CC:..          -72dB    38  ███
```

| Column | Description |
|--------|-------------|
| **Name** | SSID (on SSID screen) or MAC address (on MAC screen). Falls back to MAC if no SSID is known |
| **Security** | Encryption type detected from AP beacons. Blank for client devices |
| **RSSI** | Average signal strength in dB (closer to 0 = stronger) |
| **Count** | Total number of packets captured from this device |
| **Bar** | Visual signal strength — green (strong), yellow (moderate), red (weak) |

**Security Types:**

| Label | Meaning |
|-------|---------|
| `OPEN` | No encryption — traffic is readable by anyone |
| `WEP` | Wired Equivalent Privacy — outdated, easily cracked |
| `WPA` | Original WPA (TKIP) — outdated, vulnerable |
| `WPA2` | WPA2 (AES/CCMP) — current standard |
| `WPA3` | WPA3 (SAE) — latest standard |
| `W2/3` | WPA2/WPA3 transition mode — supports both |
| *(blank)* | Client device (phone, laptop, IoT) or not enough data yet |

### Reading the Alerts Screen

Flags devices with suspicious behavior based on heuristic thresholds:

| Alert | Trigger | Meaning |
|-------|---------|---------|
| `HIGH PROBE` | Probe request rate > 5/sec | Active WiFi scanning or enumeration |
| `HIGH RETRY` | Retry ratio > 50% (with 50+ packets) | Possible deauth attack or very poor connection |
| `MANY DSTS` | Sending to > 20 unique destinations | Network scanning or reconnaissance |
| `FLOOD` | > 200 pkt/sec with 80%+ data frames | Data flooding attack |

### Status Bar (top)

| Field | Description |
|-------|-------------|
| `CH:6` | Current WiFi channel (1-13). Asterisk (`*`) means auto-hop is active |
| `PKT:1234` | Total packets captured this session |
| `DEV:15` | Number of unique devices tracked (default max=96) |
| `ML` / `HEUR` | Classification mode — magenta = ML model, white = heuristic rules |
| `LIVE` / `STOP` | Green = capturing, Red = paused |

### Touch Buttons (bottom bar)

| Button | Action |
|--------|--------|
| **CH-** | Decrease WiFi channel. Below 1 wraps to AUTO hop mode |
| **CH+** | Increase WiFi channel. Above 13 wraps to AUTO hop mode |
| **START/STOP** | Toggle packet capture on/off. Long-press (2s) to flush devices and restart collection |
| **LOG** | Toggle SD card logging (requires SD card) |

Auto channel hop cycles through channels 1-13 every 2 seconds. The status bar shows `CH:1*` when active.


---

## Data 

### SD Card Logging

1. Insert a FAT32-formatted microSD card before powering on
2. Press **LOG** to start recording
3. Five log files are created per session (incrementing session number):
   - `sniff_N.csv` — raw packet data (one row per captured frame)
   - `feat_N.csv` — aggregated features per device (one row per device per 10s window)
   - `alert_N.csv` — devices flagged by heuristic anomaly detection
   - `ml_N.csv` — ML classification results per device (requires loaded model)
   - `cap_N.pcap` — raw packet capture, openable in Wireshark

The session counter is stored in `session_id.txt` on the SD card. Delete this file to reset numbering.

### Log Files: Column Descriptions

<details><summary><b>sniff_N.csv</b> (raw packets)</summary>

<br>

| Column | Description |
|--------|-------------|
| `timestamp` | Microseconds since boot |
| `channel` | WiFi channel (1-13) |
| `src_mac` | Source MAC address |
| `dst_mac` | Destination MAC address |
| `bssid` | Access point MAC address |
| `frame_type` | 0=Management, 1=Control, 2=Data |
| `frame_subtype` | Frame subtype (e.g. 8=Beacon, 4=Probe Request) |
| `rssi` | Signal strength in dBm |
| `pkt_len` | Frame length in bytes |
| `rate` | Data rate |
| `seq_num` | 802.11 sequence number |
| `retry` | 1 if retransmission, 0 otherwise |
| `ssid` | Network name (for beacon/probe frames, blank otherwise) |

<br>

</details>

<details><summary><b>feat_N.csv</b> (aggregated features per device)</summary>

<br>

| Column | Description |
|--------|-------------|
| `timestamp` | Microseconds since boot |
| `src_mac` | Device MAC address |
| `oui` | First 3 bytes of MAC (manufacturer identifier) |
| `ssid` | Network name (if known) |
| `security` | Encryption type (OPEN/WEP/WPA/WPA2/WPA3/W2/3) |
| `pkt_count` | Total packets from this device |
| `avg_pkt_size` | Mean packet size in bytes |
| `std_pkt_size` | Packet size standard deviation |
| `avg_rssi` | Mean signal strength in dBm |
| `pkt_rate` | Packets per second |
| `mgmt_ratio` | Fraction of management frames (0.0-1.0) |
| `data_ratio` | Fraction of data frames (0.0-1.0) |
| `ctrl_ratio` | Fraction of control frames (0.0-1.0) |
| `unique_dst_count` | Number of unique destination addresses |
| `beacon_rate` | Beacon frames per second |
| `probe_req_rate` | Probe requests per second |
| `retry_ratio` | Fraction of retransmitted frames (0.0-1.0) |

<br>

</details>


<details><summary><b>alert_N.csv</b> (devices flagged by heuristic anomaly detection, written every 10s)</summary>

<br>

| Column | Description |
|--------|-------------|
| `timestamp` | Microseconds since boot |
| `src_mac` | Device MAC address |
| `ssid` | Network name (if known) |
| `security` | Encryption type (OPEN/WEP/WPA/WPA2/WPA3/W2/3) |
| `alert` | Alert type (MANY_DSTS, HIGH_PROBE, HIGH_RETRY, FLOOD) |
| `pkt_count` | Total packets from this device |
| `pkt_rate` | Packets per second |
| `avg_rssi` | Mean signal strength in dBm |
| `probe_req_rate` | Probe requests per second |
| `retry_ratio` | Fraction of retransmitted frames (0.0-1.0) |
| `unique_dst_count` | Number of unique destination addresses |
| `data_ratio` | Fraction of data frames (0.0-1.0) |

<br>

</details>


<details><summary><b>ml_N.csv</b> (ML classification results, written every 10s when model is loaded)</summary>

<br>

| Column | Description |
|--------|-------------|
| `timestamp` | Microseconds since boot |
| `src_mac` | Device MAC address |
| `anomaly` | Anomaly classification (normal, anomalous) |
| `packet_class` | Traffic classification (normal, suspicious, malicious, unknown) |
| `protocol` | Detected protocol (wifi_mgmt, wifi_data, wifi_ctrl, dhcp, dns, http, https, mqtt, unknown) |
| `device_type` | ML-predicted device type (router, phone, laptop, iot_sensor, smart_home, camera, printer, game_console, unknown, flock) |
| `oui_device_type` | Device type inferred from on-device OUI lookup table (`src/oui_table.h`). Blank when the OUI is not in the table |
| `route_action` | Recommended action (allow, throttle, block) |
| `anomaly_score` | Anomaly confidence score (0.0-1.0) |
| `packet_class_score` | Packet-class confidence score (0.0-1.0) |

<br>

</details>

---

## ML Model Training

The training pipeline supports five model types, all sharing the same five
softmax output heads (anomaly detection, packet classification, protocol
identification, device fingerprinting, route action recommendation) over 12
scalar network-traffic features. Models are quantized to int8 and exported as a TFLite buffer + C headers for on-device inference within the ESP32's 520KB SRAM.

| Model | `--model` flag | Make target | Architecture |
|-------|----------------|-------------|--------------|
| **Dense NN** (default) | `nn` | `make train-nn` | `Dense(64) → BN → Dropout(0.3) → Dense(32) → BN → Dropout(0.2)` shared backbone → 5 softmax heads. ~4KB quantized. |
| **LSTM hybrid** | `lstm_lr` | `make train-lstm` | Sliding-window time-series input `(window, 12)` → `LSTM(64, unroll=True)` temporal encoder → BN → Dropout(0.3) → 5 Dense+softmax (logistic-regression) heads. Captures long-range gated dependencies across consecutive 10s feature windows per device. |
| **GRU hybrid** | `gru_lr` | `make train-gru` | Same shape as LSTM but uses `GRU(64, unroll=True)`. Fewer parameters and faster inference than LSTM with comparable accuracy on shorter sequences. |
| **RNN hybrid** | `rnn_lr` | `make train-rnn` | Same shape as LSTM but uses `SimpleRNN(64, unroll=True)`. Suitable when the window is short and gradients stay well-behaved. |
| **Random Forest** | `rf` | `make train-rf` | One `RandomForestClassifier(n_estimators=100, max_depth=10)` per output head. Sklearn baseline (not exported to TFLite); used for accuracy comparison and feature-importance ranking. |

All three hybrid models share `assemble_windows()` for time-series prep: every
row of `feat_*.csv` is one timestep, rows for each `src_mac` are concatenated
chronologically across files, then stride-1 sliding windows of `--window_size`
steps are extracted (short sequences zero-padded on the left).

### Setup

```bash
cd training
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 1: Collect Data

Flash the sniffer, enable logging, and let it run across your network.
Once you've collected sufficient data, copy the `feat_*.csv` and `alert_*.csv` files from the SD card to `training/data/` directory.

Then use the Python training scripts to build a TFLite model for on-device inference.

The pipeline has five additional steps: 
- device identification
- label generation
- OUI table generation
- model training
- model deployment

### Step 2: Identify Devices

Look up device manufacturers by MAC address (cached to `training/data/oui_cache.json`):

```bash
python training/identify_devices.py --data_dir training/data/
# or
make id-devices
```

### Step 3: Generate Labels

Generate training data labels using the cached OUI lookups plus heuristic rules:

```bash
python training/generate_labels.py --data_dir training/data/
# or
make labels
```

This creates `training/data/labels.csv` with heuristic-based labels for each
unique device. Alert CSVs are incorporated automatically. Devices that triggered
firmware alerts are labeled as `anomalous`, e.g.,

```csv
src_mac,anomaly,packet_class,protocol,device_type,route_action
AA:BB:CC:DD:EE:FF,normal,normal,wifi_data,phone,allow
11:22:33:44:55:66,anomalous,suspicious,unknown,unknown,block
```

You are encouraged to manually review and edit the file before initiating model training:


**Label Options:**

| Column | Values |
|--------|--------|
| anomaly | normal, anomalous |
| packet_class | normal, suspicious, malicious, unknown |
| protocol | wifi_mgmt, wifi_data, wifi_ctrl, dhcp, dns, http, https, mqtt, unknown |
| device_type | router, phone, cpu, iot_sensor, smart_home, camera, printer, game_console, unknown, flock |
| route_action | allow, throttle, block |

### Step 4: Generate OUI Table

Compile the on-device OUI → device-type lookup table (`src/oui_table.h`) from
`training/data/oui_cache.json`. Each row pairs a 24-bit OUI with its
`device_type` index (matching `DEVICE_TYPE_LABELS` in `src/label_mappings.h`);
at runtime, `oui_lookup()` does a binary search over the sorted array to
classify a device from its MAC.

Vendor → device-type mapping is driven by `OUI_DEVICE_MAP` in
[training/labels.py](training/labels.py) — to add or remove a vendor on-device,
edit that map rather than special-casing the header.

**Incremental update (default):** preserves any existing entries in
`src/oui_table.h` (including hand-added or hand-edited rows) and appends only
OUIs from the cache that aren't already in the table. All entries are
re-sorted on emit, so this is also the right command to run if the table
falls out of OUI order.

```bash
python tools/generate_oui_table.py
# or
make oui-table
```

**Full rebuild:** discards the existing `src/oui_table.h` and regenerates it
from `oui_cache.json` alone. Use this when you've changed `OUI_DEVICE_MAP`
keywords or `DEVICE_CLASSES` ordering and want every row reclassified from
scratch. Warning: this drops any hand-edits.

```bash
python tools/generate_oui_table.py --regenerate
# or
make oui-table-regenerate
```

To run identify + label + on-device OUI table generation in one shot:

```bash
make data-prep
```

### Step 5: Train Model

Pick a model and run the matching script or Make target:

```bash
# Dense NN (default)
python training/train_model.py --data_dir training/data --output_dir training/output --model nn --epochs 100

# LSTM / GRU / SimpleRNN hybrids (sliding-window time-series)
python training/train_model.py --data_dir training/data --output_dir training/output --model lstm_lr --window_size 5 --epochs 100
python training/train_model.py --data_dir training/data --output_dir training/output --model gru_lr  --window_size 5 --epochs 100
python training/train_model.py --data_dir training/data --output_dir training/output --model rnn_lr  --window_size 5 --epochs 100

# Random Forest baseline (no TFLite export)
python training/train_model.py --data_dir training/data --output_dir training/output --model rf
```

Make-target equivalents:

```bash
make train-nn
make train-lstm WINDOW=5 EPOCHS=100
make train-gru  WINDOW=5 EPOCHS=100
make train-rnn  WINDOW=5 EPOCHS=100
make train-rf
```

**Class balancing:** The training script uses sample weights to handle class
imbalance. Use `--balance` to control which heads get balanced.

Available heads: `anomaly`, `packet_class`, `protocol`, `device_type`, `route_action`.

```bash
# balance only specific heads
python training/train_model.py --data_dir training/data --output_dir training/output \
    --balance anomaly device_type packet_class

# balance across all heads
python training/train_model.py --data_dir training/data --output_dir training/output --balance
```

Make-target equivalents:

```bash
make train-nnb 
make train-lstmb WINDOW=3 BALANCE="anomaly device_type"
make train-grub BALANCE="anomaly device_type packet_class"
make train-rnnb EPOCHS=120 BALANCE="anomaly"
make train-rfb BALANCE="anomaly protocol"
```

The `--balance` flag is driven by the `BALANCE` Make variable (default is
`anomaly protocol device_type`).

**Note:** `route_action` is auto-excluded from balancing for the NN and hybrid models (inside `prepare_balance_weights()`). Random Forest honors it as an as-passed value. In general, it is advisable to skip heads with very few minority samples (e.g. `route_action` with only a handful of `block` labels), as balancing can negatively impact performance when the minority class is too small.[^1]

[^1]: `compute_class_weight("balanced", …)` weights each class inversely to its frequency, so a tiny minority gets a huge per-sample weight. Those few rows then dominate gradient updates, and the model overfits to them.

### Step 6: Deploy

Copy the generated headers to the firmware source:

```bash
cp training/output/sniffer_model.h src/
cp training/output/scaler_params.h src/
cp training/output/label_mappings.h src/
# or
make ml-copy
```

Rebuild and flash firmware.
