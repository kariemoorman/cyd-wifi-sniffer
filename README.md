# cyd-wifi-sniffer
WiFi packet sniffer and network traffic classifier for the ESP32-3248S035 (CYD) board. Captures 802.11 frames in promiscuous mode, extracts features, logs training data to microSD, and displays live traffic on the built-in touchscreen.

## Hardware

- **Board:** ESP32-3248S035 ("Cheap Yellow Display")
- **Display:** 3.5" ST7796 TFT, 480x320
- **Touch:** XPT2046 resistive touchscreen
- **Storage:** microSD card slot
- **USB:** USB-C with CH340 serial chip

## Prerequisites

- Python>=3.12
- PlatformIO (e.g., brew install platformio)

## Installation

### Clone Repository

```bash
git clone https://github.com/kariemoorman/cyd-wifi-sniffer.git
```

### Build

```bash
cd cyd-wifi-sniffer
pio run -e cyd-sniffer
```

First build takes a few minutes (downloads the ESP32 toolchain), confirming no issues.


### Flash

#### Verify the CYD is Detected

Plug in the CYD via USB-C, then run:

```bash
ls /dev/cu.*
```

You should see output similar to the following:

```
/dev/cu.Bluetooth-Incoming-Port
/dev/cu.usbserial-111240
```

The `/dev/cu.usbserial-XXXXX` entry is your CYD. If it doesn't appear:

- Try a different USB-C cable (some are charge-only, no data)
- Try a different USB port
- Confirm the driver is installed and your Mac was rebooted
- Check **System Settings > Privacy & Security** for blocked drivers

Then flash your device with the new firmware:

```bash
pio run -e cyd-sniffer -t upload --upload-port /dev/cu.usbserial-XXXXX
```

Replace `XXXXX` with your actual device ID from the `ls /dev/cu.*` step.

### Monitor Serial Output

```bash
pio device monitor -b 115200
```

---

## Usage

### Display Screens

There are 5 screens. Tap the left/right edges of the screen to switch:

| Screen | Description |
|--------|-------------|
| **SSID** | Device list showing network names (SSIDs), security type, signal strength |
| **MAC** | Device list showing MAC addresses, security type, signal strength |
| **Stats** | Frame type breakdown (MGMT/DATA/CTRL), device and packet counts |
| **Alerts** | Anomaly detection — heuristic rules or ML classification (toggle with long-press LOG) |
| **Log** | SD card status, filename, packets logged |

### Reading the Device List (SSID / MAC screens)

Each row represents a detected WiFi device, sorted by packet count:

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

**Security types:**

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
| `DEV:15` | Number of unique devices tracked (max 96) |
| `ML` / `HEUR` | Classification mode — magenta = ML model, white = heuristic rules |
| `LIVE` / `STOP` | Green = capturing, Red = paused |

### Touch Buttons (bottom bar)

| Button | Action |
|--------|--------|
| **CH-** | Decrease WiFi channel. Below 1 wraps to AUTO hop mode |
| **CH+** | Increase WiFi channel. Above 13 wraps to AUTO hop mode |
| **START/STOP** | Toggle packet capture on/off. Long-press (2s) to flush devices and restart collection |
| **LOG** | Toggle SD card logging (requires SD card). Long-press (2s) to toggle ML/heuristic mode |

Auto channel hop cycles through channels 1-13 every 2 seconds. The status bar shows `CH:6*` when active.

### SD Card Logging

1. Insert a FAT32-formatted microSD card before powering on
2. Press **LOG** to start recording
3. Five files are created per session (incrementing session number):
   - `sniff_N.csv` — raw packet data (one row per captured frame)
   - `feat_N.csv` — aggregated features per device (one row per device per 10s window)
   - `alert_N.csv` — devices flagged by heuristic anomaly detection
   - `ml_N.csv` — ML classification results per device (requires loaded model)
   - `cap_N.pcap` — raw packet capture, openable in Wireshark

The session counter is stored in `session_id.txt` on the SD card. Delete this file to reset numbering.

