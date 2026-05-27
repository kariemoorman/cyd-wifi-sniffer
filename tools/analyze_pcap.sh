#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:-}"
if [[ -z "$PCAP" || ! -f "$PCAP" ]]; then
    echo "Usage: $0 <capture.pcap> [command]"
    echo ""
    echo "Commands:"
    echo "  summary      Overview: packet count, duration, frame types (default)"
    echo "  ssids        List all SSIDs with security type and channel"
    echo "  devices      List all unique devices (source MACs) with packet counts"
    echo "  beacons      List access points from beacon frames"
    echo "  probes       List probe requests (devices scanning for networks)"
    echo "  security     Security audit: flag OPEN/WEP networks"
    echo "  traffic      Top talkers by packet count"
    echo "  channels     Packet count per WiFi channel"
    echo "  deauths      List deauthentication/disassociation frames"
    echo "  retries      Devices with high retry rates"
    echo "  conversations Device-to-device communication pairs"
    echo "  timeline     Packet rate over time (per-second buckets)"
    echo "  export-csv   Export all packets as CSV"
    echo "  raw          Raw packet list with full decode"
    exit 1
fi

CMD="${2:-summary}"

hex2ascii() {
    local hex="$1"
    if [[ -z "$hex" || "$hex" == "<MISSING>" ]]; then
        echo ""
        return
    fi
    echo "$hex" | xxd -r -p 2>/dev/null || echo "$hex"
}

case "$CMD" in

summary)
    echo "=== Capture Summary ==="
    tshark -r "$PCAP" -q -z io,stat,0 2>/dev/null | head -20
    echo ""
    echo "=== Frame Type Breakdown ==="
    tshark -r "$PCAP" -T fields -e wlan.fc.type -e wlan.fc.type_subtype 2>/dev/null \
        | sort | uniq -c | sort -rn \
        | awk '{
            ftype=$2; fsub=$3;
            if (ftype==0) tname="MGMT";
            else if (ftype==1) tname="CTRL";
            else if (ftype==2) tname="DATA";
            else tname="UNKN";
            printf "%6d  %s (type=%s subtype=%s)\n", $1, tname, ftype, fsub
        }'
    echo ""
    echo "=== Encryption Summary ==="
    tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x08" \
        -T fields -e wlan.ssid -e wlan_rsna_eapol.keydes.msgnr -e wlan.rsn.akms.type 2>/dev/null \
        | sort -u | head -30
    ;;

ssids)
    echo "=== SSIDs Detected ==="
    echo ""
    printf "%-32s %-8s %-6s %-18s\n" "SSID" "Security" "Chan" "BSSID"
    echo "--------------------------------------------------------------------"
    tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x08" \
        -T fields -e wlan.ssid -e wlan.rsn.akms.type -e wlan.ds.current_channel -e wlan.bssid 2>/dev/null \
        | sort -u -t$'\t' -k1,1 \
        | while IFS=$'\t' read -r ssid akm channel bssid; do
            ssid=$(hex2ascii "$ssid")
            if [[ -z "$ssid" ]]; then ssid="(hidden)"; fi
            if [[ "$akm" == *"8"* && "$akm" == *"2"* ]]; then sec="WPA2/WPA3"
            elif [[ "$akm" == *"8"* ]]; then sec="WPA3"
            elif [[ "$akm" == *"2"* || "$akm" == *"1"* ]]; then sec="WPA2"
            elif [[ -z "$akm" ]]; then sec="OPEN/WEP"
            else sec="WPA2"; fi
            printf "%-32s %-8s %-6s %-18s\n" "$ssid" "$sec" "$channel" "$bssid"
        done
    ;;

devices)
    echo "=== Unique Devices (by source MAC) ==="
    echo ""
    printf "%8s  %-18s  %-10s\n" "Packets" "MAC" "OUI Vendor"
    echo "-------------------------------------------"
    tshark -r "$PCAP" -T fields -e wlan.sa 2>/dev/null \
        | grep -v "^$" | sort | uniq -c | sort -rn | head -50 \
        | while read -r count mac; do
            oui=$(echo "$mac" | tr -d ':' | cut -c1-6)
            printf "%8d  %-18s  %s\n" "$count" "$mac" "$oui"
        done
    ;;

beacons)
    echo "=== Access Points (Beacon Frames) ==="
    echo ""
    printf "%-32s %-18s %-6s %6s\n" "SSID" "BSSID" "Chan" "Count"
    echo "--------------------------------------------------------------"
    tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x08" \
        -T fields -e wlan.ssid -e wlan.bssid -e wlan.ds.current_channel 2>/dev/null \
        | sort | uniq -c | sort -rn \
        | while read -r count ssid bssid channel; do
            ssid=$(hex2ascii "$ssid")
            if [[ -z "$ssid" ]]; then ssid="(hidden)"; fi
            printf "%-32s %-18s %-6s %6d\n" "$ssid" "$bssid" "$channel" "$count"
        done
    ;;

probes)
    echo "=== Probe Requests (Devices Scanning) ==="
    echo ""
    printf "%-18s  %-32s  %6s\n" "Device MAC" "Probing For" "Count"
    echo "--------------------------------------------------------------"
    tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x04" \
        -T fields -e wlan.sa -e wlan.ssid 2>/dev/null \
        | sort | uniq -c | sort -rn | head -50 \
        | while read -r count mac ssid; do
            ssid=$(hex2ascii "$ssid")
            if [[ -z "$ssid" ]]; then ssid="(broadcast)"; fi
            printf "%-18s  %-32s  %6d\n" "$mac" "$ssid" "$count"
        done
    ;;

security)
    echo "=== Security Audit ==="
    echo ""
    echo "--- OPEN Networks (no encryption) ---"
    tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x08 && !wlan.rsn.akms.type && !(wlan.fixed.capabilities.privacy==1)" \
        -T fields -e wlan.ssid -e wlan.bssid -e wlan.ds.current_channel 2>/dev/null \
        | sort -u \
        | while IFS=$'\t' read -r ssid bssid channel; do
            ssid=$(hex2ascii "$ssid")
            if [[ -z "$ssid" ]]; then ssid="(hidden)"; fi
            printf "  [OPEN] %-28s  %s  CH:%s\n" "$ssid" "$bssid" "$channel"
        done
    echo ""
    echo "--- WEP Networks (broken encryption) ---"
    tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x08 && wlan.fixed.capabilities.privacy==1 && !wlan.rsn.akms.type" \
        -T fields -e wlan.ssid -e wlan.bssid 2>/dev/null \
        | sort -u \
        | while IFS=$'\t' read -r ssid bssid; do
            ssid=$(hex2ascii "$ssid")
            if [[ -z "$ssid" ]]; then ssid="(hidden)"; fi
            printf "  [WEP]  %-28s  %s\n" "$ssid" "$bssid"
        done
    echo ""
    echo "--- Deauth/Disassoc Frames (possible attack) ---"
    deauth_count=$(tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a" 2>/dev/null | wc -l)
    echo "  Total deauth/disassoc frames: $deauth_count"
    if [[ "$deauth_count" -gt 0 ]]; then
        tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a" \
            -T fields -e wlan.sa -e wlan.da -e wlan.fc.type_subtype 2>/dev/null \
            | sort | uniq -c | sort -rn | head -10 \
            | while read -r count src dst subtype; do
                printf "  %4d  %s -> %s (subtype: %s)\n" "$count" "$src" "$dst" "$subtype"
            done
    fi
    ;;

traffic)
    echo "=== Top Talkers (by packet count) ==="
    echo ""
    printf "%8s  %-18s  %10s\n" "Packets" "MAC" "Bytes"
    echo "----------------------------------------"
    tshark -r "$PCAP" -q -z endpoints,wlan 2>/dev/null | tail -n +8 | head -30
    ;;

channels)
    echo "=== Packets Per Channel ==="
    echo ""
    printf "%8s  %s\n" "Packets" "Channel"
    echo "-------------------"
    tshark -r "$PCAP" -T fields -e wlan.ds.current_channel 2>/dev/null \
        | grep -v "^$" | sort -n | uniq -c | sort -rn \
        | while read -r count channel; do
            bar=$(printf '%*s' $((count / 50)) '' | tr ' ' '#')
            printf "%8d  CH %-2s  %s\n" "$count" "$channel" "$bar"
        done
    ;;

deauths)
    echo "=== Deauthentication / Disassociation Frames ==="
    echo ""
    deauth_count=$(tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a" 2>/dev/null | wc -l)
    echo "Total: $deauth_count frames"
    echo ""
    if [[ "$deauth_count" -gt 0 ]]; then
        printf "%-18s  %-18s  %-8s  %s\n" "Source" "Destination" "Type" "Reason"
        echo "--------------------------------------------------------------"
        tshark -r "$PCAP" -Y "wlan.fc.type_subtype==0x0c || wlan.fc.type_subtype==0x0a" \
            -T fields -e wlan.sa -e wlan.da -e wlan.fc.type_subtype -e wlan.fixed.reason_code 2>/dev/null \
            | head -50 \
            | while IFS=$'\t' read -r src dst subtype reason; do
                if [[ "$subtype" == "0x000c" ]]; then t="DEAUTH"
                else t="DISASSC"; fi
                printf "%-18s  %-18s  %-8s  %s\n" "$src" "$dst" "$t" "$reason"
            done
    fi
    ;;

retries)
    echo "=== High Retry Rate Devices ==="
    echo ""
    printf "%-18s  %8s  %8s  %6s\n" "MAC" "Total" "Retries" "Rate"
    echo "------------------------------------------------"
    tshark -r "$PCAP" -T fields -e wlan.sa -e wlan.fc.retry 2>/dev/null \
        | grep -v "^$" | sort \
        | awk -F'\t' '{
            total[$1]++;
            if ($2=="1") retry[$1]++
        }
        END {
            for (mac in total) {
                r = (mac in retry) ? retry[mac] : 0;
                rate = r / total[mac] * 100;
                if (total[mac] >= 20)
                    printf "%-18s  %8d  %8d  %5.1f%%\n", mac, total[mac], r, rate
            }
        }' | sort -t'%' -k1 -rn | head -20
    ;;

conversations)
    echo "=== Device Conversations ==="
    echo ""
    printf "%8s  %-18s  %-18s\n" "Packets" "Source" "Destination"
    echo "------------------------------------------------"
    tshark -r "$PCAP" -T fields -e wlan.sa -e wlan.da 2>/dev/null \
        | grep -v "^$" | sort | uniq -c | sort -rn | head -30 \
        | while read -r count src dst; do
            printf "%8d  %-18s  %-18s\n" "$count" "$src" "$dst"
        done
    ;;

timeline)
    echo "=== Packet Rate Over Time ==="
    echo ""
    tshark -r "$PCAP" -q -z io,stat,1 2>/dev/null | head -60
    ;;

export-csv)
    tshark -r "$PCAP" -T fields \
        -e frame.time_relative \
        -e wlan.fc.type \
        -e wlan.fc.type_subtype \
        -e wlan.sa \
        -e wlan.da \
        -e wlan.bssid \
        -e wlan.ssid \
        -e wlan.ds.current_channel \
        -e radiotap.dbm_antsignal \
        -e frame.len \
        -e wlan.fc.retry \
        -e wlan.rsn.akms.type \
        -E header=y -E separator=, -E quote=d 2>/dev/null
    ;;

raw)
    tshark -r "$PCAP" -V 2>/dev/null | head -500
    ;;

*)
    echo "Unknown command: $CMD"
    echo "Run without arguments to see available commands."
    exit 1
    ;;

esac
