#!/bin/sh
# wificli.sh — Turn individual SSIDs or entire WLAN radios on/off on
# OpenWrt One via UCI.
#
# --- WARNING: 'radio disable 5g' cuts the admin WLAN ---
# The 5 GHz radio (radio1) carries `private` — the network used to administer
# this router over WLAN. 'radio disable 5g' therefore kills your own way in,
# and takes `kids`, `tv` and `work` down with it (same radio, all four SSIDs).
# `management` has no SSID of its own any more (removed; the zone is reached
# over the wired `g8` fallback or the `adminvpn` WireGuard tunnel instead).
# The wired `g8` port into `management` is unaffected by this radio and stays
# reachable during the window (docs/network-documentation.md, section 14).
# Run this deliberately (console, `g8`, or a cron window), never casually
# over the WLAN you are sitting on.
#
# --- How it works ---
# Each SSID lives in /etc/config/wireless as its own "wifi-iface" section,
# each physical radio as a "wifi-device" section (radio0 = 2.4 GHz,
# radio1 = 5 GHz). Both have a "disabled" option (0/1).
#
# --- Finding section names ---
#   uci show wireless
# Shows e.g.:
#   wireless.@wifi-iface[0].ssid='Smarthome'
#   wireless.default_radio0=wifi-iface
#   wireless.@wifi-iface[1].ssid='Private'
#   wireless.wifi_private=wifi-iface   <- if you've named your sections
# The most stable approach is to give sections fixed names in
# /etc/config/wireless (uci rename wireless.@wifi-iface[0]='smarthome_ssid')
# instead of relying on the index number [0]/[1] — that can shift when
# the config changes.
#
# --- Adjust the configuration below ---
# SSID_MAP: "short-name:uci-section-name" pairs, space-separated.
# Section name = whatever appears before "=wifi-iface" in
# "uci show wireless" (e.g. "default_radio0" or "@wifi-iface[0]").
# Determine the section names with "uci show wireless" — they are what appears
# before "=wifi-iface". Note that the names are NOT in any meaningful order:
# wifinet2 is kids, wifinet3 is private. Do not infer them, look them up.
SSID_MAP="smarthome:default_radio0 private:wifinet3 kids:wifinet2 tv:wifinet4 work:wifinet5"

# RADIO_MAP: short name for entire radio modules.
RADIO_MAP="2g:radio0 5g:radio1"

LOGFILE="/root/wificli.log"

log() {
    ts="$(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "[$ts] $1"
    echo "[$ts] $1" >> "$LOGFILE"
    # Flash-resident log: trim to the last 500 lines once past ~64 KB.
    if [ "$(wc -c < "$LOGFILE" 2>/dev/null || echo 0)" -gt 65536 ]; then
        tail -n 500 "$LOGFILE" > "$LOGFILE.tmp" 2>/dev/null && mv "$LOGFILE.tmp" "$LOGFILE"
    fi
}

resolve_ssid() {
    for pair in $SSID_MAP; do
        name="${pair%%:*}"
        section="${pair#*:}"
        [ "$name" = "$1" ] && echo "$section" && return 0
    done
    return 1
}

resolve_radio() {
    for pair in $RADIO_MAP; do
        name="${pair%%:*}"
        section="${pair#*:}"
        [ "$name" = "$1" ] && echo "$section" && return 0
    done
    return 1
}

apply() {
    uci commit wireless
    wifi reload
}

cmd_ssid() {
    action="$1"; name="$2"
    section="$(resolve_ssid "$name")" || { echo "Unknown SSID '$name'. Known: $(echo "$SSID_MAP" | tr ' ' ',')"; exit 1; }
    case "$action" in
        disable) uci set wireless.${section}.disabled='1' ;;
        enable)  uci set wireless.${section}.disabled='0' ;;
        *) echo "Invalid action"; exit 1 ;;
    esac
    apply
    log "SSID '$name' ($section) -> $action"
}

cmd_radio() {
    action="$1"; name="$2"
    section="$(resolve_radio "$name")" || { echo "Unknown radio '$name'. Known: $(echo "$RADIO_MAP" | tr ' ' ',')"; exit 1; }
    case "$action" in
        disable) uci set wireless.${section}.disabled='1' ;;
        enable)  uci set wireless.${section}.disabled='0' ;;
        *) echo "Invalid action"; exit 1 ;;
    esac
    apply
    log "Radio '$name' ($section) -> $action"
}

cmd_status() {
    echo "--- SSIDs ---"
    for pair in $SSID_MAP; do
        name="${pair%%:*}"; section="${pair#*:}"
        state="$(uci -q get wireless.${section}.disabled)"
        [ "$state" = "1" ] && state="off" || state="on"
        ssid="$(uci -q get wireless.${section}.ssid)"
        printf "%-12s %-20s %s\n" "$name" "($ssid)" "$state"
    done
    echo "--- Radios ---"
    for pair in $RADIO_MAP; do
        name="${pair%%:*}"; section="${pair#*:}"
        state="$(uci -q get wireless.${section}.disabled)"
        [ "$state" = "1" ] && state="off" || state="on"
        printf "%-12s %s\n" "$name" "$state"
    done
}

usage() {
    cat <<EOF
Usage:
  $0 ssid disable <name>    # disable a single SSID
  $0 ssid enable  <name>    # enable a single SSID
  $0 radio disable <name>   # disable an entire radio (kills all SSIDs on it)
  $0 radio enable  <name>   # enable an entire radio
  $0 status                 # show current state of all SSIDs/radios

WARNING: 'radio disable 5g' cuts private (the admin WLAN).
The wired g8 port into management, or the USB-C console, are the way back —
never run it over the WLAN you are on.

Known SSID short names:  $(echo "$SSID_MAP" | tr ' ' ',')
Known radio short names: $(echo "$RADIO_MAP" | tr ' ' ',')

Example crontab — switching the whole radio off overnight:
  0 0 * * * /root/wificli.sh radio disable 5g
  0 6 * * * /root/wificli.sh radio enable 5g

Or per SSID, to keep one network up while the others sleep:
  0 0 * * * /root/wificli.sh ssid disable private
  0 6 * * * /root/wificli.sh ssid enable  private

Note that switching per SSID does NOT reduce RF exposure — the radio keeps
transmitting beacons for whatever remains enabled. Only "radio disable" does.
EOF
}

case "$1" in
    ssid)   cmd_ssid "$2" "$3" ;;
    radio)  cmd_radio "$2" "$3" ;;
    status) cmd_status ;;
    *)      usage; exit 1 ;;
esac
