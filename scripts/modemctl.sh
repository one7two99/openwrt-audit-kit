#!/bin/sh
# modemctl.sh — control the LTE modem on the Spitz Plus (GL-X2000)
# Usage: modemctl.sh {enable|disable|status|help}
#
# --- Finding the correct bus ID ---
# gl_modem needs the modem's USB bus ID (e.g. "2-1"), not just the network
# interface name. Here's how to determine it on a GL-X2000:
#
#   1. Identify the active modem network interface (usually wwan0):
#        ls /sys/class/net/ | grep -i wwan
#
#   2. Resolve the real sysfs device path behind it:
#        readlink -f /sys/class/net/wwan0/device
#
#      The result looks something like:
#        /sys/devices/platform/soc/8af8800.usb3/8a00000.dwc3/xhci-hcd.0.auto/usb2/2-1/2-1:1.4
#
#      The part right after the USB root hub (here "2-1") is the bus ID
#      that gl_modem expects with -B. The trailing ":1.4" is the
#      interface number on the device itself and is NOT needed for -B.
#
#   3. Verify by testing (a correct bus ID returns a response instead of
#      "Modem is not exit. Please make sure bus."):
#        gl_modem -B 2-1 AT "ATI"
#
#   If /sys/bus/usb/devices/ or /sys/bus/pci/devices/ look empty, or
#   generic filters (e.g. "grep -i qcom") find nothing: always go via the
#   network interface path (steps 1+2), it's more reliable than searching
#   by vendor/chip name, since those names vary by firmware version.
#
#   The bus ID may theoretically change after a firmware update or when
#   plugging in external USB devices — repeat steps 1-3 if in doubt.
#
# --- Checking the timezone (important for cron job timing!) ---
# Cron interprets times according to the router's system time. If it's
# running on UTC instead of local time, a cron job fires at the "wrong"
# time.
#
#   1. Check current system time/timezone:
#        date
#      If the output shows "GMT" or "UTC" instead of "CEST"/"CET", switch
#      to Europe/Berlin:
#        uci set system.@system[0].zonename='Europe/Berlin'
#        uci set system.@system[0].timezone='CET-1CEST,M3.5.0,M10.5.0/3'
#        uci commit system
#        /etc/init.d/system reload
#
#   2. Check again with "date" — it should now show CET/CEST and the
#      correct local time, including automatic DST switching.
#
# --- Setting up a cron job ---
# Example: turn the modem off daily from 00:00 to 06:30.
#   (Example only — the window used when the schedule is active is 01:30-06:00,
#   currently disabled; see section 14 of the docs.)
#
#   1. crontab -e
#   2. Add the following two lines (adjust the path if the script isn't
#      in /root/):
#        0 0 * * * /root/modemctl.sh disable
#        30 6 * * * /root/modemctl.sh enable
#   3. Save, then:
#        /etc/init.d/cron restart
#   4. To verify:
#        crontab -l
#
#   Results can later be traced via the timestamps in ${LOGFILE:-/root/modemctl.log}
#   (see the log() function below).

BUS="2-1"
IFACE="modem_2_1_4"   # netifd interface name of the active data connection
                      # (visible in LuCI under Network > Interfaces; on your
                      # device currently "modem_2_1_4" — check there and
                      # adjust here if needed)
LOGFILE="/root/modemctl.log"   # persistent log, also covers cron runs

log() {
    # Prints a line to the console AND appends it to the log file, so
    # cron runs (whose output would otherwise be lost) stay traceable.
    msg="$1"
    echo "$msg"
    echo "$msg" >> "$LOGFILE"
    # The log lives on flash: keep it bounded so it never writes the overlay
    # indefinitely. Trim to the last 500 lines once it grows past ~64 KB.
    if [ "$(wc -c < "$LOGFILE" 2>/dev/null || echo 0)" -gt 65536 ]; then
        tail -n 500 "$LOGFILE" > "$LOGFILE.tmp" 2>/dev/null && mv "$LOGFILE.tmp" "$LOGFILE"
    fi
}

usage() {
    cat <<EOF
Usage: $(basename "$0") <command>

Commands:
  enable    Turn the modem radio on (AT+CFUN=1) and rebuild the data
            connection (connect-auto)
  disable   Turn the modem radio off completely (AT+CFUN=0) — deregisters
            from the cellular network, no auto-reconnect
  status    Show current radio, connection, and port status
  port disable   Remove the unused Ethernet port ($PORT_IFACE) from the
                 lan bridge and set it down (eth1, connected to the
                 OpenWrt One, is left untouched)
  port enable    Re-enable port $PORT_IFACE
  port status    Show only the port status
  led off <all|night|name>  Turn LEDs off — "all"/"night" use the
                             gl_led service (turnoff/turnon), "night"
                             manually turns power back on afterwards
  led on  <all|night|name>  Turn LEDs back on (gl_led service restart for
                             all/night, direct write for a single LED)
  led restore                 Restart the gl_led service (all LEDs back
                              to automatic display)
  led status                 Service status + current state of all LEDs
  help      Show this help

Bus ID: ${BUS}
Log file: ${LOGFILE}
EOF
}

# Background (found on 2026-08-30): a plain AT+CFUN=0/1 can leave the
# modem, after being turned back on, connected at the radio level (good
# signal, SIM detected) but stuck at the mobility-management level in
# state "EMM detached" (visible via `gl_modem -B $BUS AT "AT+CEER"`) — the
# GUI then shows "connected, but Internet can't be accessed". A manual
# Disconnect+Connect in the GUI reliably fixed this. enable/disable now
# replicate that sequence: disable first cleanly tears down the data
# connection (like the GUI's "Disconnect"), only then does the radio turn
# off; enable turns the radio on first and then explicitly rebuilds the
# connection (like the GUI's "Connect").

# --- Unused Ethernet port (formerly WAN, now part of the lan bridge) ---
# On the Spitz Plus, WAN has already been switched to LAN ("WAN and LAN
# have been used as LAN" in the GUI). Physically the port is still called
# eth0, but it's part of the lan bridge (see /etc/config/network:
# `option ifname 'eth1 eth0'` under `config interface 'lan'`). eth1 is the
# port the OpenWrt One is connected to — NEVER disable eth1!
PORT_IFACE="eth0"
LAN_BRIDGE_IFACE_ALL="eth1 eth0"
LAN_BRIDGE_IFACE_WITHOUT_PORT="eth1"

do_port_disable() {
    # Enforce the header warning in code, not just in a comment:
    if [ "$PORT_IFACE" = "eth1" ]; then
        echo "refuse: eth1 is the OpenWrt One uplink — never remove it from the bridge" >&2
        return 1
    fi
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] PORT-DISABLE — Start"
    echo "Removing $PORT_IFACE from the lan bridge..."
    uci set network.lan.ifname="$LAN_BRIDGE_IFACE_WITHOUT_PORT"
    uci commit network
    /etc/init.d/network reload
    sleep 2
    echo "Setting $PORT_IFACE explicitly down..."
    ip link set "$PORT_IFACE" down
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] PORT-DISABLE — Done"
}

do_port_enable() {
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] PORT-ENABLE — Start"
    echo "Adding $PORT_IFACE back to the lan bridge..."
    uci set network.lan.ifname="$LAN_BRIDGE_IFACE_ALL"
    uci commit network
    ip link set "$PORT_IFACE" up
    /etc/init.d/network reload
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] PORT-ENABLE — Done"
}

do_port_status() {
    echo "--- Port $PORT_IFACE ---"
    current_ifname="$(uci -q get network.lan.ifname)"
    if echo "$current_ifname" | grep -qw "$PORT_IFACE"; then
        echo "In lan bridge: yes"
    else
        echo "In lan bridge: no"
    fi
    ip link show "$PORT_IFACE" 2>/dev/null | head -1
}

# --- LEDs ---
# Available LEDs on this device (determined via `ls /sys/class/leds/`):
#   5G:signal:led1..4  — signal strength bars
#   internet           — internet connection status
#   power               — power/operation indicator
#   wifi:2g / wifi:5g   — WLAN activity
#
# IMPORTANT (found 2026-08-30): all of these LEDs are managed centrally by
# the /etc/init.d/gl_led service (a procd instance with automatic
# respawn). Writing directly to brightness gets overwritten almost
# instantly for internet and with a delay for the signal LEDs; a simple
# `killall gl_led` doesn't help, because procd immediately restarts the
# service due to the respawn parameter. The init script already ships the
# correct commands though: `turnoff` (cleanly stops the service via
# procd, including UCI persistence) and `turnon` (starts it again). These
# control ALL LEDs together, including power — not individually.
GL_LED_INIT="/etc/init.d/gl_led"
LED_NIGHT_SET="5G:signal:led1 5G:signal:led2 5G:signal:led3 5G:signal:led4 internet wifi:2g wifi:5g"
LED_ALL_SET="$LED_NIGHT_SET power"

led_set() {
    # Only reliable while the gl_led service is stopped (see above), or
    # for LEDs outside the daemon's control.
    #
    # The variables are prefixed deliberately. An earlier version used plain
    # "action" and "name", which are the same names do_led() uses for its own
    # arguments — and sh has no function scope unless asked for. Calling
    # `led_set on power` from the "off" branch therefore overwrote do_led's
    # $action, and the log line at the end of do_led reported "on" for every
    # night shutdown. The LEDs did switch off correctly; only the log lied,
    # which is worse than an obvious failure because it looks like evidence.
    _led_action="$1"; _led_name="$2"
    if [ ! -e "/sys/class/leds/$_led_name/brightness" ]; then
        echo "Unknown LED '$_led_name'."
        return 1
    fi
    if [ "$_led_action" = "on" ]; then
        _led_value="$(cat "/sys/class/leds/$_led_name/max_brightness" 2>/dev/null || echo 1)"
    else
        _led_value=0
    fi
    echo "$_led_value" > "/sys/class/leds/$_led_name/brightness"
}

do_led() {
    action="$1"; target="$2"
    case "$target" in
        night)
            if [ "$action" = "off" ]; then
                echo "Stopping gl_led service (controls all LEDs together, including power)..."
                "$GL_LED_INIT" turnoff
                echo "Manually turning the power LED back on (stays on in night mode)..."
                led_set on power
            else
                echo "Restarting gl_led service (all LEDs back to automatic)..."
                "$GL_LED_INIT" turnon
            fi
            ;;
        all)
            if [ "$action" = "off" ]; then
                "$GL_LED_INIT" turnoff
            else
                "$GL_LED_INIT" turnon
            fi
            ;;
        "")
            echo "Usage: $(basename "$0") led {on|off} {all|night|<led-name>}"
            return 1
            ;;
        *)
            # Write a single LED directly — only reliable while the
            # gl_led service is currently stopped (turnoff).
            led_set "$action" "$target"
            ;;
    esac
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] LED $action — $target"
}

do_led_status() {
    echo "--- LEDs ---"
    if pgrep -f /usr/bin/gl_led >/dev/null 2>&1; then
        echo "gl_led service: running (automatic control active)"
    else
        echo "gl_led service: stopped"
    fi
    for led in $LED_ALL_SET; do
        if [ -e "/sys/class/leds/$led/brightness" ]; then
            b="$(cat "/sys/class/leds/$led/brightness")"
            [ "$b" = "0" ] && state="off" || state="on"
            printf "%-16s %s\n" "$led" "$state"
        fi
    done
}

do_led_restore() {
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] LED-RESTORE — Start"
    "$GL_LED_INIT" turnon
    echo "gl_led service started — LEDs back to automatic display."
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] LED-RESTORE — Done"
}

do_enable() {
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] ENABLE — Start"
    echo "Turning modem on..."
    gl_modem -B "$BUS" AT "AT+CFUN=1"
    echo "Waiting 5 seconds for network registration..."
    sleep 5
    echo "Rebuilding data connection (like the GUI's 'Connect')..."
    ubus call network.interface."$IFACE" up 2>/dev/null
    sleep 3
    gl_modem -B "$BUS" connect-auto
    # Do not claim success blindly: measure the real state and log THAT.
    # (Section 14.2: a log that lies is worse than an obvious failure.)
    sleep 3
    cfun=$(gl_modem -B "$BUS" AT "AT+CFUN?" 2>&1 | sed -n 's/.*+CFUN: *\([0-9]\).*/\1/p')
    if ping -c1 -W2 8.8.8.8 >/dev/null 2>&1 || ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
        log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] ENABLE — OK (CFUN=$cfun, internet reachable)"
    else
        log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] ENABLE — FAILED (CFUN=$cfun, no internet after connect)"
        return 1
    fi
}

do_disable() {
    log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] DISABLE — Start"
    echo "Tearing down data connection (like the GUI's 'Disconnect')..."
    ubus call network.interface."$IFACE" down 2>/dev/null
    sleep 2
    echo "Turning modem off..."
    gl_modem -B "$BUS" AT "AT+CFUN=0"
    # Verify the radio is actually off before logging success.
    sleep 1
    cfun=$(gl_modem -B "$BUS" AT "AT+CFUN?" 2>&1 | sed -n 's/.*+CFUN: *\([0-9]\).*/\1/p')
    if [ "$cfun" = "0" ]; then
        log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] DISABLE — OK (CFUN=0)"
    else
        log "[$(date '+%Y-%m-%d %H:%M:%S %Z')] DISABLE — FAILED (CFUN=$cfun, radio not off)"
        return 1
    fi
}

do_status() {
    echo "--- Radio status (AT+CFUN?) ---"
    cfun_response=$(gl_modem -B "$BUS" AT "AT+CFUN?" 2>&1)
    echo "$cfun_response"

    cfun_state=$(echo "$cfun_response" | sed -n 's/.*+CFUN: *\([0-9]\).*/\1/p')
    echo ""
    case "$cfun_state" in
        0)
            echo "Radio: OFF (CFUN=0) — modem is deregistered from the cellular network"
            ;;
        1|5|6)
            echo "Radio: ON (CFUN=$cfun_state)"
            ;;
        *)
            echo "Radio: state could not be determined unambiguously (see response above)"
            ;;
    esac

    # The interface's IP address often stays assigned after AT+CFUN=0,
    # because netifd doesn't notice the raw AT command — so it is NOT a
    # reliable indicator of actual connectivity. Test actively instead
    # whether data really gets through.
    echo ""
    echo "--- Actual connectivity (ping test) ---"
    if ip addr show wwan0_1 2>/dev/null | grep -q "inet "; then
        echo "Assigned IP: $(ip addr show wwan0_1 | awk '/inet /{print $2}')  (may be stale while the radio is off)"
    else
        echo "Assigned IP: none"
    fi

    if ping -c 2 -W 2 8.8.8.8 >/dev/null 2>&1 || ping -c 2 -W 2 1.1.1.1 >/dev/null 2>&1; then
        echo "Status: ONLINE — 8.8.8.8 is reachable"

        # Connection uptime only makes sense if actually online.
        if command -v ubus >/dev/null 2>&1 && command -v jsonfilter >/dev/null 2>&1; then
            uptime_sec=$(ubus call network.interface."$IFACE" status 2>/dev/null | jsonfilter -e '@.uptime')
            if [ -n "$uptime_sec" ]; then
                days=$((uptime_sec / 86400))
                hours=$(((uptime_sec % 86400) / 3600))
                mins=$(((uptime_sec % 3600) / 60))
                secs=$((uptime_sec % 60))
                echo "Connected for: ${days}d ${hours}h ${mins}m ${secs}s"
            fi
        fi
    else
        echo "Status: OFFLINE — no response from 8.8.8.8"
    fi
}

case "$1" in
    enable)
        do_enable
        ;;
    disable)
        do_disable
        ;;
    status)
        do_status
        do_port_status
        do_led_status
        ;;
    port)
        case "$2" in
            disable) do_port_disable ;;
            enable)  do_port_enable ;;
            status)  do_port_status ;;
            *) echo "Usage: $(basename "$0") port {disable|enable|status}"; exit 1 ;;
        esac
        ;;
    led)
        case "$2" in
            on|off) do_led "$2" "$3" ;;
            restore) do_led_restore ;;
            status) do_led_status ;;
            *) echo "Usage: $(basename "$0") led {on|off} {all|night|<led-name>} | led restore | led status"; exit 1 ;;
        esac
        ;;
    help|""|-h|--help)
        usage
        ;;
    *)
        echo "Unknown command: $1"
        echo ""
        usage
        exit 1
        ;;
esac
