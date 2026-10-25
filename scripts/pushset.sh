#!/bin/sh
#
# pushset.sh v1.1.0 -- roll a set file out to the router and (re)load the fw4 IP set.
#
# Runs on the WORKSTATION. The set's addresses live in a text file in this repo
# (one IPv4 address or IPv4/CIDR per line, `#` comments and blank lines ignored --
# exactly what fw4's `option loadfile` reads). This script
#   1. parses the file locally and refuses to continue on any invalid line,
#   2. copies it to the router (scp -O: dropbear has scp but no sftp-server),
#   3. activates it: creates the UCI ipset after asking, converts a `list entry`
#      set to `loadfile` after asking, or just runs `fw4 reload-sets`.
# Nothing is written to the router before step 1 passed; no backup is left behind.
#
# Usage:  scripts/pushset.sh            # roll out $FILE to $SET on $ROUTER
#         scripts/pushset.sh --check    # step 1 only, no router contact
# Constants below may be overridden by environment variables of the same name.
#
# Exit codes: 0 ok, 1 parse/router error, 2 usage/declined.

ROUTER="${ROUTER:-root@192.168.30.1}"         # SSH target (key auth, BatchMode)
SET="${SET:-doh_v4}"                           # UCI ipset name (= nft set name)
FILE="${FILE:-scripts/sets/doh_v4.txt}"        # source file in this repo
REMOTE_DIR="${REMOTE_DIR:-/etc/fw4-sets}"      # where the router keeps set files
MATCH="${MATCH:-dest_net}"                     # only used when the set is created
FAMILY="${FAMILY:-ipv4}"                       # only used when the set is created

SSH="ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none"
SCP="scp -O -o BatchMode=yes -o ConnectTimeout=10"
REMOTE_FILE="$REMOTE_DIR/$SET.txt"

cd "$(dirname "$0")/.." || exit 1
[ -f "$FILE" ] || { echo "pushset: $FILE nicht gefunden" >&2; exit 2; }

# ---------------------------------------------------------------- 1. parse
# IPv4 with optional /0-32 prefix, octets 0-255, no duplicates. Line numbers in errors.
errors=$(awk '
    function bad(msg) { printf "  Zeile %d: %s: %s\n", NR, msg, $0; n++ }
    {
        line = $0; sub(/\r$/, "", line); sub(/^[ \t]+/, "", line); sub(/[ \t]+$/, "", line)
        if (line == "" || substr(line, 1, 1) == "#") { if (line != "") c++; next }
        if (line ~ /[ \t]/) { bad("Leerzeichen in Eintrag"); next }
        addr = line; pfx = -1
        if (index(line, "/")) { split(line, p, "/"); addr = p[1]; pfx = p[2]
            if (pfx !~ /^[0-9]+$/ || pfx + 0 > 32) { bad("ungueltiger Praefix"); next } }
        if (split(addr, o, ".") != 4) { bad("keine IPv4-Adresse"); next }
        ok = 1
        for (i = 1; i <= 4; i++) if (o[i] !~ /^[0-9]+$/ || o[i] + 0 > 255 || (length(o[i]) > 1 && substr(o[i],1,1) == "0")) ok = 0
        if (!ok) { bad("Oktett ungueltig (0-255, keine fuehrende Null)"); next }
        if (line in seen) { bad("Duplikat von Zeile " seen[line]); next }
        seen[line] = NR; e++
    }
    END { printf "%d Eintraege, %d Kommentarzeilen\n", e, c > "/dev/stderr"; exit n ? 1 : 0 }
' "$FILE" 2>&1 1>/tmp/pushset-errors.$$)
summary=$(printf '%s\n' "$errors" | tail -1)
if [ -s /tmp/pushset-errors.$$ ]; then
    echo "pushset: $FILE hat Fehler ($summary):" >&2
    cat /tmp/pushset-errors.$$ >&2; rm -f /tmp/pushset-errors.$$
    exit 1
fi
rm -f /tmp/pushset-errors.$$
echo "pushset: $FILE geprueft: $summary"
[ "${1:-}" = "--check" ] && exit 0

# ---------------------------------------------------------------- 2. copy
$SSH "$ROUTER" "mkdir -p '$REMOTE_DIR'" || { echo "pushset: SSH zu $ROUTER fehlgeschlagen" >&2; exit 1; }
$SCP "$FILE" "$ROUTER:$REMOTE_FILE.new" >/dev/null || { echo "pushset: scp fehlgeschlagen" >&2; exit 1; }
$SSH "$ROUTER" "mv '$REMOTE_FILE.new' '$REMOTE_FILE' && chmod 644 '$REMOTE_FILE'" || exit 1
echo "pushset: kopiert nach $ROUTER:$REMOTE_FILE"

# ---------------------------------------------------------------- 3. activate
ask() { printf '%s [y/N] ' "$1"; read -r a; [ "$a" = "y" ] || [ "$a" = "Y" ]; }

# The UCI section may be anonymous (@ipset[n]); find it by its name option, never assume
# section id == set name (anonymous ids also move when sections are inserted before them).
sec=$($SSH "$ROUTER" "uci show firewall | sed -n \"s/^firewall\\.\\([^.]*\\)\\.name='$SET'\$/\\1/p\" | head -1")
if [ -z "$sec" ]; then state=missing; sec=$SET
else state=$($SSH "$ROUTER" "if uci -q get firewall.$sec.loadfile >/dev/null; then echo loadfile; else echo entries; fi"); fi

mode=reload-sets
case "$state" in
    missing)
        echo "pushset: IPset '$SET' existiert auf dem Router nicht."
        ask "Anlegen (family=$FAMILY, match=$MATCH, loadfile=$REMOTE_FILE)?" || { echo "pushset: abgebrochen" >&2; exit 2; }
        $SSH "$ROUTER" "uci set firewall.$sec=ipset && uci set firewall.$sec.name='$SET' && uci set firewall.$sec.family='$FAMILY' \
            && uci add_list firewall.$sec.match='$MATCH' && uci set firewall.$sec.loadfile='$REMOTE_FILE' && uci commit firewall" || exit 1
        mode=reload ;;
    entries)
        echo "pushset: IPset '$SET' (Section $sec) hat 'list entry'-Eintraege und kein loadfile."
        ask "Auf loadfile=$REMOTE_FILE umstellen (die entry-Liste wird geloescht)?" || { echo "pushset: abgebrochen" >&2; exit 2; }
        $SSH "$ROUTER" "uci delete firewall.$sec.entry; uci set firewall.$sec.loadfile='$REMOTE_FILE' && uci commit firewall" || exit 1
        mode=reload ;;
    loadfile) ;;
    *) echo "pushset: unerwarteter Zustand '$state'" >&2; exit 1 ;;
esac

out=$($SSH "$ROUTER" "fw4 check 2>&1 | tail -1; if [ $mode = reload ]; then fw4 reload 2>&1; else fw4 reload-sets 2>&1; fi; echo CHANGES=\$(uci changes | wc -l)")
printf '%s\n' "$out" | grep -q "passes nftables check" || { echo "pushset: fw4 check FEHLER:" >&2; printf '%s\n' "$out" >&2; exit 1; }
warn=$(printf '%s\n' "$out" | grep -i "skipping invalid\|unable to load\|references unknown set")
if [ -n "$warn" ]; then echo "pushset: fw4-Warnungen beim Laden:" >&2; printf '%s\n' "$warn" >&2; exit 1; fi
printf '%s\n' "$out" | grep -q "CHANGES=0" || { echo "pushset: uci changes nicht leer" >&2; exit 1; }

# proof: element count and a sample lookup of the first three entries
first=$(awk '/^[ \t]*[0-9]/{print $1}' "$FILE" | head -3 | tr '\n' ' ')
proof=$($SSH "$ROUTER" "n=\$(nft list set inet fw4 $SET | sed -n '/elements/,/}/p' | tr ',' '\n' | grep -c '[0-9]'); echo \"Elemente (nft, Intervalle): \$n\"
    for ip in $first; do if nft get element inet fw4 $SET \"{ \$ip }\" >/dev/null 2>&1; then echo \"  \$ip: im Set\"; else echo \"  \$ip: FEHLT\"; fi; done
    grep -q \"^$REMOTE_DIR\" /etc/sysupgrade.conf 2>/dev/null || echo \"HINWEIS: $REMOTE_DIR steht nicht in /etc/sysupgrade.conf (nicht im Backup)\"")
printf '%s\n' "$proof"
printf '%s\n' "$proof" | grep -q FEHLT && { echo "pushset: Stichprobe fehlgeschlagen" >&2; exit 1; }
echo "pushset: $SET aktiv ($mode)."
