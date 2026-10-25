#!/bin/sh
#
# factdump.sh — read-only fact inventory of the home network (four components).
#
# 1.6.2 (2026-10-17): HAOS target is the add-on's non-root user (operator@hub.home.arpa);
#   `ha` runs via sudo with the Supervisor token read from the s6 environment inside the
#   hub session (never printed). Leak-scan: path-table rows ('| /...') no longer trip the
#   long-base64 check. 1.6.1: redacts `snmp user ... sha512 <digest>` in the switch config.
#
# REPLACES statedump.sh (deleted 2026-09-12, once this script covered everything
# that one produced -- routing/pbr, /etc/hosts and the radio operating state were
# the last three gaps). Instead of a raw dump it produces a NORMALISED,
# deterministically diffable fact inventory of OpenWrt One (router/firewall/AP/
# AdGuard), the GL.iNet Spitz Plus (4G uplink), Home Assistant / HAOS (hub) and
# the NETGEAR GS108Tv3 managed switch.
# Its job is to be a MIRROR for verifying the documentation at a point in time —
# never a source. See work-orders/030-spec-factdump.md for the full spec.
#
# LEITPRINZIP (spec §0): the inventory is volatile and disposable. Nothing
# essential lives only here. On a fact mismatch the DEVICE wins (the doc is
# wrong); on the "why" the human/doc wins — this tool never judges rationale.
#
# INVARIANTS (spec §2), enforced here:
#   - READ-ONLY. Every command issued is a query (show/list/info/status/ps/
#     netstat/grep/openssl-client). No set/commit/reload/restart/toggle. The
#     command audit for this is the acceptance test (spec §8.1); grep this file
#     for the SSH heredocs to see every command sent.
#   - VOLATILE OUTPUT. Lands OUTSIDE the repo (default $HOME), is .gitignore'd
#     (factinv-*.md), never committed. The script itself is versioned.
#   - DETERMINISTIC. All lists sorted by a stable key. Volatile fields (uptime,
#     counters, PIDs, lease-remaining, free RAM, disk_used, add-on runtime state,
#     timestamps) are kept OUT of the diffable body. The head is the only place
#     with a timestamp; --body-only omits it, so two runs without a net change
#     produce a byte-identical body.
#   - FAIL-LOUD. An unreachable device is marked in the head AND at the section;
#     never a silently shortened inventory that looks complete. Exit code != 0.

#   - REDACTED. Credentials never leave the devices, by three layers:
#       1) allowlist — only non-secret fields are extracted into the tables
#          (no wireless key, no AdGuard password/hash, no WireGuard private_key,
#          no SIM PIN/APN);
#       2) redact() — statedump's credential name-class filter, applied to the
#          finished file as a net;
#       3) leak_scan() — re-reads the finished file and FAILS LOUD (renames it to
#          *.LEAK-UNSICHER and exits) on any surviving credential-named value or
#          long base64/hex blob. This output is uploaded to a chat, so a clean
#          look is not enough — it must be provably clean.
#
# READING THE OUTPUT -- rules, learned the hard way:
#   Address the tables by COLUMN NAME or by rule name, never by field index. Columns
#   get added: `fw_rules` gained `ipset` in 1.3.0, which moved `log` from field 12 to
#   13. A positional check written before that keeps running afterwards and quietly
#   returns the wrong column instead of failing -- it happened twice while this was
#   being built, once here and once in a reviewer's own verification. An index is a
#   silent dependency on a layout nobody promised to keep.
#
#   `services_enabled` (router/Spitz, added 1.6.0) lists what is REGISTERED in
#   `/etc/rc.d/S*`, not what is functionally active. GL.iNet's vendor firmware ships
#   most init scripts unconditionally and gates real behaviour behind a UCI
#   `enabled='0'` flag the script checks at runtime -- confirmed 2026-09-19 on the
#   Spitz, where `services_enabled` listed AdGuard Home/OpenVPN/Tailscale/repeater/
#   relayd/mwan3-adjacent scripts as registered while every one of them was UCI-
#   disabled, had no running daemon, or (repeater) had a supervisor process running
#   with nothing to act on because both radios are administratively down. Read this
#   table as "what boots", and cross-check UCI `enabled=`/a running process/a
#   listening port before treating a row as "this service is doing something."
#
# KNOWN GAPS (deliberate, not oversights -- listed so they are not re-derived):
#   - HAOS integrations / config entries are NOT collected. There is no reliably
#     read-only CLI path to them, and for an audit the interesting question is
#     "which integration talks to which device and which cloud service" -- which
#     guessing would answer wrongly. Open point in the spec, not a bug here.
#   - The switch section depends on an external source (see SWITCH_CONFIG above).
#   - Carrier-assigned addresses on the uplink (CGNAT) are volatile by nature and
#     stay out of the diffable body; only the interface/device name is reported.
#   - The switch password file is NOT forced onto RAM-backed storage. It lands in
#     $WORK under ${TMPDIR:-/tmp}, and that it is memory rather than disk is an
#     OPERATOR ASSUMPTION -- this workstation keeps /tmp on tmpfs -- not a property
#     this script checks or enforces. Decided 2026-09-13 after measuring the actual
#     exposure: swap is active and full, so a tmpfs page can be evicted, but the
#     swapfile sits on a LUKS volume, so what would land there is encrypted. Enforcing
#     /dev/shm with a fail-loud fallback was considered and declined as disproportionate.
#     Two consequences worth knowing rather than rediscovering: pointing TMPDIR at a
#     disk silently moves the credential there, and `shred` below is largely symbolic
#     on tmpfs, which promises no in-place overwrite. The file is still 0600, still
#     removed by the trap, and the password still never reaches argv or the environment.
#   - Every counter is out of the diffable body on purpose -- BPDU counts, the
#     spanning-tree topology-change clock, DHCP lease-remaining, anything that
#     changes on its own would make every run differ from the last for no
#     configuration reason. Anh. A F4d stays a manual check for exactly this.
#   - `leak_scan()`'s pattern has no exceptions carved out for it -- not for a URL,
#     a key ID, or a hash. A field that would trip it gets renamed (the `_path`/
#     `_file` suffix convention) or reshaped instead of adding a case to the scanner.
#   - The managed switch is queried one connection per command, never multiplexed
#     over one session or piped together -- every cheaper shape was tried and failed
#     differently (see COMPONENT 4). A new switch query needs a manual-first source
#     (the vendor CLI manual) before it is added, never trial-and-error against the
#     device -- "Unknown command" has already come back twice for a guessed one. As
#     of 1.6.0 (group 11) the device is also known to enforce its own connection-
#     rate limit ("Over maximum cli session"), worked around with a fixed cooldown
#     between connections, not with retries.
#   - VLAN membership is read from the `eth1.<vid>` sub-interface naming convention,
#     never derived from `bridge vlan show` or `config bridge-vlan` -- the router
#     uses tagged sub-interfaces, not a VLAN-aware bridge, so those commands would
#     answer a question this network does not ask.
#   - Known doc/device count mismatches (rule count, `log=1` count, redirect count;
#     see the 1.6.0 CHANGELOG entry) are surfaced by this inventory, not corrected
#     by it -- reconciling them is documentation work for a separate pass, and this
#     tool's job stops at making the mismatch visible.
#
# POSIX sh / busybox-compatible (no bashisms): parts run on OpenWrt shells.
#
# Usage:  ./factdump.sh [--out FILE] [--split] [--body-only] [--packages]
#   --out FILE     write here (default: $HOME/factinv-YYYYMMDD-HHMM.md)
#   --split        one file per component instead of one combined file
#   --body-only    omit the volatile head (for `diff` of two runs)
#   --packages     include the (long) installed-package list for the router
#   --switch-ssh   fetch the managed switch's state live over SSH. The device has no
#                  key auth, so the password is asked for ONCE on the terminal with echo
#                  off and handed to each query through an SSH_ASKPASS helper -- never
#                  stored, never in argv, never in the environment. It still opens one
#                  connection PER QUERY (five), because the CLI accepts exactly one
#                  command per session -- see COMPONENT 4 for why that is the robust
#                  shape and not an oversight, and for the cooldown between
#                  connections that this device's own session-rate limit requires.
#
#   SWITCH_CONFIG=<file>  alternative to --switch-ssh: normalise a hand-captured
#                         `show running-config` export of the managed switch
#
# Targets are overridable via environment:
ROUTER="${ROUTER:-root@192.168.30.1}"     # OpenWrt One (management)
UPLINK="${UPLINK:-root@192.168.8.1}"      # GL.iNet Spitz Plus
HAOS="${HAOS:-operator@hub.home.arpa}"      # Home Assistant / HAOS (Terminal & SSH add-on, non-root user; see collect_haos)
SWITCH="${SWITCH:-admin@192.168.30.2}"    # NETGEAR GS108Tv3 (managed switch)
# The switch has no public-key auth (vendor Lite CLI), so BatchMode SSH cannot
# reach it. Two supported sources, in this order:
#   1) SWITCH_CONFIG=<file>  a `show running-config` export captured by hand
#   2) SSH, if a key is ever installed on the device
# With neither, the section is emitted as a LOUDLY MARKED known gap rather than
# omitted -- see the note at "COMPONENT 4" for why that does not set exit 1.
SWITCH_CONFIG="${SWITCH_CONFIG:-}"

FACTDUMP_VERSION="1.6.2"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none"
# Switch: password / keyboard-interactive only (vendor Lite CLI), so no BatchMode --
# OpenSSH prompts for the password on the console (read from /dev/tty, never through
# this script, no sshpass). -T = no PTY, so the CLI dumps `show running-config`
# without paging; it does not close on EOF, so `timeout` ends the session after the
# dump (the config is fully captured by then; the exit code is irrelevant).
# SSH_ASKPASS_REQUIRE=never keeps the prompt on the TERMINAL. Without it a desktop
# session that sets SSH_ASKPASS_REQUIRE=prefer (KDE does) routes the prompt to a
# graphical helper -- and ksshaskpass cannot parse OpenSSH's "(user@host) Password:"
# phrasing at all, so the call fails with a parse error instead of asking. The comment
# below promises a console prompt; this is what makes that true.
SSH_SW_ENV="SSH_ASKPASS_REQUIRE=never"
# Authentication and data transfer are SEPARATED, and that separation is the whole
# reason this works. Three things about this CLI forced it, each verified on the device:
#   1. It supports no SSH exec channel -- `ssh host 'show ...'` returns nothing at all.
#   2. Over a single piped session it processes only the FIRST command and then stops
#      reading, so all four queries cannot share one stdin.
#   3. `ssh` cannot reliably prompt for a password from inside a pipeline: it reads from
#      /dev/tty, the job is not in the foreground, and the shell suspends it on SIGTTIN.
# A ControlMaster connection solves all three: the password is typed once, in the
# foreground, while the master connects; every later call rides the existing socket and
# needs no terminal at all. BatchMode on the data calls makes a missing master fail
# loudly instead of silently reopening a connection that then wants a password.
# NumberOfPasswordPrompts=1 matters here: OpenSSH retries three times by default, and
# with an askpass helper it re-reads the SAME stored password each time. A typo would
# therefore produce 3 failed authentications per call and 12 across the four queries --
# more than enough to trip a lockout on switch firmware that has one. One try per call
# fails fast and visibly instead.
SSH_SW="ssh -T -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o NumberOfPasswordPrompts=1 -o ConnectTimeout=15 -o ControlMaster=no -o ControlPath=none"
SWITCH_SSH_TIMEOUT="${SWITCH_SSH_TIMEOUT:-30}"

# --- credential name-class (from statedump.sh); values of options/fields whose
#     name ends in one of these are secrets. Matched as a whole trailing word. ---
SECRET_NAMES='key|password|passwd|passphrase|secret|psk|pin|pincode|token|hash|credential|credentials'

# ---------------------------------------------------------------------------
# args
# ---------------------------------------------------------------------------

# --help prints the intro and the INVARIANTS, then the options. It finds both by
# CONTENT, and that is the fix rather than a style choice: this used to be
# `sed -n '2,40p'`, which is precisely the positional dependency the READING THE
# OUTPUT rule above warns about for the inventory tables. The header grew, 40
# stopped being the end of anything, and --help began cutting off mid-sentence --
# while never showing the options at all, which is the one thing --help is for.
# An index is a silent dependency on a layout nobody promised to keep; it broke
# here for the same reason it broke there.
usage() {
    awk '
      BEGIN                          { head = 1 }
      NR == 1                        { next }              # shebang
      /^# READING THE OUTPUT/        { head = 0 }
      /^# Usage:/                    { opts = 1 }
      /^# Targets are overridable/   { opts = 0 }
      head || opts                   { print }
    ' "$0"
    printf '# The rest of the header -- how to read the output, the known gaps and\n'
    printf '# why the switch fetch looks the way it does -- is in the file itself:\n'
    printf '#   %s\n' "$0"
}

OUT=""; SPLIT=0; BODY_ONLY=0; WANT_PACKAGES=0; SWITCH_SSH=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out)        OUT="$2"; shift 2 ;;
        --split)      SPLIT=1; shift ;;
        --body-only)  BODY_ONLY=1; shift ;;
        --packages)   WANT_PACKAGES=1; shift ;;
        --switch-ssh) SWITCH_SSH=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "unbekannte Option: $1" >&2; exit 1 ;;
    esac
done
[ -n "$OUT" ] || OUT="$HOME/factinv-$(date +%Y%m%d-%H%M).md"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/factdump.XXXXXX") || { echo "mktemp fehlgeschlagen" >&2; exit 1; }
# `stty echo` is in the trap because the switch password is read with echo OFF: a
# Ctrl-C during that read would otherwise leave the operator's terminal silent.
trap 'stty echo 2>/dev/null; rm -rf "$WORK"' EXIT INT TERM

EXITCODE=0
UNREACHABLE=""

warn() { echo "$*" >&2; }

# ---------------------------------------------------------------------------
# redaction + leak scan (finished-file net; layer 2 and 3)
# ---------------------------------------------------------------------------
ENDPOINT_SED=''   # filled after router discovery

redact() {
    sed -E "s/^([]A-Za-z0-9_.@[-]*[._]($SECRET_NAMES))=.*$/\1=<REDACTED>/I" \
      | sed -E "s/^([[:space:]]*(option|list)[[:space:]]+[A-Za-z0-9_]*($SECRET_NAMES))[[:space:]].*$/\1 '<REDACTED>'/I" \
      | sed -E "s/^([[:space:]]*)([A-Za-z0-9_]*($SECRET_NAMES))[[:space:]]*:.*$/\1\2: <REDACTED>/I" \
      | sed -E "s/(ssh-[a-z0-9]+ )[A-Za-z0-9+\/=]{20,}/\1<KEY>/g" \
      `# switch CLI syntax: positional secrets that none of the name=value forms catch` \
      `# the switch's serial and password hashes use <REMOVED> (operator convention),` \
      `# distinct from <REDACTED> elsewhere; verified on the live config by the PoC.` \
      | sed -E "s/^(username[[:space:]]+\"[^\"]*\"[[:space:]]+secret[[:space:]]+encrypted)[[:space:]]+[^ ].*/\1 <REMOVED>/I" \
      | sed -E "s/^(snmp[[:space:]]+user[[:space:]]+.*(encrypted|none))[[:space:]]+[^ ].*/\1 <REMOVED>/I" \
      | sed -E "s/^(snmp[[:space:]]+user[[:space:]]+.*[[:space:]](sha512|sha256|sha|md5))[[:space:]]+[0-9A-Fa-f][0-9A-Fa-f ]*$/\1 <REMOVED>/I" \
      | sed -E "s/^(![[:space:]]*Serial Number:).*/\1 <REMOVED>/I" \
      | { if [ -n "$ENDPOINT_SED" ]; then sed -E "$ENDPOINT_SED"; else cat; fi; }
}

# Re-read the finished file; refuse to call it clean if a credential survived.
leak_scan() {   # $1 = file
    f="$1"; found=0
    if grep -niE "([._]|^|[[:space:]])($SECRET_NAMES)[[:space:]]*[:=]" "$f" \
         | grep -viE '<REDACTED>|<REMOVED>|<KEY>|_path|_file|_paths' > "$WORK/leak.a" 2>/dev/null; then
        [ -s "$WORK/leak.a" ] && { warn "LEAK ($f): Feld mit Geheimnis-Namen traegt noch einen Wert:"; cat "$WORK/leak.a" >&2; found=1; }
    fi
    # Path tables (backup_scope, local_files) are '| /...' rows; a long path matches the
    # base64 class because '/' is in it -- exclude those rows, a secret never starts with '| /'.
    if grep -nE '[A-Za-z0-9+/]{40,}={0,2}' "$f" | grep -vE '^[0-9]+:\| /' > "$WORK/leak.b" 2>/dev/null; then
        [ -s "$WORK/leak.b" ] && { warn "LEAK ($f): langer Base64/Hex-Block:"; cat "$WORK/leak.b" >&2; found=1; }
    fi
    # Switch running-config: the serial can be shorter than the 40-char blob check,
    # and a password hash must never survive -- catch both, ignoring masked lines.
    if grep -niE '^![[:space:]]*Serial Number:[[:space:]]*[A-Za-z0-9]|secret[[:space:]]+encrypted[[:space:]]+[^<[:space:]]|(encrypted|none)[[:space:]]+[A-Za-z0-9+/=]{6,}|snmp[[:space:]]+user[[:space:]].*(sha512|sha256|sha|md5)[[:space:]]+[0-9A-Fa-f]{16,}' "$f" \
         | grep -viE '<REMOVED>|<REDACTED>' > "$WORK/leak.c" 2>/dev/null; then
        [ -s "$WORK/leak.c" ] && { warn "LEAK ($f): Switch-Serial/Passwort-Hash nicht redigiert:"; cat "$WORK/leak.c" >&2; found=1; }
    fi
    return $found
}

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
# split a marked raw collection (@@@ name) into $WORK/<pfx>.<name> files
split_raw() {   # $1 rawfile  $2 pfx
    awk -v pfx="$2" '
        /^@@@ /{ name=$2; out=pfx"."name; next }
        { if(out!="") print > out }
    ' "$1"
}

na() { printf -- '— nicht verfügbar (%s) —\n\n' "$1"; }

# 8.4: a crontab holding only commented-out job lines used to produce a table
# with zero rows and no marker -- indistinguishable from "parser found
# nothing". Now every line that is (after stripping a leading "#" and
# whitespace) a valid five-field cron line gets a row, state active/commented;
# plain prose comments are still dropped. Shared by router and Spitz.
render_cron() {   # $1 = raw crontab file
    printf '### cron\n\n| schedule | command | state |\n|---|---|---|\n'
    rows=""
    if [ -s "$1" ]; then
        rows=$(awk '
          {
            line=$0; st="active"
            if (line ~ /^#/) { cand=line; sub(/^#[ \t]*/,"",cand); st="commented" } else { cand=line }
            if (cand ~ /^#/) next
            n=split(cand,f," ")
            if (n<6) next
            for (i=1;i<=5;i++) if (f[i] !~ /^[0-9*/,-]+$/) next
            sched=f[1]" "f[2]" "f[3]" "f[4]" "f[5]
            cmd=f[6]; for(i=7;i<=n;i++) cmd=cmd" "f[i]
            print sched"\t"cmd"\t"st
          }
        ' "$1" | sort)
    fi
    if [ -n "$rows" ]; then
        printf '%s\n' "$rows" | awk -F'\t' '{printf "| `%s` | %s | %s |\n",$1,$2,$3}'
    else
        printf '| — | keine aktiven Einträge | |\n'
    fi
}

# ===========================================================================
# COMPONENT 1 — OpenWrt One
# ===========================================================================
collect_router() {
    $SSH "$ROUTER" 'sh -s' > "$WORK/router.raw" 2>/dev/null <<'REOF'
echo "@@@ identity"
cat /tmp/sysinfo/model 2>/dev/null
. /etc/openwrt_release 2>/dev/null
echo "RELEASE=$DISTRIB_RELEASE"
echo "REVISION=$DISTRIB_REVISION"
echo "TARGET=$DISTRIB_TARGET"
echo "KERNEL=$(uname -r)"
echo "@@@ system"
uci -q show system | grep -vE '^system\.[^.]+\.led'
echo "@@@ dropbear"
uci -q show dropbear
echo "@@@ uhttpd"
uci -q show uhttpd | grep -E '\.(listen_http|listen_https|redirect_https|cert|key)='
echo "@@@ authorized_keys"
if [ -f /etc/dropbear/authorized_keys ]; then
    awk '{print $1}' /etc/dropbear/authorized_keys | sort | uniq -c
fi
echo "@@@ network"
uci -q show network
echo "@@@ firewall"
uci -q show firewall
echo "@@@ dhcp"
uci -q show dhcp
echo "@@@ wireless"
uci -q show wireless
echo "@@@ iwinfo"
for p in $(iwinfo 2>/dev/null | grep -oE '^[a-z0-9-]+'); do
    echo "--- $p"
    iwinfo "$p" info 2>/dev/null | grep -E 'ESSID|Channel|Tx-Power|Encryption|HW Mode'
done
echo "@@@ netstat"
netstat -tulnp 2>/dev/null
echo "@@@ adguard"
awk '
  /^[a-zA-Z_]/ { top=$0; sub(/:.*/,"",top); inlist=""; sub2="" }
  # --- scalars under dns: ---
  top=="dns" && $1=="port:"                      { port=$2 }
  top=="dns" && $1=="upstream_mode:"             { um=$2 }
  top=="dns" && $1=="ratelimit:"                 { rl=$2 }
  top=="dns" && $1=="ratelimit_subnet_len_ipv4:" { rls=$2 }
  top=="dns" && index($0,"tls://")               { dot=1 }
  # --- list-valued keys under dns: collect ALL entries, comma-joined ---
  top=="dns" && $1 ~ /^(bind_hosts|upstream_dns|fallback_dns|bootstrap_dns):$/ {
      inlist=$1; sub(/:$/,"",inlist); next }
  top=="dns" && inlist!="" && $1=="-" {
      v=$2; L[inlist]=(L[inlist]==""?v:L[inlist]","v); next }
  top=="dns" && inlist!="" && $1!="-" { inlist="" }
  # --- tls: block (the 853 and 8080/443 listeners section 9 describes) ---
  top=="tls" && $1=="enabled:"            { tls_en=$2 }
  top=="tls" && $1=="port_dns_over_tls:"  { p_dot=$2 }
  top=="tls" && $1=="port_https:"         { p_https=$2 }
  # 7.1: force_https/certificate_path/private_key_path -- all three live under
  # tls:, NOT http: as the work order assumed (widerlegte Annahme). "_path" in
  # the emitted key names is deliberate: leak_scan() already exempts lines
  # matching _path/_file/_paths, so a *_key_path field never has to fight the
  # redactor even though it contains "key".
  top=="tls" && $1=="force_https:"       { force_https=$2 }
  top=="tls" && $1=="certificate_path:"  { cert_path=$2 }
  top=="tls" && $1=="private_key_path:"  { key_path=$2 }
  # http: has nested blocks (doh:, pprof:), so the top-level key is not enough --
  # track the second level explicitly or these read as unset.
  top=="http" && $1=="doh:"   { sub2="doh";   next }
  top=="http" && $1=="pprof:" { sub2="pprof"; next }
  # Reset only on a BARE block header (NF==1). Without the NF test this also fires on
  # `insecure_enabled: true`, clearing the context one line before it is read.
  top=="http" && $1 ~ /^[a-z_]+:$/ && NF==1 && $1!="routes:" { sub2="" }
  top=="http" && sub2=="doh"   && $1=="insecure_enabled:" { doh_insec=$2 }
  top=="http" && sub2=="pprof" && $1=="enabled:"          { pprof_en=$2 }
  top=="http" && sub2=="pprof" && $1=="port:"             { pprof_port=$2 }
  # 7.1: `address:` sits after the doh:/pprof: blocks in this file and is not a
  # bare NF==1 header, so sub2 stays "doh"/"pprof" when it is reached -- no sub2
  # guard here, "address:" is a key name unique to the http block itself, never
  # nested inside doh:/pprof:. This is the actual base-listener address
  # (192.168.30.1:8080, closed at the firewall) -- NOT the 9443 web UI port,
  # which is tls.port_https above; a widerlegte Annahme worth stating plainly.
  top=="http" && $1=="address:" { http_addr=$2 }
  # 7.1: filtering: block -- protection/filtering toggles, blocking mode, the
  # rewrite-rule count, none of it read before this.
  top=="filtering" && $1=="protection_enabled:"      { prot_en=$2 }
  top=="filtering" && $1=="filtering_enabled:"       { filt_en=$2 }
  top=="filtering" && $1=="blocking_mode:"           { block_mode=$2 }
  top=="filtering" && $1=="filters_update_interval:" { filt_upd=$2 }
  top=="filtering" && $1 ~ /^rewrites:$/ { inlist_count="rewrites"; next }
  # 7.1: dns: cache/dnssec/aaaa/hostsfile scalars, plus allowed/disallowed
  # clients and blocked_hosts as COUNTS (not the addresses themselves -- the
  # point is whether an allow/deny list exists at all, not what is in it).
  top=="dns" && $1=="cache_size:"        { cache_size=$2 }
  top=="dns" && $1=="enable_dnssec:"     { dnssec=$2 }
  top=="dns" && $1=="aaaa_disabled:"     { aaaa=$2 }
  top=="dns" && $1=="hostsfile_enabled:" { hostsfile=$2 }
  top=="dns" && $1 ~ /^(allowed_clients|disallowed_clients|blocked_hosts):$/ {
      inlist_count=$1; sub(/:$/,"",inlist_count); next }
  inlist_count!="" && $1=="-" { CNT[inlist_count]++; next }
  inlist_count!="" && $1!="-" { inlist_count="" }
  # --- switches only, never contents (a diffable body has no counters) ---
  top=="querylog"   && $1=="enabled:" { ql=$2 }
  top=="statistics" && $1=="enabled:" { st=$2 }
  top=="filters"    && $1=="-" && $2=="enabled:" { fc++ }
  top=="user_rules" && $1=="-" { uc++ }
  END {
    printf "http_address=%s\n", http_addr
    printf "tls_force_https=%s\n", force_https
    printf "tls_certificate_path=%s\n", cert_path
    printf "tls_private_key_path=%s\n", key_path
    printf "filtering_protection_enabled=%s\n", prot_en
    printf "filtering_filtering_enabled=%s\n", filt_en
    printf "filtering_blocking_mode=%s\n", block_mode
    printf "filtering_filters_update_interval=%s\n", filt_upd
    printf "filtering_rewrites_count=%s\n", CNT["rewrites"]+0
    printf "dns_cache_size=%s\n", cache_size
    printf "dns_enable_dnssec=%s\n", dnssec
    printf "dns_aaaa_disabled=%s\n", aaaa
    printf "dns_hostsfile_enabled=%s\n", hostsfile
    printf "dns_allowed_clients_count=%s\n", CNT["allowed_clients"]+0
    printf "dns_disallowed_clients_count=%s\n", CNT["disallowed_clients"]+0
    printf "dns_blocked_hosts_count=%s\n", CNT["blocked_hosts"]+0
    printf "bind_host=%s\n", (L["bind_hosts"]!=""?L["bind_hosts"]:"")
    printf "bind_port=%s\n", port
    printf "upstream_mode=%s\n", um
    printf "dot_upstream=%s\n", (dot?"true":"false")
    # A resolver PROFILE ID is a secret-ish identifier: the README security note
    # withholds them by name, and this file is handed to a reviewer. Keep the provider
    # (that is the documented fact -- DoT upstream), mask the profile label.
    u = L["upstream_dns"]
    gsub(/tls:\/\/[A-Za-z0-9_-]+\.dns\.nextdns\.io/, "tls://<profile>.dns.nextdns.io", u)
    gsub(/https:\/\/[A-Za-z0-9_-]+\.dns\.nextdns\.io/, "https://<profile>.dns.nextdns.io", u)
    printf "upstream_dns=%s\n", u
    printf "fallback_dns=%s\n", L["fallback_dns"]
    printf "bootstrap_dns=%s\n", L["bootstrap_dns"]
    printf "tls_enabled=%s\n", tls_en
    printf "port_dns_over_tls=%s\n", p_dot
    printf "port_https=%s\n", p_https
    printf "doh_insecure_enabled=%s\n", doh_insec
    printf "pprof_enabled=%s\n", pprof_en
    printf "pprof_port=%s\n", pprof_port
    printf "ratelimit=%s\n", rl
    printf "ratelimit_subnet_len_ipv4=%s\n", rls
    printf "querylog_enabled=%s\n", ql
    printf "statistics_enabled=%s\n", st
    printf "blocklist_count=%s\n", fc+0
    printf "client_rules_count=%s\n", uc+0
    printf "user_rules_count=%s\n", uc+0
  }' /etc/adguardhome/adguardhome.yaml 2>/dev/null
echo "@@@ adguard_clients"
# Persistent clients: name, ids, and the two flags that are only readable together.
# No MACs are emitted -- section 9 claims AdGuard identifies clients by IP alone, and
# the ids column is what proves it, so a MAC here would both leak and contradict.
# Parsed by INDENTATION, not by key name. A persistent entry starts `    - <anything>`
# (the first key happens to be safe_search, not name), its fields sit at six spaces, and
# its id list items at eight. That matters: blocked_services carries its own `ids: []` at
# eight spaces, which a key-name match would happily mistake for the client's ids.
awk '
  function flush(){ if(name!="") print name"\t"ids"\t"ugs"\t"fe; name="";ids="";ugs="";fe="";inids=0 }
  /^clients:/            { inc=1; next }
  /^[a-zA-Z_]/           { if(inc) flush(); inc=0 }
  inc && /^    - /       { flush(); next }
  inc && /^      name: / { name=$2; next }
  inc && /^      ids:/   { inids=1; next }
  inc && inids && /^        - / { ids=(ids==""?$2:ids","$2); next }
  inc && inids                  { inids=0 }
  inc && /^      use_global_settings: / { ugs=$2; next }
  inc && /^      filtering_enabled: /   { fe=$2;  next }
  END { flush() }
' /etc/adguardhome/adguardhome.yaml 2>/dev/null
echo "@@@ adguard_filters"
# 7.2: id, name, enabled only -- no url, per the operator decision recorded in
# the work order (name is enough for a doc cross-check; a url only adds a
# leak_scan surface for no gain here). filters: entries are indented two
# spaces for the list marker, four for the fields; whitelist_filters: uses the
# identical shape when it holds entries at all.
awk '
  function flush(){ if(id!=""){ print sec"\t"id"\t"name"\t"en }; id="";name="";en="" }
  /^filters:/          { flush(); sec="filters"; next }
  /^whitelist_filters:/ { flush(); sec="whitelist"; next }
  /^[a-zA-Z_]/ && !/^filters:/ && !/^whitelist_filters:/ { flush(); sec="" }
  sec!="" && /^  - enabled: / { flush(); en=$3; next }
  sec!="" && /^    name: /    { name=$0; sub(/^    name: /,"",name); next }
  sec!="" && /^    id: /      { id=$2; next }
  END { flush() }
' /etc/adguardhome/adguardhome.yaml 2>/dev/null
echo "@@@ adguard_user_rules_raw"
# 7.3: the user_rules: YAML block, verbatim, untouched remotely -- line joining
# for wrapped entries and quote stripping both happen locally, where the
# result can be tested against a saved copy without another SSH round trip.
# `client_rules_count` above is the misleadingly named line count of this
# same block (these are global rules using $client=, not per-client rules,
# section 9); kept as-is for diffability, user_rules_count below replaces it.
awk '/^user_rules:/{f=1;next} /^[a-z_]+:/{f=0} f' /etc/adguardhome/adguardhome.yaml 2>/dev/null
echo "@@@ hosts"
grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null
echo "@@@ links"
ip -br link 2>/dev/null
echo "@@@ links_master"
# Full (non-brief) form: `ip -br link` on this iproute2 build has no master
# column despite the work order expecting one from brief mode alone -- this is
# the fallback that actually carries bridge membership, joined against the
# brief-mode table locally.
ip link show 2>/dev/null
echo "@@@ ipv6_global"
ip -6 -br addr show scope global 2>/dev/null
echo "@@@ routing_rules"
ip rule show 2>/dev/null
echo "@@@ routing_tables"
for t in main pbr_wan pbr_proton; do
    echo "--- table $t"
    ip route show table "$t" 2>/dev/null
done
echo "@@@ pbr"
uci -q show pbr
echo "@@@ pbr_nft"
ls -1 /usr/share/nftables.d/ruleset-post/ 2>/dev/null
echo "@@@ pbr_nft_chains"
grep -hoE '^add chain inet fw4 [A-Za-z0-9_]+' \
    /usr/share/nftables.d/ruleset-post/*.nft 2>/dev/null | awk '{print $NF}'
echo "@@@ pbr_nft_policies"
grep -hoE 'ip6? saddr \{[^}]*\}[^"]*comment "[^"]*"' \
    /usr/share/nftables.d/ruleset-post/*.nft 2>/dev/null
echo "@@@ pbr_chain"
nft -s list chain inet fw4 pbr_prerouting 2>/dev/null
echo "@@@ fw_nft_table"
nft -s list table inet fw4 2>/dev/null
echo "@@@ pbr_pkg"
apk list -I 2>/dev/null | grep -oE '^(luci-app-)?pbr[^ ]*'
echo "@@@ adguard_service"
uci -q show adguardhome
echo "--- version"
apk list -I 2>/dev/null | grep -E '^adguardhome-'
echo "--- gomemlimit"
# 7.4: widerlegte Annahme -- `pgrep -x AdGuardHome` matches nothing on this
# busybox build even though /proc/<pid>/comm for the real binary is exactly
# that string; plain `pgrep AdGuardHome` (no -x) finds exactly one process
# here, since the procd jail wrapper process has comm=adguardhome (lowercase)
# and does not substring-match the mixed-case query. Effective value only,
# never the whole environment.
pid=$(pgrep AdGuardHome 2>/dev/null | head -1)
if [ -n "$pid" ] && [ -r "/proc/$pid/environ" ]; then
    tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | grep '^GOMEMLIMIT='
fi
echo "@@@ services_enabled"
for f in /etc/rc.d/S*; do
    [ -e "$f" ] || continue
    n=$(basename "$f")
    echo "${n#S[0-9][0-9]}"
done
echo "@@@ local_files"
for f in /root/*.sh /etc/rc.local /etc/sysctl.conf /etc/crontabs/root; do
    [ -f "$f" ] || continue
    sz=$(wc -c < "$f" 2>/dev/null)
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    echo "$f|$sz|$h"
done
echo "@@@ backup_scope"
sysupgrade -l 2>/dev/null | sort
echo "@@@ cron"
crontab -l 2>/dev/null
echo "@@@ packages"
apk list -I 2>/dev/null | grep -oE '^[a-z0-9._+-]+'
REOF
    [ -s "$WORK/router.raw" ] && grep -q '@@@ identity' "$WORK/router.raw"
}

# discover VPN endpoints from the router's network config, for redaction
discover_endpoints() {
    for e in $(grep -oE "endpoint_host='?[^' ]+'?" "$WORK/router.network" 2>/dev/null | sed -E "s/endpoint_host='?([^']*)'?/\1/"); do
        esc=$(printf '%s' "$e" | sed 's/[][\.*^$/]/\\&/g')
        ENDPOINT_SED="${ENDPOINT_SED}s/${esc}/<PROTON_ENDPOINT>/g;"
    done
}

emit_router() {
    hdr="## OpenWrt One — $ROUTER"
    if [ -n "$1" ]; then printf '%s  \n**⚠ nicht erreichbar (%s)** — Inventar unvollständig.\n\n' "$hdr" "$1"; return; fi
    printf '%s\n\n' "$hdr"

    # identitaet
    printf '### identitaet\n\n| key | value |\n|---|---|\n'
    awk -F= '
      /^RELEASE=/{rel=$2} /^REVISION=/{rev=$2} /^TARGET=/{tgt=$2} /^KERNEL=/{k=$2}
      !/=/{ if($0!="") model=$0 }
      END{ printf "| model | %s |\n| openwrt_release | %s %s |\n| kernel | %s |\n| target | %s |\n", model, rel, rev, k, tgt }
    ' "$WORK/router.identity"
    printf '\n'

    # 8.1: `config system` was never read. Section 7.6/13/14 assert
    # ntp.enable_server=1, log_size=512, zonename=Europe/Berlin; a remote
    # syslog target (section 18, planned, not built) would show up here as
    # log_ip/log_remote if it ever gets configured.
    printf '### system\n\n| key | value |\n|---|---|\n'
    if [ -s "$WORK/router.system" ]; then
        awk '
          match($0,/^system\.(@system\[[0-9]+\])=/,m){ sid=m[1]; sysid=sid; next }
          match($0,/^system\.(@system\[[0-9]+\])\.([A-Za-z_]+)=(.*)$/,m){
            sid=m[1]; k=m[2]; v=m[3]
            if(sid==sysid){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v); V[k]=v }
          }
          match($0,/^system\.ntp\.([A-Za-z_]+)=(.*)$/,m){
            k=m[1]; v=m[2]; gsub(/'"'"'/,"",v); gsub(/ +/,",",v); N[k]=v
          }
          END{
            allow="hostname,zonename,timezone,log_size,log_ip,log_remote,log_proto,cronloglevel"
            split(allow,f,",")
            for(i=1;i<=length(f);i++){ k=f[i]; printf "| %s | %s |\n", k, (k in V?V[k]:"(unset)") }
            printf "| ntp.enabled | %s |\n", ("enabled" in N?N["enabled"]:"(unset)")
            printf "| ntp.enable_server | %s |\n", ("enable_server" in N?N["enable_server"]:"(unset)")
            printf "| ntp.server | %s |\n", ("server" in N?N["server"]:"(unset)")
          }' "$WORK/router.system"
    else
        printf '| — | nicht erfasst |\n'
    fi
    printf '\n'

    # 8.2: dropbear/uhttpd/authorized_keys -- key-only auth and the missing
    # HTTP listener were asserted in section 10 but never checked against the
    # live device config.
    printf '### dropbear\n\n| instance | Interface | DirectInterface | Port | PasswordAuth | RootPasswordAuth | GatewayPorts |\n|---|---|---|---|---|---|---|\n'
    if [ -s "$WORK/router.dropbear" ]; then
        awk '
          match($0,/^dropbear\.([^.=]+)=dropbear/,m){ sid=m[1]; seen[sid]=1; next }
          match($0,/^dropbear\.([^.]+)\.([^=]+)=(.*)$/,m){
            sid=m[1]; k=m[2]; v=m[3]
            if(sid in seen){ gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
          }
          END{
            for(s in seen){
              f="Interface,DirectInterface,Port,PasswordAuth,RootPasswordAuth,GatewayPorts"
              n=split(f,a,",")
              printf "| %s ", s
              for(i=1;i<=n;i++){ k=a[i]; printf "| %s ", ((s SUBSEP k) in V?V[s SUBSEP k]:"(unset)") }
              printf "|\n"
            }
          }' "$WORK/router.dropbear"
    else
        printf '| — | nicht erfasst | | | | | |\n'
    fi
    printf '\n'

    printf '### uhttpd\n\n| key | value |\n|---|---|\n'
    if [ -s "$WORK/router.uhttpd" ]; then
        awk -F= '
          { k=$1; v=$2; sub(/^uhttpd\.main\./,"",k); gsub(/^'"'"'|'"'"'$/,"",v) }
          k=="cert" { printf "| cert_path | %s |\n", v; next }
          k=="key"  { printf "| key_path | %s |\n", v; next }
          k!=""     { printf "| %s | %s |\n", k, v }
        ' "$WORK/router.uhttpd"
    else
        printf '| — | nicht erfasst |\n'
    fi
    printf '\n'

    printf '### authorized_keys\n\n| Schluesseltyp | Anzahl |\n|---|---|\n'
    if [ -s "$WORK/router.authorized_keys" ]; then
        awk '{ printf "| %s | %s |\n", $2, $1 }' "$WORK/router.authorized_keys"
    else
        printf '| — | 0 |\n'
    fi
    printf '\n'

    # interfaces
    # 4.2: addresses/mtu/auto/disabled appended -- the WireGuard interface
    # (`proton`) uses `addresses` (CIDR list), not `ipaddr`/`netmask`, so it
    # printed blank in this table's first two address columns regardless of its
    # actual configuration; section 17 asserts a specific MTU (1412) that was not
    # checkable at all.
    printf '### interfaces\n\n| interface | proto | ipaddr | netmask | device | addresses | mtu | auto | disabled |\n|---|---|---|---|---|---|---|---|---|\n'
    awk '
      match($0,/^network\.([^.=]+)=interface/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^network\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1]; k=m[2]; v=m[3];
        if(sid in seen){ if(k=="addresses"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) } else gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
      }
      END{
        n=0; for(s in seen){ ids[n++]=s }
        # sort
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(ids[j]<ids[i]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]
          ad=V[s,"addresses"]; if(ad=="") ad="—"
          mt=V[s,"mtu"]; if(mt=="") mt="—"
          au=V[s,"auto"]; if(au=="") au="(unset)"
          di=V[s,"disabled"]; if(di=="") di="0"
          printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", s, V[s,"proto"], V[s,"ipaddr"], V[s,"netmask"], V[s,"device"], ad, mt, au, di
        }
      }' "$WORK/router.network"
    printf '\n'

    # 4.2: peer fields by ALLOWLIST -- public_key deliberately excluded (44
    # base64 chars would trip leak_scan, correctly, and a fingerprint is not
    # needed for a doc-vs-device check). endpoint_host stays redacted by the
    # existing discover_endpoints()/ENDPOINT_SED mechanism, unchanged here.
    printf '### wg_peers\n\n| interface | description | endpoint_port | allowed_ips | route_allowed_ips | persistent_keepalive |\n|---|---|---|---|---|---|\n'
    awk '
      match($0,/^network\.(@wireguard_([A-Za-z0-9_]+)\[[0-9]+\])=/,m){ sid=m[1]; ifc[sid]=m[2]; seen[sid]=1; next }
      match($0,/^network\.(@wireguard_[A-Za-z0-9_]+\[[0-9]+\])\.([A-Za-z_]+)=(.*)$/,m){
        sid=m[1]; k=m[2]; v=m[3]
        if(sid in seen){
          if(k=="allowed_ips"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) } else gsub(/^'"'"'|'"'"'$/,"",v)
          V[sid SUBSEP k]=v
        }
      }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(ids[j]<ids[i]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]
          ep=V[s,"endpoint_port"]; if(ep=="") ep="—"
          ai=V[s,"allowed_ips"]; if(ai=="") ai="—"
          ra=V[s,"route_allowed_ips"]; if(ra=="") ra="(unset)"
          pk=V[s,"persistent_keepalive"]; if(pk=="") pk="—"
          de=V[s,"description"]; if(de=="") de="—"
          printf "| %s | %s | %s | %s | %s | %s |\n", ifc[s], de, ep, ai, ra, pk }
        if(n==0) print "| — | — | — | — | — | — |"
      }' "$WORK/router.network"
    printf '\n'

    # vlans — this router models VLANs as 802.1q sub-interface ports on bridges
    # (ports='eth1.20'), not as config bridge-vlan. vlan_id is derived from the
    # port name and marked [abgeleitet] per spec invariant #3.
    # 4.1: bridge_empty appended (Appendix A D5: br-smarthome carries it with no
    # `ports` -- previously not checkable at all) and name_len, flagged past 15
    # characters -- netifd silently refuses a longer bridge device name and stalls
    # EVERY bridge's reload, not just the long one; this is the exact failure mode
    # a prior recovery incident hit by hand, before this check existed.
    printf '### vlans [vlan_id abgeleitet aus Portname `ethN.VID`]\n\n| bridge | vlan_id | ports | bridge_empty | name_len |\n|---|---|---|---|---|\n'
    awk '
      match($0,/^network\.([^.=]+)=device/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^network\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1]; k=m[2]; v=m[3];
        if(sid in seen){ if(k=="ports"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) } else gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
      }
      END{
        n=0; for(s in seen){ if(V[s,"type"]=="bridge") ids[n++]=s }
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(V[ids[j],"name"]<V[ids[i],"name"]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]; p=V[s,"ports"]; vid="—";
          if(match(p,/\.[0-9]+/)) vid=substr(p,RSTART+1,RLENGTH-1);
          else if(p!="") vid="nativ/untagged";
          if(p=="") p="—";
          be=V[s,"bridge_empty"]; if(be=="") be="0"
          nm=V[s,"name"]; nl=length(nm); nlout=(nl>15?"**"nl" > 15**":nl)
          printf "| %s | %s | %s | %s | %s |\n", nm, vid, p, be, nlout }
        if(n==0) print "| — | — | — | — | — |"
      }' "$WORK/router.network"
    printf '\n'

    # 4.1: non-bridge `config device` sections (eth0, eth1) were invisible --
    # `vlans` above only ever selected type=bridge.
    printf '### devices_other\n\n| name | type | ports |\n|---|---|---|\n'
    awk '
      match($0,/^network\.([^.=]+)=device/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^network\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1]; k=m[2]; v=m[3];
        if(sid in seen){ if(k=="ports"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) } else gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
      }
      END{
        n=0; for(s in seen){ if(V[s,"type"]!="bridge") ids[n++]=s }
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(V[ids[j],"name"]<V[ids[i],"name"]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]; nm=V[s,"name"]; ty=V[s,"type"]; if(ty=="") ty="—"; p=V[s,"ports"]; if(p=="") p="—"
          printf "| %s | %s | %s |\n", nm, ty, p }
        if(n==0) print "| — | — | — |"
      }' "$WORK/router.network"
    printf '\n'

    # 5.1: `wifi-device` (radio) config was never read on this device -- only the
    # runtime iwinfo view below existed. Section 6.1 argues channel/width/country/
    # power as deliberate configuration; none of that was checkable against the
    # config layer, only against what happened to be running right now.
    printf '### radios\n\n| radio | band | channel | htmode | country | txpower | cell_density | mbssid | disabled |\n|---|---|---|---|---|---|---|---|---|\n'
    awk '
      match($0,/^wireless\.([^.=]+)=wifi-device/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^wireless\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1]; k=m[2]; v=m[3]; gsub(/^'"'"'|'"'"'$/,"",v);
        if(sid in seen){ V[sid SUBSEP k]=v }
      }
      END{
        n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(ids[j]<ids[i]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]
          cd=V[s,"cell_density"]; if(cd=="") cd="(unset)"
          mb=V[s,"mbssid"]; if(mb=="") mb="(unset)"
          di=V[s,"disabled"]; if(di=="") di="(unset)"
          printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", s, V[s,"band"], V[s,"channel"], V[s,"htmode"], V[s,"country"], V[s,"txpower"], cd, mb, di }
      }' "$WORK/router.wireless"
    printf '\n'

    # wireless (no key/passphrase)
    # 5.2: network/mode/ieee80211w/ocv/isolate/macfilter/maclist_entries/hidden
    # appended -- section 6.2 asserts PMF, OCV and client isolation per SSID
    # (Appendix A A7); none of that was in this table before, only
    # ssid/radio/encryption/disabled. maclist_entries is a COUNT, not the MAC
    # addresses themselves -- enough to confirm C12's retirement (section 6.2,
    # `management` no longer has a wifi-iface section at all) without widening
    # the table or duplicating what section 8's DHCP table already lists.
    printf '### wireless\n\n| section | ssid | radio | encryption | disabled | network | mode | ieee80211w | ocv | isolate | macfilter | maclist_entries | hidden |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n'
    awk '
      match($0,/^wireless\.([^.=]+)=wifi-iface/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^wireless\.([^.]+)\.maclist=(.*)$/,m){
        sid=m[1]; v=m[2]
        if(sid in seen){ n=gsub(/'"'"'/,"'"'"'",v); MLN[sid]=n/2 }
      }
      match($0,/^wireless\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1]; k=m[2]; v=m[3]; gsub(/^'"'"'|'"'"'$/,"",v);
        if((sid in seen) && k!="key" && k!="sae_password" && k!="password" && k!="maclist"){ V[sid SUBSEP k]=v }
      }
      END{
        n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++){ if(V[ids[j],"ssid"]<V[ids[i],"ssid"]){t=ids[i];ids[i]=ids[j];ids[j]=t} }
        for(i=0;i<n;i++){ s=ids[i]; d=V[s,"disabled"]; if(d=="")d="0"
          pmf=V[s,"ieee80211w"]; if(pmf=="") pmf="(unset)"
          oc=V[s,"ocv"]; if(oc=="") oc="(unset)"
          iso=V[s,"isolate"]; if(iso=="") iso="0"
          mf=V[s,"macfilter"]; if(mf=="") mf="—"
          ml=(s in MLN)?MLN[s]:0
          hd=V[s,"hidden"]; if(hd=="") hd="0"
          printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", s, V[s,"ssid"], V[s,"device"], V[s,"encryption"], d, V[s,"network"], V[s,"mode"], pmf, oc, iso, mf, ml, hd }
      }' "$WORK/router.wireless"
    printf '\n'

    # Operating state per radio, not just the configured SSID list. The doc argues
    # TX power as a deliberate value (section 6.1) and keeps radio0 on the open-items
    # list (section 12); neither is checkable from uci alone. Channel and TX power are
    # configuration-derived and stable, so they belong in the diffable body.
    printf '### radio_state [iwinfo]\n\n| iface | ssid | channel | tx_power | hw_mode | encryption |\n|---|---|---|---|---|---|\n'
    if [ -s "$WORK/router.iwinfo" ]; then
        awk '
          /^--- /{ if(p!="") emit(); p=$2; ssid="-"; ch="-"; tx="-"; hw="-"; enc="-"; next }
          /ESSID/     { if(match($0,/ESSID: "([^"]*)"/,m)) ssid=m[1] }
          /Channel:/  { if(match($0,/Channel: ([0-9]+)/,m)) ch=m[1] }
          /Tx-Power:/ { if(match($0,/Tx-Power: ([0-9]+)/,m)) tx=m[1]" dBm" }
          /HW Mode/   { if(match($0,/HW Mode\(s\): ([^ ]+)/,m)) hw=m[1] }
          /Encryption:/ { e=$0; sub(/^.*Encryption: /,"",e); sub(/[[:space:]]+$/,"",e); enc=e }
          END{ if(p!="") emit() }
          function emit(){ printf "| %s | %s | %s | %s | %s | %s |\n", p, ssid, ch, tx, hw, enc }
        ' "$WORK/router.iwinfo" | sort
    else printf '| — | nicht verfügbar (iwinfo) | — | — | — | — |\n'; fi
    printf '\n'

    emit_fw "$WORK/router.firewall" "$WORK/router.network"
    emit_dhcp "$WORK/router.dhcp"

    # listening (strip PID, keep program)
    # DETERMINISM: a transient client socket (a resolver's or DHCP client's source
    # port, always in the ephemeral range and owned by no named listener) is not a
    # listening service, and it moves on every run -- which is a spurious diff. Those
    # are dropped; anything with a process name is kept regardless of port.
    printf '### listening\n\n| proto | address:port | process |\n|---|---|---|\n'
    awk '
      $1 ~ /^(tcp|udp)/ {
        proto=$1; la=$4; prog=$NF;
        sub(/^[0-9]+\//,"",prog);            # strip PID/
        if(prog ~ /^[0-9-]+$/) prog="-";
        port=la; sub(/^.*:/,"",port);
        if(proto ~ /^udp/ && prog=="-" && port+0 >= 32768) next;
        key=proto"|"la"|"prog; if(!(key in s)){ s[key]=1; print proto"\t"la"\t"prog }
      }' "$WORK/router.netstat" | sort -t'	' -k2 | awk -F'\t' '{printf "| %s | %s | %s |\n",$1,$2,$3}'
    printf '\n'

    # adguard
    printf '### adguard\n\n| key | value |\n|---|---|\n'
    if [ -s "$WORK/router.adguard" ]; then
        awk -F= '{ printf "| %s | %s |\n", $1, $2 }' "$WORK/router.adguard"
    else printf '| — | nicht verfügbar |\n'; fi
    printf '\n'

    # Persistent clients. `filtering_enabled` is carried NEXT TO `use_global_settings`
    # on purpose: several clients read false while use_global_settings is true, in which
    # case the global setting applies. Either field alone invites the wrong conclusion.
    printf '### adguard_clients\n\n| name | ids | use_global_settings | filtering_enabled |\n|---|---|---|---|\n'
    if [ -s "$WORK/router.adguard_clients" ]; then
        sort "$WORK/router.adguard_clients" \
          | awk -F'\t' '{ printf "| %s | %s | %s | %s |\n", $1, ($2==""?"—":$2), ($3==""?"—":$3), ($4==""?"—":$4) }'
    else printf '| — | nicht verfügbar | — | — |\n'; fi
    printf '\n'

    # 7.2: subscribed filter/allow lists, name and enabled state only -- no url
    # (operator decision), so a doc cross-check is possible without adding a
    # leak_scan surface. blocklist_count above already counts filters: entries;
    # this is the same data with a name attached, plus a first read of
    # whitelist_filters (previously never collected at all).
    printf '### adguard_filters\n\n| id | name | enabled |\n|---|---|---|\n'
    if [ -s "$WORK/router.adguard_filters" ]; then
        awk -F'\t' '$1=="filters"{printf "| %s | %s | %s |\n",$2,$3,$4}' "$WORK/router.adguard_filters" | sort -n
    fi | { grep . || printf '| — | — | keine |\n'; }
    printf '\n'
    printf '### adguard_allowlists\n\n| id | name | enabled |\n|---|---|---|\n'
    if [ -s "$WORK/router.adguard_filters" ]; then
        awk -F'\t' '$1=="whitelist"{printf "| %s | %s | %s |\n",$2,$3,$4}' "$WORK/router.adguard_filters" | sort -n
    fi | { grep . || printf '| — | — | keine |\n'; }
    printf '\n'

    # 7.3: the custom filter rules verbatim, original order, numbered so a
    # position stays stable even across blank/comment separator lines. YAML
    # line-folding for a wrapped single-quoted scalar is undone here (a
    # continuation line is joined to the previous entry with one space, the
    # same rule YAML itself uses); a single-quoted entry has its outer quotes
    # stripped and any doubled '' unescaped to a literal quote. This is the
    # same data client_rules_count above already counted, correctly but under
    # a misleading name (section 9: these are global $client=-scoped rules,
    # not per-client entries) -- user_rules_count is the same count, honestly
    # named, kept alongside rather than replacing the old field.
    printf '### adguard_user_rules\n\n```\n'
    if [ -s "$WORK/router.adguard_user_rules_raw" ]; then
        awk '
          BEGIN{ q=sprintf("%c",39) }
          function flush(   v){
            if(started){
              v=buf
              if(length(v)>=2 && substr(v,1,1)==q && substr(v,length(v),1)==q){
                v=substr(v,2,length(v)-2); gsub(q q, q, v)
              }
              n++; printf "%03d %s\n", n, v
            }
            buf=""; started=0
          }
          /^  - / { flush(); buf=$0; sub(/^  - /,"",buf); started=1; next }
          started { line=$0; sub(/^[[:space:]]+/,"",line); buf=buf" "line }
          END{ flush() }
        ' "$WORK/router.adguard_user_rules_raw"
    else
        printf '(keine)\n'
    fi
    printf '```\n\n'

    # 7.4: memlimit/jail_mount from uci (section 9 asserts memlimit=0, "left
    # deliberately at 0" -- config only, easy to state and easy to get wrong by
    # trusting it); version from the installed package, not the config;
    # effective_gomemlimit is the one value the doc explicitly says to check at
    # runtime rather than trust the config for, since a unit mismatch there
    # would not otherwise be visible (section 9, GOMEMLIMIT unit trap).
    printf '### adguard_service\n\n| key | value |\n|---|---|\n'
    if [ -s "$WORK/router.adguard_service" ]; then
        awk '
          /^--- version/ { sec="version"; next }
          /^--- gomemlimit/ { sec="gomemlimit"; next }
          sec==""     && match($0,/^adguardhome\.config\.memlimit=(.*)$/,m){ v=m[1]; gsub(/^'"'"'|'"'"'$/,"",v); ml=v }
          sec==""     && match($0,/^adguardhome\.config\.jail_mount(_rw)?=(.*)$/,m){ v=m[2]; gsub(/'"'"'/,"",v); gsub(/ +/,",",v); jm=(jm==""?v:jm","v) }
          sec=="version" && NF>0 { ver=$1 }
          sec=="gomemlimit" && match($0,/^GOMEMLIMIT=(.*)$/,m){ gml=m[1] }
          END{
            printf "| memlimit | %s |\n", (ml==""?"(unset)":ml)
            printf "| jail_mount | %s |\n", (jm==""?"(keine)":jm)
            printf "| version | %s |\n", (ver==""?"—":ver)
            printf "| effective_gomemlimit | %s |\n", (gml==""?"unset":gml)
          }' "$WORK/router.adguard_service"
    else
        printf '| — | nicht erfasst |\n'
    fi
    printf '\n'

    # tls certs (openssl from the WORKSTATION)
    printf '### tls_certs\n\n| endpoint | subject | issuer | not_before | not_after | san |\n|---|---|---|---|---|---|\n'
    for hp in 192.168.30.1:443 192.168.30.1:9443; do emit_cert "$hp"; done
    printf '\n'

    # Local name resolution. AdGuard serves these via hostsfile_enabled, so the
    # doc claim "the .home.arpa names match the certificates and resolve" (section 9,
    # appendix A row E5) is only verifiable with this section.
    printf '### local_names [/etc/hosts, von AdGuard gelesen]\n\n| address | names |\n|---|---|\n'
    if [ -s "$WORK/router.hosts" ]; then
        awk 'NF>=2 { a=$1; n=""; for(i=2;i<=NF;i++) n=n (n==""?"":" ") $i; print a"\t"n }' "$WORK/router.hosts" \
          | sort | awk -F'\t' '{printf "| %s | %s |\n",$1,$2}'
    else printf '| — | nicht verfügbar |\n'; fi
    printf '\n'

    # routing / policy-based routing (spec gap closed in v1.1.0).
    # Without these three sections the central claim of doc section 17 -- private is
    # steered into the tunnel and the kill-switch is fail-closed -- is not verifiable
    # from the inventory at all.
    printf '### routing_rules\n\n| prio | selector | lookup |\n|---|---|---|\n'
    if [ -s "$WORK/router.routing_rules" ]; then
        awk '
          NF {
            line=$0
            prio=$1; sub(/:$/,"",prio)
            sel=line; sub(/^[0-9]+:[[:space:]]*/,"",sel)
            tbl="-"
            if(match(sel,/lookup [A-Za-z0-9_]+/)){ tbl=substr(sel,RSTART+7,RLENGTH-7) }
            sub(/[[:space:]]*lookup [A-Za-z0-9_]+.*$/,"",sel)
            if(sel=="") sel="-"
            printf "| %s | %s | %s |\n", prio, sel, tbl
          }' "$WORK/router.routing_rules"
    else printf '| — | nicht verfügbar | — |\n'; fi
    printf '\n'

    # Routes are sorted; the default route of a tunnel table is the one that matters,
    # so it is kept, while the carrier-assigned next hop is volatile and dropped.
    printf '### routing_tables\n\n| table | route |\n|---|---|\n'
    if [ -s "$WORK/router.routing_tables" ]; then
        awk '
          /^--- table /{ t=$3; next }
          NF { r=$0; gsub(/[[:space:]]+/," ",r); print t"\t"r }
        ' "$WORK/router.routing_tables" | sort -u | awk -F'\t' '{printf "| %s | %s |\n",$1,$2}'
    else printf '| — | nicht verfügbar |\n'; fi
    printf '\n'

    # 4.3: config vs. runtime -- Appendix A F12 (no global IPv6 address) was not
    # checkable, and no table confirmed that every bridge declared in `vlans`
    # actually exists as a live link. `ip -br link` on this iproute2 build has no
    # master column despite the work order's expectation (widerlegte Annahme,
    # reported) -- master is joined in from a second, full `ip link show` pass.
    printf '### links\n\n| name | state | master |\n|---|---|---|\n'
    if [ -s "$WORK/router.links" ]; then
        awk -v mf="$WORK/router.links_master" '
          BEGIN{
            while((getline line < mf) > 0){
              if(match(line,/^[0-9]+: ([^:@]+(@[^:]+)?): /,m)) cur=m[1]
              if(match(line,/ master ([A-Za-z0-9_-]+)/,m) && cur!="") MASTER[cur]=m[1]
            }
            close(mf)
          }
          { nm=$1; st=$2; mst=(nm in MASTER)?MASTER[nm]:"—"
            printf "| %s | %s | %s |\n", nm, st, mst }
        ' "$WORK/router.links" | sort
    else
        printf '| — | nicht erfasst | — |\n'
    fi
    printf '\n'

    printf '### ipv6_global\n\n| interface | address |\n|---|---|\n'
    if [ -s "$WORK/router.ipv6_global" ]; then
        awk '{printf "| %s | %s |\n",$1,$3}' "$WORK/router.ipv6_global"
    else
        printf '| — | keine |\n'
    fi
    printf '\n'

    printf '### pbr_config\n\n| key | value |\n|---|---|\n'
    if [ -s "$WORK/router.pbr" ]; then
        awk '
          match($0,/^pbr\.([^=]+)=(.*)$/,m){
            k=m[1]; v=m[2]; gsub(/^'"'"'|'"'"'$/,"",v)
            if(k ~ /^config\.(enabled|strict_enforcement|uplink_interface|ipv6_enabled|resolver_set|verbosity)$/ || k ~ /=policy$/ || k ~ /^@policy/)
              print k"\t"v
          }' "$WORK/router.pbr" | sort | awk -F'\t' '{printf "| %s | %s |\n",$1,$2}'
        printf '| pbr_packages | %s |\n' "$(sort "$WORK/router.pbr_pkg" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
        printf '| ruleset_post_files | %s |\n' "$(sort "$WORK/router.pbr_nft" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
        # The declared objects rather than the file body: statedump.sh used to cat
        # 30-pbr.nft, but a raw dump is not normalisable. What an audit needs is
        # whether the marking machinery is actually installed.
        printf '| ruleset_post_chains | %s |\n' "$(sort -u "$WORK/router.pbr_nft_chains" 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')"
    else
        printf '| — | nicht verfügbar (pbr nicht installiert?) |\n'
    fi
    printf '\n'

    # 1.1: `pbr_config` above only ever matched `config.*` and the anonymous
    # `@policy[N]` array form -- a NAMED policy section (`pbr.private_local_bypass=policy`)
    # has k=m[1]="private_local_bypass", which contains no "=" at all, so the old
    # `k ~ /=policy$/` filter could never match it and the two live policies this
    # network actually runs on fell through silently. Read by SECTION instead of by
    # matching the filter inline, so both forms (named and `@policy[N]`) are covered
    # the same way. `pos` = the line's position in `uci show pbr`, since fw4/pbr
    # evaluates policies in declaration order and that order is what section 17's
    # claim (bypass before the VPN policy) depends on -- not derivable by sorting.
    printf '### pbr_policy_config\n\n| pos | section | name | src_addr | dest_addr | interface | enabled |\n|---|---|---|---|---|---|---|\n'
    if [ -s "$WORK/router.pbr" ]; then
        awk '
          match($0,/^pbr\.([^.=]+)=policy$/,m){
            sid=m[1]; if(!(sid in seen)){ seen[sid]=1; pos[sid]=NR; ord[n++]=sid }
            next
          }
          match($0,/^pbr\.([^.=]+)\.([A-Za-z_]+)=(.*)$/,m){
            sid=m[1]; k=m[2]; v=m[3]
            if(sid in seen){ gsub(/^'"'"'|'"'"'$/,"",v); V[sid,k]=v }
          }
          END{
            for(i=0;i<n;i++){
              sid=ord[i]
              nm=(V[sid,"name"]!=""?V[sid,"name"]:"—")
              sa=(V[sid,"src_addr"]!=""?V[sid,"src_addr"]:"—")
              da=(V[sid,"dest_addr"]!=""?V[sid,"dest_addr"]:"—")
              ifc=(V[sid,"interface"]!=""?V[sid,"interface"]:"—")
              en=(((sid,"enabled") in V) ? V[sid,"enabled"] : "(unset)")
              printf "| %s | %s | %s | %s | %s | %s | %s |\n", pos[sid], sid, nm, sa, da, ifc, en
            }
          }' "$WORK/router.pbr"
    else
        printf '| — | — | — | — | — | — | — |\n'
    fi
    printf '\n'

    # 1.2: `pbr_policies` below (kept as-is, see its own note) reads the static
    # ruleset-post SOURCE FILE and sorts it -- so it can show the right two
    # policies in the right-looking order purely because "private-local-bypass"
    # sorts before "private-via-proton" alphabetically. A swapped chain would print
    # identically. `pbr_chain` instead reads the COMPILED, LOADED chain in its
    # actual evaluation order, with the verdict (`return` vs `goto pbr_mark_...`)
    # that section 17's claim ("goto does not return") depends on. A parser that
    # cannot split a line still reports it, with verdict=? -- never silently drops it.
    printf '### pbr_chain [aus der geladenen Kette `pbr_prerouting`, `nft -s`]\n\n| pos | match | verdict | comment |\n|---|---|---|---|\n'
    if [ -s "$WORK/router.pbr_chain" ]; then
        awk '
          /^\t\t[a-z]/ {
            line=$0; sub(/^\t\t/,"",line)
            cmt="—"
            if(match(line,/comment "[^"]*"/)){
              cmt=substr(line,RSTART+9,RLENGTH-10)
              line=substr(line,1,RSTART-1) substr(line,RSTART+RLENGTH)
            }
            gsub(/[[:space:]]+$/,"",line)
            vd="?"; mt=line
            if(match(line,/(goto|jump) [A-Za-z0-9_]+[[:space:]]*$/)){
              vd=substr(line,RSTART,RLENGTH); gsub(/[[:space:]]+$/,"",vd)
              mt=substr(line,1,RSTART-1)
            } else if(match(line,/(accept|drop|return)[[:space:]]*$/)){
              vd=substr(line,RSTART,RLENGTH); gsub(/[[:space:]]+$/,"",vd)
              mt=substr(line,1,RSTART-1)
            }
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",mt)
            gsub(/[[:space:]]+/," ",mt)
            n++; printf "| %s | %s | %s | %s |\n", n, (mt==""?"—":mt), vd, cmt
          }
        ' "$WORK/router.pbr_chain"
    else
        printf '| — | nicht erfasst | — | — |\n'
    fi
    printf '\n'
    printf -- '> `pbr_chain` liest die geladene Kette, `pbr_policies` unten die statische\n'
    printf -- '> Quelldatei (sortiert, nicht Ketten-Reihenfolge) -- zwei verschiedene\n'
    printf -- '> Prüfwege, `pbr_chain` trägt die Reihenfolge und das Verdikt.\n\n'

    # The actual steering rule, which is the section-17 claim in one line: which
    # source prefix is marked for which table. statedump.sh only cat'ed the file.
    # KEPT AS-IS (sorted by source, not chain order) so old runs stay diffable;
    # `pbr_chain` above is the ordered, verdict-bearing replacement for that claim.
    printf '### pbr_policies [aus `30-pbr.nft`, generiert, sortiert -- keine Ketten-Reihenfolge]\n\n| marked source | policy comment |\n|---|---|\n'
    if [ -s "$WORK/router.pbr_nft_policies" ]; then
        awk '
          { src="-"; cmt="-"
            if(match($0,/\{[^}]*\}/)) { src=substr($0,RSTART+1,RLENGTH-2); gsub(/^[[:space:]]+|[[:space:]]+$/,"",src) }
            if(match($0,/comment "[^"]*"/)) { cmt=substr($0,RSTART+9,RLENGTH-9); gsub(/"/,"",cmt) }
            print src"\t"cmt }
        ' "$WORK/router.pbr_nft_policies" | sort -u | awk -F'\t' '{printf "| %s | %s |\n",$1,$2}'
    else
        printf '| — | keine Policy-Regel gefunden |\n'
    fi
    printf '\n'
    printf -- '> `30-pbr.nft` is GENERATED from `/etc/config/pbr`; it lives outside `/etc` and is\n'
    printf -- '> therefore NOT in `sysupgrade -b`. Neither are the `pbr` packages. After a\n'
    printf -- '> bare-metal restore, `private` has no egress until they are reinstalled — the\n'
    printf -- '> kill-switch working as designed, looking like a defect (doc section 15.1).\n\n'

    # 8.3: which init scripts are actually enabled, drift on the own scripts
    # crontab depends on but never shows directly, and whether the pbr-gap
    # claim in section 15.1 actually holds against the real backup archive.
    printf '### services_enabled\n\n| service |\n|---|\n'
    if [ -s "$WORK/router.services_enabled" ]; then
        sort -u "$WORK/router.services_enabled" | awk '{printf "| %s |\n",$0}'
    else
        printf '| — |\n'
    fi
    printf '\n'

    printf '### local_files\n\n| path | size | sha256_12 |\n|---|---|---|\n'
    if [ -s "$WORK/router.local_files" ]; then
        awk -F'|' '{printf "| %s | %s | %s |\n",$1,$2,$3}' "$WORK/router.local_files" | sort
    else
        printf '| — | | |\n'
    fi
    printf '\n'

    printf '### backup_scope\n\n| path |\n|---|\n'
    if [ -s "$WORK/router.backup_scope" ]; then
        awk '{printf "| %s |\n",$0}' "$WORK/router.backup_scope"
    else
        printf '| — |\n'
    fi
    printf '\n'
    if grep -qx '/etc/config/pbr' "$WORK/router.backup_scope" 2>/dev/null; then pbr_in=ja; else pbr_in=nein; fi
    if grep -q '30-pbr.nft' "$WORK/router.backup_scope" 2>/dev/null; then nft_in=ja; else nft_in=nein; fi
    printf '> `contains /etc/config/pbr`: %s -- `contains ruleset-post/30-pbr.nft`: %s\n\n' "$pbr_in" "$nft_in"

    # cron
    render_cron "$WORK/router.cron"
    printf '\n'

    if [ "$WANT_PACKAGES" = 1 ]; then
        printf '### packages\n\n'
        sort "$WORK/router.packages" 2>/dev/null | awk '{printf "- %s\n",$0}'
        printf '\n'
    fi
}

# firewall tables shared shape (router uses full set)
emit_fw() {   # $1 firewall-raw  $2 network-raw (unused placeholder)
    fwr="$1"
    # 2.2: masq/mtu_fix appended -- section 7's zone table and section 17 both
    # assert masquerading for wan/wgvpn and MTU clamping for wgvpn, previously
    # only checkable by reading raw uci. family/log checked live (P0 audit)
    # against every zone section and never occur there (only on rule/redirect
    # sections) -- not added as columns, would be "—" for all ten zones.
    printf '### fw_zones\n\n| zone | input | output | forward | networks | masq | mtu_fix |\n|---|---|---|---|---|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=zone/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1]; k=m[2]; v=m[3];
        if(sid in seen){ if(k=="network"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) } else gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
      }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(V[ids[j],"name"]<V[ids[i],"name"]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]
          mq=V[s,"masq"]; if(mq=="") mq="—"
          mf=V[s,"mtu_fix"]; if(mf=="") mf="—"
          printf "| %s | %s | %s | %s | %s | %s | %s |\n", V[s,"name"], V[s,"input"], V[s,"output"], V[s,"forward"], V[s,"network"], mq, mf }
      }' "$fwr"
    printf '\n'

    # 2.3: `config defaults` and `config include` were not read at all -- section 7
    # *Removed defaults* describes the zone-default policy but nothing confirmed it
    # against the live config. Emitted generically (whatever keys the section
    # actually carries), not a hardcoded field list, so it tracks the device
    # rather than a guess about which knobs are set.
    printf '### fw_defaults\n\n| key | value |\n|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=defaults/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1];k=m[2];v=m[3];
        if(sid in seen){ gsub(/^'"'"'|'"'"'$/,"",v); print k"\t"v }
      }' "$fwr" | sort | awk -F'\t' '{printf "| %s | %s |\n",$1,$2}' > "$WORK/fw_defaults.tmp"
    if [ -s "$WORK/fw_defaults.tmp" ]; then cat "$WORK/fw_defaults.tmp"; else printf '| — | keine |\n'; fi
    printf '\n'

    printf '### fw_includes\n\n| section | type | path | enabled |\n|---|---|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=include/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1];k=m[2];v=m[3];
        if(sid in seen){ gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
      }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(ids[j]<ids[i]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]; ty=V[s,"type"]; if(ty=="") ty="—"; en=V[s,"enabled"]; if(en=="") en="(unset)"
          printf "| %s | %s | %s | %s |\n", s, ty, V[s,"path"], en }
        if(n==0) print "| — | — | keine | — |"
      }' "$fwr"
    printf '\n'

    printf '### fw_forwardings\n\n| src | dest |\n|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=forwarding/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){ sid=m[1];k=m[2];v=m[3];gsub(/^'"'"'|'"'"'$/,"",v); if(sid in seen)V[sid SUBSEP k]=v }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) rows[i]=V[ids[i],"src"]"\t"V[ids[i],"dest"]
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(rows[j]<rows[i]){t=rows[i];rows[i]=rows[j];rows[j]=t}
        for(i=0;i<n;i++){ split(rows[i],a,"\t"); printf "| %s | %s |\n",a[1],a[2] } }' "$fwr"
    printf '\n'

    # C1: without this section the `src_ip` column is empty for every admin rule and the
    # inventory reads as if ANY private device reached the router and the switch. The
    # restriction lives in an ipset, which statedump.sh carried by dumping raw uci and the
    # move to normalised tables silently dropped. A privilege-narrowing control that is
    # invisible in the mirror is worse than one that is merely undocumented.
    printf '### fw_ipsets\n\n| name | family | match | entries | timeout | counters |\n|---|---|---|---|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=ipset/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1];k=m[2];v=m[3];
        if(sid in seen){ if(k=="entry"||k=="match"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) } else gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
      }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(V[ids[j],"name"]<V[ids[i],"name"]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i];
          nm=V[s,"name"]; if(nm=="") nm=s
          printf "| %s | %s | %s | %s | %s | %s |\n", nm,
            (V[s,"family"]==""?"ipv4 (default)":V[s,"family"]),
            (V[s,"match"]==""?"—":V[s,"match"]),
            (V[s,"entry"]==""?"—":V[s,"entry"]),
            (V[s,"timeout"]==""?"—":V[s,"timeout"]),
            (V[s,"counters"]==""?"—":V[s,"counters"]) }
        if(n==0) print "| — | — | — | — | — | — |"
      }' "$fwr"
    printf '\n'

    # 2.1: pos (declaration position -- fw4 emits in config order, and
    # firewall-rules.md needed a full hand re-check against the compiled chains on
    # 2026-09-18 for exactly this reason, section 7), family and icmp_type always
    # (section 7 *Address families*; the two ICMP echo admin rules), and the
    # list-normalisation now also covers src_mac/dest_ip/icmp_type -- previously
    # only proto/dest_port/src_ip got it, so a multi-value src_mac (IP+MAC-pinned
    # admin rules, Appendix A C4) kept its inner quotes verbatim
    # (`4C:1D:96:B7:87:9D' 'C0:7A:D6:35:B0:F7`). src_port/limit/limit_burst/extra
    # checked live against this router (P0 audit) and do not occur on any rule --
    # not added, per "only columns that occur".
    printf '### fw_rules\n\n| name | src | dest | src_ip | ipset | dest_ip | src_mac | proto | dest_port | target | enabled | log | pos | family | icmp_type |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=rule/,m){ sid=m[1]; seen[sid]=1; pos[sid]=NR; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1];k=m[2];v=m[3];
        if(sid in seen){
          if(k=="proto"||k=="dest_port"||k=="src_ip"||k=="src_mac"||k=="dest_ip"||k=="icmp_type"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) }
          else gsub(/^'"'"'|'"'"'$/,"",v)
          V[sid SUBSEP k]=v
        }
      }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(V[ids[j],"name"]<V[ids[i],"name"]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]; en=V[s,"enabled"]; if(en=="")en="(unset)"; lg=V[s,"log"]; if(lg=="")lg="0";
          # An ipset here IS the effective source restriction, even with src_ip empty.
          ips=V[s,"ipset"]; if(ips=="") ips="—"
          fam=V[s,"family"]; if(fam=="") fam="—"
          it=V[s,"icmp_type"]; if(it=="") it="—"
          printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
            V[s,"name"],V[s,"src"],V[s,"dest"],V[s,"src_ip"],ips,V[s,"dest_ip"],V[s,"src_mac"],V[s,"proto"],V[s,"dest_port"],V[s,"target"],en,lg,pos[s],fam,it }
      }' "$fwr"
    printf '\n'

    # 2.1: same section data, sorted by src zone then declaration position, so a
    # zone's rules read in the order fw4 actually compiles them -- the zone tables
    # in firewall-rules.md/network-documentation.md can be checked against this
    # directly, without re-sorting by hand.
    printf '### fw_rules_by_zone\n\n| pos | name |\n|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=rule/,m){ sid=m[1]; seen[sid]=1; pos[sid]=NR; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1];k=m[2];v=m[3];
        if(sid in seen && (k=="src"||k=="name")){ gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
      }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) rows[i]=V[ids[i],"src"]"\t"sprintf("%06d",pos[ids[i]])"\t"pos[ids[i]]"\t"V[ids[i],"name"]
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(rows[j]<rows[i]){t=rows[i];rows[i]=rows[j];rows[j]=t}
        for(i=0;i<n;i++){ split(rows[i],a,"\t"); printf "| %s | %s |\n",a[3],a[4] }
      }' "$fwr"
    printf '\n'

    # 2.4: proto/dest/src_ip/family/enabled/pos appended -- previously only half
    # of Appendix A B1/B2 (the DNS/NTP DNAT redirects) was checkable, since the
    # protocol and destination zone weren't in the table at all.
    printf '### fw_redirects\n\n| name | src | src_dport | dest_ip | dest_port | target | proto | dest | src_ip | family | enabled | pos |\n|---|---|---|---|---|---|---|---|---|---|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=redirect/,m){ sid=m[1]; seen[sid]=1; pos[sid]=NR; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){
        sid=m[1];k=m[2];v=m[3];
        if(sid in seen){
          if(k=="proto"||k=="src_ip"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) }
          else gsub(/^'"'"'|'"'"'$/,"",v)
          V[sid SUBSEP k]=v
        }
      }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(V[ids[j],"name"]<V[ids[i],"name"]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]
          pr=V[s,"proto"]; if(pr=="") pr="—"
          ds=V[s,"dest"]; if(ds=="") ds="—"
          si=V[s,"src_ip"]; if(si=="") si="—"
          fa=V[s,"family"]; if(fa=="") fa="—"
          en=V[s,"enabled"]; if(en=="") en="(unset)"
          printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",V[s,"name"],V[s,"src"],V[s,"src_dport"],V[s,"dest_ip"],V[s,"dest_port"],V[s,"target"],pr,ds,si,fa,en,pos[s] }
      }' "$fwr"
    printf '\n'

    # 3.1: everything above is the UCI layer; Appendix A checks the COMPILED
    # ruleset at several rows (B1, B4, B6, B7, B7b-d, C7, D1, E4) -- the UCI `pos`
    # column is a proxy for that, not an observation of it. Excludes pbr_* chains
    # (covered by pbr_chain, group 1). `match`/`verdict` split at the LAST
    # recognised verdict keyword before an optional `comment "..."`; a line this
    # cannot split (e.g. `ct state vmap {...}`, which has no trailing bare verdict
    # at all) is emitted VERBATIM with verdict=? rather than silently dropped or
    # mis-split -- that is the point of doing this per-line instead of assuming a
    # fixed grammar.
    fwn="$WORK/router.fw_nft_table"
    : > "$WORK/fw_chains.tsv"
    if [ -s "$fwn" ]; then
        awk '
          /^\tchain [A-Za-z0-9_]+ \{/ { chain=$2; skip=(chain ~ /^pbr_/); rpos=0; next }
          /^\t\}[[:space:]]*$/ { next }
          skip { next }
          /^\t\t/ {
            line=$0; sub(/^\t\t/,"",line)
            if(line=="") next
            cmt="—"
            if(match(line,/comment "[^"]*"/)){
              cmt=substr(line,RSTART+9,RLENGTH-10)
              line=substr(line,1,RSTART-1)
            }
            gsub(/[[:space:]]+$/,"",line)
            vd="?"; mt=line
            if(match(line,/reject with .*$/)){
              vd=substr(line,RSTART,RLENGTH); gsub(/[[:space:]]+$/,"",vd); mt=substr(line,1,RSTART-1)
            } else if(match(line,/dnat (ip |ip6 )?to [^ ]+[[:space:]]*$/)){
              vd=substr(line,RSTART,RLENGTH); gsub(/[[:space:]]+$/,"",vd); mt=substr(line,1,RSTART-1)
            } else if(match(line,/(goto|jump) [A-Za-z0-9_]+[[:space:]]*$/)){
              vd=substr(line,RSTART,RLENGTH); gsub(/[[:space:]]+$/,"",vd); mt=substr(line,1,RSTART-1)
            } else if(match(line,/(accept|drop|return|reject)[[:space:]]*$/)){
              vd=substr(line,RSTART,RLENGTH); gsub(/[[:space:]]+$/,"",vd); mt=substr(line,1,RSTART-1)
            }
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",mt); gsub(/[[:space:]]+/," ",mt)
            rpos++
            print chain"\t"rpos"\t"(mt==""?"—":mt)"\t"vd"\t"cmt
          }
        ' "$fwn" | sort -t "$(printf '\t')" -k1,1 -s > "$WORK/fw_chains.tsv"
    fi
    printf '### fw_chains [aus der geladenen `nft -s list table inet fw4`, ohne `pbr_*`]\n\n| chain | pos | match | verdict | comment |\n|---|---|---|---|---|\n'
    if [ -s "$WORK/fw_chains.tsv" ]; then
        awk -F'\t' '{printf "| %s | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5}' "$WORK/fw_chains.tsv"
    else
        printf '| — | — | nicht erfasst | — | — |\n'
    fi
    printf '\n'

    # Cross-check: every UCI rule/redirect name should appear as a `!fw4: <name>`
    # comment somewhere in the compiled chains, and (the noisier direction) any
    # chain comment that LOOKS like one of this repo's own rule names
    # (Capitalised-with-a-hyphen, matching the Allow-/Block-/Redirect-/Silent-
    # convention) but has no UCI counterpart is worth a second look. fw4's own
    # generated comments ("Handle private IPv4/IPv6 input traffic", "accept
    # private IPv4/IPv6 traffic", ...) never match that shape, so they are not
    # false positives here -- the two directions stay separate because a full
    # comment<->name diff would otherwise be almost entirely fw4 boilerplate.
    printf '### fw_uci_nft_orphans\n\n| direction | name |\n|---|---|\n'
    awk -v chains="$WORK/fw_chains.tsv" '
      match($0,/^firewall\.([^.=]+)=(rule|redirect)/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^firewall\.([^.]+)\.name=(.*)$/,m){
        sid=m[1]; v=m[2]; gsub(/^'"'"'|'"'"'$/,"",v)
        if(sid in seen && v!="") KNOWN[v]=1
      }
      END{
        while((getline line < chains) > 0){
          n=split(line,a,"\t"); cmt=a[5]
          if(cmt=="—") continue
          sub(/^!fw4: /,"",cmt)   # fw4 prefixes every UCI-derived comment this way
          SEEN[cmt]=1
        }
        close(chains)
        any=0
        for(k in KNOWN) if(!(k in SEEN)){ print "uci_ohne_kette\t"k; any=1 }
        for(k in SEEN) if(!(k in KNOWN) && k ~ /^[A-Z][A-Za-z0-9_]*-[A-Za-z0-9_-]+$/){ print "kette_ohne_uci\t"k; any=1 }
      }' "$fwr" | sort | awk -F'\t' '{printf "| %s | %s |\n",$1,$2}' > "$WORK/fw_orphans.tmp"
    if [ -s "$WORK/fw_orphans.tmp" ]; then cat "$WORK/fw_orphans.tmp"; else printf '| — | keine |\n'; fi
    printf '\n'
}

emit_dhcp() {   # $1 dhcp-raw
    dr="$1"
    # 6.1a: dnsmasq's own section was never read at all -- section 9's claim that
    # dnsmasq does DHCP only (`port='0'`, DNS fully handed to AdGuard) was not
    # checkable.
    printf '### dnsmasq\n\n| key | value |\n|---|---|\n'
    awk '
      match($0,/^dhcp\.(@dnsmasq\[[0-9]+\])=dnsmasq/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^dhcp\.(@dnsmasq\[[0-9]+\])\.([A-Za-z_]+)=(.*)$/,m){
        sid=m[1]; k=m[2]; v=m[3]
        allow = (k=="port"||k=="domain"||k=="local"||k=="rebind_protection"||k=="noresolv"||k=="localservice"||k=="logqueries"||k=="interface"||k=="notinterface")
        if((sid in seen) && allow){ gsub(/^'"'"'|'"'"'$/,"",v); print k"\t"v }
      }' "$dr" | sort > "$WORK/dnsmasq.tmp"
    if [ -s "$WORK/dnsmasq.tmp" ]; then
        awk -F'\t' '{printf "| %s | %s |\n",$1,$2}' "$WORK/dnsmasq.tmp"
    else
        printf '| — | keine |\n'
    fi
    printf '\n'

    # 6.1b: force/ignore/dhcpv4/dhcpv6/ra appended -- section 8 asserts `kids`
    # alone carries `force='1'`; `ignore` was already folded into the leasetime
    # column as a "(ignore)" suffix (kept, for diffability against old runs) but
    # not exposed as its own field.
    printf '### dhcp_pools\n\n| interface | start | limit | leasetime | dhcp_options | force | ignore | dhcpv4 | dhcpv6 | ra |\n|---|---|---|---|---|---|---|---|---|---|\n'
    awk '
      match($0,/^dhcp\.([^.=]+)=dhcp/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^dhcp\.([^.]+)\.([^=]+)=(.*)$/,m){ sid=m[1];k=m[2];v=m[3];
        if(sid in seen){ if(k=="dhcp_option"){ gsub(/'"'"'/,"",v); gsub(/ +/," ",v) } else gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
      }
      # F4: normalise the option list. The zones were written at different times, so
      # smarthome carries "42,... 6,..." and the others "6,... 42,...". Same config,
      # different text -- which shows up as a diff between two runs that changed
      # nothing. Strip the space after the comma and sort by option number.
      function norm_opts(s,   a,n,i,j,t) {
        gsub(/,[[:space:]]+/, ",", s)
        n=split(s, a, /[[:space:]]+/)
        for(i=1;i<=n;i++) for(j=i+1;j<=n;j++){
          if((a[j]+0) < (a[i]+0)){ t=a[i]; a[i]=a[j]; a[j]=t }
        }
        s=a[1]; for(i=2;i<=n;i++) s=s" "a[i]
        return s
      }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(V[ids[j],"interface"]<V[ids[i],"interface"]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]; ign=V[s,"ignore"]; lt=V[s,"leasetime"]; if(ign=="1")lt=lt" (ignore)"
          fo=V[s,"force"]; if(fo=="") fo="0"
          ig2=ign; if(ig2=="") ig2="0"
          d4=V[s,"dhcpv4"]; if(d4=="") d4="—"
          d6=V[s,"dhcpv6"]; if(d6=="") d6="—"
          ra=V[s,"ra"]; if(ra=="") ra="—"
          printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",V[s,"interface"],V[s,"start"],V[s,"limit"],lt,norm_opts(V[s,"dhcp_option"]),fo,ig2,d4,d6,ra }
      }' "$dr"
    printf '\n'

    # 6.1c: `tag`-scoped sections were not surfaced at all -- Appendix A E8 claims
    # there is none, which was an assertion, not a checked fact. Generic per-type
    # count, not hardcoded to a "dhcp/host/tag" list, so a section type this
    # config doesn't currently use (e.g. `boot`) still shows up if it appears.
    printf '### dhcp_sections\n\n| type | count |\n|---|---|\n'
    awk -F= '
      /^dhcp\.[^.]+=[A-Za-z_]+$/{ ty=$2; C[ty]++ }
      END{ n=0; for(t in C) ids[n++]=t
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(ids[j]<ids[i]){t2=ids[i];ids[i]=ids[j];ids[j]=t2}
        for(i=0;i<n;i++){ t=ids[i]; printf "| %s | %s |\n",t,C[t] }
        if(n==0) print "| — | 0 |"
      }' "$dr"
    printf '\n'

    printf '### dhcp_reservations\n\n| ip | mac | name | tag |\n|---|---|---|---|\n'
    awk '
      match($0,/^dhcp\.([^.=]+)=host/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^dhcp\.([^.]+)\.([^=]+)=(.*)$/,m){ sid=m[1];k=m[2];v=m[3];gsub(/^'"'"'|'"'"'$/,"",v); if(sid in seen)V[sid SUBSEP k]=v }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) rows[i]=V[ids[i],"ip"]"\t"V[ids[i],"mac"]"\t"V[ids[i],"name"]"\t"V[ids[i],"tag"]
        # sort by ip numerically
        for(i=0;i<n;i++){ split(rows[i],a,"\t"); split(a[1],o,"."); key[i]=sprintf("%03d%03d%03d%03d",o[1],o[2],o[3],o[4]) }
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(key[j]<key[i]){t=rows[i];rows[i]=rows[j];rows[j]=t; t2=key[i];key[i]=key[j];key[j]=t2}
        for(i=0;i<n;i++){ split(rows[i],a,"\t"); tg=a[4]; if(tg=="")tg="(none)"; printf "| %s | %s | %s | %s |\n",a[1],a[2],a[3],tg }
      }' "$dr"
    printf '\n'
}

emit_cert() {   # $1 host:port  — runs openssl on the WORKSTATION
    hp="$1"
    out=$(echo | openssl s_client -connect "$hp" 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null)
    if [ -z "$out" ]; then printf '| %s | — nicht erreichbar — | | | | |\n' "$hp"; return; fi
    subj=$(printf '%s\n' "$out" | sed -n 's/^subject=//p' | tr -d '|')
    iss=$(printf '%s\n' "$out"  | sed -n 's/^issuer=//p'  | tr -d '|')
    nb=$(printf '%s\n' "$out"   | sed -n 's/^notBefore=//p')
    na=$(printf '%s\n' "$out"   | sed -n 's/^notAfter=//p')
    san=$(printf '%s\n' "$out"  | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^ *//' | tr -d '|')
    printf '| %s | %s | %s | %s | %s | %s |\n' "$hp" "$subj" "$iss" "$nb" "$na" "$san"
}

# ===========================================================================
# COMPONENT 2 — Spitz Plus
# ===========================================================================
collect_spitz() {
    $SSH "$UPLINK" 'sh -s' > "$WORK/spitz.raw" 2>/dev/null <<'SEOF'
echo "@@@ identity"
echo "GLVERSION=$(cat /etc/glversion 2>/dev/null)"
. /etc/openwrt_release 2>/dev/null
echo "RELEASE=$DISTRIB_RELEASE"
echo "DESC=$DISTRIB_DESCRIPTION"
echo "MODEL=$(cat /tmp/sysinfo/model 2>/dev/null)"
echo "@@@ dropbear"
ps w 2>/dev/null | grep '[d]ropbear -F' | head -1
echo "@@@ wireless"
uci -q show wireless
echo "@@@ firewall"
uci -q show firewall
echo "@@@ netstat"
netstat -tulnp 2>/dev/null
echo "@@@ uplink"
/root/modemctl.sh status 2>/dev/null
echo "@@@ route"
ip route show default 2>/dev/null
echo "@@@ cron"
crontab -l 2>/dev/null
echo "@@@ dhcp"
uci -q show dhcp
echo "@@@ links"
ip -br link 2>/dev/null
echo "@@@ services_enabled"
for f in /etc/rc.d/S*; do
    [ -e "$f" ] || continue
    n=$(basename "$f")
    echo "${n#S[0-9][0-9]}"
done
echo "@@@ local_files"
for f in /root/modemctl.sh; do
    [ -f "$f" ] || continue
    sz=$(wc -c < "$f" 2>/dev/null)
    h=$(sha256sum "$f" 2>/dev/null | awk '{print substr($1,1,12)}')
    echo "$f|$sz|$h"
done
SEOF
    [ -s "$WORK/spitz.raw" ] && grep -q '@@@ identity' "$WORK/spitz.raw"
}

emit_spitz() {
    hdr="## Spitz Plus (GL-X2000) — $UPLINK"
    if [ -n "$1" ]; then printf '%s  \n**⚠ nicht erreichbar (%s)** — Inventar unvollständig.\n\n' "$hdr" "$1"; return; fi
    printf '%s\n\n' "$hdr"
    split_raw "$WORK/spitz.raw" "$WORK/spitz"

    printf '### identitaet\n\n| key | value |\n|---|---|\n'
    awk -F= '/^GLVERSION=/{g=$2}/^DESC=/{d=$2}/^MODEL=/{mo=$2}
      END{ sub(/ +$/,"",d); printf "| gl_version | %s |\n| openwrt_base | %s |\n| model | %s |\n", g, d, mo }' "$WORK/spitz.identity"
    printf '\n'

    printf '### dropbear\n\n| key | value |\n|---|---|\n'
    awk '{ ko=($0 ~ / -s( |$)/)?"true":"false"; rp=($0 ~ / -g( |$)/)?"true":"false";
           p="-"; if(match($0,/ -p ([0-9]+)/,m)) p=m[1];
           printf "| key_only | %s |\n| root_pw_disabled | %s |\n| listen_port | %s |\n", ko, rp, p }' "$WORK/spitz.dropbear"
    printf '\n'

    printf '### radios\n\n| radio | disabled |\n|---|---|\n'
    awk '
      match($0,/^wireless\.([^.=]+)=wifi-device/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^wireless\.([^.]+)\.disabled=(.*)$/,m){ sid=m[1];v=m[2];gsub(/^'"'"'|'"'"'$/,"",v); if(sid in seen)D[sid]=v }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(ids[j]<ids[i]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]; d=D[s]; if(d=="")d="0"; printf "| %s | %s |\n",s,d } }' "$WORK/spitz.wireless"
    printf '\n'

    printf '### fw_zones\n\n| zone | input | forward | networks |\n|---|---|---|---|\n'
    awk '
      match($0,/^firewall\.([^.=]+)=zone/,m){ sid=m[1]; seen[sid]=1; next }
      match($0,/^firewall\.([^.]+)\.([^=]+)=(.*)$/,m){ sid=m[1];k=m[2];v=m[3];
        if(sid in seen){ if(k=="network"){ gsub(/'"'"'/,"",v); gsub(/ +/,",",v) } else gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v } }
      END{ n=0; for(s in seen) ids[n++]=s
        for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(V[ids[j],"name"]<V[ids[i],"name"]){t=ids[i];ids[i]=ids[j];ids[j]=t}
        for(i=0;i<n;i++){ s=ids[i]; printf "| %s | %s | %s | %s |\n",V[s,"name"],V[s,"input"],V[s,"forward"],V[s,"network"] } }' "$WORK/spitz.firewall"
    printf '\n'

    # 9.1: `class` distinguishes lan/loopback/carrier bindings; a carrier-class
    # address is replaced with a placeholder because it is CGNAT-assigned and
    # changes on its own, which would otherwise produce a diff with no
    # configuration change behind it. `process` comes from -p, confirmed
    # supported by this busybox netstat build.
    printf '### listening\n\n| proto | address:port | process | class |\n|---|---|---|---|\n'
    awk '
      $1 ~ /^(tcp|udp)/ {
        proto=$1; la=$4; prog=$NF;
        sub(/^[0-9]+\//,"",prog);
        if(prog ~ /^[0-9-]+$/) prog="-";
        port=la; sub(/^.*:/,"",port);
        if(proto ~ /^udp/ && prog=="-" && port+0 >= 32768) next;
        addr=la; sub(/:[0-9]+$/,"",addr);
        if(addr=="192.168.8.1" || addr=="0.0.0.0" || addr=="::" || addr=="[::]") cls="lan";
        else if(addr=="127.0.0.1" || addr=="::1" || addr=="[::1]") cls="loopback";
        else cls="carrier";
        disp=la;
        if(cls=="carrier"){ if(la ~ /^\[?fe80:/) disp="<wwan-ll>:"port; else disp="<wwan>:"port }
        key=proto"|"disp"|"prog; if(!(key in s)){ s[key]=1; print proto"\t"disp"\t"prog"\t"cls }
      }' "$WORK/spitz.netstat" | sort -t'	' -k2 | awk -F'\t' '{printf "| %s | %s | %s | %s |\n",$1,$2,$3,$4}'
    printf '\n'

    printf '### uplink\n\n| key | value |\n|---|---|\n'
    if [ -s "$WORK/spitz.uplink" ]; then
        ms=$(grep -E '^Radio:' "$WORK/spitz.uplink" | head -1 | sed 's/^Radio: //')
        [ -n "$ms" ] && printf '| modem_state | %s |\n' "$ms" || printf '| modem_state | — nicht ausgelesen — |\n'
    else printf '| — | nicht verfügbar (modemctl.sh) |\n'; fi
    # The uplink device name comes from the DEFAULT ROUTE, not from modemctl's text
    # output -- that output never contains one, which is why this read
    # "— nicht ausgelesen (Radio evtl. aus) —" in v1.0.0 regardless of radio state.
    # The next hop is carrier-assigned and volatile, so only the device is reported.
    iface=$(awk '/^default /{ for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit} }' "$WORK/spitz.route" 2>/dev/null)
    if [ -n "$iface" ]; then printf '| uplink_device | %s |\n' "$iface"
    else printf '| uplink_device | — keine Default-Route (offline) — |\n'; fi
    printf '\n'

    # F3: the doc names four internal-CA services, two of them here. Without these
    # rows that claim is unbacked by the inventory.
    printf '### tls_certs\n\n| endpoint | subject | issuer | not_before | not_after | san |\n|---|---|---|---|---|---|\n'
    for hp in 192.168.8.1:443 192.168.8.1:8443; do emit_cert "$hp"; done
    printf '\n'

    # 9.2: pool size, reservations (MACs allowed -- inventory is not sanitized),
    # which services are actually enabled, and whether the radios are admin-down
    # as section 3 claims -- none of this was checked against the live device.
    printf '### dhcp_pool\n\n| interface | start | limit | leasetime | ignore |\n|---|---|---|---|---|\n'
    if [ -s "$WORK/spitz.dhcp" ]; then
        awk '
          match($0,/^dhcp\.([^.=]+)=dhcp/,m){ sid=m[1]; seen[sid]=1; next }
          match($0,/^dhcp\.([^.]+)\.([^=]+)=(.*)$/,m){
            sid=m[1]; k=m[2]; v=m[3]
            if(sid in seen){ gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
          }
          END{
            n=0; for(s in seen) ids[n++]=s
            for(i=0;i<n;i++) for(j=i+1;j<n;j++) if(ids[j]<ids[i]){t=ids[i];ids[i]=ids[j];ids[j]=t}
            for(i=0;i<n;i++){ s=ids[i]
              printf "| %s | %s | %s | %s | %s |\n", s,
                ((s SUBSEP "start") in V?V[s SUBSEP "start"]:"(unset)"),
                ((s SUBSEP "limit") in V?V[s SUBSEP "limit"]:"(unset)"),
                ((s SUBSEP "leasetime") in V?V[s SUBSEP "leasetime"]:"(unset)"),
                ((s SUBSEP "ignore") in V?V[s SUBSEP "ignore"]:"0")
            }
          }' "$WORK/spitz.dhcp"
    else
        printf '| — | | | | |\n'
    fi
    printf '\n'

    printf '### dhcp_reservations\n\n| mac | ip | tag |\n|---|---|---|\n'
    if [ -s "$WORK/spitz.dhcp" ]; then
        awk '
          match($0,/^dhcp\.(@host\[[0-9]+\])=host/,m){ sid=m[1]; seen[sid]=1; next }
          match($0,/^dhcp\.(@host\[[0-9]+\])\.([^=]+)=(.*)$/,m){
            sid=m[1]; k=m[2]; v=m[3]
            if(sid in seen){ gsub(/^'"'"'|'"'"'$/,"",v); V[sid SUBSEP k]=v }
          }
          END{
            for(s in seen){
              printf "| %s | %s | %s |\n",
                ((s SUBSEP "mac") in V?V[s SUBSEP "mac"]:"(unset)"),
                ((s SUBSEP "ip") in V?V[s SUBSEP "ip"]:"(unset)"),
                ((s SUBSEP "tag") in V?V[s SUBSEP "tag"]:"-")
            }
          }' "$WORK/spitz.dhcp" | sort
    fi
    printf '\n'

    printf '### services_enabled\n\n| service |\n|---|\n'
    if [ -s "$WORK/spitz.services_enabled" ]; then
        sort -u "$WORK/spitz.services_enabled" | awk '{printf "| %s |\n",$0}'
    else
        printf '| — |\n'
    fi
    printf '\n'

    # radio_links: UCI wifi-device section names on this platform ARE the
    # kernel interface names (wifi0/wifi1) -- no separate name mapping needed.
    printf '### radio_links\n\n| name | state |\n|---|---|\n'
    if [ -s "$WORK/spitz.wireless" ] && [ -s "$WORK/spitz.links" ]; then
        awk '
          match($0,/^wireless\.([^.=]+)=wifi-device/,m){ print m[1] }
        ' "$WORK/spitz.wireless" | sort -u > "$WORK/spitz.radios.tmp"
        awk 'NR==FNR{want[$1]=1;next} { name=$1; if(name in want){ printf "%s\t%s\n",name,$2 } }' \
          "$WORK/spitz.radios.tmp" "$WORK/spitz.links" | sort
    fi | awk -F'\t' '{printf "| %s | %s |\n",$1,$2}'
    printf '\n'

    printf '### local_files\n\n| path | size | sha256_12 |\n|---|---|---|\n'
    if [ -s "$WORK/spitz.local_files" ]; then
        awk -F'|' '{printf "| %s | %s | %s |\n",$1,$2,$3}' "$WORK/spitz.local_files"
    else
        printf '| — | | |\n'
    fi
    printf '\n'

    render_cron "$WORK/spitz.cron"
    printf '\n'
}

# ===========================================================================
# COMPONENT 3 — Home Assistant / HAOS
# ===========================================================================
collect_haos() {
    $SSH "$HAOS" 'sh -s' > "$WORK/haos.raw" 2>/dev/null <<'HEOF'
# The add-on's login user is not root since 2026-10-17; `ha` needs the Supervisor token,
# which only root can read from the s6 container environment. The token never leaves
# the hub session and is not printed. As root (older setups) `ha` works directly.
ha() { if [ "$(id -u)" != 0 ]; then sudo -n sh -c 'SUPERVISOR_TOKEN=$(cat /run/s6/container_environment/SUPERVISOR_TOKEN 2>/dev/null) ha "$@"' _ "$@"; else command ha "$@"; fi; }
echo "@@@ core";       ha core info --raw-json 2>/dev/null; echo
echo "@@@ os";         ha os info --raw-json 2>/dev/null; echo
echo "@@@ supervisor"; ha supervisor info --raw-json 2>/dev/null; echo
echo "@@@ host";       ha host info --raw-json 2>/dev/null; echo
echo "@@@ network";    ha network info --raw-json 2>/dev/null; echo
echo "@@@ addons";     ha addons --raw-json 2>/dev/null; echo
echo "@@@ backups";    ha backups --raw-json 2>/dev/null; echo
echo "@@@ dns";        ha dns info --raw-json 2>/dev/null; echo
HEOF
    [ -s "$WORK/haos.raw" ] && grep -q '@@@ core' "$WORK/haos.raw"
}

jqr() { jq -S "$@" 2>/dev/null; }   # normalised

emit_haos() {
    hdr="## Home Assistant / HAOS — $HAOS"
    if [ -n "$1" ]; then printf '%s  \n**⚠ nicht erreichbar (%s)** — Inventar unvollständig.\n\n' "$hdr" "$1"; return; fi
    printf '%s\n\n' "$hdr"
    split_raw "$WORK/haos.raw" "$WORK/haos"

    printf '### versions\n\n| component | version |\n|---|---|\n'
    cv=$(jqr -r '.data.version // .version // empty' "$WORK/haos.core")
    ov=$(jqr -r '.data.version // .version // empty' "$WORK/haos.os")
    sv=$(jqr -r '.data.version // .version // empty' "$WORK/haos.supervisor")
    printf '| core | %s |\n| os | %s |\n| supervisor | %s |\n' "$cv" "$ov" "$sv"
    printf '\n'

    printf '### host\n\n| key | value |\n|---|---|\n'
    board=$(jqr -r '.data.board // empty' "$WORK/haos.os")
    dep=$(jqr -r '.data.deployment // empty' "$WORK/haos.host")
    dt=$(jqr -r '.data.disk_total // empty' "$WORK/haos.host")
    printf '| board | %s |\n| deployment | %s |\n| disk_total | %s GB |\n' "$board" "$dep" "$dt"
    printf '\n'

    printf '### network\n\n| interface | ipv4_address | dns_servers |\n|---|---|---|\n'
    jqr -r '.data.interfaces[]? | [ (.interface // "-"), ((.ipv4.address // []) | join(",")), ((.ipv4.nameservers // .ipv4.gateway // [] ) | if type=="array" then join(",") else tostring end) ] | @tsv' "$WORK/haos.network" 2>/dev/null \
      | sort | awk -F'\t' '{printf "| %s | %s | %s |\n",$1,$2,$3}'
    printf '\n'

    printf '### addons\n\n| slug | name | version |\n|---|---|---|\n'
    jqr -r '.data.addons[]? | [ (.slug // "-"), (.name // "-"), (.version // "-") ] | @tsv' "$WORK/haos.addons" 2>/dev/null \
      | sort | awk -F'\t' '{printf "| %s | %s | %s |\n",$1,$2,$3}'
    printf '\n'

    printf '### backups\n\n| name | date | size | type |\n|---|---|---|---|\n'
    jqr -r '.data.backups[]? | [ (.name // .slug // "-"), (.date // "-"), ((.size // "-")|tostring), (.type // "-") ] | @tsv' "$WORK/haos.backups" 2>/dev/null \
      | sort | awk -F'\t' '{printf "| %s | %s | %s | %s |\n",$1,$2,$3,$4}'
    printf '\n'

    printf '> Integrationen/Config-Entries bewusst nicht in v1 (nicht zuverlässig read-only per CLI) — offener Punkt.\n\n'

    # 10.1: section 16.2 asserts fallback/locals/servers but nothing read them.
    printf '### dns_resolver\n\n| key | value |\n|---|---|\n'
    fb=$(jqr -r '.data.fallback | if . == null then empty else tostring end' "$WORK/haos.dns")
    lo=$(jqr -r '(.data.locals // []) | join(",")' "$WORK/haos.dns")
    sv=$(jqr -r '(.data.servers // []) | join(",")' "$WORK/haos.dns")
    printf '| fallback | %s |\n| locals | %s |\n| servers | %s |\n' "$fb" "${lo:-(keine)}" "${sv:-(keine)}"
    printf '\n'
}

# ===========================================================================
# COMPONENT 4 — NETGEAR GS108Tv3 managed switch
# ===========================================================================
# Two sources, in order: an export file (SWITCH_CONFIG) or SSH. The device has
# no public-key auth, so BatchMode SSH only works if a key is ever installed --
# until then SWITCH_CONFIG is the real path.
#
# On "no source at all" this does NOT set EXITCODE=1, and that is deliberate.
# The fail-loud invariant exists so a shortened inventory is never mistaken for a
# complete one -- which is satisfied by emitting a loudly marked gap in the body
# AND in the head. Exiting non-zero on every ordinary run would instead train the
# operator to ignore the exit code, which is the opposite of fail-loud. Exit 1 is
# reserved for a source that was configured and then failed.
collect_switch() {
    if [ -n "$SWITCH_CONFIG" ]; then
        if [ -r "$SWITCH_CONFIG" ]; then
            cat "$SWITCH_CONFIG" > "$WORK/switch.raw" 2>/dev/null
        else
            SWUNREACH="SWITCH_CONFIG=$SWITCH_CONFIG nicht lesbar"; return 1
        fi
    elif [ "$SWITCH_SSH" = 1 ]; then
        # ONE CONNECTION PER COMMAND, but only ONE password prompt.
        #
        # Why one connection per command: this CLI accepts exactly one. Everything
        # cheaper was tried against the device and failed, each differently --
        #   * all four down one pipe with sleeps: the CLI drops input arriving while it
        #     is still writing, so each command needs more time than the PREVIOUS output
        #     takes. That is a guess about output length, and it shifts whenever a port
        #     or VLAN is added. Tuned for the config, it swallowed the query behind it.
        #   * reordered so the long output goes last: same failure, one position along.
        #   * one ControlMaster with four sessions over it: switch section came back
        #     empty -- the embedded server appears to allow a single session channel.
        #
        # Why only one prompt: `ssh` cannot read a password from a file, but it will run
        # an SSH_ASKPASS helper and take that helper's stdout. So the password is asked
        # for once, here, on the terminal with echo off, kept in a 0600 file inside the
        # work directory that is already removed on exit, and handed to each of the four
        # calls through a three-line helper. It never reaches argv and never reaches the
        # environment -- only the helper's PATH does. This also stops `timeout` from
        # racing the operator's typing, which four separate prompts would have caused.
        [ -r /dev/tty ] || { SWUNREACH="kein Terminal für die Passwort-Eingabe"; return 1; }
        SWPWF="$WORK/sw.pw"; SWASK="$WORK/sw.askpass"
        ( umask 077; : > "$SWPWF"; : > "$SWASK" )
        printf '\n>>> Passwort für %s (einmalig, für 5 Abfragen): ' "$SWITCH" >&2
        stty -echo 2>/dev/null
        IFS= read -r _swpw < /dev/tty
        stty echo 2>/dev/null
        printf '\n' >&2
        printf '%s\n' "$_swpw" > "$SWPWF"; _swpw=
        [ -s "$SWPWF" ] || { SWUNREACH="kein Passwort eingegeben"; return 1; }
        printf '#!/bin/sh\ncat %s\n' "$SWPWF" > "$SWASK"; chmod 700 "$SWASK"

        : > "$WORK/switch.raw"
        # 11.2 (work order 001) found that this device enforces its own connection-rate
        # limit ("Over maximum cli session !!! Do not allow new session !!!") that a
        # too-fast sequence of otherwise-independent connections can trip -- most likely
        # the same root cause behind occasional missing sections seen even at four
        # connections before this group. A fixed cooldown BETWEEN every connection (not
        # just before the newly added fifth) is cheaper than retrying and stays within
        # "one connection per command, never probe the device."
        SW_COOLDOWN=10
        _sw_q() {   # $1 = seconds, $2 = label, $3 = command
            [ -s "$WORK/switch.raw" ] && sleep "$SW_COOLDOWN"
            printf '    ... %s\n' "$2" >&2
            printf '%s\n' "$3" \
              | env SSH_ASKPASS="$SWASK" SSH_ASKPASS_REQUIRE=force \
                    timeout "$1" $SSH_SW "$SWITCH" \
                    >> "$WORK/switch.raw" 2>>"$WORK/switch.err"
        }
        _sw_q 15 '1/5 spanning-tree'       'show spanning-tree'
        _sw_q 20 '2/5 spanning-tree ports' 'show spanning-tree interface g1-8'
        _sw_q 15 '3/5 interface status'    'show interfaces GigabitEthernet 1-8 status'
        _sw_q "$SWITCH_SSH_TIMEOUT" '4/5 running-config' 'show running-config'
        _sw_q 25 '5/5 sntp'                'show sntp'
        # Shred the credential now rather than relying only on the exit trap.
        command -v shred >/dev/null 2>&1 && shred -u "$SWPWF" 2>/dev/null || rm -f "$SWPWF"
        if [ ! -s "$WORK/switch.raw" ]; then
            SWUNREACH="SSH-Fetch leer: $(tr -d '\r' < "$WORK/switch.err" 2>/dev/null | grep -viE 'pseudo-terminal|^$' | tail -1)"
            return 1
        fi
    else
        SWNOSOURCE=1; return 1
    fi
    # A paging terminal adds --More-- and escape noise; the interactive session also
    # leaves a trailing CLI prompt line. Strip both, plus CRs.
    sed -e 's/\r$//' -e 's/\x1b\[[0-9;]*[A-Za-z]//g' -e '/^--More--/d' \
        -e 's/^\[A\[2K//' -e '/^[A-Za-z0-9_-]*#.*$/d' \
        "$WORK/switch.raw" > "$WORK/switch.all" 2>/dev/null

    # Split by ANCHORS, not by prompt parsing: every output has a unique first line.
    # `switch.clean` keeps its old meaning (the running-config alone) so the sections
    # written before 1.3.0 are unaffected.
    awk '
      /^SYSTEM CONFIG FILE ::= BEGIN/           { out="clean" }
      /^Spanning tree enabled mode/             { out="stp" }
      /^Port g[0-9]+ (enabled|disabled)/        { out="stpports" }
      /^Port[[:space:]]+Name[[:space:]]+Status/ { out="ifstatus" }
      /^SNTP is /                               { out="sntp" }
      out!="" { print > (dir "/switch." out) }
    ' dir="$WORK" "$WORK/switch.all"

    # An offline SWITCH_CONFIG export holds only the running-config and carries no
    # anchor for the other three, so fall back to the whole file as before.
    [ -s "$WORK/switch.clean" ] || cp "$WORK/switch.all" "$WORK/switch.clean" 2>/dev/null

    # Fail loud rather than emitting an empty table: this CLI answers `Unknown command`
    # for things that look plausible, and it has done so twice already.
    if grep -qi 'Unknown command' "$WORK/switch.all"; then
        SWCMDFAIL=$(grep -i -B1 'Unknown command' "$WORK/switch.all" | head -2 | tr '\n' ' ')
    fi
    # 11.2: the device's own connection-rate limit rejects a query outright rather
    # than answering it -- surface it the same way as a rejected command, since an
    # empty/short section here is a device-side refusal, not "nothing configured."
    if grep -qi 'Over maximum cli session' "$WORK/switch.all"; then
        SWCMDFAIL="${SWCMDFAIL}${SWCMDFAIL:+ | }Over maximum cli session (Verbindungslimit des Geraets)"
    fi
    [ -s "$WORK/switch.clean" ] && grep -q 'interface g1' "$WORK/switch.clean"
}

# 11.1: the admin HTTPS cert on 192.168.30.2 needs only the workstation's own
# openssl, not the Lite-CLI source (SWITCH_CONFIG/--switch-ssh) at all -- so it
# is emitted in every branch of emit_switch, including the two "no CLI data"
# gaps below.
emit_switch_certs() {
    printf '### tls_certs\n\n| endpoint | subject | issuer | not_before | not_after | san |\n|---|---|---|---|---|---|\n'
    emit_cert "192.168.30.2:443"
    printf '\n'
}

emit_switch() {
    hdr="## Managed Switch (GS108Tv3) — $SWITCH"
    if [ "$SWNOSOURCE" = 1 ]; then
        printf '%s  \n' "$hdr"
        printf '**⚠ NICHT ERFASST — bekannte Lücke, keine Störung.** Das Gerät kennt keine\n'
        printf 'Public-Key-Authentifizierung (Hersteller-Lite-CLI), also kommt Standard-SSH\n'
        printf 'nicht durch. Eine der beiden Quellen angeben, dann erscheint dieser Abschnitt:\n\n'
        printf '```\n./factdump.sh --switch-ssh          # live, fragt das Switch-Passwort ab\n'
        printf 'SWITCH_CONFIG=~/gs108t-config.txt ./factdump.sh   # oder: Hand-Export\n```\n\n'
        printf 'Bis dahin ist die verkabelte L2-Seite **nicht** gegen die Doku prüfbar\n'
        printf '(Doku Abschnitt 5.1, Anhang A Zeilen F2–F8).\n\n'
        emit_switch_certs
        return
    fi
    if [ -n "$SWUNREACH" ]; then
        printf '%s  \n**⚠ nicht erreichbar (%s)** — Inventar unvollständig.\n\n' "$hdr" "$SWUNREACH"
        emit_switch_certs
        return
    fi
    printf '%s\n\n' "$hdr"
    emit_switch_certs
    # A rejected command must be visible, not silently become an empty table. This CLI
    # answers `Unknown command` for plausible-looking input and has done so twice
    # (`show snmp`, and `show interfaces status` without the explicit range).
    if [ -n "$SWCMDFAIL" ]; then
        printf '**⚠ Mindestens ein Abfragekommando wurde abgelehnt** — betroffene Sektionen sind\n'
        printf 'als *nicht erfasst* markiert, nicht als leer:\n\n```\n%s\n```\n\n' "$SWCMDFAIL"
    fi
    c="$WORK/switch.clean"

    printf '### identitaet\n\n| key | value |\n|---|---|\n'
    awk '
      /^! Model:/                { sub(/^! Model:[[:space:]]*/,""); model=$0 }
      /^! Firmware Version:/     { sub(/^! Firmware Version:[[:space:]]*/,""); fw=$0 }
      /^! Loader Version:/       { sub(/^! Loader Version:[[:space:]]*/,""); ldr=$0 }
      /^ip address /             { addr=$3; mask=$5 }
      /^ip default-gateway /     { gw=$3 }
      /^management-vlan vlan /   { mvlan=$3 }
      END{
        printf "| model | %s |\n", model
        printf "| firmware | %s |\n", fw
        printf "| loader | %s |\n", ldr
        printf "| mgmt_address | %s/%s |\n", addr, mask
        printf "| default_gateway | %s |\n", gw
        printf "| management_vlan | %s |\n", mvlan
      }' "$c"
    printf '\n'

    printf '### hardening\n\n| key | value |\n|---|---|\n'
    awk '
      /^no cloudAgent$/                 { cloud=1 }
      /^no cloudAgent discoveryAgent$/  { clouddisc=1 }
      /^no ip domain lookup$/           { nodns=1 }
      /^no ipv6$/                       { noipv6=1 }
      /^ip https$/                      { https=1 }
      /^ip http$/                       { http=1 }
      /^no snmp trap /                  { traps++ }
      /^sntp [0-9]+ host /              { sntp=$4 }
      /^clock timezone /                { tz=$0; sub(/^clock timezone[[:space:]]*/,"",tz); sub(/[[:space:]]+$/,"",tz) }
      /^clock summer-time /             { dst=$0; sub(/^clock summer-time[[:space:]]*/,"",dst); sub(/[[:space:]]+$/,"",dst) }
      /^clock source /                  { csrc=$3 }
      END{
        printf "| cloud_agent | %s |\n",        (cloud?"disabled":"ENABLED")
        printf "| cloud_discovery | %s |\n",    (clouddisc?"disabled":"ENABLED")
        printf "| ip_domain_lookup | %s |\n",   (nodns?"disabled":"enabled")
        printf "| ipv6 | %s |\n",               (noipv6?"disabled":"enabled")
        printf "| web_https | %s |\n",          (https?"enabled":"disabled")
        printf "| web_http | %s |\n",           (http?"ENABLED":"disabled")
        printf "| snmp_traps_disabled | %s |\n", traps+0
        printf "| sntp_host | %s |\n", sntp
        printf "| clock_timezone | %s |\n", tz
        printf "| clock_summer_time | %s |\n", dst
        printf "| clock_source | %s |\n", csrc
      }' "$c"
    printf '\n'

    # 11.2: source and status from the live `show sntp` query (5th connection).
    # Confirmed against a real device response (factinv-20260919, --switch-ssh):
    # the CLI lists THREE server priority slots, most unpopulated (address
    # blank, all-zero fields); only configured slots get a row. Status is the
    # LITERAL `reason:` field value, not a derived failures==0 check -- the
    # live device showed failures=904 out of attemps=9261 with reason=Success
    # at the same time, so failures is a lifetime counter, not a health flag.
    printf '### sntp\n\n| source | status |\n|---|---|\n'
    if [ -s "$WORK/switch.sntp" ]; then
        awk '
          BEGIN { n=0 }
          /^SNTP Server address:/ {
            if (cur_addr != "") { ADDR[n]=cur_addr; REASON[n]=cur_reason; n++ }
            s=$0; sub(/^.*address:[[:space:]]*/,"",s); cur_addr=s; cur_reason=""
          }
          /^SNTP Server reason:/ {
            s=$0; sub(/^.*reason:[[:space:]]*/,"",s); gsub(/[[:space:]]+$/,"",s); cur_reason=s
          }
          END {
            if (cur_addr != "") { ADDR[n]=cur_addr; REASON[n]=cur_reason; n++ }
            if (n==0) { printf "| — | nicht erfasst |\n"; exit }
            for (i=0;i<n;i++) printf "| %s | %s |\n", ADDR[i], (REASON[i]==""?"(leer)":REASON[i])
          }' "$WORK/switch.sntp"
    else
        printf '| — | nicht erfasst |\n'
    fi
    printf '\n'

    # SNMP: the Lite CLI has no `show snmp`, so this is derived from the config.
    # The v3 digest is COMPARED with the admin secret and only the verdict is
    # emitted -- never either value. That is the fact an audit needs.
    printf '### snmp [abgeleitet aus running-config; `show snmp` fehlt in der Lite CLI]\n\n| key | value |\n|---|---|\n'
    awk '
      # C3: take the FIRST encrypted line, not the last -- with several such lines $NF
      # from the last one would win, which is order-dependent for no reason.
      /^username .* secret encrypted / { if(admin=="") admin=$NF }
      /^snmp user /                    { lines++; if($0 ~ /encrypted/ && digest=="") digest=$NF; if($0 ~ /"NOAUTH"/) noauth++ }
      /^snmp community/                { comm++ }
      END{
        # C4: this counts LINES, not users. The device has exactly one v3 profile bound to
        # the admin account; the second line is that profile encryption slot. Naming the
        # field for what it measures stops "two v3 users" being read out of it.
        printf "| v3_user_lines | %s |\n", lines+0
        printf "| v3_lines_noauth_mode | %s |\n", noauth+0
        printf "| communities | %s |\n", comm+0
        # C3: a source that was redacted BEFORE it reached us carries <REMOVED> in both
        # fields -- equal, non-empty, and meaningless. Comparing them would manufacture a
        # `true`. Guard on the placeholder, not just on emptiness.
        red = (admin=="<REMOVED>" || digest=="<REMOVED>" || admin=="<REDACTED>" || digest=="<REDACTED>")
        if(admin=="" || digest=="")
          printf "| v3_digest_equals_admin_secret | — nicht ableitbar (Feld fehlt) — |\n"
        else if(red)
          printf "| v3_digest_equals_admin_secret | — nicht ableitbar (redigierte Quelle) — |\n"
        else
          printf "| v3_digest_equals_admin_secret | %s |\n", (admin==digest?"**true**":"false")
      }' "$c"
    printf '\n'
    printf -- '> Einordnung: Doku §5.1.\n\n'

    printf '### vlans\n\n| vlan_id | name |\n|---|---|\n'
    awk '
      /^vlan [0-9]+$/ { vid=$2; next }
      /^ name "/      { if(vid!=""){ nm=$0; sub(/^ name "/,"",nm); sub(/"$/,"",nm); print vid"\t"nm; vid="" } }
    ' "$c" | sort -n | awk -F'\t' '{ v=$1; n=$2; if(v+0>=4086) n=n" *(Hersteller-Auto-VLAN)*"; printf "| %s | %s |\n", v, n }'
    printf '\n'

    # PVID and membership are separate columns on purpose: membership decides how a
    # frame LEAVES the port, PVID which VLAN an incoming UNTAGGED frame joins. A
    # mismatch is the classic silent misconfiguration (doc section 5.1).
    # `link` comes from `show interfaces GigabitEthernet 1-8 status` (this CLI has no
    # bare `show interfaces status`). It is the distinction the config alone cannot make:
    # admin_state says whether the port is enabled, link says whether anything is on it.
    if [ -s "$WORK/switch.ifstatus" ]; then
        # Parsed by SCANNING for the status keyword, not by column position: the Name
        # field contains spaces (`Uplink OpenWRT`, `--- DISABLED ---`), so the VLAN sits
        # at a different field index per row. The status word plus a numeric field right
        # after it is the one stable landmark.
        awk 'NR>1 && $1 ~ /^g[0-9]+$/ {
               st="—"; vl="—"
               for(i=2;i<NF;i++){
                 if(($i=="connected" || $i=="notconnect" || $i=="disable") && $(i+1) ~ /^[0-9]+$/){
                   vl=$(i+1)
                   # Single-word tokens on purpose: the reader below splits on whitespace,
                   # and "no link" would arrive as two fields and be dropped silently.
                   if($i=="notconnect")     st="no-link"
                   else if($i=="connected") st="**connected**"
                   else                     st="admin-down"
                   break
                 }
               }
               # Marker prefix, not file position: see the reader below.
               print "@LINK@\t"$1"\t"st"\t"vl }' "$WORK/switch.ifstatus" > "$WORK/switch.link"
    fi
    printf '### portplan\n\n| port | description | pvid | link_vlan | untagged | tagged | vlan1_removed | admin_state | link |\n|---|---|---|---|---|---|---|---|---|\n'
    # Concatenated into ONE stream and separated by a marker, deliberately not by
    # FNR==NR: when the link file is missing or empty, FNR==NR stays true across the
    # SECOND file too, and `interface g1` (two fields) is then eaten as a link line --
    # which silently emptied the whole port plan on the first live run.
    : > "$WORK/switch.link.x"
    [ -s "$WORK/switch.link" ] && cat "$WORK/switch.link" >> "$WORK/switch.link.x"
    cat "$c" >> "$WORK/switch.link.x"
    awk '
      /^@LINK@\t/ { split($0,a,"\t"); LINK[a[2]]=a[3]; LVLAN[a[2]]=a[4]; next }
      /^interface /{
        if(p!="") emit()
        p=$2; desc=""; pvid="-"; unt="-"; tag="-"; rm="no"; st="up"; next
      }
      /^ switchport hybrid pvid /              { pvid=$4 }
      /^ switchport hybrid allowed vlan add /  { if($7=="untagged") unt=$6; else if($7=="tagged") tag=$6 }
      /^ switchport hybrid allowed vlan remove 1$/ { rm="yes" }
      /^ description "/ { desc=$0; sub(/^ description "/,"",desc); sub(/"$/,"",desc) }
      /^ shutdown$/     { st="**shutdown**" }
      END{ if(p!="") emit() }
      function emit(  lk, lv){
        if(p ~ /^g[0-9]+$/){
          lk = (p in LINK)  ? LINK[p]  : "— nicht erfasst —"
          lv = (p in LVLAN) ? LVLAN[p] : "—"
          # link_vlan is the VLAN the port actually carries at runtime, read from a
          # different command than pvid, which comes from the configuration. Two sources
          # that CAN disagree are worth more than one that confirms itself -- so a
          # mismatch is marked rather than left for the reader to spot. Only flagged when
          # both are known: a shutdown port legitimately reports VLAN 1 while the config
          # assigns it none.
          if(lv != "—" && pvid != "-" && lv != pvid) lv = lv " **\u2260 pvid**"
          printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", p, desc, pvid, lv, unt, tag, rm, st, lk
        }
        else if(p ~ /^lag/) { lagdown = lagdown (st=="**shutdown**" ? 1 : 0) }
      }
    ' "$WORK/switch.link.x"
    printf '\n'
    printf '### lags\n\n| key | value |\n|---|---|\n'
    awk '/^interface lag/{n++} /^ shutdown$/{if(inlag)d++} /^interface lag/{inlag=1;next} /^interface g/{inlag=0}
         END{ printf "| lag_interfaces | %s |\n| lag_shutdown | %s |\n", n+0, d+0 }' "$c"
    printf '\n'

    # C5: STP is only visible at runtime -- the running-config holds nothing but the
    # default `spanning-tree mst configuration` block. Two volatile fields are dropped
    # on purpose: the "last change occurred N ago" clock and the per-port BPDU counters.
    # Keeping a non-zero `BPDU received` on an access port would be a security signal,
    # but it is a counter, and counters make the body undiffable (see the invariants at
    # the top). Open question, recorded rather than decided: a later `--runtime` section
    # that is explicitly not diffable.
    printf '### spanning_tree\n\n| key | value |\n|---|---|\n'
    if [ -s "$WORK/switch.stp" ]; then
        awk '
          /^Spanning tree enabled mode/ { mode=$NF }
          /Priority[[:space:]]+[0-9]+/  { if(prio=="" && match($0,/Priority[[:space:]]+[0-9]+/)) {
                                            s=substr($0,RSTART,RLENGTH); sub(/Priority[[:space:]]+/,"",s); prio=s } }
          /This switch is the root/     { root="true" }
          /Number of topology changes/  { if(match($0,/changes[[:space:]]+[0-9]+/)) {
                                            s=substr($0,RSTART,RLENGTH); sub(/changes[[:space:]]+/,"",s); tc=s } }
          END{
            printf "| mode | %s |\n", (mode==""?"—":mode)
            printf "| is_root | %s |\n", (root==""?"false":root)
            printf "| root_priority | %s |\n", (prio==""?"—":prio)
            printf "| topology_changes | %s |\n", (tc==""?"—":tc)
          }' "$WORK/switch.stp"
    else printf '| — | nicht erfasst (Laufzeitabfrage) |\n'; fi
    printf '\n'

    printf '### spanning_tree_ports\n\n| port | state | role | edge_port | type | bpdu_filter | bpdu_guard |\n|---|---|---|---|---|---|---|\n'
    if [ -s "$WORK/switch.stpports" ]; then
        awk '
          function grab(line, key,   s){
            if(!match(line, key "[[:space:]]*:[[:space:]]*[^[:space:]]+")) return "—"
            s=substr(line,RSTART,RLENGTH); sub(key "[[:space:]]*:[[:space:]]*","",s); return s
          }
          function flush(){ if(p!="") printf "| %s | %s | %s | %s | %s | %s | %s |\n", p,stt,role,edge,typ,bf,bg }
          /^Port g[0-9]+ /      { flush(); p=$2; stt=role=edge=typ=bf=bg="—"; next }
          /State:/              { stt=grab($0,"State"); role=grab($0,"Role") }
          /Type:/               { if(match($0,/Type:[[:space:]]*.*\)/)){ typ=substr($0,RSTART,RLENGTH); sub(/Type:[[:space:]]*/,"",typ) }
                                  edge=grab($0,"Edge Port") }
          /BPDU Filter:/        { bf=grab($0,"BPDU Filter"); bg=grab($0,"BPDU guard") }
          END{ flush() }
        ' "$WORK/switch.stpports"
    else printf '| — | nicht erfasst (Laufzeitabfrage) | — | — | — | — | — |\n'; fi
    printf '\n'
    printf -- '> Einordnung: Doku §5.1. `BPDU sent/received` und die verstrichene Zeit seit dem\n'
    printf -- '> letzten Topology-Change sind bewusst nicht aufgenommen — Zähler bzw. Uhr, beide\n'
    printf -- '> machen den Body undiffbar.\n\n'

    # Full running-config, verbatim except: the serial number and every password
    # hash are replaced with <REMOVED> (central redact(), verified by leak_scan),
    # and the volatile "System Up Time" line is dropped for a deterministic body.
    printf '### running-config (redigiert)\n\n'
    printf -- '> Vollständige `show running-config`. **Serial-Nummer und Passwort-Hashes** sind\n'
    printf -- '> durch `<REMOVED>` ersetzt; die volatile `System Up Time`-Zeile ist entfernt.\n'
    printf -- '> System Name und MAC-Adresse bleiben bewusst erhalten (Fakten-Inventur).\n\n'
    printf '```\n'
    grep -v '! System Up Time:' "$c"
    printf '\n```\n\n'
}

# ===========================================================================
# assemble
# ===========================================================================
mk_head() {   # $1 title  $2 source
    printf '# Fakten-Inventur — %s\n\n' "$1"
    printf '> **FLÜCHTIG · KEIN QUELLDOKUMENT.** Bei Faktenabweichung gilt das Gerät;\n'
    printf '> das Warum steht in der Dokumentation. Nicht ins Repo committen.\n>\n'
    printf '> Erzeugt: %s · Werkzeug: factdump v%s · Quelle: %s\n' "$(date -u '+%Y-%m-%d %H:%M UTC')" "$FACTDUMP_VERSION" "$2"
    printf '> Redigiert: Credentials/Keys/Passphrases/Hashes · Behalten: Adressen, MACs, Gerätenamen\n\n'
    [ -n "$UNREACHABLE" ] && printf '> **⚠ Nicht erreichbar:%s** — Teil-Inventur.\n\n' "$UNREACHABLE"
    [ -n "$NOSOURCE" ] && printf '> **⚠ Nicht erfasst (keine Quelle konfiguriert):%s** — bekannte Lücke, siehe Abschnitt.\n\n' "$NOSOURCE"
    printf -- '---\n\n'
}

# reachability + collection
collect_router || { UNREACHABLE="$UNREACHABLE $ROUTER"; EXITCODE=1; RUNREACH="SSH-Timeout"; }
collect_spitz  || { UNREACHABLE="$UNREACHABLE $UPLINK"; EXITCODE=1; SUNREACH="SSH-Timeout"; }
collect_haos   || { UNREACHABLE="$UNREACHABLE $HAOS";  EXITCODE=1; HUNREACH="SSH-Timeout"; }
# The switch fails exit-1 only if a source was configured and did not work; a
# missing source is a marked gap, not an error (see COMPONENT 4).
collect_switch || {
    if [ "$SWNOSOURCE" = 1 ]; then NOSOURCE="$NOSOURCE $SWITCH"
    else UNREACHABLE="$UNREACHABLE $SWITCH"; EXITCODE=1
         [ -z "$SWUNREACH" ] && SWUNREACH="unbrauchbarer Export"
    fi
}

# 12.1: static coverage map -- which inventory table makes which documentation
# claim checkable. Hand-written and kept in sync by eye, not derived by parsing
# the docs (the docs are prose; a parser here would be guessing at meaning).
# Anh. A = docs/network-documentation.md, "Appendix A -- Expected state /
# testable claims"; row IDs (A1, B7, F8, ...) are that appendix's own.
emit_coverage() {
    cat <<'COVEOF'
## coverage

Welche Inventar-Tabelle welche Behauptung prüfbar macht. Anh. A = `docs/
network-documentation.md`, Appendix A; Doku-§§ im selben Dokument, sofern
nicht anders vermerkt.

### OpenWrt One

| Tabelle | Anh. A | Doku |
|---|---|---|
| `system` | — | §7.6, §13, §14 |
| `dropbear`, `uhttpd`, `authorized_keys` | C9 | §10 |
| `services_enabled`, `local_files`, `backup_scope` | F10, G1 | §15.1 |
| `cron` | — | §14.1–14.3 |
| `pbr_config`, `pbr_policy_config`, `pbr_policies`, `pbr_chain` | F9, F9a, F10 | §17 |
| `fw_rules`, `fw_rules_by_zone` | A1–A7, B6, B7, B7a–d, C4, F11, F13 | §7 |
| `fw_zones` | A1, A2, A3 | §7 |
| `fw_defaults`, `fw_includes` | — | §7 (*Removed defaults*) |
| `fw_redirects` | B1, B2, B9, B10 | §7.1, §7.6, §8 |
| `fw_chains` | B4, B6, B7, D1 | §7 |
| `fw_uci_nft_orphans` | F13 (Drift-Ergänzung) | §7 |
| `vlans`, `devices_other` | D5, F1 | §5 |
| `interfaces` | — | §17 |
| `wg_peers` | — | §17 |
| `links`, `ipv6_global` | F12 | §5, §7 (*Address families*) |
| `radios` | F4c | §6.1, §6.2 |
| `wireless` | A7, C12 | §6.2 |
| `dnsmasq`, `dhcp_pools`, `dhcp_sections` | B10, E8 | §8, §9 |
| `adguard` | E5, E6 | §9 |
| `adguard_filters`, `adguard_allowlists` | — | §9 (*Subscribed blocklists*) |
| `adguard_user_rules` | — | §9 |
| `adguard_service` | — | §9 (`GOMEMLIMIT`), §13 |
| `listening` | C1, E1, E2 | §9, §10 |
| `tls_certs` | E5, E6 | §9 |

### Spitz Plus

| Tabelle | Anh. A | Doku |
|---|---|---|
| `listening` (`class`/`process`) | E3, E4 | §3 |
| `dhcp_pool`, `dhcp_reservations` | — | §3 |
| `services_enabled`, `radio_links` | — | §3 |
| `local_files`, `cron` | — | §14.2, §14.3 |
| `tls_certs` | E5 | §3 |

### Home Assistant / HAOS

| Tabelle | Anh. A | Doku |
|---|---|---|
| `dns_resolver` | — | §16.2 |

### Managed Switch (GS108Tv3)

| Tabelle | Anh. A | Doku |
|---|---|---|
| `identitaet`, `hardening`, `snmp` | F1, F2, F5–F7 | §5.1 |
| `spanning_tree`, `spanning_tree_ports` | F4b, F4d (Zähler bewusst manuell) | §5.1 |
| `running-config` | F3, F4 | §5.1 |
| `tls_certs` | E5 | §5.1 |
| `sntp` | F8 | §5.1, §7.6 |

Nicht abgedeckt (Sperrliste, siehe Skriptkopf KNOWN GAPS): HAOS-Integrationen/
Config-Entries; jede Art Zähler (BPDU, Topology-Change, Lease-Restzeit);
`[Z]`-Proben (Testhost in einer Zone); Off-Device-Stände (`sysupgrade -b`
tatsächlich zurückspielen, HAOS-Backup restaurieren).

COVEOF
}

# discover endpoints early (router.network may not be split yet -> split first)
[ -f "$WORK/router.raw" ] && split_raw "$WORK/router.raw" "$WORK/router" && discover_endpoints

# build the body/bodies
build_router_body()   { emit_router "$RUNREACH"; }
build_spitz_body()    { emit_spitz  "$SUNREACH"; }
build_haos_body()     { emit_haos   "$HUNREACH"; }
build_switch_body()   { emit_switch; }
build_coverage_body() { emit_coverage; }

write_file() {   # $1 outfile  $2 title  $3 source  $4 body-fn
    b="$WORK/body.$$"; ( "$4" ) > "$b"
    ( if [ "$BODY_ONLY" = 0 ]; then mk_head "$2" "$3"; fi; cat "$b" ) | redact > "$1"
    if ! leak_scan "$1"; then
        mv "$1" "$1.LEAK-UNSICHER"
        warn ""; warn "ABBRUCH: mutmasslich Geheimnisse in der Ausgabe — Datei umbenannt zu:"
        warn "  $1.LEAK-UNSICHER  — NICHT hochladen, bis geklaert."
        EXITCODE=2
    fi
}

if [ "$SPLIT" = 1 ]; then
    base="${OUT%.md}"
    write_file "${base}-router.md" "OpenWrt One"       "$ROUTER" build_router_body
    write_file "${base}-spitz.md"  "Spitz Plus"         "$UPLINK" build_spitz_body
    write_file "${base}-haos.md"   "Home Assistant/HAOS" "$HAOS"  build_haos_body
    write_file "${base}-switch.md" "Managed Switch"      "$SWITCH" build_switch_body
    write_file "${base}-coverage.md" "coverage" "—" build_coverage_body
    echo "geschrieben: ${base}-router.md ${base}-spitz.md ${base}-haos.md ${base}-switch.md ${base}-coverage.md"
else
    b="$WORK/body.all"; { build_router_body; printf -- '---\n\n'; build_spitz_body; printf -- '---\n\n'; build_haos_body; printf -- '---\n\n'; build_switch_body; printf -- '---\n\n'; build_coverage_body; } > "$b"
    ( if [ "$BODY_ONLY" = 0 ]; then mk_head "Homelab (4 Komponenten)" "$ROUTER + $UPLINK + $HAOS + $SWITCH"; fi; cat "$b" ) | redact > "$OUT"
    if ! leak_scan "$OUT"; then
        mv "$OUT" "$OUT.LEAK-UNSICHER"
        warn ""; warn "ABBRUCH: mutmasslich Geheimnisse in der Ausgabe — Datei umbenannt zu:"
        warn "  $OUT.LEAK-UNSICHER  — NICHT hochladen, bis geklaert."
        EXITCODE=2
    else
        echo "geschrieben: $OUT"
        echo "Zeilen: $(wc -l < "$OUT")"
    fi
fi

[ "$EXITCODE" = 0 ] && echo "Redaktions-Selbsttest: ok"
exit $EXITCODE
