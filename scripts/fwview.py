#!/usr/bin/env python3
"""fwview.py 1.6.0 -- render the router's firewall rules as ONE self-contained HTML page
and ALWAYS write the same data as a JSON report for analysis (e.g. by an LLM).

Reads the LIVE firewall over SSH, read-only (`uci export firewall|dhcp|network`) and writes
a single HTML file: one section per source zone, in each section the rules to the router
itself (INPUT) apart from the forwarded ones (FORWARD), then the DNAT redirects.
Every rule is one row: position, status, name, action, source (IPs, MACs, device names),
destination, protocol, ports (with service names), logging, remaining UCI options.

The page is a MIRROR for reading, never a source (docs/firewall-rules.md is the source of
truth, the device wins over both). It contains real IPs and MACs: the output file name
fwview-*.html is ignored by git and must not be committed or published.

The JSON report (fwview-*.json, same base name, same git ignore) holds the fully resolved
rule set: per rule chain, direction, source/destination with device names and MACs, ports
with service names, status, log, remaining options, plus zones, forwardings, IPsets,
includes, warnings and a short semantics note for the reader. It carries the same real
IPs/MACs as the HTML: hand it only to a model you are willing to give that data.

Usage:   scripts/fwview.py [--host root@192.168.30.1] [--out FILE] [--json FILE]
         scripts/fwview.py --from-dir DIR [--out FILE] [--json FILE]
  --host      SSH target (default root@192.168.30.1; BatchMode, key auth, nothing is written)
  --from-dir  read firewall.uci, dhcp.uci, network.uci from DIR instead of SSH
              (saved `uci export` output, for tests without the router); the runtime set
              check runs only if DIR/nft-sets.txt holds a saved `nft list sets inet`
  --out       HTML file (default ./fwview-YYYYMMDD-HHMM.html)
  --json      JSON report (default: --out with .html replaced by .json)

Exit codes: 0 ok, 1 SSH/read error or empty export, 2 usage.
Only the Python 3 standard library is used.

1.4.0: a rule may carry several `list ipset` entries (fw4-multi-ipset patch, see
docs/firewall-rules.md "fw4-Patch multi-ipset"). All of them are rendered; the JSON
report lists them in `ipsets[]` (AND-ed) and keeps `ipset` as the first one for older
readers. Warning when a rule pins its source inline although a set holds that exact pair.

1.5.0: IPsets are rendered as cards (SET badge, name linking to the appendix, member
count or file, members indented below), visibly apart from addresses pinned inline in
the rule; several conditions of one side are separated by "und". Sets with `option
loadfile` are read from the device (one extra read-only `cat`, `--from-dir` reads
DIR/sets/<basename>) and listed in HTML and JSON (`loadfile_entries`, `entry_count`).
The appendix lists every set with its fields, origin, members and the rules using it
(`used_by`); an unused set or an unreadable set file is a warning. Rule rows carry
`id="r-<name>"`, sets `id="set-<name>"`.

1.6.0: two checks on the IP sets, after `teams_media_v4` held two Teams relay networks as
`dest_ip` and therefore matched exactly two addresses, so `Allow-work-wan-teams` never fired
(2026-10-20). fw4 renders a set whose `match` names no `*_net` field WITHOUT `flags interval`,
and nftables then truncates every CIDR member to its network address -- silently, no error
anywhere. The config check reads that from the export alone; the runtime check compares it
against the live set (one extra read-only `nft list sets inet`, skipped with `--from-dir`
unless DIR/nft-sets.txt exists) and reports a set whose kernel flags no longer match the
configuration -- the state in which neither a reload nor LuCI's *Save & Apply* can help.
"""
import argparse
import datetime
import html
import ipaddress
import json
import os
import shlex
import subprocess
import sys

VERSION = "1.6.0"
DEFAULT_HOST = "root@192.168.30.1"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
       "-o", "ControlMaster=no", "-o", "ControlPath=none"]

# Trust order of the source zones; zones not listed follow alphabetically.
ZONE_ORDER = ["adminvpn", "management", "private", "smarthome_srv", "smarthome",
              "kids", "tv", "work", "wgvpn", "wan"]

# Service names for the ports that occur in the rule set (docs/firewall-rules.md, Port-Legende).
PORTS = {
    "22": "SSH", "53": "DNS", "67": "DHCP", "80": "HTTP", "123": "NTP", "443": "HTTPS",
    "853": "DoT", "1883": "MQTT", "3232": "ESPHome-OTA", "6053": "ESPHome-API",
    "8080": "HTTP-Alt (Nuki-Bridge / AdGuard)", "8097": "Music Assistant",
    "8123": "Home Assistant", "8443": "Uplink-LuCI", "8883": "MQTT/TLS", "8893": "MQTT (Hersteller)",
    "9443": "AdGuard-UI", "51821": "WireGuard (Admin-Tunnel)",
    "3478-3481": "Teams-Medien (STUN/TURN)", "1024-65535": "alle hohen Ports",
}

# Addresses that are not DHCP hosts but have a fixed role.
ROLES = {"192.168.8.1": "Uplink (Spitz)", "192.168.30.2": "Managed Switch"}

# UCI options a rule row shows in its own columns; anything else lands in "Zusatz".
RULE_KNOWN = {"name", "src", "dest", "src_ip", "src_mac", "dest_ip", "proto", "dest_port",
              "target", "enabled", "log", "log_limit", "family", "icmp_type", "ipset"}
REDIR_KNOWN = {"name", "src", "proto", "src_dport", "dest_ip", "dest_port", "target",
               "family", "enabled", "src_ip", "src_mac", "dest", "log", "log_limit"}


# ---------------------------------------------------------------- reading

def fetch(host, what):
    r = subprocess.run(SSH + [host, "uci export " + what], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        sys.exit("fwview: 'uci export %s' auf %s fehlgeschlagen: %s"
                 % (what, host, (r.stderr.strip() or "leere Ausgabe")))
    return r.stdout


def read_dir(d, what):
    path = os.path.join(d, what + ".uci")
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        sys.exit("fwview: %s" % e)
    if not text.strip():
        sys.exit("fwview: %s ist leer" % path)
    return text


def fetch_files(host, paths):
    """Read the `loadfile` set files, read-only, in ONE ssh call -> {path: text or None}."""
    if not paths:
        return {}
    cmd = "; ".join("echo '=== %s'; if [ -r '%s' ]; then cat '%s'; else echo '=== MISSING'; fi" % (p, p, p)
                    for p in paths)
    r = subprocess.run(SSH + [host, cmd], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("fwview: Lesen der Set-Dateien auf %s fehlgeschlagen: %s" % (host, r.stderr.strip()))
    out, cur = {}, None
    for line in r.stdout.splitlines():
        if line.startswith("=== "):
            tag = line[4:]
            if tag == "MISSING" and cur is not None:
                out[cur] = None
            else:
                cur = tag
                out[cur] = ""
        elif cur is not None and out[cur] is not None:
            out[cur] += line + "\n"
    return {p: out.get(p) for p in paths}


def read_dir_files(d, paths):
    """`--from-dir`: set files are expected as DIR/sets/<basename> -> {path: text or None}."""
    out = {}
    for p in paths:
        try:
            out[p] = open(os.path.join(d, "sets", os.path.basename(p)), encoding="utf-8").read()
        except OSError:
            out[p] = None
    return out


def fetch_setflags(host):
    """Live set declarations -> {name: has `flags interval`}; None when nft cannot be read.
    Read-only, one call, elements included in the output but not looked at."""
    r = subprocess.run(SSH + [host, "nft list sets inet"], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return parse_setflags(r.stdout)


def read_dir_setflags(d):
    """`--from-dir`: saved `nft list sets inet` as DIR/nft-sets.txt, None when absent."""
    try:
        return parse_setflags(open(os.path.join(d, "nft-sets.txt"), encoding="utf-8").read())
    except OSError:
        return None


def parse_setflags(text):
    """`nft list sets inet` -> {set name: True if the set carries `flags interval`}."""
    out, cur = {}, None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("set ") and line.endswith("{"):
            cur = line[4:-1].strip()
            out[cur] = False
        elif cur and line.startswith("flags ") and "interval" in line:
            out[cur] = True
        elif line == "}":
            cur = None
    return out


def parse_setfile(text):
    """Addresses of a set file as fw4 loads it: blank lines and `#` comments dropped."""
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line.split()[0])
    return out


def attach_setfiles(ipsets, get_files):
    """Store each loadfile set's members on its section (`file_entries`, None if unreadable);
    returns warnings for unreadable files."""
    paths = [(nm, s["opts"]["loadfile"][0]) for nm, s in ipsets.items() if s["opts"].get("loadfile")]
    texts = get_files([p for _, p in paths])
    warns = []
    for nm, p in paths:
        t = texts.get(p)
        ipsets[nm]["file_entries"] = parse_setfile(t) if t is not None else None
        if t is None:
            warns.append("IPset '%s': Datei %s auf dem Geraet nicht lesbar (Set ist leer)" % (nm, p))
    return warns


def set_field_types(sec):
    """Field types of a set from its `match` option, direction prefix stripped (fw4 default
    is a single `src_ip`)."""
    return [m.partition("_")[2] or m for m in sec["opts"].get("match", [])] or ["ip"]


def set_rows(sec):
    """Members of a set as lists of values: the UCI `list entry` lines, or for a `loadfile`
    set the addresses read from that file (empty while they have not been read)."""
    return ([e.split() for e in sec["opts"].get("entry", [])]
            or [[e] for e in (sec.get("file_entries") or [])])


def check_set_match(ipsets):
    """A member written as a CIDR prefix in a field of type `ip` is lost: fw4 renders such a
    set without `flags interval`, nftables keeps only the network address, and every rule using
    the set matches almost nothing. Nobody reports it -- not fw4, not LuCI, not the log."""
    warns = []
    for nm in sorted(ipsets):
        sec = ipsets[nm]
        types = set_field_types(sec)
        if "net" in types:
            continue
        bad = sorted({v for row in set_rows(sec) for i, v in enumerate(row)
                      if (types[i] if i < len(types) else types[0]) == "ip"
                      and "/" in v and v.rsplit("/", 1)[1] != "32"})
        if bad:
            match = sec["opts"].get("match", []) or ["src_ip"]
            warns.append("IPset '%s': Praefix-Eintraege (%s) in einem Feld vom Typ 'ip' -- fw4 erzeugt "
                         "das Set ohne 'flags interval' und kuerzt jedes Praefix still auf die "
                         "Netzadresse. Abhilfe: match '%s' -> '%s', danach Regel und Set loeschen und "
                         "'fw4 restart'" % (nm, ", ".join(bad), " ".join(match),
                                            " ".join(m.replace("_ip", "_net") for m in match)))
    return warns


def check_set_runtime(ipsets, flags):
    """Configuration and live set disagree about `flags interval`: fw4 has not rebuilt the
    ruleset since the change, and it cannot -- nftables will not change the flags of an existing
    set, so fw4 rejects the whole rendered ruleset ("existing set lacks interval flag") and a
    reload or LuCI's *Save & Apply* leaves the old set in place. The referencing rule and the set
    have to be deleted before `fw4 restart`."""
    warns = []
    for nm in sorted(ipsets):
        want = "net" in set_field_types(ipsets[nm])
        have = flags.get(nm)
        if have is None:
            warns.append("IPset '%s': im laufenden Regelwerk nicht vorhanden" % nm)
        elif want != have:
            warns.append("IPset '%s': Konfiguration sagt '%s', das laufende Set hat %s 'flags interval' "
                         "-- fw4 wurde seit der Aenderung nicht neu gebaut und kann es so auch nicht: "
                         "Regel und Set loeschen, dann 'fw4 restart'"
                         % (nm, " ".join(ipsets[nm]["opts"].get("match", [])) or "src_ip",
                            "kein" if not have else "bereits"))
    return warns


def parse_uci(text):
    """`uci export` -> list of sections {type, id, opts: {key: [values]}} in file order."""
    secs = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "package")):
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if parts[0] == "config" and len(parts) >= 2:
            secs.append({"type": parts[1], "id": parts[2] if len(parts) > 2 else "", "opts": {}})
        elif parts[0] in ("option", "list") and len(parts) >= 3 and secs:
            key, val = parts[1], " ".join(parts[2:])
            if parts[0] == "option":
                # UCI 'option' with spaces (proto 'tcp udp') is a list in disguise
                secs[-1]["opts"][key] = val.split() if key in ("proto", "icmp_type") else [val]
            else:
                secs[-1]["opts"].setdefault(key, []).append(val)
    return secs


# ---------------------------------------------------------------- model

class Net:
    """Names for addresses: DHCP hosts, router addresses per zone, zone subnets."""

    def __init__(self, dhcp, network, zones):
        self.by_ip, self.by_mac, self.router_ip, self.subnets = {}, {}, {}, []
        self.mac_of_ip, self.ip_of_mac = {}, {}
        for s in dhcp:
            if s["type"] != "host":
                continue
            name = (s["opts"].get("name") or [""])[0]
            for ip in s["opts"].get("ip", []):
                self.by_ip[ip] = name
                if s["opts"].get("mac"):
                    self.mac_of_ip[ip] = s["opts"]["mac"][0].upper()
            for mac in s["opts"].get("mac", []):
                self.by_mac[mac.upper()] = name
                if s["opts"].get("ip"):
                    self.ip_of_mac[mac.upper()] = s["opts"]["ip"][0]
        zone_of_net = {}
        for z in zones:
            for n in z["opts"].get("network", []):
                zone_of_net[n] = z["opts"]["name"][0]
        for s in network:
            if s["type"] != "interface" or s["id"] not in zone_of_net:
                continue
            addr = (s["opts"].get("ipaddr") or s["opts"].get("addresses") or [""])[0]
            mask = (s["opts"].get("netmask") or [""])[0]
            if not addr or addr.startswith("127."):
                continue
            try:
                iface = ipaddress.ip_interface(addr if "/" in addr else "%s/%s" % (addr, mask))
            except ValueError:
                continue
            z = zone_of_net[s["id"]]
            self.router_ip[str(iface.ip)] = z
            self.subnets.append((iface.network, z))

    def name_ip(self, v):
        """-> (text, label) -- label is the device/role name or ''."""
        base = v.split("/")[0]
        if base in ROLES:
            return v, ROLES[base]
        if base in self.router_ip and "/" not in v:
            return v, "Router (%s)" % self.router_ip[base]
        if v in self.by_ip:
            return v, self.by_ip[v]
        if "/" in v:
            try:
                net = ipaddress.ip_network(v, strict=False)
            except ValueError:
                return v, ""
            for n, z in self.subnets:
                if net == n:
                    return v, "ganzes Subnetz %s" % z
            if net.prefixlen == 32 and str(net.network_address) in self.by_ip:
                return v, self.by_ip[str(net.network_address)]
            for ip, nm in self.by_ip.items():
                if ipaddress.ip_address(ip) in net and net.prefixlen < 32:
                    return v, "enthaelt u. a. %s" % nm
        return v, ""

    def name_mac(self, v):
        return v.upper(), self.by_mac.get(v.upper(), "")


def build(fw, net):
    zones = [s for s in fw if s["type"] == "zone"]
    zone_names = [z["opts"]["name"][0] for z in zones]
    ipsets = {s["opts"]["name"][0]: s for s in fw if s["type"] == "ipset"}
    rules, redirs, warns = [], [], []
    seen = {}
    for s in fw:
        if s["type"] not in ("rule", "redirect"):
            continue
        o = s["opts"]
        g = lambda k, o=o: (o.get(k) or [""])[0]
        name = g("name")
        enabled = g("enabled") != "0"
        row = {"sid": s["id"], "name": name, "o": o, "enabled": enabled,
               "src": g("src"), "dest": g("dest"), "target": g("target") or "ACCEPT"}
        known = RULE_KNOWN if s["type"] == "rule" else REDIR_KNOWN
        row["extra"] = {k: v for k, v in o.items() if k not in known}
        if not name:
            warns.append("Eintrag '%s' (%s) hat keinen Namen" % (s["id"], s["type"]))
        else:
            seen[name] = seen.get(name, 0) + 1
        if name.startswith("DISABLED-") == enabled:
            warns.append("%s: %s" % (name, "Praefix DISABLED- bei aktiver Regel" if enabled
                                     else "enabled=0 ohne Praefix DISABLED-"))
        for key in ("src", "dest"):
            z = row[key]
            if z and z != "*" and z not in zone_names:
                warns.append("%s: %s-Zone '%s' existiert nicht" % (name, key, z))
        for k in row["extra"]:
            warns.append("%s: UCI-Option '%s' wird nicht eigens dargestellt (steht unter Zusatz)" % (name, k))
        for ipset in o.get("ipset", []):
            if ipset.split()[0].lstrip("!") not in ipsets:
                warns.append("%s: IPset '%s' nicht definiert" % (name, ipset))
        if len(o.get("src_ip", [])) == 1 and len(o.get("src_mac", [])) == 1:
            pin = "%s %s" % (o["src_ip"][0], o["src_mac"][0].upper())
            for nm, sec in ipsets.items():
                if pin in [" ".join(e.upper().split()) for e in sec["opts"].get("entry", [])]:
                    warns.append("%s: Quelle inline gepinnt (%s), obwohl Set '%s' genau dieses Paar enthaelt "
                                 "(Sets sind WER, Regeln sind WAS)" % (name, pin, nm))
        (rules if s["type"] == "rule" else redirs).append(row)
    for n, c in seen.items():
        if c > 1:
            warns.append("Regelname '%s' kommt %d-mal vor" % (n, c))
    used = {v.replace(",", " ").split()[0].lstrip("!") for r in rules + redirs for v in r["o"].get("ipset", []) if v.strip()}
    for nm in ipsets:
        if nm not in used:
            warns.append("IPset '%s' wird von keiner Regel genutzt" % nm)
    for i, r in enumerate(rules, 1):
        r["pos"] = i
    for i, r in enumerate(redirs, 1):
        r["pos"] = i
    return zones, ipsets, rules, redirs, warns


def zone_key(z):
    return (ZONE_ORDER.index(z), "") if z in ZONE_ORDER else (len(ZONE_ORDER), z)


# ---------------------------------------------------------------- html helpers

def esc(s):
    return html.escape(str(s), quote=True)


def chip(text, label="", cls=""):
    lab = '<span class="lab">%s</span>' % esc(label) if label else ""
    return '<span class="chip %s"><code>%s</code>%s</span>' % (cls, esc(text), lab)


def entry(ip="", label="", mac=""):
    """One device per line: IP, name, MAC (empty parts stay empty cells)."""
    return ('<div class="ent"><code class="ip">%s</code><span class="lab">%s</span><code class="mac">%s</code></div>'
            % (esc(ip), esc(label), esc(mac)))


def addr_cell(vals_ip, vals_mac, net):
    """Inline addresses of a rule, one device per line (IP / name / MAC). IPs carry the MAC of
    their DHCP host, MACs that match no listed IP follow as their own lines."""
    lines, used = [], set()
    for v in vals_ip:
        text, label = net.name_ip(v)
        mac = net.mac_of_ip.get(v, "")
        if mac:
            used.add(mac)
        lines.append(entry(text, label, mac))
    for m in vals_mac:
        mac, label = net.name_mac(m)
        if mac in used:
            continue
        lines.append(entry(net.ip_of_mac.get(mac, ""), label, mac))
    if not lines:
        return '<span class="dim">beliebig</span>'
    pin = ""
    if vals_ip and vals_mac:
        pin = ('<div class="pin" title="fw4 verlangt: IP in der Liste UND MAC in der Liste. '
               'Die Listen sind nicht paarweise verknuepft.">IP + MAC gepinnt</div>')
    return '<div class="inline">%s</div>%s' % ("".join(lines), pin)


def anchor_id(prefix, name):
    """Stable fragment id for a rule or set name (only [A-Za-z0-9_-] survive)."""
    return prefix + "".join(c if c.isalnum() or c in "_-" else "-" for c in name)


# ---------------------------------------------------------------- ipsets

FOLD_ABOVE = 8   # a set with more members than this starts folded


def ipset_infos(o, ipsets):
    """All `list ipset` entries of a rule, resolved (see ipset_info). AND-ed by fw4."""
    return [i for i in (ipset_info(v, ipsets) for v in o.get("ipset", [])) if i]


def ipset_info(val, ipsets):
    """One rule entry `ipset '<name> [!] [dir ...]'` + set definition -> resolved set or None.
    Field i of the set is matched in the direction the rule names for it (src/dest after the
    set name), else in the direction of the set's own `match` (src_/dest_ prefix, default src).
    `rows` are the members, one list of values per member (one value per field): the UCI
    `list entry` lines, or for a `loadfile` set the addresses read from that file."""
    val = (val or "").strip()
    if not val:
        return None
    toks = val.replace(",", " ").split()
    neg = toks[0].startswith("!") or (len(toks) > 1 and toks[1] == "!")
    name = toks[0].lstrip("!")
    dirs = [t for t in toks[1:] if t in ("src", "dest", "dst")]
    sec = ipsets.get(name)
    if not sec:
        return {"name": name, "negated": neg, "fields": [], "entries": [], "rows": [], "known": False,
                "loadfile": "", "file_entries": None}
    fields = []
    for i, m in enumerate(sec["opts"].get("match", [])):
        pre, _, typ = m.partition("_")
        if pre in ("src", "dst", "dest") and typ:
            d, t = ("src" if pre == "src" else "dest"), typ
        else:
            d, t = "src", m
        if i < len(dirs):
            d = "src" if dirs[i] == "src" else "dest"
        fields.append({"type": t, "dir": d})
    entries = [e.split() for e in sec["opts"].get("entry", [])]
    loadfile = (sec["opts"].get("loadfile") or [""])[0]
    file_entries = sec.get("file_entries") if loadfile else None
    rows = entries if not loadfile else [[e] for e in (file_entries or [])]
    return {"name": name, "negated": neg, "fields": fields, "entries": entries, "rows": rows,
            "known": True, "loadfile": loadfile, "file_entries": file_entries}


def set_kind(info):
    """-> ('pair'|'mac'|'net'|'ip'|'port'|'?', count label) from the set's fields and members."""
    types = [f["type"] for f in info["fields"]]
    n = len(info["rows"])
    if "mac" in types and ("ip" in types or "net" in types):
        kind, one, many = "pair", "Geraet", "Geraete"
    elif types == ["mac"]:
        kind, one, many = "mac", "Geraet", "Geraete"
    elif types == ["port"]:
        kind, one, many = "port", "Port", "Ports"
    elif types and set(types) <= {"ip", "net"}:
        slashes = ["/" in r[0] and not r[0].endswith("/32") for r in info["rows"] if r]
        if slashes and all(slashes):
            kind, one, many = "net", "Netz", "Netze"
        elif any(slashes):
            kind, one, many = "net", "Eintrag", "Eintraege (Adressen und Netze)"
        else:
            kind, one, many = "ip", "Adresse", "Adressen"
    else:
        kind, one, many = "?", "Eintrag", "Eintraege"
    return kind, "%d %s" % (n, one if n == 1 else many)


def set_member_rows(info, net):
    """Members of a set as entry lines (IP / name / MAC), in file/UCI order."""
    types = [f["type"] for f in info["fields"]]
    ipi = next((i for i, t in enumerate(types) if t in ("ip", "net")), None)
    maci = next((i for i, t in enumerate(types) if t == "mac"), None)
    out = []
    for row in info["rows"]:
        ip = row[ipi] if ipi is not None and ipi < len(row) else ""
        mac = row[maci].upper() if maci is not None and maci < len(row) else ""
        text, label = net.name_ip(ip) if ip else ("", "")
        if mac and not label:
            label = net.by_mac.get(mac, "")
        if mac and not ip:
            text = net.ip_of_mac.get(mac, "")
        if ipi is None and maci is None:
            text = " ".join(row)
        out.append(entry(text, label, mac))
    return "".join(out)


def set_card(info, net, where="rule", force_open=None):
    """One IPset as a card: header (SET badge, name -> appendix, count or file) and the member
    list below it. Folded when long or read from a file; the bar's checkbox folds/unfolds all."""
    if not info["known"]:
        return ('<div class="set unknown"><span class="sk">SET</span><code class="sn">%s</code>'
                '<span class="sc warn">nicht definiert</span></div>' % esc(info["name"]))
    kind, count = set_kind(info)
    body = set_member_rows(info, net)
    is_open = force_open if force_open is not None else (len(info["rows"]) <= FOLD_ABOVE and not info["loadfile"])
    head = ['<span class="sk">SET</span>']
    if info["negated"]:
        head.append('<span class="sneg">nicht in</span>')
    if where == "rule":
        head.append('<a class="sn" href="#%s" title="Definition im Anhang"><code>%s</code></a>'
                    % (anchor_id("set-", info["name"]), esc(info["name"])))
    else:
        head.append('<code class="sn">%s</code>' % esc(info["name"]))
    head.append('<span class="sc">%s</span>' % esc(count))
    if info["loadfile"]:
        if info["file_entries"] is None:
            head.append('<span class="sc warn">Datei nicht lesbar</span>')
        head.append('<span class="sf" title="option loadfile: Inhalt vom Geraet gelesen">Datei <code>%s</code></span>'
                    % esc(info["loadfile"]))
    if not body:
        body = '<div class="dim">keine Mitglieder</div>'
    named = ' named' if '<span class="lab">' in body.replace('<span class="lab"></span>', '') else ''
    return ('<details class="set %s%s"%s><summary>%s</summary><div class="members">%s</div></details>'
            % (kind, named, " open" if is_open else "", "".join(head), body))


def set_side(info):
    """-> set of sides ('src'/'dest') the set's fields are matched on."""
    return {f["dir"] for f in info["fields"]} or {"src"}


def join_and(parts):
    """Cell content from several AND-ed parts (inline addresses, set cards)."""
    parts = [p for p in parts if p]
    return '<div class="and">und</div>'.join(parts)


def ipset_cells_all(infos, net):
    """-> (src_parts, dest_parts, ports_html) for all sets of a rule, in rule order."""
    src, dest, ports = [], [], ""
    for info in infos:
        card = set_card(info, net)
        sides = set_side(info) if info["known"] else {"src"}
        if "src" in sides:
            src.append(card)
        if "dest" in sides:
            dest.append(card)
        pi = [i for i, f in enumerate(info["fields"]) if f["type"] == "port"]
        if pi:
            ports += "".join(chip(row[pi[0]], PORTS.get(row[pi[0]], "")) for row in info["rows"])
    return src, dest, ports


def set_members_text(infos):
    """Member values of all sets of a rule, for the filter haystack."""
    return " ".join(" ".join(row) for i in infos for row in i["rows"])


def ports_cell(ports):
    if not ports:
        return '<span class="dim">alle</span>'
    out = []
    for p in ports:
        for q in p.split():
            svc = PORTS.get(q, "")
            out.append(chip(q, svc))
    return "".join(out)


def action_cls(t):
    return {"ACCEPT": "acc", "REJECT": "rej", "DROP": "rej", "DNAT": "dnat"}.get(t.upper(), "oth")


def zone_label(z):
    return esc(z) if z else "—"


def extra_cell(r, kind):
    o, bits = r["o"], []
    fam = (o.get("family") or [""])[0]
    if fam:
        bits.append("family: " + fam)
    if (o.get("icmp_type") or []):
        bits.append("icmp-type: " + " ".join(o["icmp_type"]))
    for k, v in r["extra"].items():
        bits.append("%s: %s" % (k, " ".join(v)))
    return "".join('<div class="x">%s</div>' % esc(b) for b in bits) or '<span class="dim">—</span>'


def log_cell(o):
    if (o.get("log") or ["0"])[0] != "1":
        return '<span class="dim">—</span>'
    lim = (o.get("log_limit") or [""])[0]
    return '<span class="log" title="Logzeile mit Regelnamen als Praefix">log</span> %s' % esc(lim)


def row_html(r, net, ipsets, mode, rid):
    """One rule as a table row. Source/destination cells list the AND-ed parts: inline
    addresses (plain lines) and IPsets (cards), separated by 'und'."""
    o = r["o"]
    proto = " ".join(o.get("proto", [])) if o.get("proto") else ""
    infos = ipset_infos(o, ipsets)
    set_src, set_dest, set_ports = ipset_cells_all(infos, net)
    has_src = bool(o.get("src_ip") or o.get("src_mac"))
    if mode == "redirect":
        dest_cell = addr_cell(o.get("dest_ip", []), [], net)
        dest_cell += '<div class="grp"><span class="k">Port</span>%s</div>' % ports_cell(o.get("dest_port", []))
        src_cell = join_and([addr_cell(o.get("src_ip", []), o.get("src_mac", []), net) if (has_src or not set_src) else ""]
                            + set_src)
        port_cell = ports_cell(o.get("src_dport", []))
    else:
        if mode == "forward":
            dest_cell = '<div class="zone"><span class="zk">Zone</span>%s</div>' % zone_label(r["dest"])
        else:
            dest_cell = '<div class="zone"><span class="zk">Ziel</span>Router</div>'
        parts = []
        if o.get("dest_ip"):
            parts.append(addr_cell(o["dest_ip"], [], net))
        elif mode == "forward" and not set_dest:
            parts.append('<div class="dim">alle Adressen</div>')
        dest_cell += join_and(parts + set_dest)
        src_cell = join_and([addr_cell(o.get("src_ip", []), o.get("src_mac", []), net) if (has_src or not set_src) else ""]
                            + set_src)
        port_cell = ports_cell(o.get("dest_port", [])) if (o.get("dest_port") or not set_ports) else ""
        port_cell += set_ports
    status = '<span class="st on">aktiv</span>' if r["enabled"] else '<span class="st off">deaktiviert</span>'
    cls = "r %s%s" % (action_cls(r["target"]), "" if r["enabled"] else " dis")
    hay = " ".join([r["name"], r["src"], r["dest"], proto, set_members_text(infos)] + sum(o.values(), []))
    num = ('<td class="n" title="UCI-Reihenfolge gesamt: %d">%s</td>'
           % (r["pos"], r["cpos"] if r.get("cpos") else '<span title="deaktiviert: nicht in der Kette">–</span>'))
    cols = (num + '<td>%s</td><td class="nm"><b>%s</b></td><td><span class="act %s">%s</span></td>'
            '<td class="ad">%s</td>' % (status, esc(r["name"]), action_cls(r["target"]), esc(r["target"]), src_cell))
    cols += ('<td class="ad">%s</td>' % dest_cell + "<td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
             % (esc(proto) or '<span class="dim">alle</span>', port_cell, log_cell(o), extra_cell(r, mode)))
    return '<tr class="%s" id="%s" data-s="%s">%s</tr>' % (cls, esc(rid), esc(hay.lower()), cols)


def rule_ids(rows):
    """-> {id(row): fragment id}; duplicate names get the UCI index appended."""
    seen, out = {}, {}
    for r in rows:
        base = anchor_id("r-", r["name"] or "unnamed")
        seen[base] = seen.get(base, 0) + 1
        out[id(r)] = base if seen[base] == 1 else "%s-%d" % (base, r["pos"])
    return out


def sets_used_by(rows):
    """-> {set name: [rule rows that reference it]} in UCI order."""
    out = {}
    for r in rows:
        for v in r["o"].get("ipset", []):
            nm = v.replace(",", " ").split()[0].lstrip("!") if v.strip() else ""
            if nm and r not in out.setdefault(nm, []):
                out[nm].append(r)
    return out


def note_row(text):
    return '<tr class="note"><td colspan="10">%s</td></tr>' % text


def table_html(title, rows_html, mode, before=(), after=()):
    """rows_html are the rule rows in chain order; before/after are note rows for what the chain
    holds outside UCI (nft includes) and for the zone default that follows the last rule."""
    dest_h = "Ziel" if mode != "redirect" else "Umleitung nach"
    port_h = "Ziel-Port" if mode != "redirect" else "Port (Quelle)"
    return ('<h3>%s <span class="cnt">%d</span></h3><div class="scroll"><table>'
            '<thead><tr><th title="Reihenfolge in der Kette: die erste passende Regel gewinnt">#</th><th>Status</th><th>Regel</th><th>Aktion</th><th>Quelle</th>'
            '<th>%s</th><th>Proto</th><th>%s</th><th>Log</th><th>Zusatz</th></tr></thead><tbody>%s%s%s</tbody></table></div>'
            % (esc(title), len(rows_html), dest_h, port_h, "".join(before), "".join(rows_html), "".join(after)))


CSS = """
:root{--bg:#fbfaf8;--fg:#1c1b19;--muted:#5c5a55;--rule:#ddd9d2;--code:#f2efe9;--head:#efece5;--stripe:#f6f4ef;
--accept:#1a7d3c;--reject:#b3311c;--dnat:#1d5fa8;--warn:#9a6a00;--accent:#7a4b1e;--set:#5b4b9e;--setbg:#efecf7}
@media (prefers-color-scheme:dark){:root{--bg:#1b1a18;--fg:#e6e3dd;--muted:#9d9890;--rule:#38352f;--code:#262420;
--head:#262420;--stripe:#201e1b;--accept:#5fbf7f;--reject:#e8776a;--dnat:#6fa8e8;--warn:#d9a441;--accent:#d3a06a;
--set:#b3a4ea;--setbg:#26233a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
#wrap{max-width:112rem;margin:0 auto;padding:1rem 16px 5rem}
h1{margin:.2rem 0;font-size:1.5rem}h2{margin:2.2rem 0 .3rem;padding-top:.8rem;border-top:2px solid var(--rule);font-size:1.25rem}
h3{margin:1.2rem 0 .4rem;font-size:1rem}
h2[id]{scroll-margin-top:calc(var(--bar-h,9rem) + .5rem)}.cnt{background:var(--head);border-radius:9px;padding:0 .5rem;font-size:.8rem;color:var(--muted)}
.sub,.dim,.meta{color:var(--muted)}.meta{margin:.2rem 0 .6rem;font-size:.85rem}
#bar{position:sticky;top:0;z-index:5;background:var(--bg);padding:.5rem 0;border-bottom:1px solid var(--rule)}
#bar a{margin-right:.7rem;color:var(--accent);text-decoration:none;white-space:nowrap}
#bar input[type=search]{padding:.3rem .5rem;border:1px solid var(--rule);background:var(--code);color:var(--fg);border-radius:4px;width:min(24rem,100%)}
.stats span{margin-right:1rem}.warnbox{border:1px solid var(--warn);border-left-width:5px;padding:.4rem .8rem;margin:.8rem 0}
.legend{font-size:.85rem;color:var(--muted)}.legend .act{margin-right:.2rem}
.scroll{overflow-x:auto;border:1px solid var(--rule)}table{border-collapse:collapse;width:100%;min-width:62rem}
th,td{padding:.35rem .5rem;border-bottom:1px solid var(--rule);text-align:left;vertical-align:top}
th{background:var(--head);position:sticky;top:0;font-size:.8rem;white-space:nowrap}tbody tr:nth-child(even){background:var(--stripe)}
td.n{color:var(--muted);text-align:right}td.nm{min-width:12rem;overflow-wrap:anywhere}
tr.r td:first-child{border-left:5px solid var(--muted)}tr.acc td:first-child{border-left-color:var(--accept)}
tr.rej td:first-child{border-left-color:var(--reject)}tr.dnat td:first-child{border-left-color:var(--dnat)}
tr.dis td{opacity:.55}tr.dis td.nm b{text-decoration:line-through}
.act{font-weight:600;font-size:.8rem}.act.acc{color:var(--accept)}.act.rej{color:var(--reject)}.act.dnat{color:var(--dnat)}
.st{font-size:.75rem;border-radius:4px;padding:0 .35rem;border:1px solid}.st.on{color:var(--accept)}.st.off{color:var(--warn)}
.grp{margin:.1rem 0}.k{display:inline-block;min-width:2.6rem;font-size:.7rem;color:var(--muted);text-transform:uppercase}
.chip{display:inline-block;margin:0 .25rem .15rem 0;padding:0 .35rem;background:var(--code);border-radius:4px;border:1px solid var(--rule)}
.chip code{font:12px ui-monospace,Consolas,monospace}.chip .lab{margin-left:.35rem;color:var(--muted);font-size:.8rem}
td.ad{min-width:20rem}
.ent{display:grid;grid-template-columns:max-content max-content max-content;gap:0 .7rem;align-items:baseline;margin:.1rem 0;white-space:nowrap}
.ent code{font:12px ui-monospace,Consolas,monospace}.ent .lab{color:var(--fg);font-weight:600;font-size:.85rem}
.ent code.mac{color:var(--muted)}.ent code:empty,.ent .lab:empty{display:none}
.inline{margin:.1rem 0}.pin{font-size:.75rem;color:var(--warn)}
.zone{font-weight:600;margin-bottom:.15rem}.zk{display:inline-block;margin-right:.4rem;padding:0 .3rem;border-radius:3px;
background:var(--head);color:var(--muted);font-size:.65rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;vertical-align:middle}
/* IPset card: header = SET badge, name, count/file; members indented below a guide line */
.set{margin:.25rem 0;padding:.2rem .5rem .25rem .45rem;border-left:3px solid var(--set);border-radius:0 5px 5px 0;background:var(--setbg)}
.set>summary{list-style:none;cursor:pointer;white-space:nowrap;display:flex;align-items:baseline;gap:.45rem;flex-wrap:wrap}
.set>summary::-webkit-details-marker{display:none}
.set>summary::before{content:"\\25B8";color:var(--set);font-size:.8rem;width:.6rem;flex:none}
.set[open]>summary::before{content:"\\25BE"}
.sk{display:inline-block;padding:0 .3rem;border-radius:3px;background:var(--set);color:var(--bg);font-size:.65rem;font-weight:700;letter-spacing:.06em}
.sn{text-decoration:none}.sn code,code.sn{font:600 12.5px ui-monospace,Consolas,monospace;color:var(--set)}
a.sn:hover code{text-decoration:underline}
.sc{font-size:.75rem;color:var(--muted)}.sc.warn{color:var(--warn);font-weight:600}
.sf{font-size:.75rem;color:var(--muted)}.sf code{font:11.5px ui-monospace,Consolas,monospace}
.sneg{color:var(--reject);font-weight:700;font-size:.8rem}
.members{margin:.15rem 0 0 .25rem;padding-left:.55rem;border-left:1px dotted var(--set)}
.set.unknown{border-left-color:var(--warn);background:transparent}
.and{margin:.15rem 0 .15rem .3rem;font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.log{background:var(--head);border-radius:4px;padding:0 .3rem;font-size:.75rem}.x{font-size:.8rem;color:var(--muted)}
.zinfo{margin:.1rem 0 .6rem;color:var(--muted);font-size:.85rem}
table.small td,table.small th{font-size:.85rem}table.sets td.ad{min-width:18rem}
table.sets .set.net:not(.named) .members,table.sets .set.ip:not(.named) .members{columns:4 9rem;column-gap:1rem}
table.sets .members .ent{break-inside:avoid}table.sets td.nw{white-space:nowrap}
tr.note td{font-size:.8rem;color:var(--muted);font-style:italic;background:var(--head)}
.uses a{margin-right:.5rem;color:var(--accent);text-decoration:none;white-space:nowrap}.uses a:hover{text-decoration:underline}
.legend .sk{vertical-align:middle}
@media print{#bar{display:none}.scroll{overflow:visible}tr.dis{display:table-row}.set>summary::before{content:""}}
"""

JS = """
(function(){
var bar=document.getElementById('bar');
function bh(){document.documentElement.style.setProperty('--bar-h',bar.offsetHeight+'px');}
bh();window.addEventListener('resize',bh);
var q=document.getElementById('q'),h=document.getElementById('hide'),f=document.getElementById('fold');
function apply(){var t=q.value.trim().toLowerCase();document.querySelectorAll('tr.r').forEach(function(r){
var ok=(!t||r.getAttribute('data-s').indexOf(t)>=0)&&!(h.checked&&r.classList.contains('dis'));
r.style.display=ok?'':'none';});}
function sets(open){document.querySelectorAll('tr.r details.set').forEach(function(d){d.open=open;});}
q.addEventListener('input',apply);h.addEventListener('change',apply);
f.addEventListener('change',function(){sets(!f.checked);});
var saved=[];window.addEventListener('beforeprint',function(){saved=[];document.querySelectorAll('details.set').forEach(
function(d){saved.push([d,d.open]);d.open=true;});});
window.addEventListener('afterprint',function(){saved.forEach(function(p){p[0].open=p[1];});});})();
"""


def render(zones, ipsets, rules, redirs, warns, fw, net, host, stamp):
    zinfo = {z["opts"]["name"][0]: z for z in zones}
    fwd_map = {}
    for s in fw:
        if s["type"] == "forwarding":
            fwd_map.setdefault(s["opts"]["src"][0], []).append(s["opts"]["dest"][0])
    defaults = next((s["opts"] for s in fw if s["type"] == "defaults"), {})
    srcs = sorted({r["src"] for r in rules + redirs if r["src"]} | set(zinfo), key=zone_key)
    active = sum(1 for r in rules if r["enabled"])
    logged = sum(1 for r in rules if (r["o"].get("log") or ["0"])[0] == "1")
    nav = "".join('<a href="#z-%s">%s</a>' % (esc(z), esc(z)) for z in srcs) + '<a href="#anhang">Anhang</a>'
    rid = rule_ids(rules + redirs)
    used_by = sets_used_by(rules + redirs)
    out = ['<!doctype html><html lang="de"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width,initial-scale=1">'
           '<title>Firewall-Regeln</title><style>%s</style></head><body><div id="wrap">' % CSS,
           '<h1>Firewall-Regeln</h1><div class="meta">Quelle: %s &middot; Stand %s &middot; fwview %s &middot; '
           'Spiegel zum Lesen, nicht Quelle: bei Abweichung gilt das Geraet. Enthaelt echte IPs/MACs, nicht veroeffentlichen.</div>'
           % (esc(host), esc(stamp), VERSION),
           '<div id="bar"><div>%s</div><div style="margin-top:.4rem"><input id="q" type="search" '
           'placeholder="Filter: Name, IP, MAC, Port, Zone, Set-Mitglied ..."> <label><input id="hide" type="checkbox"> '
           'deaktivierte ausblenden</label> <label><input id="fold" type="checkbox"> Set-Mitglieder einklappen</label>'
           '</div></div>' % nav,
           '<p class="stats"><span><b>%d</b> Regeln</span><span><b>%d</b> aktiv</span><span><b>%d</b> deaktiviert</span>'
           '<span><b>%d</b> mit Log</span><span><b>%d</b> DNAT-Umleitungen</span></p>'
           % (len(rules), active, len(rules) - active, logged, len(redirs)),
           '<p class="legend"><span class="act acc">ACCEPT</span> erlaubt &middot; <span class="act rej">REJECT/DROP</span> '
           'gesperrt &middot; <span class="act dnat">DNAT</span> umgeleitet. <b>#</b> = Reihenfolge im Regelwerk '
           '(Nummer in der Kette; die erste passende Regel gewinnt, danach der Zonen-Standard; deaktivierte Regeln haben keine Nummer). Mehrere Werte in einem Feld '
           'sind ODER-verknuepft, verschiedene Felder UND-verknuepft. Standard: input=%s, forward=%s, output=%s. '
           'Adressen direkt in der Regel stehen als Klartextzeilen; ein <span class="sk">SET</span> ist ein IPset '
           '(Karte, Mitglieder darunter eingerueckt, Name verweist auf die Definition im Anhang); '
           '<i>und</i> trennt mehrere Bedingungen einer Seite.</p>'
           % (esc(" ".join(defaults.get("input", ["?"]))), esc(" ".join(defaults.get("forward", ["?"]))),
              esc(" ".join(defaults.get("output", ["?"]))))]
    if warns:
        out.append('<div class="warnbox"><b>Auffaelligkeiten (%d)</b><ul>%s</ul></div>'
                   % (len(warns), "".join("<li>%s</li>" % esc(w) for w in warns)))
    for z in srcs:
        zi = zinfo.get(z, {"opts": {}})["opts"]
        nets = ", ".join("%s (%s)" % (n, ", ".join(str(sn) for sn, zz in net.subnets if zz == z) or "?")
                         for n in zi.get("network", [])) or "—"
        info = "Netz: %s &middot; Zonen-Standard input=%s forward=%s &middot; Weiterleitung erlaubt nach: %s%s" % (
            esc(nets), esc((zi.get("input") or ["?"])[0]), esc((zi.get("forward") or ["?"])[0]),
            esc(", ".join(fwd_map.get(z, [])) or "nirgends (nur durch Regeln)"),
            " &middot; Masquerading" if (zi.get("masq") or ["0"])[0] == "1" else "")
        out.append('<h2 id="z-%s">Quelle: %s</h2><div class="zinfo">%s</div>' % (esc(z), esc(z), info))
        # chain order = UCI order (fw4 emits the rules of a chain in file order, whatever the destination)
        inp = [r for r in rules if r["src"] == z and not r["dest"]]
        fwd = [r for r in rules if r["src"] == z and r["dest"]]
        red = [r for r in redirs if r["src"] == z]
        for lst in (inp, fwd, red):
            n = 0
            for r in lst:
                if r["enabled"]:
                    n += 1
                    r["cpos"] = n
                else:
                    r["cpos"] = 0

        def incl_rows(chain, where):
            return [note_row("nft-Include <code>%s</code> (<code>%s</code>) %s dieser Kette"
                             % (esc(x["id"]), esc((x["opts"].get("path") or ["?"])[0]),
                                "vor den Regeln" if where == "chain-prepend" else "nach den Regeln"))
                    for x in fw if x["type"] == "include" and (x["opts"].get("chain") or [""])[0] == chain
                    and (x["opts"].get("position") or [""])[0] == where]

        def default_row(kind):
            return [note_row("danach: Zonen-Standard <b>%s</b>%s" % (
                esc((zi.get(kind) or ["?"])[0]),
                " (mit Zonen-Log, %s)" % esc((zi.get("log_limit") or [""])[0]) if (zi.get("log") or ["0"])[0] == "1" else ""))]
        if inp:
            out.append(table_html("Eingehend am Router (INPUT)", [row_html(r, net, ipsets, "input", rid[id(r)]) for r in inp], "input",
                                  incl_rows("input_" + z, "chain-prepend"),
                                  incl_rows("input_" + z, "chain-append") + default_row("input")))
        if fwd:
            out.append(table_html("Weiterleitung (FORWARD)", [row_html(r, net, ipsets, "forward", rid[id(r)]) for r in fwd], "forward",
                                  incl_rows("forward_" + z, "chain-prepend"),
                                  incl_rows("forward_" + z, "chain-append") + default_row("forward")))
        if red:
            out.append(table_html("DNAT-Umleitungen", [row_html(r, net, ipsets, "redirect", rid[id(r)]) for r in red], "redirect"))
        if not (inp or fwd or red):
            out.append('<p class="dim">Keine Regeln: es gilt nur der Zonen-Standard.</p>')
    # appendix
    out.append('<h2 id="anhang">Anhang</h2><h3>Zonen</h3><div class="scroll"><table class="small"><thead><tr>'
               '<th>Zone</th><th>Netze</th><th>input</th><th>forward</th><th>output</th><th>Masq</th><th>Log (Zone)</th></tr></thead><tbody>')
    for z in sorted(zinfo, key=zone_key):
        o = zinfo[z]["opts"]
        g = lambda k: (o.get(k) or ["—"])[0]
        out.append("<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(z), esc(", ".join(o.get("network", []) + o.get("device", []))), esc(g("input")), esc(g("forward")),
            esc(g("output")), "ja" if g("masq") == "1" else "—",
            esc(g("log_limit")) if g("log") == "1" else "—"))
    out.append("</tbody></table></div>")
    if fwd_map:
        out.append("<h3>Zonen-Weiterleitungen (<code>config forwarding</code>)</h3><ul>%s</ul>" % "".join(
            "<li>%s &rarr; %s</li>" % (esc(s), esc(", ".join(d))) for s, d in sorted(fwd_map.items())))
    if ipsets:
        out.append('<h3 id="ipsets">IPsets <span class="cnt">%d</span></h3>'
                   '<p class="dim">Sets sind WER (Geraete, Netze), Regeln sind WAS. Mitglieder wie vom Geraet geladen: '
                   '<code>list entry</code> aus der UCI-Konfiguration oder der Inhalt der <code>loadfile</code>-Datei '
                   '(Kommentare entfernt; Quelle der Dateien: Repo <code>scripts/sets/</code>).</p>'
                   '<div class="scroll"><table class="small sets"><thead><tr><th>Set</th><th>Familie</th><th>Felder</th>'
                   '<th>Herkunft</th><th>Mitglieder</th><th>Genutzt von</th></tr></thead><tbody>' % len(ipsets))
        for nm, s in ipsets.items():
            o = s["opts"]
            info = ipset_info(nm, ipsets)
            by_dir = {}
            for f in info["fields"]:
                by_dir.setdefault("Quelle" if f["dir"] == "src" else "Ziel", []).append(
                    {"ip": "IP", "net": "Netz", "mac": "MAC", "port": "Port"}.get(f["type"], f["type"]))
            fields = "; ".join("%s: %s" % (d, " + ".join(t)) for d, t in by_dir.items()) or "—"
            origin = ('Datei <code>%s</code>' % esc(info["loadfile"])) if info["loadfile"] else '<code>list entry</code> (UCI)'
            uses = used_by.get(nm, [])
            uses_html = (" ".join('<a href="#%s">%s</a>' % (esc(rid[id(r)]), esc(r["name"])) for r in uses)
                         if uses else '<span class="sc warn">keine Regel</span>')
            out.append('<tr id="%s"><td><code class="sn">%s</code></td><td>%s</td><td class="nw">%s</td><td>%s</td>'
                       '<td class="ad">%s</td><td class="uses">%s</td></tr>' % (
                           anchor_id("set-", nm), esc(nm), esc((o.get("family") or ["?"])[0]), esc(fields), origin,
                           set_card(info, net, where="appendix", force_open=True), uses_html))
        out.append("</tbody></table></div>")
    inc = [s for s in fw if s["type"] == "include"]
    if inc:
        out.append("<h3>nft-Includes (Regeln ausserhalb von UCI)</h3><div class='scroll'><table class='small'><thead><tr>"
                   "<th>Name</th><th>Datei</th><th>Kette</th><th>Position</th></tr></thead><tbody>")
        for s in inc:
            o = s["opts"]
            g = lambda k: (o.get(k) or ["—"])[0]
            out.append("<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
                esc(s["id"]), esc(g("path")), esc(g("chain")), esc(g("position"))))
        out.append("</tbody></table></div>")
    out.append("<script>%s</script></div></body></html>" % JS)
    return "".join(out)


# ---------------------------------------------------------------- json report

SEMANTICS = [
    "Packets are checked per chain; the first matching rule decides. chain_position is the rule's place in its chain (1 = checked first; null = disabled, not in the chain); uci_index is its place in the whole UCI file. After the last rule the zone default (zones[].input / forward) applies.",
    "Values inside one list field (src_ip, dest_port, proto ...) are ORed; different fields of one rule are ANDed.",
    "direction 'input' = traffic to the router itself, 'forward' = traffic routed between zones, 'dnat' = redirect.",
    "Zone defaults apply when no rule matches (see zones[].input / forward). 'REJECT' answers, 'DROP' is silent.",
    "src_ip and src_mac of one rule are independent lists (not pairs): a packet needs an IP from the first AND a MAC from the second.",
    "A rule with enabled=false (name prefix DISABLED-) has no effect.",
    "An empty list/null means 'any'. Device names come from the router's DHCP reservations, not from the rule.",
    "Each entry of a rule's 'ipsets' adds a further AND-condition ('ipset' is the first one, kept for older readers). "
    "Its fields (see fields: matched_on source/destination) apply to the packet's source or destination; entries of one set "
    "are ORed. With paired_fields=true each entry is one tuple (e.g. IP and MAC of the same device) and the packet must match "
    "a whole tuple, unlike separate src_ip/src_mac lists. Several sets in one rule: the packet must match every set.",
    "A set with a loadfile keeps its members in loadfile_entries (read from the file on the device, comments dropped) "
    "and has an empty entries list; entry_count counts whichever applies. loadfile_entries null with a loadfile set "
    "means the file could not be read (see warnings): the set is then empty on the device.",
]


def ent_json(net, ips, macs):
    """Sources/destinations as a list of devices: ip, name, mac (resolved where known)."""
    out, used = [], set()
    for v in ips:
        text, label = net.name_ip(v)
        mac = net.mac_of_ip.get(v, "")
        if mac:
            used.add(mac)
        out.append({"ip": text, "name": label or None, "mac": mac or None})
    for m in macs:
        mac, label = net.name_mac(m)
        if mac in used:
            continue
        out.append({"ip": net.ip_of_mac.get(mac) or None, "name": label or None, "mac": mac})
    return out


def ipset_json(info, net):
    if not info:
        return None
    rows = []
    for row in info["entries"]:
        d = {}
        for f, v in zip(info["fields"], row):
            d[f["type"]] = v.upper() if f["type"] == "mac" else v
        ip = d.get("ip") or d.get("net")
        d["name"] = (net.name_ip(ip)[1] if ip else net.by_mac.get(d.get("mac", ""), "")) or None
        rows.append(d)
    return {"name": info["name"], "negated": info["negated"], "defined": info["known"],
            "loadfile": info.get("loadfile") or None,
            "fields": [{"type": f["type"], "matched_on": "source" if f["dir"] == "src" else "destination"}
                       for f in info["fields"]],
            "paired_fields": len(info["fields"]) > 1,
            "entries": rows,
            "loadfile_entries": info.get("file_entries") if info.get("loadfile") else None,
            "entry_count": len(info["rows"])}


def port_list(ports):
    return [{"port": q, "service": PORTS.get(q)} for p in ports for q in p.split()]


def json_report(zones, ipsets, rules, redirs, warns, fw, net, host, stamp):
    zinfo = {z["opts"]["name"][0]: z["opts"] for z in zones}
    g = lambda o, k: (o.get(k) or [None])[0]
    out_rules, counters = [], {}
    for r in rules + redirs:
        o = r["o"]
        is_redir = "src_dport" in o or r["target"].upper() == "DNAT"
        direction = "dnat" if is_redir else ("forward" if r["dest"] else "input")
        item = {
            "name": r["name"], "uci_index": r["pos"], "direction": direction,
            "chain": ("%s_%s" % (direction, r["src"])) if direction != "dnat" else "dstnat_%s" % r["src"],
            "enabled": r["enabled"], "action": r["target"],
            "src_zone": r["src"] or None,
            "dest_zone": ("router" if direction == "input" else r["dest"]) if direction != "dnat" else None,
            "source": ent_json(net, o.get("src_ip", []), o.get("src_mac", [])),
            "source_is_ip_and_mac_pinned": bool(o.get("src_ip") and o.get("src_mac")),
            "destination": ent_json(net, [] if is_redir else o.get("dest_ip", []), []),
            "ipsets": [ipset_json(i, net) for i in ipset_infos(o, ipsets)],
            "ipset": ipset_json((ipset_infos(o, ipsets) or [None])[0], net),
            "protocols": o.get("proto", []),
            "ports": port_list(o.get("src_dport" if is_redir else "dest_port", [])),
            "icmp_types": o.get("icmp_type", []),
            "family": g(o, "family"),
            "log": g(o, "log") == "1", "log_limit": g(o, "log_limit"),
            "other_options": r["extra"],
        }
        if is_redir:
            item["redirect_to"] = ent_json(net, o.get("dest_ip", []), [])[:1]
            item["redirect_to_port"] = port_list(o.get("dest_port", []))
        key = item["chain"]
        if r["enabled"]:
            counters[key] = counters.get(key, 0) + 1
        item["chain_position"] = counters[key] if r["enabled"] else None
        out_rules.append(item)
    fwd = [{"src": x["opts"]["src"][0], "dest": x["opts"]["dest"][0]} for x in fw if x["type"] == "forwarding"]
    defaults = next((x["opts"] for x in fw if x["type"] == "defaults"), {})
    used_by = sets_used_by(rules + redirs)
    rep = {
        "report": {"tool": "fwview", "version": VERSION, "generated": stamp, "source": host,
                   "device": "OpenWrt One router (fw4/nftables), zones = VLANs; see docs/firewall-rules.md",
                   "note": "Mirror for analysis, not a source. Contains real IPs/MACs."},
        "how_to_read": SEMANTICS,
        "summary": {"rules": len(rules), "enabled": sum(1 for r in rules if r["enabled"]),
                    "disabled": sum(1 for r in rules if not r["enabled"]),
                    "logging": sum(1 for r in rules if (r["o"].get("log") or ["0"])[0] == "1"),
                    "redirects": len(redirs), "warnings": len(warns),
                    "rules_per_source_zone": {z: sum(1 for r in rules + redirs if r["src"] == z)
                                              for z in sorted({r["src"] for r in rules + redirs}, key=zone_key)}},
        "defaults": {k: " ".join(v) for k, v in defaults.items()},
        "zones": [{"name": n, "networks": o.get("network", []) + o.get("device", []),
                   "subnets": [str(sn) for sn, zz in net.subnets if zz == n],
                   "input": g(o, "input"), "forward": g(o, "forward"), "output": g(o, "output"),
                   "masquerade": g(o, "masq") == "1", "log": g(o, "log") == "1", "log_limit": g(o, "log_limit")}
                  for n, o in sorted(zinfo.items(), key=lambda kv: zone_key(kv[0]))],
        "zone_forwardings": fwd,
        "rules": out_rules,
        "ipsets": [{"name": n, "family": g(s["opts"], "family"), "match": " ".join(s["opts"].get("match", [])),
                    "loadfile": g(s["opts"], "loadfile"),
                    "entries": s["opts"].get("entry", []),
                    "loadfile_entries": s.get("file_entries") if s["opts"].get("loadfile") else None,
                    "entry_count": len(s["opts"].get("entry", [])) if not s["opts"].get("loadfile") else len(s.get("file_entries") or []),
                    "used_by": [r["name"] for r in used_by.get(n, [])]} for n, s in ipsets.items()],
        "nft_includes": [{"name": x["id"], "path": g(x["opts"], "path"), "chain": g(x["opts"], "chain"),
                          "position": g(x["opts"], "position")} for x in fw if x["type"] == "include"],
        "warnings": warns,
        "known_devices": [{"name": nm, "ip": ip, "mac": net.mac_of_ip.get(ip)} for ip, nm in sorted(net.by_ip.items())],
    }
    return json.dumps(rep, ensure_ascii=False, indent=2) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Firewallregeln als HTML-Seite (read-only)")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--from-dir")
    ap.add_argument("--out")
    ap.add_argument("--json")
    a = ap.parse_args()
    get = (lambda w: read_dir(a.from_dir, w)) if a.from_dir else (lambda w: fetch(a.host, w))
    fw = parse_uci(get("firewall"))
    dhcp = parse_uci(get("dhcp"))
    network = parse_uci(get("network"))
    if not any(s["type"] == "rule" for s in fw):
        sys.exit("fwview: keine Regeln im Export gefunden")
    zones = [s for s in fw if s["type"] == "zone"]
    net = Net(dhcp, network, zones)
    zones, ipsets, rules, redirs, warns = build(fw, net)
    get_files = (lambda ps: read_dir_files(a.from_dir, ps)) if a.from_dir else (lambda ps: fetch_files(a.host, ps))
    warns += attach_setfiles(ipsets, get_files)
    warns += check_set_match(ipsets)
    setflags = read_dir_setflags(a.from_dir) if a.from_dir else fetch_setflags(a.host)
    if setflags is not None:
        warns += check_set_runtime(ipsets, setflags)
    now = datetime.datetime.now()
    out = a.out or "fwview-%s.html" % now.strftime("%Y%m%d-%H%M")
    page = render(zones, ipsets, rules, redirs, warns, fw, net,
                  a.from_dir or a.host, now.strftime("%Y-%m-%d %H:%M"))
    jout = a.json or (out[:-5] if out.endswith(".html") else out) + ".json"
    report = json_report(zones, ipsets, rules, redirs, warns, fw, net,
                         a.from_dir or a.host, now.strftime("%Y-%m-%d %H:%M"))
    with open(out, "w", encoding="utf-8") as f:
        f.write(page)
    with open(jout, "w", encoding="utf-8") as f:
        f.write(report)
    print("fwview: %d Regeln (%d deaktiviert), %d Umleitungen, %d Auffaelligkeiten -> %s, %s"
          % (len(rules), sum(1 for r in rules if not r["enabled"]), len(redirs), len(warns), out, jout))


if __name__ == "__main__":
    main()
