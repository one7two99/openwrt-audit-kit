#!/usr/bin/env python3
"""fwlog-audit.py 1.0.0 -- tables for a firewall-log audit of the router, read-only.

Reads the router's persistent system log (`/mnt/nvme/log/system.log`, section 13 of the
network documentation) over SSH or from a saved copy, keeps the firewall lines
(`kern.warn kernel: ... <prefix>: IN=... OUT=... SRC=... DST=... PROTO=...`) from a start
time on, and writes the analysis tables as Markdown: lines per log class and day, hourly
profile, top sources/destinations/pairs per class, INPUT noise per zone, lateral traffic
between zones, egress blocks per rule, rate-limit saturation (minutes at the limit = lines
lost), scan indicators (many ports or hosts from one source), pairs seen on one day only.

The tables are the DATA of an audit report (docs/audits/); the findings and proposals are
written by hand. Rerun with the same --since on a later log to compare against the baseline.
Device names come from the router's DHCP reservations (same resolver as fwview.py).

Usage:  scripts/fwlog-audit.py --since '2026-10-12 00:00' [--host root@192.168.30.1] [--out FILE]
        scripts/fwlog-audit.py --since '2026-10-12 00:00' --from-dir DIR [--out FILE]
  --since     start of the audit window, local router time ('YYYY-MM-DD HH:MM')
  --until     end of the window (default: last line)
  --host      SSH target, read-only (`cat` of the log, `uci export dhcp|network|firewall`)
  --from-dir  read system.log, dhcp.uci, network.uci, firewall.uci from DIR instead
  --out       Markdown file (default ./fwlog-audit-<since>.md)
  --top N     rows per top-N table (default 12)

Exit codes: 0 ok, 1 read error / no firewall lines, 2 usage. Python 3 standard library only.
"""
import argparse
import collections
import datetime
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwview  # noqa: E402  (parse_uci, Net, SSH, PORTS)

VERSION = "1.0.0"
LOG_PATH = "/mnt/nvme/log/system.log"

# Ports that explain most LAN noise, in addition to fwview.PORTS (service ports of the rule set).
NOISE_PORTS = {
    "137": "NetBIOS-NS", "138": "NetBIOS-DGM", "1900": "SSDP", "5351": "NAT-PMP/PCP", "5353": "mDNS",
    "5355": "LLMNR", "3702": "WS-Discovery", "1982": "Yeelight", "6667": "Tuya-Broadcast",
    "7": "Echo", "68": "DHCP-Client", "546": "DHCPv6-Client", "547": "DHCPv6-Server",
    "17500": "Dropbox-LAN-Sync", "21027": "Syncthing-Discovery", "32412": "Plex-GDM", "32414": "Plex-GDM",
    "8008": "Chromecast", "8009": "Chromecast", "10001": "Ubiquiti-Discovery", "3478": "STUN",
    "41641": "Tailscale", "1194": "OpenVPN", "500": "IKE", "4500": "IPsec-NAT-T", "993": "IMAPS",
    "5228": "Google-Push", "5223": "Apple-Push", "123": "NTP", "853": "DoT",
}
# Limits per log class, as configured (docs/firewall-rules.md, Logging): rules 6/min, zones 10/min,
# the collective include 20/min burst 30. Used for the saturation table only.
LIMITS = {"rule": 6, "zone-in": 10, "zone-fwd": 10, "zone-out": 10, "collective": 20}

LINE = re.compile(r"^(\w{3} \w{3} {1,2}\d{1,2} \d\d:\d\d:\d\d \d{4}) kern\.warn kernel: \[[\d. ]+\] (.+?): IN=(\S*) OUT=(\S*) (.*)$")
KV = re.compile(r"(\w+)=(\S*)")


def when(s):
    return datetime.datetime.strptime(" ".join(s.split()), "%a %b %d %H:%M:%S %Y")


def classify(prefix):
    m = re.match(r"reject (\w+) (in|forward|out)$", prefix)
    if m:
        return {"in": "zone-in", "forward": "zone-fwd", "out": "zone-out"}[m.group(2)], m.group(1)
    if prefix == "fw4 forward-reject":
        return "collective", ""
    if prefix.startswith(("Block-", "Mute-")):
        return "rule", prefix.split("-")[1]
    if prefix.startswith("drop ") and "invalid" in prefix:
        return "invalid", prefix.split()[1]
    return "other", ""


def read_all(a):
    if a.from_dir:
        def get(name):
            try:
                return open(os.path.join(a.from_dir, name), encoding="utf-8", errors="replace").read()
            except OSError as e:
                sys.exit("fwlog-audit: %s" % e)
        return get("system.log"), get("dhcp.uci"), get("network.uci"), get("firewall.uci")

    def ssh(cmd):
        r = subprocess.run(fwview.SSH + [a.host, cmd], capture_output=True, text=True, errors="replace")
        if r.returncode != 0 or not r.stdout:
            sys.exit("fwlog-audit: '%s' auf %s fehlgeschlagen: %s" % (cmd, a.host, r.stderr.strip() or "leer"))
        return r.stdout
    return (ssh("cat " + LOG_PATH), ssh("uci export dhcp"), ssh("uci export network"), ssh("uci export firewall"))


class Resolver:
    def __init__(self, dhcp, network, firewall):
        zones = [s for s in firewall if s["type"] == "zone"]
        self.net = fwview.Net(dhcp, network, zones)
        self.if_zone = {}
        iface_dev = {}
        for s in network:
            if s["type"] == "interface":
                dev = (s["opts"].get("device") or [s["id"]])[0]
                iface_dev[s["id"]] = dev
        for z in zones:
            for n in z["opts"].get("network", []):
                self.if_zone[iface_dev.get(n, n)] = z["opts"]["name"][0]
            for d in z["opts"].get("device", []):
                self.if_zone[d] = z["opts"]["name"][0]

    def zone(self, ifname):
        return self.if_zone.get(ifname, ifname or "-")

    def host(self, ip):
        if not ip:
            return "-"
        if ip.startswith("255.") or ip.endswith(".255"):
            return "%s (Broadcast)" % ip
        if ip.startswith(("224.", "239.")):
            return "%s (Multicast)" % ip
        text, label = self.net.name_ip(ip)
        return "%s (%s)" % (ip, label) if label else ip

    def local(self, ip):
        try:
            return any(ip and __import__("ipaddress").ip_address(ip) in n for n, _ in self.net.subnets)
        except ValueError:
            return False


def svc(proto, dport, icmp_type):
    if proto == "ICMP":
        return {"8": "echo-request", "0": "echo-reply", "3": "unreachable", "11": "ttl-exceeded"}.get(icmp_type, "type %s" % icmp_type)
    name = NOISE_PORTS.get(dport) or fwview.PORTS.get(dport)
    return "%s/%s%s" % (proto.lower(), dport, " (%s)" % name if name else "")


def parse(log, since, until):
    rows = []
    for line in log.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        t = when(m.group(1))
        if t < since or (until and t > until):
            continue
        kv = dict(KV.findall(m.group(5)))
        cls, zone = classify(m.group(2))
        rows.append({"t": t, "prefix": m.group(2), "cls": cls, "zone": zone, "in": m.group(3), "out": m.group(4),
                     "src": kv.get("SRC", ""), "dst": kv.get("DST", ""), "proto": kv.get("PROTO", "?"),
                     "spt": kv.get("SPT", ""), "dpt": kv.get("DPT", ""), "itype": kv.get("TYPE", ""),
                     "mac": kv.get("MAC", "")})
    return rows


# ---------------------------------------------------------------- tables

def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def pct(n, total):
    return "%.1f %%" % (100.0 * n / total) if total else "-"


def top(counter, n):
    return counter.most_common(n)


def report(rows, R, since, until, top_n, source):
    total = len(rows)
    days = sorted({r["t"].date() for r in rows})
    out = []
    w = out.append
    w("<!-- generated by scripts/fwlog-audit.py %s, source %s, window %s .. %s, %d firewall lines -->\n"
      % (VERSION, source, since, until, total))

    # 1 classes
    by_prefix = collections.Counter(r["prefix"] for r in rows)
    first = {}; last = {}; permin = collections.defaultdict(collections.Counter)
    for r in rows:
        p = r["prefix"]
        first.setdefault(p, r["t"]); last[p] = r["t"]
        permin[p][r["t"].replace(second=0)] += 1
    w("### T1 Zeilen je Log-Klasse\n")
    t = []
    for p, n in by_prefix.most_common():
        cls = classify(p)[0]
        lim = LIMITS.get(cls)
        sat = sum(1 for v in permin[p].values() if lim and v >= lim)
        t.append([f"`{p}`", cls, n, pct(n, total), first[p].strftime("%d.%m. %H:%M"), last[p].strftime("%d.%m. %H:%M"),
                  max(permin[p].values()), lim or "-", sat])
    w(md_table(["Präfix", "Klasse", "Zeilen", "Anteil", "erste", "letzte", "max/min", "Limit/min", "Minuten am Limit"], t))
    w("\n`Minuten am Limit`: Minuten, in denen so viele Zeilen wie das Limit erlaubt geschrieben wurden; "
      "in diesen Minuten sind weitere Treffer **nicht** im Log (Dunkelziffer).\n")

    # 2 per day
    w("\n### T2 Zeilen je Tag und Klasse\n")
    cls_names = ["zone-in", "zone-fwd", "collective", "rule", "invalid", "zone-out", "other"]
    perday = collections.defaultdict(collections.Counter)
    for r in rows:
        perday[r["t"].date()][r["cls"]] += 1
    t = [[d.strftime("%a %d.%m."), *[perday[d][c] for c in cls_names], sum(perday[d].values())] for d in days]
    w(md_table(["Tag", *cls_names, "gesamt"], t))

    # 3 hourly
    w("\n### T3 Tagesprofil (Zeilen je Stunde, Summe über die Tage)\n")
    hours = collections.defaultdict(collections.Counter)
    for r in rows:
        hours[r["cls"]][r["t"].hour] += 1
        hours["gesamt"][r["t"].hour] += 1
    t = [[c, *[hours[c][h] for h in range(24)]] for c in ["gesamt", "zone-in", "rule", "zone-fwd", "collective", "invalid"]]
    w(md_table(["Klasse", *["%02d" % h for h in range(24)]], t))

    # 4 INPUT noise per zone
    w("\n### T4 INPUT-Abweisungen je Zone (`reject <zone> in`): Quelle → Router-Adresse, Dienst\n")
    inp = [r for r in rows if r["cls"] == "zone-in"]
    t = []
    for z in sorted({r["zone"] for r in inp}):
        c = collections.Counter((r["src"], r["dst"], svc(r["proto"], r["dpt"], r["itype"])) for r in inp if r["zone"] == z)
        zn = sum(c.values())
        for (s, d, sv), n in top(c, top_n):
            t.append([z, R.host(s), R.host(d), sv, n, pct(n, zn)])
    w(md_table(["Zone", "Quelle", "Ziel", "Dienst", "Zeilen", "Anteil in Zone"], t))

    # 5 lateral
    w("\n### T5 Abweisungen zwischen Zonen (FORWARD ohne Regel: Zonen-Log + Sammelzeile)\n")
    lat = [r for r in rows if r["cls"] in ("zone-fwd", "collective")]
    c = collections.Counter((R.zone(r["in"]), R.zone(r["out"]), r["src"], r["dst"], svc(r["proto"], r["dpt"], r["itype"]), r["prefix"]) for r in lat)
    t = [[a, b, R.host(s), R.host(d), sv, f"`{p}`", n] for (a, b, s, d, sv, p), n in top(c, top_n * 2)]
    w(md_table(["von Zone", "nach Zone", "Quelle", "Ziel", "Dienst", "Präfix", "Zeilen"], t))
    pairs = collections.Counter((R.zone(r["in"]), R.zone(r["out"])) for r in lat)
    w("\nZonen-Paare gesamt: " + ", ".join("%s→%s %d" % (a, b, n) for (a, b), n in pairs.most_common()) + "\n")

    # 6 egress rules
    w("\n### T6 Egress-Blocks je Regel (`Block-*`): Quelle, Ziel, Dienst\n")
    t = []
    for p in [p for p, _ in by_prefix.most_common() if classify(p)[0] == "rule"]:
        sub = [r for r in rows if r["prefix"] == p]
        c = collections.Counter((r["src"], r["dst"], svc(r["proto"], r["dpt"], r["itype"])) for r in sub)
        prot = collections.Counter(r["proto"] for r in sub)
        ndst = len({r["dst"] for r in sub})
        t.append([f"`{p}`", len(sub), " ".join("%s %d" % kv for kv in prot.most_common()), ndst, "", "", ""])
        for (s, d, sv), n in top(c, min(top_n, 8)):
            t.append(["", "", "", "", R.host(s), R.host(d) if R.local(d) else d, "%s ×%d" % (sv, n)])
    w(md_table(["Regel", "Zeilen", "Protokolle", "Ziel-IPs", "Quelle", "Ziel", "Dienst × Zeilen"], t))

    # 7 wgvpn / invalid
    w("\n### T7 Tunnel-Eingang `wgvpn` (INPUT-Abweisungen und `invalid ct state`)\n")
    wg = [r for r in rows if (r["cls"] == "zone-in" and r["zone"] == "wgvpn") or r["cls"] == "invalid"]
    c = collections.Counter((r["prefix"], r["src"], r["dst"], svc(r["proto"], r["dpt"], r["itype"])) for r in wg)
    t = [[f"`{p}`", s, R.host(d), sv, n] for (p, s, d, sv), n in top(c, top_n)]
    w(md_table(["Präfix", "Quelle (extern)", "Ziel", "Dienst", "Zeilen"], t))
    w("\nverschiedene externe Quellen: %d; Ziel-Ports (udp/tcp) verschieden: %d\n"
      % (len({r["src"] for r in wg}), len({(r["proto"], r["dpt"]) for r in wg if r["dpt"]})))

    # 8 scan indicators
    w("\n### T8 Scan-Indikatoren: Quellen mit vielen verschiedenen Ziel-Ports oder Ziel-Hosts\n")
    by_src = collections.defaultdict(list)
    for r in rows:
        if r["cls"] != "invalid":
            by_src[r["src"]].append(r)
    t = []
    for s, lst in by_src.items():
        dpts = {(r["proto"], r["dpt"]) for r in lst if r["dpt"]}
        dsts = {r["dst"] for r in lst}
        # max distinct ports within any 10-minute window
        lst.sort(key=lambda r: r["t"])
        best = 0; i = 0
        for j in range(len(lst)):
            while lst[j]["t"] - lst[i]["t"] > datetime.timedelta(minutes=10):
                i += 1
            win = {(r["proto"], r["dpt"]) for r in lst[i:j + 1] if r["dpt"]}
            best = max(best, len(win))
        if len(dpts) >= 15 or len(dsts) >= 15 or best >= 10:
            t.append([R.host(s), len(lst), len(dpts), best, len(dsts),
                      ", ".join(sorted({r["prefix"] for r in lst}))])
    t.sort(key=lambda x: -x[2])
    w(md_table(["Quelle", "Zeilen", "Ziel-Ports verschieden", "max Ports in 10 min", "Ziel-Hosts verschieden", "Präfixe"], t[:top_n]))

    # 9 one-day pairs
    w("\n### T9 Nur an einem Tag gesehene Quelle→Ziel-Paare (≥ 5 Zeilen)\n")
    pdays = collections.defaultdict(set); pcount = collections.Counter()
    for r in rows:
        k = (r["prefix"], r["src"], r["dst"], svc(r["proto"], r["dpt"], r["itype"]))
        pdays[k].add(r["t"].date()); pcount[k] += 1
    t = [[next(iter(pdays[k])).strftime("%d.%m."), f"`{k[0]}`", R.host(k[1]), R.host(k[2]) if R.local(k[2]) else k[2], k[3], n]
         for k, n in pcount.most_common() if len(pdays[k]) == 1 and n >= 5][:top_n * 2]
    w(md_table(["Tag", "Präfix", "Quelle", "Ziel", "Dienst", "Zeilen"], t))

    # 10 all sources
    w("\n### T10 Alle Quellen mit Zeilenanzahl (ohne `invalid`)\n")
    c = collections.Counter(r["src"] for r in rows if r["cls"] != "invalid")
    t = [[R.host(s), n, pct(n, total), ", ".join(sorted({r["prefix"] for r in by_src[s]}))] for s, n in c.most_common()]
    w(md_table(["Quelle", "Zeilen", "Anteil", "Präfixe"], t))
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description="Firewall-Log-Audit: Tabellen als Markdown (read-only)")
    ap.add_argument("--since", required=True)
    ap.add_argument("--until")
    ap.add_argument("--host", default=fwview.DEFAULT_HOST)
    ap.add_argument("--from-dir")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=12)
    a = ap.parse_args()
    since = datetime.datetime.strptime(a.since, "%Y-%m-%d %H:%M")
    until = datetime.datetime.strptime(a.until, "%Y-%m-%d %H:%M") if a.until else None
    log, dhcp, network, firewall = read_all(a)
    rows = parse(log, since, until)
    if not rows:
        sys.exit("fwlog-audit: keine Firewall-Zeilen im Fenster")
    R = Resolver(fwview.parse_uci(dhcp), fwview.parse_uci(network), fwview.parse_uci(firewall))
    out = a.out or "fwlog-audit-%s.md" % since.strftime("%Y%m%d")
    text = report(rows, R, since, until or rows[-1]["t"], a.top, a.from_dir or a.host)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print("fwlog-audit: %d Firewall-Zeilen %s .. %s -> %s" % (len(rows), since, until or rows[-1]["t"], out))


if __name__ == "__main__":
    main()
