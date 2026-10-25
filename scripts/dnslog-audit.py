#!/usr/bin/env python3
"""dnslog-audit.py 1.0.0 -- tables for an audit of AdGuard Home's query log, read-only.

Reads AdGuard Home's query log on the router (`/var/persist/adguardhome/data/querylog.json`
plus the rotated `.1`, one JSON object per line, section 13 of the network documentation) over
SSH (compressed in transit) or from a saved copy, keeps the entries of a time window, and
writes the analysis tables as Markdown: volume per day and hour, per client (name and zone
from the router's DHCP reservations and zone subnets, like fwview.py), blocked share and the
filter lists that fire, the domains the default-deny IoT zones actually reach, encrypted-DNS
bypass attempts, query types, NXDOMAIN/SERVFAIL, tunnelling heuristics (many subdomains, long
names), unknown clients, rate-limit saturation (seconds at AdGuard's `ratelimit` per /24),
upstream/cache performance, and the domains that appeared only on the last day.

The tables are the DATA of an audit report (docs/audits/); the findings are written by hand.
AdGuard's rate limiter drops queries *before* they are logged, so the log never shows a
dropped query -- the saturation table is the only trace.

Usage:  scripts/dnslog-audit.py --since '2026-10-11 00:00' [--host root@192.168.30.1] [--out FILE]
        scripts/dnslog-audit.py --since '...' --querylog FILE[.gz] [--host ...]   (log from a copy,
                                                                                   names from the router)
        scripts/dnslog-audit.py --since '...' --from-dir DIR [--out FILE]
  --since / --until  window in local router time ('YYYY-MM-DD HH:MM'); the log stores UTC
  --host      SSH target, read-only (`gzip -c` of the log, `uci export`, the `filters:` and
              `clients:` sections of adguardhome.yaml -- never the whole file, it holds credentials)
  --querylog  local copy of querylog.json (optionally gzip), skips the big transfer
  --from-dir  read querylog.json[.gz], dhcp.uci, network.uci, firewall.uci, adguard-sections.yaml from DIR
  --out       Markdown file (default ./dnslog-audit-<since>.md)
  --top N     rows per top-N table (default 15)

Exit codes: 0 ok, 1 read error / no entries, 2 usage. Python 3 standard library only.
"""
import argparse
import base64
import collections
import datetime
import gzip
import io
import json
import os
import re
import subprocess
import sys
import zoneinfo

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwview  # noqa: E402  (parse_uci, Net, SSH, DEFAULT_HOST)

VERSION = "1.0.0"
LOG_PATHS = ["/var/persist/adguardhome/data/querylog.json", "/var/persist/adguardhome/data/querylog.json.1"]
YAML_PATH = "/etc/adguardhome/adguardhome.yaml"
TZ = zoneinfo.ZoneInfo("Europe/Berlin")

# AdGuard Home filtering.Reason (internal/filtering/filtering.go), by value.
REASONS = {0: "nicht gefiltert", 1: "Allowlist", 2: "Fehler (nicht gefiltert)", 3: "Blockliste", 4: "Safe Browsing",
           5: "Kindersicherung", 6: "ungültig", 7: "Safe Search", 8: "gesperrter Dienst", 9: "Rewrite",
           10: "Rewrite (hosts)", 11: "Rewrite (Regel)"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
# Public encrypted-DNS endpoints and canaries, name-based (the IP side lives in the firewall set doh_v4).
BYPASS = re.compile(r"(^|\.)(dns\.google|cloudflare-dns\.com|one\.one\.one\.one|dns\.quad9\.net|dns\.nextdns\.io|"
                    r"dns\.adguard(-dns)?\.com|doh\.opendns\.com|dns\.mullvad\.net|dns0\.eu|dns\.sb|"
                    r"use-application-dns\.net|dns\.alidns\.com|doh\.pub|dns\.controld\.com|"
                    r"family\.cloudflare-dns\.com|security\.cloudflare-dns\.com|dns\.switch\.ch|"
                    r"resolver\.arpa|dns\.apple\.com|doh\.dns\.apple\.com|mask\.icloud\.com|mask-h2\.icloud\.com)$"
                    r"|^(doh|dot|doq)[.-]")
UNUSUAL_QT = {"TXT", "ANY", "NULL", "SRV", "CNAME", "MX", "NS", "SOA", "HINFO", "AXFR", "IXFR"}


def ssh_text(host, cmd, binary=False):
    r = subprocess.run(fwview.SSH + [host, cmd], capture_output=True, text=not binary)
    if r.returncode != 0:
        sys.exit("dnslog-audit: '%s' auf %s fehlgeschlagen: %s" % (cmd[:60], host,
                 (r.stderr if isinstance(r.stderr, str) else r.stderr.decode(errors="replace")).strip() or "leer"))
    return r.stdout


def read_text(path):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                return f.read()
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        sys.exit("dnslog-audit: %s" % e)


def read_all(a):
    """-> (querylog text, dhcp, network, firewall, adguard sections yaml text)"""
    if a.from_dir:
        g = lambda n: read_text(os.path.join(a.from_dir, n))
        ql = os.path.join(a.from_dir, "querylog.json")
        log = read_text(ql + ".gz" if os.path.exists(ql + ".gz") else ql)
        return log, g("dhcp.uci"), g("network.uci"), g("firewall.uci"), g("adguard-sections.yaml")
    if a.querylog:
        log = read_text(a.querylog)
    else:
        raw = ssh_text(a.host, "gzip -c %s" % " ".join(LOG_PATHS), binary=True)
        log = gzip.GzipFile(fileobj=io.BytesIO(raw)).read().decode("utf-8", errors="replace")
    sections = ssh_text(a.host, "sed -n '/^filters:/,/^whitelist_filters:/p;/^clients:/,/^log:/p;"
                                "/^dns:/,/^tls:/p' %s | grep -vE '^\\s*(password|uid):'" % YAML_PATH)
    return (log, ssh_text(a.host, "uci export dhcp"), ssh_text(a.host, "uci export network"),
            ssh_text(a.host, "uci export firewall"), sections)


def parse_sections(text):
    """filters (id -> name), persistent clients, dns.ratelimit -- from the yaml excerpt, no yaml module."""
    filters, clients, ratelimit = {0: "Benutzerregeln"}, [], None
    block, cur = None, None
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.strip()
        if re.match(r"^(filters|clients|dns|whitelist_filters|log|tls):", line):
            block = line.split(":")[0]
            continue
        if block == "dns":
            m = re.match(r"^\s{2}ratelimit:\s*(\d+)", line)
            if m:
                ratelimit = int(m.group(1))
        elif block == "filters":
            if s.startswith("- enabled:"):
                cur = {"enabled": s.endswith("true")}
            elif cur is not None and s.startswith("name:"):
                cur["name"] = s[5:].strip().strip("'\"")
            elif cur is not None and s.startswith("id:"):
                filters[int(s[3:].strip())] = cur.get("name", "?") + ("" if cur["enabled"] else " (aus)")
        elif block == "clients":
            if s == "- safe_search:" or s.startswith("- name:"):
                cur = {"ids": []}
                clients.append(cur)
                if s.startswith("- name:"):
                    cur["name"] = s[7:].strip()
            elif cur is not None:
                if s.startswith("name:"):
                    cur["name"] = s[5:].strip()
                elif re.match(r"^- [0-9a-fA-F:.]+$", s) and "ids_open" in cur:
                    cur["ids"].append(s[2:])
                elif s == "ids:":
                    cur["ids_open"] = True
                elif s.startswith(("tags:", "upstreams:")):
                    cur.pop("ids_open", None)
                for k in ("use_global_settings", "filtering_enabled", "ignore_querylog", "use_global_blocked_services"):
                    if s.startswith(k + ":"):
                        cur[k] = s.endswith("true")
    return filters, [c for c in clients if c.get("name")], ratelimit


def rcode_of(answer):
    if not answer:
        return None
    try:
        b = base64.b64decode(answer)
    except Exception:
        return None
    return b[3] & 0x0F if len(b) >= 4 else None


def parse(log, since, until):
    rows = []
    bad = 0
    for line in log.splitlines():
        if not line.startswith("{"):
            continue
        try:
            e = json.loads(line)
            t = datetime.datetime.strptime(e["T"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).astimezone(TZ).replace(tzinfo=None)
        except (ValueError, KeyError):
            bad += 1
            continue
        if t < since or (until and t > until):
            continue
        res = e.get("Result") or {}
        rules = res.get("Rules") or []
        rows.append({"t": t, "qh": (e.get("QH") or "").lower().rstrip("."), "qt": e.get("QT") or "?", "ip": e.get("IP") or "",
                     "cp": e.get("CP") or "", "reason": res.get("Reason", 0), "filtered": bool(res.get("IsFiltered")),
                     "list": rules[0].get("FilterListID") if rules else None, "rule": rules[0].get("Text", "") if rules else "",
                     "svc": res.get("ServiceName", ""), "rcode": rcode_of(e.get("Answer")),
                     "cached": bool(e.get("Cached")), "upstream": e.get("Upstream", ""), "ms": (e.get("Elapsed") or 0) / 1e6})
    rows.sort(key=lambda r: r["t"])
    return rows, bad


class Resolver:
    def __init__(self, dhcp, network, firewall):
        zones = [s for s in firewall if s["type"] == "zone"]
        self.net = fwview.Net(dhcp, network, zones)
        self._zone = {}

    def zone(self, ip):
        if ip not in self._zone:
            z = self.net.router_ip.get(ip)
            if z:
                z = "Router (%s)" % z
            else:
                try:
                    a = __import__("ipaddress").ip_address(ip)
                    z = next((zn for n, zn in self.net.subnets if a in n), "")
                except ValueError:
                    z = ""
            self._zone[ip] = z or "unbekannt"
        return self._zone[ip]

    def name(self, ip):
        _, label = self.net.name_ip(ip)
        return label or "-"

    def host(self, ip):
        label = self.name(ip)
        return "%s (%s)" % (ip, label) if label != "-" else ip


def reg_domain(qh):
    """crude registrable domain: last two labels, three for common second-level suffixes."""
    p = qh.split(".")
    if len(p) >= 3 and p[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p) >= 2 else qh


def md_table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def pct(n, total):
    return "%.1f %%" % (100.0 * n / total) if total else "-"


def percentile(vals, p):
    if not vals:
        return 0.0
    vals = sorted(vals)
    return vals[min(len(vals) - 1, int(round(p / 100.0 * (len(vals) - 1))))]


def report(rows, R, filters, clients, ratelimit, since, until, top_n, source, bad):
    total = len(rows)
    days = sorted({r["t"].date() for r in rows})
    out = []
    w = out.append
    w("<!-- generated by scripts/dnslog-audit.py %s, source %s, window %s .. %s, %d entries, %d unparsable lines -->\n"
      % (VERSION, source, since, until, total, bad))
    blocked = [r for r in rows if r["filtered"]]
    by_client = collections.defaultdict(list)
    for r in rows:
        by_client[r["ip"]].append(r)
    zone_of = {ip: R.zone(ip) for ip in by_client}
    lname = lambda i: filters.get(i, "Liste %s" % i) if i is not None else "-"

    # D1 frame
    w("### D1 Rahmen\n")
    reasons = collections.Counter(r["reason"] for r in rows)
    t = [["Einträge", total], ["Zeitraum", "%s .. %s (%d Tage)" % (since, until, len(days))],
         ["Clients (IPs)", len(by_client)], ["verschiedene Namen", len({r["qh"] for r in rows})],
         ["geblockt (`IsFiltered`)", "%d (%s)" % (len(blocked), pct(len(blocked), total))],
         ["aus Cache beantwortet", "%d (%s)" % (sum(1 for r in rows if r["cached"]), pct(sum(1 for r in rows if r["cached"]), total))],
         ["Client-Protokoll", ", ".join("%s %d" % (k or "plain", v) for k, v in collections.Counter(r["cp"] for r in rows).most_common())],
         ["AdGuard `ratelimit`", "%s/s je /24" % ratelimit if ratelimit else "unbekannt"]]
    w(md_table(["Größe", "Wert"], t))
    w("\n**Ergebnisklassen (`Result.Reason`):**\n\n")
    w(md_table(["Reason", "Bedeutung", "Einträge", "Anteil"],
               [[k, REASONS.get(k, "?"), n, pct(n, total)] for k, n in reasons.most_common()]))

    # D2 per day
    w("\n### D2 Anfragen je Tag\n")
    perday = collections.defaultdict(lambda: {"n": 0, "b": 0, "c": set(), "d": set(), "nx": 0, "err": 0})
    for r in rows:
        d = perday[r["t"].date()]
        d["n"] += 1; d["b"] += r["filtered"]; d["c"].add(r["ip"]); d["d"].add(r["qh"])
        d["nx"] += r["rcode"] == 3; d["err"] += (r["rcode"] == 2 or r["reason"] == 2)
    w(md_table(["Tag", "Anfragen", "geblockt", "Anteil", "Clients", "Namen", "NXDOMAIN", "SERVFAIL/Fehler"],
               [[d.strftime("%a %d.%m."), v["n"], v["b"], pct(v["b"], v["n"]), len(v["c"]), len(v["d"]), v["nx"], v["err"]]
                for d, v in sorted(perday.items())]))

    # D3 hourly
    w("\n### D3 Tagesprofil (Anfragen je Stunde, Summe über die Tage)\n")
    hours = collections.defaultdict(collections.Counter)
    for r in rows:
        hours["gesamt"][r["t"].hour] += 1
        hours[zone_of[r["ip"]]][r["t"].hour] += 1
    zones_sorted = ["gesamt"] + sorted(z for z in hours if z != "gesamt")
    w(md_table(["Zone", *["%02d" % h for h in range(24)]], [[z, *[hours[z][h] for h in range(24)]] for z in zones_sorted]))

    # D4 per client
    w("\n### D4 Je Client: Volumen, Block-Anteil, Breite\n")
    t = []
    for ip, lst in sorted(by_client.items(), key=lambda kv: -len(kv[1])):
        n = len(lst); b = sum(1 for r in lst if r["filtered"])
        persec = collections.Counter(r["t"].replace(microsecond=0) for r in lst)
        permin = collections.Counter(r["t"].replace(second=0, microsecond=0) for r in lst)
        t.append([R.host(ip), zone_of[ip], n, pct(n, total), b, pct(b, n), len({r["qh"] for r in lst}),
                  sum(1 for r in lst if r["rcode"] == 3), max(persec.values()), max(permin.values()),
                  lst[0]["t"].strftime("%d.%m. %H:%M"), lst[-1]["t"].strftime("%d.%m. %H:%M")])
    w(md_table(["Client", "Zone", "Anfragen", "Anteil", "geblockt", "Block-Anteil", "Namen", "NXDOMAIN", "max/s", "max/min", "erste", "letzte"], t))

    # D5 per zone
    w("\n### D5 Je Zone\n")
    t = []
    for z in sorted({zone_of[ip] for ip in by_client}):
        lst = [r for r in rows if zone_of[r["ip"]] == z]
        b = sum(1 for r in lst if r["filtered"])
        t.append([z, len({r["ip"] for r in lst}), len(lst), pct(len(lst), total), b, pct(b, len(lst)), len({r["qh"] for r in lst})])
    w(md_table(["Zone", "Clients", "Anfragen", "Anteil", "geblockt", "Block-Anteil", "Namen"], t))

    # D6 blocked by list
    w("\n### D6 Blocks je Filterliste\n")
    c = collections.Counter(r["list"] for r in blocked)
    t = [[lname(k), n, pct(n, len(blocked)), len({r["qh"] for r in blocked if r["list"] == k}), len({r["ip"] for r in blocked if r["list"] == k})]
         for k, n in c.most_common()]
    w(md_table(["Liste", "Blocks", "Anteil", "Namen", "Clients"], t))

    # D7 top blocked domains
    w("\n### D7 Meistgeblockte Namen\n")
    c = collections.Counter(r["qh"] for r in blocked)
    t = []
    for qh, n in c.most_common(top_n * 2):
        sub = [r for r in blocked if r["qh"] == qh]
        cl = collections.Counter(R.name(r["ip"]) + "" for r in sub)
        t.append([f"`{qh}`", n, ", ".join("%s %d" % kv for kv in cl.most_common(3)), lname(collections.Counter(r["list"] for r in sub).most_common(1)[0][0]),
                  f"`{sub[0]['rule']}`" if sub[0]["rule"] else "-"])
    w(md_table(["Name", "Blocks", "Clients", "Liste", "Regel"], t))

    # D8 top blocked per client
    w("\n### D8 Je Client die meistgeblockten Namen (Top 5)\n")
    t = []
    for ip, lst in sorted(by_client.items(), key=lambda kv: -len(kv[1])):
        bl = [r for r in lst if r["filtered"]]
        if not bl:
            continue
        c = collections.Counter(r["qh"] for r in bl)
        t.append([R.host(ip), len(bl), "<br>".join("`%s` ×%d" % kv for kv in c.most_common(5))])
    w(md_table(["Client", "Blocks", "Namen"], t))

    # D9 IoT default-deny: what gets through
    w("\n### D9 Default-Deny-Zonen (`smarthome`, `smarthome_srv`): erlaubte Namen je Gerät (vollständig)\n")
    t = []
    for ip, lst in sorted(by_client.items(), key=lambda kv: -len(kv[1])):
        if zone_of[ip] not in ("smarthome", "smarthome_srv"):
            continue
        ok = collections.Counter(r["qh"] for r in lst if not r["filtered"])
        bl = collections.Counter(r["qh"] for r in lst if r["filtered"])
        t.append([R.host(ip), len(lst), sum(ok.values()), sum(bl.values()), len(ok),
                  "<br>".join("`%s` ×%d" % kv for kv in ok.most_common(40)) + (" …" if len(ok) > 40 else ""),
                  "<br>".join("`%s` ×%d" % kv for kv in bl.most_common(8)) + (" …" if len(bl) > 8 else "")])
    w(md_table(["Gerät", "Anfragen", "erlaubt", "geblockt", "erlaubte Namen", "erlaubt (Name × Anfragen)", "geblockt (Top 8)"], t))

    # D10 encrypted-DNS bypass
    w("\n### D10 Verschlüsseltes DNS umgehen: Anfragen nach DoH/DoT-Endpunkten und Canaries\n")
    byp_list = next((k for k, v in filters.items() if "Encrypted DNS" in v), None)
    byp = [r for r in rows if BYPASS.search(r["qh"]) or r["list"] == byp_list]
    c = collections.Counter((r["ip"], r["qh"], "geblockt" if r["filtered"] else "erlaubt") for r in byp)
    t = [[R.host(ip), zone_of[ip], f"`{qh}`", st, n] for (ip, qh, st), n in c.most_common(top_n * 2)]
    w(md_table(["Client", "Zone", "Name", "Ergebnis", "Anfragen"], t))
    w("\ngesamt %d Anfragen von %d Clients; erlaubt: %d\n" % (len(byp), len({r["ip"] for r in byp}), sum(1 for r in byp if not r["filtered"])))

    # D11 query types
    w("\n### D11 Anfragetypen\n")
    c = collections.Counter(r["qt"] for r in rows)
    w(md_table(["Typ", "Anfragen", "Anteil"], [[k, n, pct(n, total)] for k, n in c.most_common()]))
    unusual = [r for r in rows if r["qt"] in UNUSUAL_QT]
    c = collections.Counter((r["ip"], r["qt"], reg_domain(r["qh"])) for r in unusual)
    w("\n**Ungewöhnliche Typen je Client** (%s):\n\n" % ", ".join(sorted(UNUSUAL_QT)))
    w(md_table(["Client", "Typ", "Domain", "Anfragen"], [[R.host(ip), qt, f"`{d}`", n] for (ip, qt, d), n in c.most_common(top_n)]))

    # D12 NXDOMAIN / SERVFAIL
    w("\n### D12 NXDOMAIN und SERVFAIL\n")
    nx = [r for r in rows if r["rcode"] == 3 and not r["filtered"]]
    c = collections.Counter((r["ip"], r["qh"]) for r in nx)
    w(md_table(["Client", "Name", "NXDOMAIN"], [[R.host(ip), f"`{qh}`", n] for (ip, qh), n in c.most_common(top_n)]))
    sf = [r for r in rows if r["rcode"] == 2 or r["reason"] == 2]
    c = collections.Counter((r["ip"], r["qh"], r["upstream"] or "-") for r in sf)
    w("\n**SERVFAIL / Upstream-Fehler** (%d gesamt):\n\n" % len(sf))
    w(md_table(["Client", "Name", "Upstream", "Anfragen"], [[R.host(ip), f"`{qh}`", up, n] for (ip, qh, up), n in c.most_common(top_n)]))

    # D13 tunnelling heuristics
    w("\n### D13 Tunnel-Heuristik: viele verschiedene Subdomains je Domain, lange Namen\n")
    subs = collections.defaultdict(set)
    for r in rows:
        subs[(r["ip"], reg_domain(r["qh"]))].add(r["qh"])
    t = [[R.host(ip), f"`{d}`", len(s), max(len(x) for x in s), "geblockt" if all(r["filtered"] for r in by_client[ip] if reg_domain(r["qh"]) == d) else "erlaubt"]
         for (ip, d), s in sorted(subs.items(), key=lambda kv: -len(kv[1]))[:top_n] if len(s) >= 20]
    w(md_table(["Client", "Domain", "verschiedene Namen", "längster Name", "Ergebnis"], t))
    longest = sorted({(len(r["qh"]), r["qh"], r["ip"]) for r in rows}, reverse=True)[:8]
    w("\n**Längste Namen:** " + "; ".join("`%s` (%d, %s)" % (q, n, R.name(ip)) for n, q, ip in longest) + "\n")

    # D14 unknown clients / routers
    w("\n### D14 Clients ohne Reservierung oder außerhalb der Zonen-Netze, Router-eigene Anfragen\n")
    t = [[R.host(ip), zone_of[ip], len(lst), ", ".join("`%s`" % q for q, _ in collections.Counter(r["qh"] for r in lst).most_common(4))]
         for ip, lst in sorted(by_client.items(), key=lambda kv: -len(kv[1]))
         if R.name(ip) == "-" or zone_of[ip] == "unbekannt" or zone_of[ip].startswith("Router")]
    w(md_table(["Client", "Zone", "Anfragen", "häufigste Namen"], t))

    # D15 rate-limit saturation
    w("\n### D15 Rate-Limit-Sättigung: Sekunden mit ≥ `ratelimit` Anfragen je /24 (Dunkelziffer: verworfene Anfragen stehen nicht im Log)\n")
    lim = ratelimit or 20
    per = collections.defaultdict(collections.Counter)
    for r in rows:
        per[".".join(r["ip"].split(".")[:3]) + ".0/24"][r["t"].replace(microsecond=0)] += 1
    t = []
    for net, c in per.items():
        sat = [(s, n) for s, n in c.items() if n >= lim]
        mx = max(c.values())
        t.append([net, zone_of[list(by_client)[0]] if False else next((zone_of[ip] for ip in by_client if ip.startswith(net[:-5])), "-"),
                  mx, len(sat), sat and max(sat, key=lambda x: x[1])[0].strftime("%d.%m. %H:%M:%S") or "-",
                  len({s.replace(second=0) for s, _ in sat})])
    t.sort(key=lambda x: -x[3])
    w(md_table(["/24", "Zone", "max Anfragen/s", "Sekunden ≥ Limit", "schlimmste Sekunde", "betroffene Minuten"], t))

    # D16 performance
    w("\n### D16 Upstream und Cache\n")
    up = [r for r in rows if not r["cached"] and not r["filtered"]]
    ms = [r["ms"] for r in up]
    t = [["Upstream-Antworten (nicht Cache, nicht geblockt)", len(up)],
         ["Upstreams", ", ".join("%s %d" % kv for kv in collections.Counter(r["upstream"] or "-" for r in up).most_common(5))],
         ["Latenz p50 / p90 / p99 (ms)", "%.0f / %.0f / %.0f" % (percentile(ms, 50), percentile(ms, 90), percentile(ms, 99))],
         ["Antworten > 1 s", sum(1 for m in ms if m > 1000)],
         ["Cache-Trefferquote (nicht geblockt)", pct(sum(1 for r in rows if r["cached"]), sum(1 for r in rows if not r["filtered"]))]]
    w(md_table(["Größe", "Wert"], t))

    # D17 top allowed domains
    w("\n### D17 Meistangefragte erlaubte Namen\n")
    c = collections.Counter(r["qh"] for r in rows if not r["filtered"])
    t = [[f"`{qh}`", n, ", ".join("%s %d" % kv for kv in collections.Counter(R.name(r["ip"]) for r in rows if r["qh"] == qh and not r["filtered"]).most_common(3))]
         for qh, n in c.most_common(top_n * 2)]
    w(md_table(["Name", "Anfragen", "Clients"], t))

    # D18 new on last day
    w("\n### D18 Nur am letzten Tag gesehene Namen (≥ 3 Anfragen, je Client)\n")
    if len(days) >= 2:
        last = days[-1]
        seen = collections.defaultdict(set); cnt = collections.Counter()
        for r in rows:
            seen[(r["ip"], r["qh"])].add(r["t"].date()); cnt[(r["ip"], r["qh"])] += 1
        t = [[R.host(ip), f"`{qh}`", n, "geblockt" if any(r["filtered"] for r in by_client[ip] if r["qh"] == qh) else "erlaubt"]
             for (ip, qh), n in cnt.most_common() if seen[(ip, qh)] == {last} and n >= 3][:top_n * 2]
        w(md_table(["Client", "Name", "Anfragen", "Ergebnis"], t))
    else:
        w("(Fenster umfasst nur einen Tag)\n")

    # D19 AdGuard persistent clients
    w("\n### D19 AdGuard-Clients (persistent) und ihre Schalter\n")
    t = [[c.get("name", "?"), ", ".join(c["ids"]), c.get("use_global_settings"), c.get("filtering_enabled"), c.get("ignore_querylog")] for c in clients]
    w(md_table(["Name", "IDs", "globale Einstellungen", "filtering_enabled", "ignore_querylog"], t))
    w("\n`filtering_enabled` wirkt nur, wenn `globale Einstellungen` False ist.\n")
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description="AdGuard-Query-Log-Audit: Tabellen als Markdown (read-only)")
    ap.add_argument("--since", required=True)
    ap.add_argument("--until")
    ap.add_argument("--host", default=fwview.DEFAULT_HOST)
    ap.add_argument("--querylog")
    ap.add_argument("--from-dir")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=15)
    a = ap.parse_args()
    since = datetime.datetime.strptime(a.since, "%Y-%m-%d %H:%M")
    until = datetime.datetime.strptime(a.until, "%Y-%m-%d %H:%M") if a.until else None
    log, dhcp, network, firewall, sections = read_all(a)
    rows, bad = parse(log, since, until)
    if not rows:
        sys.exit("dnslog-audit: keine Einträge im Fenster")
    filters, clients, ratelimit = parse_sections(sections)
    R = Resolver(fwview.parse_uci(dhcp), fwview.parse_uci(network), fwview.parse_uci(firewall))
    out = a.out or "dnslog-audit-%s.md" % since.strftime("%Y%m%d")
    text = report(rows, R, filters, clients, ratelimit, since, until or rows[-1]["t"], a.top,
                  a.from_dir or a.querylog or a.host, bad)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    print("dnslog-audit: %d Einträge %s .. %s, %d Clients -> %s" % (len(rows), since, until or rows[-1]["t"], len({r["ip"] for r in rows}), out))


if __name__ == "__main__":
    main()
