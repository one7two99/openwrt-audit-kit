#!/usr/bin/env python3
"""agview.py 1.0.0 -- render AdGuard Home's custom filtering rules as ONE self-contained HTML
page and ALWAYS write the same data as a JSON report for analysis (e.g. by an LLM).

Reads the LIVE rule set over SSH, read-only: only the `user_rules:`, `filtering:` (rewrites)
and `clients:` sections of adguardhome.yaml (never the whole file -- it holds the admin
password hash and TLS key paths; `password`/`uid` lines are dropped on the device), plus
`uci export dhcp|network|firewall` for device names and zones (same resolver as fwview.py).
Every rule is one row: position, type, the rule as written, domain or pattern with its reach
(subdomains or exact), effect, client scope resolved to device name and zone, modifiers,
the comment lines above it as rationale, and -- with --querylog -- how often it fired.
Rules are grouped by the `! --- ... ---` headings of the list; commented-out rules
(`! DISABLED ...`, `!@@||...`) are shown as disabled.

The page is a MIRROR for reading, never a source (docs/dns-filtering.md Teil A is the source
of truth, the device wins over both). With --doc (default: docs/dns-filtering.md next to this
script's repo) the device rules are compared against the Teil A tables: rules on the device
that the document lacks, and documented rules the device lacks, are reported as warnings.
Output carries real client IPs and device names: agview-*.html/.json are ignored by git.

Usage:   scripts/agview.py [--host root@192.168.30.1] [--out FILE] [--json FILE]
                            [--doc docs/dns-filtering.md | --no-doc] [--querylog FILE[.gz]]
         scripts/agview.py --from-dir DIR [...]
  --host      SSH target (default root@192.168.30.1; BatchMode, key auth, nothing is written)
  --from-dir  read adguard-rules.yaml, dhcp.uci, network.uci, firewall.uci from DIR instead of SSH
  --out       HTML file (default ./agview-YYYYMMDD-HHMM.html)
  --json      JSON report (default: --out with .html replaced by .json)
  --doc       Markdown file with the documented rule set (Teil A tables); --no-doc skips the check
  --querylog  AdGuard querylog.json (optionally .gz) -- hits per rule from Result.Rules[].Text
Exit codes: 0 ok, 1 read error, 2 usage. Only the Python 3 standard library is used.

AdGuard precedence (what the HTML legend and the JSON `semantics` say): rule ORDER does not
matter. `@@` with `$important` > block with `$important` > `@@` > block; regex and domain
rules rank equally; `$client` restricts a rule to those clients (IP, CIDR or persistent
client name); `$dnsrewrite=NXDOMAIN` answers locally without an upstream query.
"""
import argparse
import datetime
import gzip
import html
import ipaddress
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fwview  # noqa: E402  (SSH, parse_uci, Net, CSS, DEFAULT_HOST)

VERSION = "1.0.0"
YAML_PATH = "/etc/adguardhome/adguardhome.yaml"
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DOC = os.path.join(REPO, "docs", "dns-filtering.md")

# Rules the document keeps on purpose but the device does not carry 1:1 (none today).
SEMANTICS = ("Reihenfolge der Zeilen ohne Bedeutung. Praezedenz: @@ mit $important > Sperre mit $important > "
             "@@ > Sperre; Regex- und Domain-Regeln gleichrangig. $client beschraenkt die Regel auf diese Clients "
             "(IP, CIDR oder Name eines persistenten Clients); ohne $client gilt sie netzweit. ||x^ trifft x und alle "
             "Subdomains; |x^ nur x; /regex/ wird gegen den ganzen Namen geprueft. $dnsrewrite=NXDOMAIN antwortet "
             "lokal, nichts geht zum Upstream. Rewrites (Abschnitt filtering.rewrites) gehen den Filterregeln vor. "
             "Kommentare beginnen mit '!'. Diese Seite spiegelt das Geraet; docs/dns-filtering.md Teil A ist die Quelle.")


# ---------------------------------------------------------------- input

def ssh_text(host, cmd):
    r = subprocess.run(fwview.SSH + [host, cmd], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit("agview: '%s' auf %s fehlgeschlagen: %s" % (cmd[:50], host, r.stderr.strip() or "leer"))
    return r.stdout


def read_file(path):
    try:
        if path.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                return f.read()
        return open(path, encoding="utf-8", errors="replace").read()
    except OSError as e:
        sys.exit("agview: %s" % e)


def read_all(a):
    """-> (yaml excerpt, dhcp, network, firewall)"""
    if a.from_dir:
        g = lambda n: read_file(os.path.join(a.from_dir, n))
        return g("adguard-rules.yaml"), g("dhcp.uci"), g("network.uci"), g("firewall.uci")
    excerpt = ssh_text(a.host, "sed -n '/^user_rules:/,/^dhcp:/p;/^filtering:/,/^clients:/p;/^clients:/,/^log:/p' %s"
                               " | grep -vE '^\\s*(password|uid):'" % YAML_PATH)
    if "user_rules:" not in excerpt:
        sys.exit("agview: kein user_rules-Abschnitt in %s auf %s" % (YAML_PATH, a.host))
    return (excerpt, ssh_text(a.host, "uci export dhcp"), ssh_text(a.host, "uci export network"),
            ssh_text(a.host, "uci export firewall"))


# ---------------------------------------------------------------- yaml excerpt (no yaml module)

def yaml_scalar(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        try:
            return json.loads(s)
        except ValueError:
            return s[1:-1]
    return s


def parse_excerpt(text):
    """-> (user_rules [str], rewrites [{domain, answer, enabled}], persistent clients [dict])"""
    items, rewrites, clients = [], [], []
    block, sub, cur, in_ids, in_rw = None, None, None, False, False
    for raw in text.splitlines():
        if re.match(r"^[a-z_]+:", raw):
            block = raw.split(":")[0]
            sub, cur, in_ids, in_rw = None, None, False, False
            continue
        s = raw.strip()
        if block == "user_rules":
            if raw.startswith("  - "):
                items.append(raw[4:])
            elif raw.startswith("    ") and items:
                items[-1] += " " + s          # folded continuation of a quoted scalar
        elif block == "filtering":
            if re.match(r"^  [a-z_]+:", raw):
                in_rw = raw.strip().startswith("rewrites:")
                continue
            if in_rw:
                if s.startswith("- domain:"):
                    rewrites.append({"domain": yaml_scalar(s[9:]), "answer": "", "enabled": True})
                elif rewrites and s.startswith("answer:"):
                    rewrites[-1]["answer"] = yaml_scalar(s[7:])
                elif rewrites and s.startswith("enabled:"):
                    rewrites[-1]["enabled"] = s.endswith("true")
        elif block == "clients":
            if re.match(r"^  [a-z_]+:", raw):
                sub = raw.strip().split(":")[0]
                cur = None
                continue
            if sub != "persistent":
                continue
            if raw.startswith("    - "):
                cur = {"name": "", "ids": [], "use_global_settings": None, "filtering_enabled": None,
                       "tags": [], "blocked_services": []}
                clients.append(cur)
                in_ids = False
                s = s[2:]
            if cur is None:
                continue
            if s.startswith("name:"):
                cur["name"] = yaml_scalar(s[5:])
            elif s.startswith("ids:"):
                in_ids = not s.endswith("[]")
            elif s.startswith("tags:"):
                in_ids = False
            elif s.startswith("use_global_settings:"):
                cur["use_global_settings"] = s.endswith("true")
            elif s.startswith("filtering_enabled:"):
                cur["filtering_enabled"] = s.endswith("true")
            elif in_ids and s.startswith("- ") and raw.startswith("        - "):
                cur["ids"].append(yaml_scalar(s[2:]))
            elif re.match(r"^[a-z_]+:", s) and not raw.startswith("        "):
                in_ids = False
    rules = [yaml_scalar(x) for x in items]
    return rules, rewrites, clients


# ---------------------------------------------------------------- rule model

RE_HEADER = re.compile(r"^!\s*-{2,}\s*(.+?)\s*-{2,}\s*$")
RE_PART = re.compile(r"^!\s*TEIL\s+\S+\s*[—–-]\s*(.+?)\s*$")
RE_FRAME = re.compile(r"^!\s*(#{3,}|={3,})\s*$")


def split_modifiers(text):
    """'||x^$client=a,important' -> ('||x^', {'client': ['a'], 'important': True, ...})"""
    body, mods = text, {}
    # the $ that starts the modifier list is the last one outside a /regex/ body
    if text.startswith("/"):
        end = text.rfind("/$")
        if end > 0:
            body, modtext = text[:end + 1], text[end + 2:]
        else:
            modtext = ""
    else:
        i = text.rfind("$")
        if i > 0:
            body, modtext = text[:i], text[i + 1:]
        else:
            modtext = ""
    if modtext:
        # values may contain commas inside quotes ($client='a','b') or ;; (dnsrewrite)
        parts, buf, q = [], "", None
        for ch in modtext:
            if q:
                buf += ch
                if ch == q:
                    q = None
            elif ch in "'\"":
                q = ch
                buf += ch
            elif ch == ",":
                parts.append(buf)
                buf = ""
            else:
                buf += ch
        parts.append(buf)
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if "=" in p:
                k, v = p.split("=", 1)
                k = k.strip()
                if k == "client":
                    vals = [x.strip().strip("'\"") for x in re.split(r"\|", v)]
                    mods.setdefault("client", []).extend(x for x in vals if x)
                elif k == "dnsrewrite":
                    mods["dnsrewrite"] = v.rstrip(";")
                else:
                    mods[k] = v
            else:
                mods[p] = True
    return body, mods


def classify(body):
    """-> (type, pattern, reach)  type in block|allow|regex_block|regex_allow"""
    allow = body.startswith("@@")
    core = body[2:] if allow else body
    if core.startswith("/") and core.endswith("/") and len(core) > 1:
        return ("regex_allow" if allow else "regex_block"), core[1:-1], "regex"
    reach = "exact"
    if core.startswith("||"):
        core, reach = core[2:], "domain+sub"
    elif core.startswith("|"):
        core = core[1:]
    core = core.rstrip("^").rstrip("|")
    if core.startswith("*"):
        reach = "wildcard"
    return ("allow" if allow else "block"), core, reach


def client_info(spec, net, persistent):
    """-> {spec, kind, name, zone}"""
    info = {"spec": spec, "kind": "", "name": "", "zone": ""}
    if "/" in spec:
        info["kind"] = "cidr"
        try:
            n = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            return info
        for sn, z in net.subnets:
            if n == sn:
                info["zone"] = z
                info["name"] = "ganzes %s-Subnetz" % z
        return info
    try:
        ip = ipaddress.ip_address(spec)
    except ValueError:
        info["kind"] = "name"
        for c in persistent:
            if c["name"] == spec:
                info["name"] = spec
                for i in c["ids"]:
                    try:
                        for sn, z in net.subnets:
                            if ipaddress.ip_address(i) in sn:
                                info["zone"] = z
                    except ValueError:
                        pass
        return info
    info["kind"] = "ip"
    info["name"] = net.by_ip.get(spec, "")
    if spec in net.router_ip:
        info["name"] = "Router (%s)" % net.router_ip[spec]
    for sn, z in net.subnets:
        if ip in sn:
            info["zone"] = z
    return info


def effect_text(r):
    t = r["type"]
    rw = r["mods"].get("dnsrewrite")
    if rw:
        return "lokal antworten: %s" % rw
    if t in ("allow", "regex_allow"):
        return "erlauben"
    return "sperren"


def build_rules(lines, net, persistent):
    """-> rules, groups [(part, section)] in file order. Parts come from '! TEIL n — title' between
    '! ====' frames, sections from '! --- title ---'; '!' alone ends a comment paragraph, the '! ####'
    title block at the top is skipped."""
    rules, groups, pending, part, section, pos = [], [], [], "", "", 0
    frame = None
    for raw in lines:
        s = raw.strip()
        if s.startswith("!"):
            m = RE_FRAME.match(s)
            if m:
                kind = m.group(1)[0] * 4           # '####' title block, '====' part header
                frame = None if frame == kind else kind
                pending = []
                continue
            if frame == "####":
                continue
            m = RE_PART.match(s)
            if m and frame == "====":
                part, section = m.group(1), ""
                if (part, section) not in groups:
                    groups.append((part, section))
                pending = []
                continue
            m = RE_HEADER.match(s)
            if m:
                section = m.group(1)
                if (part, section) not in groups:
                    groups.append((part, section))
                pending = []
                continue
            body = s[1:].strip()
            if not body:
                pending = []
                continue
            # commented-out rule: '! DISABLED <rule>' or '!<rule>'
            cand = body[len("DISABLED"):].strip() if body.upper().startswith("DISABLED") else body
            if cand.startswith(("@@||", "||", "/", "|")) and ("^" in cand or cand.endswith("/") or "$" in cand):
                rules.append(make_rule(cand, pos, part, section, pending, net, persistent, enabled=False, raw=raw))
                pending = []
                continue
            pending.append(body)
            continue
        if not s:
            continue
        pos += 1
        if (part, section) not in groups:
            groups.append((part, section))
        rules.append(make_rule(s, pos, part, section, pending, net, persistent, enabled=True, raw=raw))
        pending = []
    return rules, groups


def make_rule(text, pos, part, section, comments, net, persistent, enabled, raw):
    body, mods = split_modifiers(text)
    typ, pattern, reach = classify(body)
    clients = [client_info(c, net, persistent) for c in mods.get("client", [])]
    r = {"pos": pos if enabled else None, "enabled": enabled, "raw": text, "part": part or "(ohne Teil)",
         "section": section,
         "type": typ, "pattern": pattern, "reach": reach, "mods": mods, "important": bool(mods.get("important")),
         "clients": clients, "comments": list(comments), "hits": None}
    r["effect"] = effect_text(r)
    return r


# ---------------------------------------------------------------- checks

def check(rules, rewrites, persistent, net):
    warns, notes = [], []
    seen = {}
    pnames = {c["name"] for c in persistent}
    for r in rules:
        if not r["enabled"]:
            continue
        key = r["raw"]
        if key in seen:
            warns.append("Doppelte Regel (Zeile %d und %d): %s" % (seen[key], r["pos"], key))
        seen[key] = r["pos"]
        for c in r["clients"]:
            if c["kind"] == "ip" and not c["name"]:
                warns.append("Regel %d: Client %s hat keine DHCP-Reservierung und ist keine Router-Adresse: %s"
                             % (r["pos"], c["spec"], r["raw"]))
            elif c["kind"] == "ip" and not c["zone"]:
                warns.append("Regel %d: Client %s liegt in keinem Zonen-Netz: %s" % (r["pos"], c["spec"], r["raw"]))
            elif c["kind"] == "cidr" and not c["zone"]:
                warns.append("Regel %d: CIDR %s ist kein Zonen-Netz: %s" % (r["pos"], c["spec"], r["raw"]))
            elif c["kind"] == "name" and c["spec"] not in pnames:
                warns.append("Regel %d: $client-Name '%s' ist kein persistenter AdGuard-Client: %s"
                             % (r["pos"], c["spec"], r["raw"]))
        if r["type"].startswith("regex"):
            p = r["pattern"]
            if p == ".*" and not r["clients"]:
                warns.append("Regel %d: Catch-all-Regex ohne $client -- sperrt das ganze Netz: %s" % (r["pos"], r["raw"]))
            elif p != ".*" and not (p.startswith("^") or p.endswith("$")):
                warns.append("Regel %d: Regex ohne Anker (^/$), prueft jeden Namen voll: %s" % (r["pos"], r["raw"]))
        if r["reach"] == "wildcard" and r["type"] == "allow" and r["clients"]:
            warns.append("Regel %d: Pauschalfreigabe fuer %s: %s" % (r["pos"], ", ".join(c["spec"] for c in r["clients"]), r["raw"]))
        if not r["comments"] and r["enabled"]:
            pass  # a rule without a comment is allowed; the section heading is the context
    # allow/block pairs on the same domain and client scope
    by_dom = {}
    for r in rules:
        if r["enabled"] and r["type"] in ("allow", "block"):
            scope = tuple(sorted(c["spec"] for c in r["clients"]))
            by_dom.setdefault((r["pattern"], scope), []).append(r)
    for (dom, scope), rs in by_dom.items():
        kinds = {(r["type"], r["important"]) for r in rs}
        if ("allow", False) in kinds and ("block", False) in kinds:
            warns.append("Domain %s (%s): Freigabe und Sperre ohne $important -- die Freigabe gewinnt, die Sperre ist wirkungslos"
                         % (dom, ", ".join(scope) or "netzweit"))
    # persistent clients whose ids are not reserved
    for c in persistent:
        for i in c["ids"]:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", i) and i not in net.by_ip and i not in net.router_ip:
                try:
                    inzone = any(ipaddress.ip_address(i) in sn for sn, z in net.subnets)
                except ValueError:
                    inzone = False
                (notes if inzone else warns).append("AdGuard-Client '%s': ID %s ohne DHCP-Reservierung%s"
                                                   % (c["name"], i, " (Roaming-Adresse in einer Zone)" if inzone else ""))
        if c["use_global_settings"] and c["filtering_enabled"] is False:
            notes.append("AdGuard-Client '%s': filtering_enabled=false ist wirkungslos, solange globale Einstellungen gelten" % c["name"])
    for rw in rewrites:
        if not rw["enabled"]:
            warns.append("Rewrite %s -> %s ist deaktiviert" % (rw["domain"], rw["answer"]))
    return warns, notes


def doc_rules(path):
    """-> (rules documented in Teil A tables, rewrite domains documented in the Rewrites table), None | error.
    First backticked cell of each table row, the escaped pipe unescaped; the Rewrites table starts at '### DNS-Rewrites'."""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        return None, None, str(e)
    part = text.split("## Teil B")[0]
    rules_part, _, rw_part = part.partition("### DNS-Rewrites")
    cell = lambda chunk: [m.group(1).replace("\\|", "|") for m in
                          (re.match(r"^\|\s*`([^`]+)`\s*\|", ln) for ln in chunk.splitlines()) if m]
    return cell(rules_part), cell(rw_part), None


def doc_check(rules, rewrites, path):
    doc, doc_rw, err = doc_rules(path)
    if err:
        return {"path": path, "error": err, "missing_in_doc": [], "missing_on_device": []}, ["Doku-Abgleich: %s" % err]
    dev = {r["raw"] for r in rules if r["enabled"]}
    docset = set(doc)
    # the document masks one customer domain
    masked = {d for d in docset if "<firmendom" in d or "kunde-" in d}
    missing_in_doc = sorted(d for d in dev - docset if not any(
        re.sub(r"\\\.[a-z0-9-]+\\\.[a-z]+\$", "", d) == re.sub(r"\\\.<firmendomäne>\$", "", m) for m in masked))
    missing_on_device = sorted(d for d in docset - dev if d not in masked)
    warns = []
    if missing_in_doc:
        warns.append("Doku-Abgleich: %d Regel(n) auf dem Geraet fehlen in Teil A: %s"
                     % (len(missing_in_doc), "; ".join(missing_in_doc)))
    if missing_on_device:
        warns.append("Doku-Abgleich: %d dokumentierte Regel(n) stehen nicht auf dem Geraet: %s"
                     % (len(missing_on_device), "; ".join(missing_on_device)))
    dev_rw = {rw["domain"] for rw in rewrites if rw["enabled"]}
    rw_missing_in_doc, rw_missing_on_device = sorted(dev_rw - set(doc_rw)), sorted(set(doc_rw) - dev_rw)
    if rw_missing_in_doc:
        warns.append("Doku-Abgleich: Rewrite(s) auf dem Geraet fehlen in der Doku: %s" % ", ".join(rw_missing_in_doc))
    if rw_missing_on_device:
        warns.append("Doku-Abgleich: dokumentierte Rewrite(s) fehlen auf dem Geraet: %s" % ", ".join(rw_missing_on_device))
    return {"path": path, "documented": len(docset), "on_device": len(dev), "missing_in_doc": missing_in_doc,
            "missing_on_device": missing_on_device, "masked_in_doc": sorted(masked),
            "rewrites_documented": len(doc_rw), "rewrites_missing_in_doc": rw_missing_in_doc,
            "rewrites_missing_on_device": rw_missing_on_device}, warns


def count_hits(rules, path):
    """Hits per rule text from AdGuard's query log (Result.Rules[].Text, FilterListID 0 = user rules)."""
    text = read_file(path)
    hits, first, last, n = {}, {}, {}, 0
    for line in text.splitlines():
        if '"Rules"' not in line:
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        n += 1
        t = e.get("T", "")[:16]
        for ru in e.get("Result", {}).get("Rules", []):
            if ru.get("FilterListID", 0) == 0 and ru.get("Text"):
                k = ru["Text"]
                hits[k] = hits.get(k, 0) + 1
                first.setdefault(k, t)
                last[k] = t
    for r in rules:
        r["hits"] = hits.get(r["raw"], 0)
        r["hits_first"], r["hits_last"] = first.get(r["raw"], ""), last.get(r["raw"], "")
    return {"path": path, "entries_with_rules": n, "distinct_rules_hit": len(hits)}


# ---------------------------------------------------------------- html

EXTRA_CSS = """
table.rules td.raw{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.82rem;white-space:nowrap}
td.cm{color:var(--muted);font-size:.82rem;max-width:34rem}
.t-allow{color:var(--accept);font-weight:600}.t-block{color:var(--reject);font-weight:600}
.t-rw{color:var(--dnat);font-weight:600}.imp{background:var(--warn);color:#fff;border-radius:4px;padding:0 .3rem;font-size:.75rem}
tr.off td{opacity:.55}.hits{text-align:right;font-variant-numeric:tabular-nums}
table.rules{border-collapse:collapse;width:100%;margin:.4rem 0 1rem}table.rules th,table.rules td{border-bottom:1px solid var(--rule);padding:.3rem .45rem;vertical-align:top;text-align:left}
table.rules th{background:var(--head);position:sticky;top:var(--bar-h,6rem)}table.rules tr:nth-child(even) td{background:var(--stripe)}
.warnbox{border:1px solid var(--warn);border-radius:6px;padding:.5rem .8rem;margin:.8rem 0;background:var(--code)}
.stats span{margin-right:1rem}.legend{font-size:.85rem;color:var(--muted)}
.chip{display:inline-block;background:var(--code);border-radius:4px;padding:0 .35rem;margin:0 .15rem .15rem 0;font-size:.8rem}
"""


def esc(s):
    return html.escape(str(s), quote=True)


def type_cell(r):
    if r["mods"].get("dnsrewrite"):
        return '<span class="t-rw">REWRITE</span>'
    if r["type"] in ("allow", "regex_allow"):
        return '<span class="t-allow">ALLOW</span>' + (' <span class="imp">important</span>' if r["important"] else "")
    return '<span class="t-block">BLOCK</span>' + (' <span class="imp">important</span>' if r["important"] else "")


def client_cell(r):
    if not r["clients"]:
        return '<i>netzweit</i>'
    out = []
    for c in r["clients"]:
        label = c["name"] or ("?" if c["kind"] != "cidr" else "")
        out.append('<span class="chip">%s%s%s</span>' % (esc(c["spec"]), (" " + esc(label)) if label else "",
                                                           (" <small>%s</small>" % esc(c["zone"])) if c["zone"] else ""))
    return "".join(out)


def mods_cell(r):
    parts = [k if v is True else "%s=%s" % (k, v) for k, v in r["mods"].items() if k not in ("client", "important")]
    return esc(", ".join(parts)) or "—"


def row_html(r, with_hits):
    reach = {"domain+sub": "+ Subdomains", "exact": "exakt", "regex": "Regex", "wildcard": "Wildcard"}[r["reach"]]
    cells = ['<td>%s</td>' % (r["pos"] if r["enabled"] else "aus"), '<td>%s</td>' % type_cell(r),
             '<td class="raw">%s</td>' % esc(r["raw"]),
             '<td>%s <small class="dim">%s</small></td>' % (esc(r["pattern"]), reach),
             '<td>%s</td>' % esc(r["effect"]), '<td>%s</td>' % client_cell(r), '<td>%s</td>' % mods_cell(r),
             '<td class="cm">%s</td>' % esc(" ".join(r["comments"]))]
    if with_hits:
        cells.append('<td class="hits">%s</td>' % ("—" if r["hits"] is None else r["hits"]))
    return '<tr class="%s">%s</tr>' % ("" if r["enabled"] else "off", "".join(cells))


def render(rules, groups, rewrites, persistent, warns, notes, doc, hits_info, host, stamp):
    with_hits = hits_info is not None
    parts = []
    for p_, s_ in groups:
        if p_ not in parts:
            parts.append(p_)
    active = [r for r in rules if r["enabled"]]
    n_allow = sum(1 for r in active if r["type"] in ("allow", "regex_allow") and not r["mods"].get("dnsrewrite"))
    n_block = sum(1 for r in active if r["type"] in ("block", "regex_block") and not r["mods"].get("dnsrewrite"))
    n_rw = sum(1 for r in active if r["mods"].get("dnsrewrite"))
    nav = " ".join('<a href="#p-%d">%s</a>' % (i, esc(p_)) for i, p_ in enumerate(parts))
    out = ['<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           '<title>AdGuard-Regeln</title><style>%s%s</style></head><body><div id="wrap">' % (fwview.CSS, EXTRA_CSS),
           '<h1>AdGuard Home: benutzerdefinierte Filterregeln</h1><div class="meta">Quelle: %s &middot; Stand %s &middot; agview %s &middot; '
           'Spiegel zum Lesen, nicht Quelle: bei Abweichung gilt das Geraet, docs/dns-filtering.md Teil A ist die Doku. '
           'Enthaelt Client-IPs und Geraetenamen, nicht veroeffentlichen.</div>' % (esc(host), esc(stamp), VERSION),
           '<div id="bar"><div>%s <a href="#rewrites">Rewrites</a> <a href="#clients">Clients</a></div>'
           '<div style="margin-top:.4rem"><input id="q" type="search" placeholder="Filter: Domain, Client, Geraet, Zone, Kommentar ...">'
           ' <label><input id="hide" type="checkbox"> deaktivierte ausblenden</label></div></div>' % nav,
           '<p class="stats"><span><b>%d</b> Regeln aktiv</span><span><b>%d</b> Freigaben</span><span><b>%d</b> Sperren</span>'
           '<span><b>%d</b> lokale Antworten</span><span><b>%d</b> auskommentiert</span><span><b>%d</b> Rewrites</span>'
           '<span><b>%d</b> persistente Clients</span></p>' % (len(active), n_allow, n_block, n_rw, len(rules) - len(active),
                                                                 len(rewrites), len(persistent)),
           '<p class="legend">%s</p>' % esc(SEMANTICS)]
    if with_hits:
        out.append('<p class="legend">Treffer: aus %s, %d Eintraege mit Regeltreffer, %d verschiedene Regeln getroffen. '
                   '0 bei einer Freigabe heisst: im Fenster nie gebraucht.</p>'
                   % (esc(os.path.basename(hits_info["path"])), hits_info["entries_with_rules"], hits_info["distinct_rules_hit"]))
    if doc and not doc.get("error"):
        out.append('<p class="legend">Doku-Abgleich mit %s: %d dokumentiert, %d aktiv auf dem Geraet, %d fehlen in der Doku, %d fehlen auf dem Geraet.</p>'
                   % (esc(os.path.basename(doc["path"])), doc["documented"], doc["on_device"], len(doc["missing_in_doc"]), len(doc["missing_on_device"])))
    if warns:
        out.append('<div class="warnbox"><b>Auffaelligkeiten (%d)</b><ul>%s</ul></div>' % (len(warns), "".join("<li>%s</li>" % esc(w) for w in warns)))
    if notes:
        out.append('<div class="warnbox" style="border-color:var(--rule)"><b>Hinweise (%d)</b><ul>%s</ul></div>' % (len(notes), "".join("<li>%s</li>" % esc(n) for n in notes)))
    head = '<tr><th>#</th><th>Typ</th><th>Regel</th><th>Domain / Muster</th><th>Wirkung</th><th>Client</th><th>Modifier</th><th>Begruendung (Kommentar)</th>%s</tr>' % ('<th>Treffer</th>' if with_hits else "")
    for i, p_ in enumerate(parts):
        prs = [r for r in rules if r["part"] == p_]
        out.append('<h2 id="p-%d">%s <span class="cnt">%d</span></h2>' % (i, esc(p_), sum(1 for r in prs if r["enabled"])))
        for (pp, s_) in groups:
            if pp != p_:
                continue
            rs = [r for r in prs if r["section"] == s_]
            if not rs:
                continue
            if s_:
                out.append('<h3>%s <span class="cnt">%d</span></h3>' % (esc(s_), sum(1 for r in rs if r["enabled"])))
            out.append('<table class="rules">%s%s</table>' % (head, "".join(row_html(r, with_hits) for r in rs)))
    out.append('<h2 id="rewrites">DNS-Rewrites (filtering.rewrites)</h2><table class="rules"><tr><th>Domain</th><th>Antwort</th><th>Status</th></tr>%s</table>'
               % "".join('<tr><td class="raw">%s</td><td>%s</td><td>%s</td></tr>' % (esc(rw["domain"]), esc(rw["answer"]), "aktiv" if rw["enabled"] else "aus") for rw in rewrites))
    out.append('<h2 id="clients">Persistente AdGuard-Clients</h2><table class="rules"><tr><th>Name</th><th>IDs</th><th>globale Einstellungen</th><th>filtering_enabled</th><th>Regeln mit $client</th></tr>')
    for c in persistent:
        n = sum(1 for r in active for cc in r["clients"] if cc["spec"] in c["ids"] or cc["spec"] == c["name"])
        out.append('<tr><td>%s</td><td class="raw">%s</td><td>%s</td><td>%s</td><td>%d</td></tr>' % (
            esc(c["name"]), esc(", ".join(c["ids"])), c["use_global_settings"], c["filtering_enabled"], n))
    out.append('</table>')
    out.append("""<script>
const q=document.getElementById('q'),hide=document.getElementById('hide');
function apply(){const f=q.value.toLowerCase();document.querySelectorAll('table.rules tr').forEach(tr=>{if(!tr.querySelector('td'))return;
const t=tr.textContent.toLowerCase();tr.style.display=((!f||t.includes(f))&&!(hide.checked&&tr.classList.contains('off')))?'':'none';});}
q.addEventListener('input',apply);hide.addEventListener('change',apply);
document.documentElement.style.setProperty('--bar-h',document.getElementById('bar').offsetHeight+'px');
</script></div></body></html>""")
    return "\n".join(out)


# ---------------------------------------------------------------- json

def json_report(rules, groups, rewrites, persistent, warns, notes, doc, hits_info, host, stamp):
    return {"tool": "agview %s" % VERSION, "source": host, "generated": stamp, "semantics": SEMANTICS,
            "stats": {"rules_active": sum(1 for r in rules if r["enabled"]), "rules_disabled": sum(1 for r in rules if not r["enabled"]),
                      "rewrites": len(rewrites), "persistent_clients": len(persistent)},
            "groups": [{"part": p_, "section": s_} for p_, s_ in groups],
            "rules": [dict({k: r[k] for k in ("pos", "enabled", "raw", "part", "section", "type", "pattern", "reach", "effect",
                                              "important", "mods", "clients", "comments", "hits")},
                           **({"hits_first": r.get("hits_first", ""), "hits_last": r.get("hits_last", "")} if hits_info else {}))
                      for r in rules],
            "rewrites": rewrites, "persistent_clients": persistent, "warnings": warns, "notes": notes,
            "doc_check": doc, "querylog": hits_info}


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="AdGuard Home custom rules as HTML page + JSON report (read-only)")
    ap.add_argument("--host", default=fwview.DEFAULT_HOST)
    ap.add_argument("--from-dir")
    ap.add_argument("--out")
    ap.add_argument("--json")
    ap.add_argument("--doc", default=DEFAULT_DOC)
    ap.add_argument("--no-doc", action="store_true")
    ap.add_argument("--querylog")
    a = ap.parse_args()
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    out = a.out or "agview-%s.html" % datetime.datetime.now().strftime("%Y%m%d-%H%M")
    jout = a.json or re.sub(r"\.html?$", "", out) + ".json"
    excerpt, dhcp, network, firewall = read_all(a)
    lines, rewrites, persistent = parse_excerpt(excerpt)
    fw = fwview.parse_uci(firewall)
    net = fwview.Net(fwview.parse_uci(dhcp), fwview.parse_uci(network), [s for s in fw if s["type"] == "zone"])
    rules, groups = build_rules(lines, net, persistent)
    if not rules:
        sys.exit("agview: keine Regeln gefunden")
    warns, notes = check(rules, rewrites, persistent, net)
    doc = None
    if not a.no_doc and (a.doc != DEFAULT_DOC or os.path.exists(a.doc)):
        # the default document belongs to the network documentation repo; without it, skip quietly
        doc, dw = doc_check(rules, rewrites, a.doc)
        warns.extend(dw)
    hits_info = count_hits(rules, a.querylog) if a.querylog else None
    if hits_info:
        dead = [r["raw"] for r in rules if r["enabled"] and r["type"] in ("allow", "regex_allow") and r["hits"] == 0]
        if dead:
            notes.append("%d Freigabe(n) ohne Treffer im Query-Log-Fenster: %s" % (len(dead), "; ".join(dead)))
    host = a.from_dir or a.host
    open(out, "w", encoding="utf-8").write(render(rules, groups, rewrites, persistent, warns, notes, doc, hits_info, host, stamp))
    open(jout, "w", encoding="utf-8").write(json.dumps(json_report(rules, groups, rewrites, persistent, warns, notes, doc, hits_info, host, stamp),
                                                     ensure_ascii=False, indent=1))
    print("agview: %d Regeln (%d aktiv), %d Rewrites, %d Clients, %d Auffaelligkeiten, %d Hinweise -> %s, %s"
          % (len(rules), sum(1 for r in rules if r["enabled"]), len(rewrites), len(persistent), len(warns), len(notes), out, jout))


if __name__ == "__main__":
    main()
