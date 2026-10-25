# Firewall- und DNS-Audit 2026-10-24 (Firewall-Log, AdGuard-Query-Log)

**Stand:** 2026-10-24, 10:30 Uhr. Dritter Lauf nach den Audits vom 17.10. und 22.10.
(`firewall-dns-audit-2026-10-22.md`), vom Operator als Wochenlauf angefordert. Ausgeführt aus der
`claude-home`-Session (Coding Agent, T0), lesend; keine Änderung am Gerät. Firmen- und Kundendomänen
in den Anhängen durch dieselben Platzhalter ersetzt wie am 22.10. (`firma-intern.tld`, `kunde-a.tld` …).
Leitfragen des Operators: Was ist auffällig? Was läuft gut? Wo nachschärfen? Wo fehlt Sichtbarkeit?

## 1. Rahmen

| Quelle | Fenster | Umfang |
|---|---|---|
| Firewall-Log (`/mnt/nvme/log/system.log`, `scripts/fwlog-audit.py --since '2026-10-18 00:00'`) | **tatsächlich 21.10. 21:24 – 24.10. 10:26** (61 h) | 1.240 Zeilen (22.10. 23:25: 876; seither +364 ≈ 10/h) |
| AdGuard-Query-Log (`querylog.json`, `scripts/dnslog-audit.py --since '2026-10-18 00:00' --querylog <gzip-Kopie>`) | **tatsächlich 21.10. 21:14 – 24.10. 10:24** (61 h); `querylog.json.1` fehlt weiterhin | 164.000 Einträge, 17 Clients, 2.732 Namen, 44,2 % geblockt |
| Regelwerk | 1.44.3 (unverändert seit 22.10. 22:59) | Guard: 43 Regeln mit Set-Referenz rendern, Patch-Dateien unverändert |
| Ergänzend | `nlbwmon` (Volumen je Gerät, Oktober), `logread`, `/proc/uptime`, `wg show`, AdGuard-YAML (nur `ratelimit`, `user_rules`, `upstream`, `tls`-Pfade) | lesend |

Beide Logs beginnen am 21.10. abends; die Woche 18.–21.10. ist nicht auditierbar (Befund F1).
Die Kinder-Geräte (`kids`) waren im Fenster nicht im Netz (keine hostapd-, DHCP-, Firewall- oder
DNS-Zeile); der K1-DROID-Befund vom 18.10. (Private DNS) ist deshalb nicht nachgeprüft (S6).

## 2. Ergebnis in Kürze

**Auffällig**

- **F1 Boot-Rätsel vom 22.10. gelöst:** nicht drei Boots, sondern zwei — 21.10. 23:00 und 22.10. 17:36.
  Der Router hat keine RTC; die ersten ~90 s nach dem Boot vom 22.10. tragen den Zeitstempel
  „21.10. 23:00:37–23:01:26" (`crond: time disparity of 1116 minutes` um 17:37:52). Davor
  17:22:27 `eth0 link is down`. Lücke 18.–21.10.: Query-Log 21:14 **und** System-Log 21:23 am 21.10.
  neu begonnen, ohne Reboot (Kernel-Uptime lief seit 16.10. durch) — Operator-Eingriff wahrscheinlich.
  Beide Boots laut Operator (24.10.) beabsichtigte Stromausfälle (Umbau der zentralen Stromversorgung); das Leeren
  beider Logs am 21.10. ebenfalls vom Operator, beabsichtigt. **F1 geschlossen.**
- **F2 `.20.217` identifiziert und geschlossen:** Zufalls-MAC `02:dc:e2:be:bd:15` = `OP-S25` beim ersten Verbinden
  mit dem neuen Passwort (21.10. 22:30, Randomisierung noch an, 3 s später echte MAC auf derselben Association-ID).
  `.20.115` vom 17.10. laut Operator derselbe Fall.
- **F3 Docker-Quelladresse im LAN:** `172.21.0.2` (Container-Netz von `OP-T490`) → Anthropic-API
  `tcp/443`, 9× am 23.10. 14:03, vom Router abgewiesen. **Geklärt:** eine Verbindung, zehn Sekunden nach dem
  manuellen ProtonVPN-Trennen auf dem Laptop; Masquerade-Regel vorhanden, einmaliges Race beim Interface-Umbau.
- **F4 Hub-PTR-Sweep weiter aktiv:** 13.000 Blocks (68 % des Hub-DNS), 544 s am Rate-Limit in 124 Minuten;
  `ratelimit_whitelist` leer — V1 vom 17.10. unverändert offen. **Umgesetzt 24.10. 13:13 (1.45.3).**
- **F6 Upstream-Latenz:** p99 3,0 s, 1.029 Antworten > 1 s, 76 Quad9-Fallbacks — wie am 22.10., kein Einzelfall.

**Läuft gut** (Abschnitt 4): Egress-Policy hält in jeder Zone (0 DoT/DoH-Durchbrüche, 63 Namensversuche
alle geblockt), Management nur über den Tunnel (4 Direktversuche abgewiesen, zuletzt heute 10:24),
`private`-Pins (F2 bekam kein DNS), Panel nach dem Umbau mit 3 Block-Zeilen in 36 h, Default-Deny-IoT
exakt auf den Positivlisten, `.lan`-Leak geschlossen (V2 vom 22.10. wirkt: 294× lokal NXDOMAIN, 0 am Upstream).

**Nachschärfen** (Abschnitt 5): Rate-Limit-Ausnahme Hub (V1), `wpad`/`_ldap`/`_autodiscover` des
Work-Laptops lokal beantworten statt an NextDNS leaken (V2), Zufalls-MAC-Gerät inventarisieren (V3),
Docker-NAT auf `OP-T490` (V4), optionale Mutes Work-Sonden/TV-QUIC (V5), `a-api.anthropic.com`-Entscheidung (V6),
Panel-Einzelfreigaben ab 26.10. (V7, Datengrundlage liegt in D9).

**Sichtbarkeit fehlt** (Abschnitt 6): kein Remote-Syslog (Lücke 18.–21.10. unwiederbringlich, Logs lokal
löschbar), AdGuard-Rate-Limit-Drops unsichtbar (641 s über drei Zonen), keine RTC (Boot-Minute falsch
gestempelt), Query-Log ohne Rotationsdatei, erlaubter Verkehr nur als `nlbwmon`-Volumen (bisher nicht
im Audit), `kids`-Zone ohne Verkehr, DNS-Pfad von `.50.238` am 22.10. ungeklärt.

## 3. Befunde

| Nr. | Befund | Tabellen | Einordnung |
|---|---|---|---|
| F1 | **Boots und Log-Lücke.** Kernel-Uptime 147.017 s um 10:26 → Boot **22.10. 17:36:09**. Davor `eth0 link is down` / `wan connectivity loss` 17:22:27, danach erste Zeilen 17:37:48. Die Zeilen „21.10. 23:00:37 kernel [3.8 s]" bis „23:01:26 AdGuard start" im RAM-Puffer (`logread`, der den 21.10.-Boot nicht überlebt hätte) gehören zum 22.10.-Boot: ohne RTC startet die Uhr mit dem letzten bekannten Stand, NTP korrigiert um 17:37:52 (`crond: time disparity of 1116 minutes`, `collectd: next interval 66921 s`). Damit: Boot 1 = 21.10. 23:00:13 (`init complete`), Boot 2 = 22.10. 17:36 (im Log als 23:00:51). Beide AdGuard-Starts (23:01:17, 23:01:26) sind je ein Boot. **Lücke:** Query-Log beginnt 21.10. 19:14Z = 21:14, `/mnt/nvme/log` 21:23:10 neu befüllt, System-Log ab 21:24:07 — bei durchlaufendem Kernel (ts 482.097 s = Boot 16.10.). Muster „beide Dateien weg, keine `.1`" = AdGuard-GUI „Query-Log leeren" plus Löschen/Neustart von `logd`. Kein Commit am 21.10. Abend; 22:29 `AP-DISABLED` (WLAN-Neustart), 23:00 Reboot → Operator-Abend. **Operator 24.10.: beide Stromausfälle waren beabsichtigt (Umbau der zentralen Stromversorgung).** **Operator 24.10.: Query-Log und System-Log am 21.10. bewusst gelöscht.** F1 damit vollständig geklärt; die Lücke 18.–21.10. ist gewollt | T1, T2 | **Geschlossen.** §13-Hinweis zur fehlenden RTC ergänzt (1.45.2) |
| F2 | **`192.168.20.217` = Zufalls-MAC `02:dc:e2:be:bd:15`** (lokal verwaltet), `phy1-ap0` (`private`, 5 GHz), `auth_alg=sae` erfolgreich 21.10. 22:30:52, Abmeldung 22:31:01. 6× `udp/53` an `192.168.20.1` abgewiesen (`Allow-private-router-dns` nur `admin_pins`); kein DHCP-Dialog (Adresse aus altem Lease), keine AdGuard-Anfrage. **`/etc/config/wireless` wurde 22:28:58 geschrieben (Passwortwechsel `private`, Operator), AP-Neustart 22:29:00 — die Anmeldung 112 s später gelang also mit dem neuen Passwort** (SAE scheitert mit falschem Passwort vor dem Handshake, ohne `AP-STA-CONNECTED`). **Operator 24.10.: das war `OP-S25` beim ersten Verbinden mit dem neuen Passwort, MAC-Randomisierung noch aktiv.** Log bestätigt: Abmeldung `aa:42…` 22:31:01, Anmeldung `02:3b:91:99:ee:97` (`OP-S25`) 22:31:04 auf derselben `aid 2`, danach Randomisierung aus. Altes Lease `.217` = frühere Besuche mit derselben Zufalls-MAC. **Geklärt.** `.20.115` (`02:ec:4d:41:97:8e`, 17.10.) laut Operator 24.10. ebenfalls `OP-S25` mit damals aktiver Randomisierung — **beide Zufalls-MAC-Funde geschlossen** Gleiche Klasse: `.20.115` vom 17.10. (nlbwmon: MAC `02:ec:4d:41:97:8e`, ebenfalls Zufalls-MAC) | T4, T9 | **Inventar (V3)** |
| F3 | **Un-NATete Container-Pakete:** `SRC=172.21.0.2 DST=160.79.104.10 tcp/443` (Anthropic-API), 9 Zeilen 23.10. 14:03:34–14:04:48, `reject private forward` (`OUT=eth0`). `172.21.0.0/16` ist die Docker-Bridge `br-580de9460563` auf `OP-T490` (Bridge-Adresse `.1`). Der Laptop leitet Container-Pakete ohne Masquerade ins LAN; der Router hat keine Route zurück und weist korrekt ab. **Geklärt 24.10. (Journal des Laptops):** 14:03:24 ProtonVPN in der App getrennt, NetworkManager löscht `proton0` und Kill-Switch-Interface, Routen neu; 14:03:34 **eine** Container-Verbindung (Quellport 37940, neun SYN-Wiederholungen bis 14:04:48) ohne NAT. Race beim VPN-Umschalten — NAT-Entscheidung fiel beim ersten Paket während des Interface-Umbaus. Masquerade-Regel `-s 172.21.0.0/16 ! -o br-580de9460563 -j MASQUERADE` vorhanden (283 Pakete seither), Docker-Backend iptables-nft, ufw aktiv | T5, T9 | **Geschlossen**, kein Konfigurationsfehler; Router korrekt |
| F4 | **Hub-PTR-Sweep unverändert** (N1 17.10., F2 22.10.): 254 `in-addr.arpa`-Namen, 13.000 Blocks = 68 % des Hub-DNS, 544 Sekunden ≥ 20/s in 124 Minuten; dazu 136 `NS`-Anfragen für den Root. `ratelimit_whitelist: []`. **Nachtrag 24.10. 11:13:** Sweep per Ignorierliste (`\|\|60.168.192.in-addr.arpa^`, Query-Log + Statistik) aus dem Log genommen (Operator, GUI); Rate-Limit-Wirkung unverändert, D15 sieht sie ab jetzt nicht mehr. **13:13:** `ratelimit_whitelist` = `192.168.60.245` gesetzt (Operator, GUI) | D4, D8, D9, D11, D15 | **V1 umgesetzt**, Validierung im nächsten Audit |
| F5 | **Rate-Limit trifft auch Admin-Geräte:** `private` 9 s am Limit (alle drei Admin-Clients mit max 20/s), `work` 88 s (Laptop 43/s). Verworfene Anfragen stehen nicht im Log | D4, D15 | Mit V1 entscheiden: Ausnahme nur Hub oder Limit anheben |
| F6 | **Upstream:** NextDNS 57.688 Antworten, p50 47 ms, p90 145 ms, **p99 3.048 ms, 1.029 > 1 s**; Quad9-Fallback 76× (49 + 27). Zweiter Lauf in Folge mit diesem Bild (22.10.: p99 3,1 s, 594 > 1 s, 76 Fallbacks) | D16 | **Beobachten → NextDNS-Status prüfen (V9)** |
| F7 | **Hub→Panel ohne Conntrack** (F6 22.10.): 85 Zeilen am 22.10., 27 am 23.10. bis 08:51:38, seither keine. 5 Minuten `Block-iotsrv-wan-all` + 2 Minuten Zonen-Log am Limit | T1, T5, T6 | Abgeklungen; V4 vom 22.10. nicht nötig |
| F8 | **`.lan`-Leak geschlossen:** `\|\|lan^$dnsrewrite=NXDOMAIN` steht in den Benutzerregeln; 294 `.lan`-Anfragen im Fenster (`localhost.lan` 238, `patchpilot-*.lan` 21, `_9443._https.adguard.home.arpa.lan` 11) alle `Reason 11`, Upstream `-`. `.local`: 0 Anfragen, Regel nicht nötig | D12 | Erledigt (V2 22.10.) |
| F9 | **Work-Laptop:** 96.750 Anfragen an zwei Arbeitstagen (59 % des Gesamtvolumens), 34,5 % geblockt. `ipv6.msftconnecttest.com` 10.439× geblockt (`$important`-Benutzerregel, Laptop wiederholt), 6.058 NXDOMAIN: `wpad.firma-intern.tld` 3.893, `_autodiscover._tcp.kunde-a.tld` 739, `ccm1.intern.kunde-b.tld` 242, `_ldap._tcp.*` je 22 — **alle am Upstream**. 613 PTR-Namen (`in-addr.arpa`, erlaubt). Firewall: 332 Zeilen, davon 284 ICMP/`udp/33434`-Sonden zu drei Zscaler-Adressen, 4 Minuten am Limit; `tcp/8443` zu `192.168.5.221` (Firmenadresse, Skript-Label „Uplink-LuCI" falsch) | D4, D7, D12, D13, T6, T9 | Policy hält; **Hygiene (V2)**, optional **V5** |
| F10 | **TV:** 15.895 Anfragen, 91,1 % geblockt (`leiniao.com` 6.853, Google-Assistant 5.482, Apple-Medien 1.367, `mefo1.zdf.de` 588); konstant ≈ 660/h auch nachts (Gerät im Standby). Firewall: 103 Zeilen `Block-tv-wan-all`, 84 davon QUIC `udp/443` zu Google, 2 Minuten am Limit; 2× DoT-Versuch an den Router | D4, D7, D8, T6 | Bestätigung; optional **V5** (QUIC-Mute, V6 vom 17.10.) |
| F11 | **Panel nach dem Umbau:** `Block-panel-wan-all` 3 Zeilen seit 22.10. 22:52 — 2× `tcp/8123` 22:52 (Log-vor-Zone-Artefakt, dokumentiert), 1× `51.159.23.43 tcp/443` 23.10. 19:21 (Scaleway/Poney Telecom, außerhalb der drei Sets, einmalig). DNS 368 Anfragen, 36 erlaubte Namen: `hub.home.arpa` 181, `f-droid.org` + 14 Mirrors, `update.googleapis.com`, `edgedl.me.gvt1.com`, `my.`/`www.home-assistant.io`, `suggestqueries.google.com`, Browser-Startseiten (`www.google/twitter/facebook/yahoo`), `t0/t1.gstatic.com`, `raw.githubusercontent.com`, `version.pm2.io`; 133 geblockt (NTP-Namen vor der Umleitung, `eu-apia.coolkit.cc` 1× erlaubt um 18:14 **vor** der `$important`-Sperre, danach keine). 6× DoT an den Router (`tcp/853`, Android „Privates DNS automatisch") | D9, D14, T4, T6 | **V7** vorbereitet |
| F12 | `a-api.anthropic.com` 505× geblockt (`OP-S25`, HaGeZi Ultimate); `api.anthropic.com` 2.284× erlaubt (drei Geräte). Entscheidung V6 vom 22.10. offen | D7, D8, D17 | **Entscheidung (V6)** |
| F13 | **DoH/DoT-Namen:** 63 Anfragen, 0 erlaubt — `cloudflare-dns.com` (OP-S25 22, OP-T41S 14), `dns.google(.com)` 11, `mozilla.cloudflare-dns.com` 8, Quad9 6, `dnsforge.de` 1. Browser-Sonden; in `private` ist DoH per IP bewusst offen (V7 17.10.) | D10 | Bestätigung |
| F14 | **Rauschen im Zonen-Log:** Router-eigene DHCP-Antworten (`SRC=192.168.70.1 → 255.255.255.255 udp/67→68`, 12× `reject work in`; 1× `smarthome`) — Hairpin eigener Broadcasts, kein Client. `OP-T490` sendet Broadcasts `udp/1716` (KDE Connect), `udp/161` (SNMP), `udp/8610/8612` (Canon BJNP), `udp/3289` | T4 | Hinweis; Skript-Klasse für „eigene Adresse als Quelle" fehlt |
| F15 | **`wgvpn`:** 116 Gateway-Pings `10.2.0.1`, 131 `invalid ct state` (Rückläufer abgelaufener Sitzungen, `OP-T41S`/`OP-S25`), 43 externe Quellen — Antwortseiten eigener Verbindungen (`82.220.37.2` 85 Ports = T41S-Sitzung), kein Scan | T4, T7, T8 | Wie L2 (17.10.), V4 (17.10.) offen |
| F16 | **AdGuard-TLS-Warnung beim Start:** `tls_manager: validating certificate pair: certificate signed by unknown authority` (2×, beide Boots). `cert.pem` von der internen CA (Maßnahme D), die CA liegt nicht im Trust-Store des Routers; AdGuard bedient `9443` trotzdem (Warnung, kein Fehler) | — | Hinweis (V10, kosmetisch) |
| F17 | **Admin-Tunnel:** seit dem Boot nur der Laptop-Peer mit Handshake; Phone- und T41S-Peer 0 (nicht genutzt). C18 (Reboot-Test) damit für den Laptop zum zweiten Mal bestätigt, für die beiden anderen weiter offen | — | Bestätigung |
| F18 | **Router-eigene Anfragen** `hf.co`/`huggingface.co` (F16 22.10.) nur 21.10. 22:56, danach keine | D14 | Erledigt (einmalig) |
| F19 | **Volumen (nlbwmon, Oktober):** WAN 37,5 GB ↓ / 5,4 GB ↑; TV 29,4 GB ↓ (Streaming), Work-Laptop 24,9/9,9 GB, T41S 19,5 GB, S25 11,1 GB, Hub 6,1 GB (334.610 Verbindungen — Tailscale/Polling), **K1-DROID 2,3 MB** (passt zum Private-DNS-Befund vom 18.10.: faktisch kein Verkehr), K2-iPhone15 1,1 GB, `.20.115` (`02:ec:4d:41:97:8e`) 50 KB | — | Neue Sichtbarkeitsquelle (S5) |

## 4. Was läuft gut

| Nr. | Nachweis | Daten |
|---|---|---|
| G1 | **Egress-Policy je Zone:** keine Zeile `Block-*-wan-dot`/`-doh`/`-uplink-all` in 61 h; DoT-Versuche enden am Router (`reject <zone> in`, TV 2, Panel 6+2); 63 DoH/DoT-Namensanfragen, 0 beantwortet | T1, T4, D10 |
| G2 | **Management nur über `wgadm`:** `OP-T490` → `192.168.30.1` `tcp/443` 3× und `tcp/22` 2× abgewiesen (`reject private in`, zuletzt 24.10. 10:24 — der eigene Versuch vor dem Tunnelstart) | T4 |
| G3 | **`private`-Pins:** unbekanntes Gerät (F2) bekam kein DNS; `OP-S25` → Router `tcp/80` 3× abgewiesen | T4 |
| G4 | **`tv`-Pins:** fremder Client `.50.238` am 22.10. ohne DNS vom Router (32 Abweisungen) | T4 |
| G5 | **Panel:** drei Kategorie-Sets reichen — 3 Block-Zeilen in 36 h, davon 2 Artefakt; Hub-Verkehr `tcp/8123` läuft über `Allow-panel-hub-ha` | T6 |
| G6 | **Default-Deny-IoT:** Govee 4 erlaubt (`time.google.com`) / 366 geblockt; Voice-Assistants nur `firmware.esphome.io`; Nuki-Bridge nur `sse*-bridge.nuki.io`; `.10.189` (Panel vor Reservierung) 230/230 geblockt | D9 |
| G7 | **`.lan`-Leak geschlossen** (F8) | D12 |
| G8 | **Logvolumen:** 20 Zeilen/h im Fenster, ≈ 10/h seit dem Umbau-Abend; 17 Limit-Minuten gesamt, keine davon sicherheitsrelevant; 0 SERVFAIL, Cache-Trefferquote 35,7 % | T1, D16 |
| G9 | **Patch-Guard:** stündlich (`17 * * * *`), 43/18, Patch-Dateien unverändert | — |
| G10 | **Keine Scan-Indikatoren:** T8 enthält nur eigene Geräte und Antwortseiten | T8 |
| G11 | **`forward_kids`-Zähler** seit dem Boot 0 auf allen Block-Regeln (keine Kinder-Geräte im Netz, kein Fremdverkehr aus `kids`) | — |

## 5. Vorschläge (nachschärfen)

Reihenfolge nach Wirkung. AdGuard nur über die Oberfläche; Firewall je Vorschlag ein Schritt, ein Commit.

| Nr. | Ziel | Änderung | Risiko / Aufwand |
|---|---|---|---|
| V1 | Hub-Drops (F4, F5) | **Umgesetzt 24.10. 13:13 (Whitelist, `ratelimit` bleibt 20).** Ursprünglich: `ratelimit_whitelist` = `192.168.60.245` (GUI → DNS-Einstellungen). Dazu entscheiden, ob `ratelimit` von 20 auf 50/s geht (Admin-Geräte erreichen das Limit; `work` 88 s) | GUI-Änderung, sofort messbar in D15 |
| V2 | Firmen-Namen am Upstream (F9) | Benutzerregeln mit lokalem NXDOMAIN für Namen, die nur ein Firmen-Resolver kennt: `/^wpad\./$dnsrewrite=NXDOMAIN;;`, `/^_ldap\._tcp\./$dnsrewrite=NXDOMAIN;;`, `/^_autodiscover\._tcp\./$dnsrewrite=NXDOMAIN;;`, jeweils `$client=192.168.70.0/24`. Entfernt ≈ 2.600 Leaks je Arbeitstag (≈ 5.300 im Fenster; die erste Fassung nannte 4.700/Tag); Antwort bleibt NXDOMAIN wie heute. **Umgesetzt 2026-10-24 11:45 (Operator), 1.44.12.** Regex mit Anker, kein Catch-all | Keins für den Laptop (bekommt dieselbe Antwort); `dns-filtering.md` A.3 |
| V3 | Inventar (F2) | **Erledigt (Operator 24.10.):** `02:dc:e2:be:bd:15` und `02:ec:4d:41:97:8e` (`.20.115`) waren beide `OP-S25` mit aktiver MAC-Randomisierung, inzwischen abgeschaltet. Verbleibende Handlungsanweisung für künftige Fälle: auf den Haushaltsgeräten „Private WLAN-Adresse" für die `private`-SSID prüfen (iOS: WLAN → (i) → Private Wi-Fi Address; Android: Netzwerkdetails → Datenschutz). Entweder Randomisierung für diese SSID aus und reservieren, oder bewusst ohne Dienste lassen (heute: WLAN ja, DNS/Internet nein) | Operator, 10 Minuten |
| V4 | Docker-NAT auf `OP-T490` (F3) | **Erledigt 24.10.:** Regel vorhanden, Ursache war ein einmaliges Race beim VPN-Trennen (F3). Ursprüngliche Prüfanweisung: `sudo iptables -t nat -S POSTROUTING \| grep 172.21` bzw. `sudo nft list chain ip nat POSTROUTING`; fehlt die MASQUERADE-Regel für `172.21.0.0/16`, Docker-Daemon-Option `iptables`/`ip6tables` bzw. Backend (nftables vs. iptables-legacy) prüfen, Docker neu starten | Laptop-seitig, kein Router |
| V5 | Log-Rauschen (F9, F10, optional) | `Mute-work-wan-probe` (ICMP echo + `udp/33434-33534` → `wan`, `work_pins`) und `Mute-tv-wan-quic` (`udp/443`, `tv_pins`) nach dem Muster `Mute-work-wan-quic` — ohne Log, vor dem jeweiligen `Block-*-wan-all` | Kein Policy-Effekt, −390 Zeilen in diesem Fenster |
| V6 | Claude-App (F12) | **Unverändert V6 vom 22.10.:** `@@\|\|a-api.anthropic.com^$client=192.168.20.189` oder bewusst gesperrt lassen; in `dns-filtering.md` Teil B einstufen | Nur Doku + eine Regel |
| V7 | Panel-DNS (F11) | Ab 26.10. Pauschalfreigabe `@@\|\|*^$client=192.168.10.11` ersetzen durch: `@@\|\|f-droid.org^`, Mirror-Liste aus D9 (14 Namen) **oder** `\|\|*^$client=192.168.10.11` als Default-Deny plus F-Droid-Mirrors per Regex `/^(mirror|mirrors|ftp)\./` — Entscheidung Operator; `update.googleapis.com`, `edgedl.me.gvt1.com`, `my.`/`www.home-assistant.io`, `hub.home.arpa` (Rewrite, unberührt). `suggestqueries.google.com`, Startseiten-Checks und `version.pm2.io` **nicht** freigeben (Browser-Komfort, kein Bedarf). eWeLink-Sperren danach überflüssig | Wie geplant; D9 ist die Liste |
| V8 | Log-Lücke (F1) | **Erledigt:** Boots (Stromarbeiten) und Log-Löschung am 21.10. vom Operator am 24.10. bestätigt, beides beabsichtigt. Doku §13: „kein RTC — Zeilen der ersten Minute nach dem Boot tragen den letzten bekannten Zeitstempel, Marker `crond: time disparity`"; `logread`-Puffer überlebt keinen Boot (S1). CHANGELOG-Nachtrag für den 21.10., falls es ein bewusster Eingriff war | Nur Doku |
| V9 | Upstream-Latenz (F6) | Wenn p99 > 1 s im dritten Lauf bleibt: NextDNS-Status (`my.nextdns.io` → Logs/Latenz), `upstream_mode` `load_balance` → `parallel` mit Quad9 als zweitem Upstream erwägen (Policy: NextDNS-Profil filtert; Quad9 nur Fallback) | GUI; Policy-Entscheidung |
| V10 | AdGuard-TLS-Warnung (F16) | Interne CA nach `/etc/ssl/certs/` (`ca-certificates`-Pfad) auf dem Router, oder Warnung dokumentiert hinnehmen | Kosmetisch |
| V11 | Audit-Skripte | `dnslog-audit.py`: fehlende `querylog.json.1` tolerieren (seit 22.10. bekannt); `fwlog-audit.py`: Klasse „eigene Adresse als Quelle" (F14), Label `192.168.5.221` ≠ Uplink; beide: Boot-Marker und `time disparity` ausweisen | Skript, ein Commit |

## 6. Wo Sichtbarkeit fehlt

| Nr. | Lücke | Folge im Fenster | Hebel |
|---|---|---|---|
| S1 | **Kein Remote-Syslog.** Logs liegen nur auf dem Router (NVMe + RAM-Puffer); lokal löschbar, Boot verliert den Puffer | 18.–21.10. unwiederbringlich weg; zwei Logs am 21.10. ohne Spur geleert | Syslog-Host (Maßnahme A, X250) — `logd` kann parallel per `log_ip`/`log_port` senden |
| S2 | **AdGuard-Rate-Limit verwirft stumm** | 544 s (Hub) + 88 s (Work) + 9 s (private) am Limit, Anzahl verworfener Anfragen unbekannt | V1; AdGuard loggt Drops nicht, nur `ratelimit_whitelist` macht sie sichtbar |
| S3 | **Keine RTC** | Erste ~90 s nach jedem Boot falsch gestempelt; Audit-Skripte sortieren sie in den falschen Tag; Boot-Zählung am 22.10. deshalb falsch | Doku (V8), Skript-Marker (V11); Hardware nicht änderbar |
| S4 | **Query-Log ohne `.1`** seit dem Leeren; Skript bricht ohne die Datei ab | Umweg über gzip-Kopie | V11 |
| S5 | **Erlaubter Verkehr ist unsichtbar** (nur Panel-Allows loggen) — `nlbwmon` läuft seit 10.10. mit Monats-DB auf der NVMe, wurde bisher nicht ausgewertet | F19 zeigt, was möglich ist: Volumen je Gerät, Verbindungsanzahl (Hub 334.610) | `nlbw -c show -g mac,ip` in den Audit-Turnus aufnehmen; `database_generations` 10 reicht für 10 Monate |
| S6 | **`kids` ohne Verkehr im Fenster** | K1-DROID-Befund vom 18.10. (Private DNS → kein DNS) nicht nachgeprüft; nlbwmon: 2,3 MB im ganzen Oktober | Beim nächsten Besuch: Private DNS aus, dann D4/T6 für `.40.218` prüfen |
| S7 | **DNS-Pfad `.50.238` → AdGuard** (F5 22.10.) | 16 AnyDesk-Anfragen kamen an, 32 wurden abgewiesen; Zonen-Log 10/min verdeckt den Rest | Beim nächsten `tv`-Besuch des Laptops: `conntrack -L \| grep 50.238` live |
| S8 | **Log-Limits** 6/min je Block-Regel, 10/min je Zone | 17 Limit-Minuten → in diesen Minuten fehlen Zeilen (Work-Sonden, Hub→Panel) | V5 senkt die Treffer; Limit nicht anheben (Logvolumen) |
| S9 | **HA-Ereignisse nicht im Router-Log** | Hub→Panel-Rückläufer (F7) nur zeitlich mit HA-Neustart korrelierbar | HA-SSH-Key (offen seit 17.10.) → `ha core logs` im Audit |
| S10 | **AdGuard-Client-Schalter** (`filtering_enabled: false` bei 8 Clients wirkungslos, alle „globale Einstellungen") | Falle bleibt (N14 17.10., F15 22.10.) | Doku-Hinweis in `dns-filtering.md` A.1, keine Änderung |

## 7. Methode

`scripts/fwlog-audit.py 1.0.0` (SSH, `cat` des Logs, `uci export`), `scripts/dnslog-audit.py 1.0.0`
(`gzip -c querylog.json` → `--querylog`, da `.1` fehlt). Ergänzend auf dem Router: `logread`,
`/proc/uptime`, `ls --full-time /mnt/nvme/*`, `mount`, `head -c 60 querylog.json`, `cat /etc/init.d/nvme-guard`,
`grep` auf `time disparity`/`init complete`/`AP-STA-CONNECTED`/`DHCPACK`, `nft list chain inet fw4 forward_kids`,
`wg show wgadm latest-handshakes`, `/etc/fw4-multi-ipset/guard.sh report`, `nlbw -c show -g mac,ip`,
`nslookup`, AdGuard-YAML nur die Abschnitte `ratelimit*`, `upstream_dns`, `fallback_dns`, `user_rules` (grep),
`tls` (Pfade). Keine Änderung am Gerät. Firmen-/Kundendomänen in den Anhängen durch Platzhalter ersetzt.

## Anhang A: Firewall-Log-Tabellen (generiert, Fenster 21.10. 21:24 – 24.10. 10:26)

<!-- generated by scripts/fwlog-audit.py 1.0.0, source root@192.168.30.1, window 2026-10-18 00:00:00 .. 2026-10-24 10:26:07, 1240 firewall lines -->
#### T1 Zeilen je Log-Klasse
| Präfix | Klasse | Zeilen | Anteil | erste | letzte | max/min | Limit/min | Minuten am Limit |
|---|---|---|---|---|---|---|---|---|
| `Block-work-wan-all` | rule | 332 | 26.8 % | 21.10. 21:24 | 23.10. 16:58 | 10 | 6 | 4 |
| `reject wgvpn in` | zone-in | 282 | 22.7 % | 21.10. 21:34 | 23.10. 21:46 | 12 | 10 | 2 |
| `drop wgvpn invalid ct state` | invalid | 131 | 10.6 % | 21.10. 22:30 | 23.10. 22:50 | 7 | - | 0 |
| `Allow-panel-wan-all` | other | 131 | 10.6 % | 22.10. 18:38 | 22.10. 22:41 | 14 | - | 0 |
| `Block-tv-wan-all` | rule | 103 | 8.3 % | 21.10. 21:28 | 22.10. 21:57 | 6 | 6 | 2 |
| `reject smarthome_srv forward` | zone-fwd | 62 | 5.0 % | 22.10. 19:25 | 23.10. 08:51 | 14 | 10 | 2 |
| `Block-iotsrv-wan-all` | rule | 50 | 4.0 % | 22.10. 19:25 | 23.10. 08:51 | 10 | 6 | 5 |
| `reject tv in` | zone-in | 34 | 2.7 % | 22.10. 16:45 | 22.10. 19:14 | 10 | 10 | 2 |
| `Allow-panel-hub-ha` | other | 31 | 2.5 % | 22.10. 19:06 | 22.10. 20:48 | 4 | - | 0 |
| `reject private forward` | zone-fwd | 27 | 2.2 % | 22.10. 12:22 | 24.10. 10:26 | 7 | 10 | 0 |
| `reject private in` | zone-in | 21 | 1.7 % | 21.10. 22:30 | 24.10. 10:24 | 5 | 10 | 0 |
| `reject work in` | zone-in | 12 | 1.0 % | 22.10. 08:44 | 23.10. 08:58 | 3 | 10 | 0 |
| `reject smarthome in` | zone-in | 9 | 0.7 % | 22.10. 17:39 | 22.10. 18:47 | 3 | 10 | 0 |
| `Block-iot-wan-all` | rule | 9 | 0.7 % | 22.10. 18:58 | 22.10. 19:00 | 5 | 6 | 0 |
| `reject smarthome forward` | zone-fwd | 3 | 0.2 % | 22.10. 18:58 | 22.10. 18:59 | 2 | 10 | 0 |
| `Block-panel-wan-all` | rule | 3 | 0.2 % | 22.10. 22:52 | 23.10. 19:21 | 2 | 6 | 0 |

`Minuten am Limit`: Minuten, in denen so viele Zeilen wie das Limit erlaubt geschrieben wurden; in diesen Minuten sind weitere Treffer **nicht** im Log (Dunkelziffer).

#### T2 Zeilen je Tag und Klasse
| Tag | zone-in | zone-fwd | collective | rule | invalid | zone-out | other | gesamt |
|---|---|---|---|---|---|---|---|---|
| Wed 21.10. | 34 | 0 | 0 | 52 | 56 | 0 | 0 | 142 |
| Thu 22.10. | 169 | 67 | 0 | 303 | 34 | 0 | 162 | 735 |
| Fri 23.10. | 154 | 24 | 0 | 142 | 41 | 0 | 0 | 361 |
| Sat 24.10. | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 2 |

#### T3 Tagesprofil (Zeilen je Stunde, Summe über die Tage)
| Klasse | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gesamt | 23 | 30 | 12 | 16 | 6 | 5 | 12 | 1 | 72 | 60 | 40 | 48 | 68 | 39 | 65 | 38 | 117 | 53 | 79 | 139 | 27 | 113 | 153 | 24 |
| zone-in | 19 | 29 | 5 | 7 | 4 | 2 | 0 | 0 | 15 | 12 | 2 | 12 | 10 | 7 | 18 | 4 | 69 | 27 | 14 | 15 | 14 | 28 | 30 | 15 |
| rule | 2 | 0 | 2 | 2 | 2 | 3 | 11 | 0 | 34 | 38 | 36 | 34 | 47 | 32 | 36 | 30 | 39 | 14 | 16 | 35 | 2 | 45 | 29 | 8 |
| zone-fwd | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 15 | 0 | 1 | 0 | 7 | 0 | 9 | 0 | 0 | 5 | 4 | 18 | 0 | 19 | 14 | 0 |
| collective | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| invalid | 2 | 1 | 5 | 7 | 0 | 0 | 1 | 1 | 8 | 10 | 1 | 2 | 4 | 0 | 2 | 4 | 9 | 7 | 3 | 0 | 1 | 0 | 62 | 1 |

#### T4 INPUT-Abweisungen je Zone (`reject <zone> in`): Quelle → Router-Adresse, Dienst
| Zone | Quelle | Ziel | Dienst | Zeilen | Anteil in Zone |
|---|---|---|---|---|---|
| private | 192.168.20.217 | 192.168.20.1 (Router (private)) | udp/53 (DNS) | 6 | 28.6 % |
| private | 192.168.20.238 (OP-T490) | 255.255.255.255 (Broadcast) | udp/1716 | 6 | 28.6 % |
| private | 192.168.20.189 (OP-S25) | 192.168.20.1 (Router (private)) | tcp/80 (HTTP) | 3 | 14.3 % |
| private | 192.168.20.238 (OP-T490) | 192.168.30.1 (Router (management)) | tcp/443 (HTTPS) | 3 | 14.3 % |
| private | 192.168.20.238 (OP-T490) | 255.255.255.255 (Broadcast) | udp/3289 | 1 | 4.8 % |
| private | 192.168.20.238 (OP-T490) | 255.255.255.255 (Broadcast) | udp/1124 | 1 | 4.8 % |
| private | 192.168.20.238 (OP-T490) | 192.168.30.1 (Router (management)) | tcp/22 (SSH) | 1 | 4.8 % |
| smarthome | 192.168.10.11 (Sonoff-Panel) | 192.168.10.1 (Router (smarthome)) | tcp/853 (DoT) | 6 | 66.7 % |
| smarthome | 192.168.10.189 | 192.168.10.1 (Router (smarthome)) | tcp/853 (DoT) | 2 | 22.2 % |
| smarthome | 192.168.10.1 (Router (smarthome)) | 255.255.255.255 (Broadcast) | udp/68 (DHCP-Client) | 1 | 11.1 % |
| tv | 192.168.50.238 | 192.168.50.1 (Router (tv)) | udp/53 (DNS) | 20 | 58.8 % |
| tv | 192.168.50.238 | 192.168.50.1 (Router (tv)) | tcp/53 (DNS) | 12 | 35.3 % |
| tv | 192.168.50.158 (TV) | 192.168.50.1 (Router (tv)) | tcp/853 (DoT) | 2 | 5.9 % |
| wgvpn | 10.2.0.1 | 10.2.0.2 (Router (wgvpn)) | echo-request | 116 | 41.1 % |
| wgvpn | 3.124.167.37 | 10.2.0.2 (Router (wgvpn)) | tcp/40944 | 2 | 0.7 % |
| wgvpn | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/37305 | 2 | 0.7 % |
| wgvpn | 63.187.216.73 | 10.2.0.2 (Router (wgvpn)) | tcp/57006 | 2 | 0.7 % |
| wgvpn | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/55851 | 2 | 0.7 % |
| wgvpn | 3.123.248.102 | 10.2.0.2 (Router (wgvpn)) | tcp/39216 | 2 | 0.7 % |
| wgvpn | 3.125.141.80 | 10.2.0.2 (Router (wgvpn)) | tcp/42758 | 2 | 0.7 % |
| wgvpn | 161.69.245.10 | 10.2.0.2 (Router (wgvpn)) | tcp/33554 | 2 | 0.7 % |
| wgvpn | 161.69.245.5 | 10.2.0.2 (Router (wgvpn)) | tcp/46484 | 2 | 0.7 % |
| wgvpn | 161.69.245.5 | 10.2.0.2 (Router (wgvpn)) | tcp/41528 | 2 | 0.7 % |
| wgvpn | 52.57.41.49 | 10.2.0.2 (Router (wgvpn)) | tcp/41396 | 2 | 0.7 % |
| wgvpn | 63.184.38.189 | 10.2.0.2 (Router (wgvpn)) | tcp/36430 | 2 | 0.7 % |
| work | 192.168.70.1 (Router (work)) | 255.255.255.255 (Broadcast) | udp/68 (DHCP-Client) | 12 | 100.0 % |

#### T5 Abweisungen zwischen Zonen (FORWARD ohne Regel: Zonen-Log + Sammelzeile)
| von Zone | nach Zone | Quelle | Ziel | Dienst | Präfix | Zeilen |
|---|---|---|---|---|---|---|
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35550 | `reject smarthome_srv forward` | 9 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35546 | `reject smarthome_srv forward` | 9 |
| private | wan | 172.21.0.2 | 160.79.104.10 | tcp/443 (HTTPS) | `reject private forward` | 9 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35656 | `reject smarthome_srv forward` | 6 |
| private | smarthome | 192.168.20.238 (OP-T490) | 192.168.10.189 | echo-request | `reject private forward` | 5 |
| private | smarthome | 192.168.20.238 (OP-T490) | 192.168.10.11 (Sonoff-Panel) | tcp/80 (HTTP) | `reject private forward` | 5 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35688 | `reject smarthome_srv forward` | 5 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35684 | `reject smarthome_srv forward` | 5 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35522 | `reject smarthome_srv forward` | 4 |
| private | wan | 192.168.20.189 (OP-S25) | 192.168.178.27 | udp/50004 | `reject private forward` | 3 |
| smarthome | smarthome_srv | 192.168.10.11 (Sonoff-Panel) | 192.168.60.245 (homeassistant) | tcp/443 (HTTPS) | `reject smarthome forward` | 3 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35532 | `reject smarthome_srv forward` | 3 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35658 | `reject smarthome_srv forward` | 3 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35652 | `reject smarthome_srv forward` | 3 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35686 | `reject smarthome_srv forward` | 3 |
| private | wan | 192.168.20.189 (OP-S25) | 192.168.178.27 | udp/50030 | `reject private forward` | 2 |
| private | wan | 192.168.20.189 (OP-S25) | 192.168.178.27 | udp/50046 | `reject private forward` | 2 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35526 | `reject smarthome_srv forward` | 2 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35524 | `reject smarthome_srv forward` | 2 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35530 | `reject smarthome_srv forward` | 2 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35660 | `reject smarthome_srv forward` | 2 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35682 | `reject smarthome_srv forward` | 2 |
| private | smarthome | 192.168.20.238 (OP-T490) | 192.168.10.11 (Sonoff-Panel) | echo-request | `reject private forward` | 1 |
| smarthome_srv | private | 192.168.60.245 (homeassistant) | 192.168.20.189 (OP-S25) | tcp/54210 | `reject smarthome_srv forward` | 1 |

Zonen-Paare gesamt: smarthome_srv→smarthome 61, private→wan 16, private→smarthome 11, smarthome→smarthome_srv 3, smarthome_srv→private 1

#### T6 Egress-Blocks je Regel (`Block-*`): Quelle, Ziel, Dienst
| Regel | Zeilen | Protokolle | Ziel-IPs | Quelle | Ziel | Dienst × Zeilen |
|---|---|---|---|---|---|---|
| `Block-work-wan-all` | 332 | UDP 163 ICMP 143 TCP 26 | 20 |  |  |  |
|  |  |  |  | 192.168.70.188 (OP-Work-Laptop) | 147.161.139.245 | echo-request ×70 |
|  |  |  |  | 192.168.70.188 (OP-Work-Laptop) | 147.161.139.245 | udp/33434 ×70 |
|  |  |  |  | 192.168.70.188 (OP-Work-Laptop) | 165.225.25.237 | echo-request ×47 |
|  |  |  |  | 192.168.70.188 (OP-Work-Laptop) | 165.225.25.237 | udp/33434 ×47 |
|  |  |  |  | 192.168.70.188 (OP-Work-Laptop) | 87.58.122.21 | echo-request ×8 |
|  |  |  |  | 192.168.70.188 (OP-Work-Laptop) | 87.58.122.21 | udp/33434 ×8 |
|  |  |  |  | 192.168.70.188 (OP-Work-Laptop) | 192.168.5.221 | tcp/8443 (Uplink-LuCI) ×8 |
|  |  |  |  | 192.168.70.188 (OP-Work-Laptop) | 192.168.178.27 | udp/50012 ×6 |
| `Block-tv-wan-all` | 103 | UDP 84 TCP 19 | 31 |  |  |  |
|  |  |  |  | 192.168.50.158 (TV) | 172.217.115.4 | udp/443 (HTTPS) ×10 |
|  |  |  |  | 192.168.50.158 (TV) | 142.251.150.120 | udp/443 (HTTPS) ×9 |
|  |  |  |  | 192.168.50.158 (TV) | 172.217.19.174 | udp/443 (HTTPS) ×8 |
|  |  |  |  | 192.168.50.158 (TV) | 172.217.118.4 | udp/443 (HTTPS) ×7 |
|  |  |  |  | 192.168.50.158 (TV) | 172.217.116.4 | udp/443 (HTTPS) ×7 |
|  |  |  |  | 192.168.50.158 (TV) | 142.251.143.14 | udp/443 (HTTPS) ×6 |
|  |  |  |  | 192.168.50.158 (TV) | 172.217.113.4 | udp/443 (HTTPS) ×6 |
|  |  |  |  | 192.168.50.158 (TV) | 172.217.112.4 | udp/443 (HTTPS) ×6 |
| `Block-iotsrv-wan-all` | 50 | TCP 50 | 2 |  |  |  |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35550 ×8 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35546 ×8 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35656 ×5 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35686 ×5 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35688 ×4 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35522 ×3 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35652 ×3 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35524 ×2 |
| `Block-iot-wan-all` | 9 | TCP 9 | 1 |  |  |  |
|  |  |  |  | 192.168.10.11 (Sonoff-Panel) | 192.168.60.245 (homeassistant) | tcp/443 (HTTPS) ×9 |
| `Block-panel-wan-all` | 3 | TCP 3 | 2 |  |  |  |
|  |  |  |  | 192.168.10.11 (Sonoff-Panel) | 192.168.60.245 (homeassistant) | tcp/8123 (Home Assistant) ×2 |
|  |  |  |  | 192.168.10.11 (Sonoff-Panel) | 51.159.23.43 | tcp/443 (HTTPS) ×1 |

#### T7 Tunnel-Eingang `wgvpn` (INPUT-Abweisungen und `invalid ct state`)
| Präfix | Quelle (extern) | Ziel | Dienst | Zeilen |
|---|---|---|---|---|
| `reject wgvpn in` | 10.2.0.1 | 10.2.0.2 (Router (wgvpn)) | echo-request | 116 |
| `drop wgvpn invalid ct state` | 192.168.20.111 | 34.104.35.123 | tcp/80 (HTTP) | 24 |
| `drop wgvpn invalid ct state` | 192.168.20.189 | 82.220.37.2 | tcp/443 (HTTPS) | 17 |
| `drop wgvpn invalid ct state` | 192.168.20.111 | 172.217.116.4 | tcp/443 (HTTPS) | 8 |
| `drop wgvpn invalid ct state` | 192.168.20.189 | 23.50.131.222 | tcp/443 (HTTPS) | 8 |
| `drop wgvpn invalid ct state` | 192.168.20.189 | 23.207.210.132 | tcp/443 (HTTPS) | 6 |
| `drop wgvpn invalid ct state` | 192.168.20.189 | 172.217.118.4 | tcp/443 (HTTPS) | 6 |
| `drop wgvpn invalid ct state` | 192.168.20.111 | 160.79.104.10 | tcp/443 (HTTPS) | 5 |
| `drop wgvpn invalid ct state` | 192.168.20.111 | 172.217.119.4 | tcp/443 (HTTPS) | 4 |
| `drop wgvpn invalid ct state` | 192.168.20.111 | 172.217.118.4 | tcp/443 (HTTPS) | 4 |
| `drop wgvpn invalid ct state` | 192.168.20.111 | 142.250.203.206 | tcp/443 (HTTPS) | 4 |
| `drop wgvpn invalid ct state` | 192.168.20.111 | 172.217.112.4 | tcp/443 (HTTPS) | 4 |

verschiedene externe Quellen: 43; Ziel-Ports (udp/tcp) verschieden: 159

#### T8 Scan-Indikatoren: Quellen mit vielen verschiedenen Ziel-Ports oder Ziel-Hosts
| Quelle | Zeilen | Ziel-Ports verschieden | max Ports in 10 min | Ziel-Hosts verschieden | Präfixe |
|---|---|---|---|---|---|
| 82.220.37.2 | 87 | 85 | 1 | 1 | reject wgvpn in |
| 192.168.60.245 (homeassistant) | 112 | 17 | 7 | 2 | Block-iotsrv-wan-all, reject smarthome_srv forward |
| 192.168.70.188 (OP-Work-Laptop) | 332 | 11 | 4 | 20 | Block-work-wan-all |
| 192.168.50.158 (TV) | 92 | 3 | 2 | 29 | Block-tv-wan-all, reject tv in |
| 192.168.10.11 (Sonoff-Panel) | 183 | 3 | 2 | 24 | Allow-panel-hub-ha, Allow-panel-wan-all, Block-iot-wan-all, Block-panel-wan-all, reject smarthome forward, reject smarthome in |

#### T9 Nur an einem Tag gesehene Quelle→Ziel-Paare (≥ 5 Zeilen)
| Tag | Präfix | Quelle | Ziel | Dienst | Zeilen |
|---|---|---|---|---|---|
| 22.10. | `Allow-panel-wan-all` | 192.168.10.11 (Sonoff-Panel) | 192.168.60.245 (homeassistant) | tcp/8123 (Home Assistant) | 79 |
| 22.10. | `Block-work-wan-all` | 192.168.70.188 (OP-Work-Laptop) | 147.161.139.245 | echo-request | 70 |
| 22.10. | `Block-work-wan-all` | 192.168.70.188 (OP-Work-Laptop) | 147.161.139.245 | udp/33434 | 70 |
| 23.10. | `Block-work-wan-all` | 192.168.70.188 (OP-Work-Laptop) | 165.225.25.237 | echo-request | 47 |
| 23.10. | `Block-work-wan-all` | 192.168.70.188 (OP-Work-Laptop) | 165.225.25.237 | udp/33434 | 47 |
| 22.10. | `Allow-panel-hub-ha` | 192.168.10.11 (Sonoff-Panel) | 192.168.60.245 (homeassistant) | tcp/8123 (Home Assistant) | 31 |
| 21.10. | `drop wgvpn invalid ct state` | 192.168.20.111 (OP-T41S) | 34.104.35.123 | tcp/80 (HTTP) | 24 |
| 22.10. | `reject tv in` | 192.168.50.238 | 192.168.50.1 (Router (tv)) | udp/53 (DNS) | 20 |
| 22.10. | `Allow-panel-wan-all` | 192.168.10.11 (Sonoff-Panel) | 142.251.143.14 | tcp/443 (HTTPS) | 18 |
| 22.10. | `reject tv in` | 192.168.50.238 | 192.168.50.1 (Router (tv)) | tcp/53 (DNS) | 12 |
| 22.10. | `Block-tv-wan-all` | 192.168.50.158 (TV) | 172.217.115.4 | udp/443 (HTTPS) | 10 |
| 22.10. | `Block-iot-wan-all` | 192.168.10.11 (Sonoff-Panel) | 192.168.60.245 (homeassistant) | tcp/443 (HTTPS) | 9 |
| 22.10. | `reject smarthome_srv forward` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35550 | 9 |
| 22.10. | `reject smarthome_srv forward` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35546 | 9 |
| 23.10. | `reject private forward` | 172.21.0.2 | 160.79.104.10 | tcp/443 (HTTPS) | 9 |
| 21.10. | `Block-work-wan-all` | 192.168.70.188 (OP-Work-Laptop) | 87.58.122.21 | echo-request | 8 |
| 21.10. | `Block-work-wan-all` | 192.168.70.188 (OP-Work-Laptop) | 87.58.122.21 | udp/33434 | 8 |
| 21.10. | `drop wgvpn invalid ct state` | 192.168.20.111 (OP-T41S) | 172.217.116.4 | tcp/443 (HTTPS) | 8 |
| 22.10. | `Block-tv-wan-all` | 192.168.50.158 (TV) | 172.217.19.174 | udp/443 (HTTPS) | 8 |
| 22.10. | `drop wgvpn invalid ct state` | 192.168.20.189 (OP-S25) | 23.50.131.222 | tcp/443 (HTTPS) | 8 |
| 22.10. | `Block-iotsrv-wan-all` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35550 | 8 |
| 22.10. | `Block-iotsrv-wan-all` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35546 | 8 |
| 21.10. | `reject private in` | 192.168.20.217 | 192.168.20.1 (Router (private)) | udp/53 (DNS) | 6 |
| 22.10. | `Block-tv-wan-all` | 192.168.50.158 (TV) | 172.217.112.4 | udp/443 (HTTPS) | 6 |

#### T10 Alle Quellen mit Zeilenanzahl (ohne `invalid`)
| Quelle | Zeilen | Anteil | Präfixe |
|---|---|---|---|
| 192.168.70.188 (OP-Work-Laptop) | 332 | 26.8 % | Block-work-wan-all |
| 192.168.10.11 (Sonoff-Panel) | 183 | 14.8 % | Allow-panel-hub-ha, Allow-panel-wan-all, Block-iot-wan-all, Block-panel-wan-all, reject smarthome forward, reject smarthome in |
| 10.2.0.1 | 116 | 9.4 % | reject wgvpn in |
| 192.168.60.245 (homeassistant) | 112 | 9.0 % | Block-iotsrv-wan-all, reject smarthome_srv forward |
| 192.168.50.158 (TV) | 92 | 7.4 % | Block-tv-wan-all, reject tv in |
| 82.220.37.2 | 87 | 7.0 % | reject wgvpn in |
| 192.168.50.238 | 45 | 3.6 % | Block-tv-wan-all, reject tv in |
| 192.168.20.238 (OP-T490) | 23 | 1.9 % | reject private forward, reject private in |
| 146.75.121.91 | 12 | 1.0 % | reject wgvpn in |
| 192.168.70.1 (Router (work)) | 12 | 1.0 % | reject work in |
| 192.168.20.189 (OP-S25) | 10 | 0.8 % | reject private forward, reject private in |
| 172.21.0.2 | 9 | 0.7 % | reject private forward |
| 192.168.20.217 | 6 | 0.5 % | reject private in |
| 160.79.104.10 | 5 | 0.4 % | reject wgvpn in |
| 13.226.155.79 | 4 | 0.3 % | reject wgvpn in |
| 161.69.245.5 | 4 | 0.3 % | reject wgvpn in |
| 54.195.140.245 | 3 | 0.2 % | reject wgvpn in |
| 99.80.128.60 | 3 | 0.2 % | reject wgvpn in |
| 63.184.38.189 | 3 | 0.2 % | reject wgvpn in |
| 89.31.137.221 | 3 | 0.2 % | reject wgvpn in |
| 3.124.167.37 | 2 | 0.2 % | reject wgvpn in |
| 35.158.78.150 | 2 | 0.2 % | reject wgvpn in |
| 63.187.216.73 | 2 | 0.2 % | reject wgvpn in |
| 23.207.210.132 | 2 | 0.2 % | reject wgvpn in |
| 34.247.205.63 | 2 | 0.2 % | reject wgvpn in |
| 3.123.248.102 | 2 | 0.2 % | reject wgvpn in |
| 192.168.10.189 | 2 | 0.2 % | reject smarthome in |
| 3.125.141.80 | 2 | 0.2 % | reject wgvpn in |
| 161.69.245.10 | 2 | 0.2 % | reject wgvpn in |
| 108.132.52.37 | 2 | 0.2 % | reject wgvpn in |
| 3.248.147.52 | 2 | 0.2 % | reject wgvpn in |
| 52.57.41.49 | 2 | 0.2 % | reject wgvpn in |
| 51.81.92.24 | 2 | 0.2 % | reject wgvpn in |
| 52.210.61.139 | 2 | 0.2 % | reject wgvpn in |
| 13.226.155.51 | 1 | 0.1 % | reject wgvpn in |
| 63.182.85.211 | 1 | 0.1 % | reject wgvpn in |
| 34.253.249.14 | 1 | 0.1 % | reject wgvpn in |
| 18.173.233.116 | 1 | 0.1 % | reject wgvpn in |
| 54.230.172.58 | 1 | 0.1 % | reject wgvpn in |
| 18.173.233.13 | 1 | 0.1 % | reject wgvpn in |
| 18.202.121.53 | 1 | 0.1 % | reject wgvpn in |
| 63.183.37.214 | 1 | 0.1 % | reject wgvpn in |
| 23.50.131.222 | 1 | 0.1 % | reject wgvpn in |
| 35.162.253.124 | 1 | 0.1 % | reject wgvpn in |
| 192.168.10.1 (Router (smarthome)) | 1 | 0.1 % | reject smarthome in |
| 40.180.194.125 | 1 | 0.1 % | reject wgvpn in |
| 23.103.241.71 | 1 | 0.1 % | reject wgvpn in |
| 13.226.155.90 | 1 | 0.1 % | reject wgvpn in |
| 44.238.40.20 | 1 | 0.1 % | reject wgvpn in |
| 13.226.155.96 | 1 | 0.1 % | reject wgvpn in |
| 92.123.104.34 | 1 | 0.1 % | reject wgvpn in |

## Anhang B: AdGuard-Query-Log-Tabellen (generiert, Fenster 21.10. 21:14 – 24.10. 10:24)

<!-- generated by scripts/dnslog-audit.py 1.0.0, source <scratch>/querylog.json.gz, window 2026-10-18 00:00:00 .. 2026-10-24 10:24:02, 164000 entries, 0 unparsable lines -->
#### D1 Rahmen
| Größe | Wert |
|---|---|
| Einträge | 164000 |
| Zeitraum | 2026-10-18 00:00:00 .. 2026-10-24 10:24:02 (4 Tage) |
| Clients (IPs) | 17 |
| verschiedene Namen | 2732 |
| geblockt (`IsFiltered`) | 72443 (44.2 %) |
| aus Cache beantwortet | 32711 (19.9 %) |
| Client-Protokoll | plain 164000 |
| AdGuard `ratelimit` | 20/s je /24 |

**Ergebnisklassen (`Result.Reason`):**

| Reason | Bedeutung | Einträge | Anteil |
|---|---|---|---|
| 0 | nicht gefiltert | 77698 | 47.4 % |
| 3 | Blockliste | 72443 | 44.2 % |
| 1 | Allowlist | 12768 | 7.8 % |
| 9 | Rewrite | 797 | 0.5 % |
| 11 | Rewrite (Regel) | 294 | 0.2 % |

#### D2 Anfragen je Tag
| Tag | Anfragen | geblockt | Anteil | Clients | Namen | NXDOMAIN | SERVFAIL/Fehler |
|---|---|---|---|---|---|---|---|
| Wed 21.10. | 10320 | 4919 | 47.7 % | 12 | 668 | 594 | 0 |
| Thu 22.10. | 84074 | 38608 | 45.9 % | 16 | 1938 | 3367 | 0 |
| Fri 23.10. | 63603 | 25821 | 40.6 % | 10 | 1694 | 2480 | 0 |
| Sat 24.10. | 6003 | 3095 | 51.6 % | 8 | 314 | 18 | 0 |

#### D3 Tagesprofil (Anfragen je Stunde, Summe über die Tage)
| Zone | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gesamt | 3250 | 3161 | 2783 | 2425 | 2341 | 2224 | 2262 | 2119 | 6086 | 15392 | 13265 | 13800 | 13965 | 13834 | 12891 | 10242 | 11154 | 6334 | 4192 | 3148 | 2817 | 7370 | 5340 | 3605 |
| Router (private) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 14 | 0 |
| private | 1573 | 1424 | 1097 | 806 | 828 | 579 | 659 | 510 | 1599 | 1414 | 1050 | 904 | 1312 | 647 | 1874 | 753 | 2221 | 1464 | 1544 | 1270 | 1087 | 2321 | 2376 | 1840 |
| smarthome | 53 | 57 | 9 | 8 | 8 | 16 | 10 | 14 | 11 | 9 | 7 | 9 | 4 | 6 | 5 | 4 | 4 | 232 | 200 | 69 | 51 | 94 | 56 | 71 |
| smarthome_srv | 962 | 1027 | 1014 | 949 | 837 | 971 | 896 | 933 | 936 | 913 | 721 | 573 | 634 | 578 | 560 | 558 | 511 | 563 | 564 | 904 | 730 | 823 | 993 | 980 |
| tv | 662 | 653 | 663 | 662 | 668 | 658 | 697 | 662 | 655 | 653 | 658 | 655 | 649 | 658 | 657 | 655 | 674 | 197 | 0 | 905 | 949 | 1291 | 674 | 656 |
| unbekannt | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 16 | 0 | 0 | 0 | 4 | 0 | 16 |
| work | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2885 | 12403 | 10829 | 11659 | 11366 | 11945 | 9795 | 8272 | 7744 | 3862 | 1884 | 0 | 0 | 2837 | 1227 | 42 |

#### D4 Je Client: Volumen, Block-Anteil, Breite
| Client | Zone | Anfragen | Anteil | geblockt | Block-Anteil | Namen | NXDOMAIN | max/s | max/min | erste | letzte |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 192.168.70.188 (OP-Work-Laptop) | work | 96750 | 59.0 % | 33353 | 34.5 % | 1348 | 6058 | 43 | 544 | 21.10. 21:14 | 23.10. 17:24 |
| 192.168.60.245 (homeassistant) | smarthome_srv | 19130 | 11.7 % | 13000 | 68.0 % | 291 | 0 | 21 | 199 | 21.10. 21:14 | 24.10. 10:24 |
| 192.168.50.158 (TV) | tv | 15895 | 9.7 % | 14477 | 91.1 % | 104 | 0 | 8 | 78 | 21.10. 21:14 | 22.10. 21:58 |
| 192.168.20.111 (OP-T41S) | private | 13120 | 8.0 % | 4815 | 36.7 % | 365 | 334 | 20 | 75 | 21.10. 21:14 | 24.10. 10:22 |
| 192.168.20.189 (OP-S25) | private | 12780 | 7.8 % | 4637 | 36.3 % | 767 | 17 | 20 | 116 | 21.10. 21:15 | 23.10. 21:52 |
| 192.168.20.238 (OP-T490) | private | 5252 | 3.2 % | 1422 | 27.1 % | 236 | 50 | 20 | 64 | 21.10. 23:01 | 24.10. 10:22 |
| 192.168.10.31 (Govee-TV-Light) | smarthome | 370 | 0.2 % | 366 | 98.9 % | 3 | 0 | 5 | 5 | 21.10. 21:15 | 22.10. 21:57 |
| 192.168.10.11 (Sonoff-Panel) | smarthome | 368 | 0.2 % | 133 | 36.1 % | 54 | 0 | 14 | 25 | 22.10. 18:02 | 24.10. 10:22 |
| 192.168.10.189 | smarthome | 230 | 0.1 % | 230 | 100.0 % | 33 | 0 | 8 | 27 | 22.10. 17:39 | 22.10. 18:01 |
| 127.0.0.1 | unbekannt | 20 | 0.0 % | 0 | 0.0 % | 6 | 0 | 8 | 8 | 21.10. 21:23 | 22.10. 17:38 |
| ::1 | unbekannt | 16 | 0.0 % | 0 | 0.0 % | 4 | 0 | 8 | 8 | 21.10. 23:01 | 22.10. 17:38 |
| 192.168.50.238 | tv | 16 | 0.0 % | 0 | 0.0 % | 2 | 0 | 2 | 8 | 22.10. 16:45 | 22.10. 16:48 |
| 192.168.20.1 (Router (private)) | Router (private) | 14 | 0.0 % | 10 | 71.4 % | 5 | 0 | 10 | 10 | 21.10. 22:56 | 21.10. 22:57 |
| 192.168.10.10 (Nuki-Bridge) | smarthome | 12 | 0.0 % | 0 | 0.0 % | 5 | 0 | 4 | 4 | 22.10. 07:05 | 24.10. 07:05 |
| 192.168.10.20 (Voice-Assistant-WoZi) | smarthome | 9 | 0.0 % | 0 | 0.0 % | 1 | 0 | 1 | 1 | 21.10. 23:18 | 24.10. 05:36 |
| 192.168.10.22 (Voice-Assistant-Kids) | smarthome | 9 | 0.0 % | 0 | 0.0 % | 1 | 0 | 1 | 1 | 21.10. 23:44 | 24.10. 05:36 |
| 192.168.10.23 (Voice-Assistant-Kitchen) | smarthome | 9 | 0.0 % | 0 | 0.0 % | 1 | 0 | 1 | 1 | 22.10. 01:47 | 24.10. 05:36 |

#### D5 Je Zone
| Zone | Clients | Anfragen | Anteil | geblockt | Block-Anteil | Namen |
|---|---|---|---|---|---|---|
| Router (private) | 1 | 14 | 0.0 % | 10 | 71.4 % | 5 |
| private | 3 | 31152 | 19.0 % | 10874 | 34.9 % | 1159 |
| smarthome | 7 | 1007 | 0.6 % | 729 | 72.4 % | 63 |
| smarthome_srv | 1 | 19130 | 11.7 % | 13000 | 68.0 % | 291 |
| tv | 2 | 15911 | 9.7 % | 14477 | 91.0 % | 106 |
| unbekannt | 2 | 36 | 0.0 % | 0 | 0.0 % | 6 |
| work | 1 | 96750 | 59.0 % | 33353 | 34.5 % | 1348 |

#### D6 Blocks je Filterliste
| Liste | Blocks | Anteil | Namen | Clients |
|---|---|---|---|---|
| - | 39010 | 53.8 % | 335 | 8 |
| HaGeZi's Windows/Office Tracker Blocklist | 23987 | 33.1 % | 16 | 4 |
| HaGeZi's Ultimate Blocklist | 8558 | 11.8 % | 128 | 5 |
| AdGuard DNS filter | 809 | 1.1 % | 49 | 4 |
| HaGeZi's Encrypted DNS Bypass | 63 | 0.1 % | 7 | 3 |
| HaGeZi's URL Shortener Blocklist | 14 | 0.0 % | 3 | 2 |
| HaGeZi's The World's Most Abused TLDs | 2 | 0.0 % | 1 | 1 |

#### D7 Meistgeblockte Namen
| Name | Blocks | Clients | Liste | Regel |
|---|---|---|---|---|
| `ipv6.msftconnecttest.com` | 10439 | OP-Work-Laptop 10439 | - | `||ipv6.msftconnecttest.com^$important` |
| `eu-mobile.events.data.microsoft.com` | 7104 | OP-Work-Laptop 6547, OP-S25 557 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `on-hweudc-o.api.leiniao.com` | 6853 | TV 6853 | - | `||leiniao.com^` |
| `embeddedassistant.googleapis.com` | 5482 | TV 5482 | - | `||embeddedassistant.googleapis.com^$client=192.168.50.0/24` |
| `self.events.data.microsoft.com` | 5015 | OP-Work-Laptop 4995, OP-S25 20 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `eu-teams.events.data.microsoft.com` | 3299 | OP-Work-Laptop 3131, OP-S25 163, OP-T41S 5 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `teams.events.data.microsoft.com` | 2997 | OP-Work-Laptop 2350, OP-S25 647 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `http-intake.logs.us5.datadoghq.com` | 2698 | OP-T41S 2327, OP-T490 371 | HaGeZi's Ultimate Blocklist | `||logs.us5.datadoghq.com^` |
| `mobile.events.data.microsoft.com` | 2350 | OP-T41S 1850, OP-Work-Laptop 340, OP-T490 126 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `eu-office.events.data.microsoft.com` | 1466 | OP-Work-Laptop 1463, OP-T41S 2, OP-S25 1 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `mediaservices.cdn-apple.com` | 1367 | TV 1367 | - | `||mediaservices.cdn-apple.com^$client=192.168.50.0/24` |
| `mobile.pipe.aria.microsoft.com` | 780 | OP-S25 780 | HaGeZi's Windows/Office Tracker Blocklist | `||pipe.aria.microsoft.com^` |
| `nexus-websocket-a.intercom.io` | 722 | OP-Work-Laptop 509, OP-T41S 156, OP-T490 57 | HaGeZi's Ultimate Blocklist | `||nexus-websocket-a.intercom.io^` |
| `m365cdn.nel.measure.office.net` | 590 | OP-Work-Laptop 590 | HaGeZi's Ultimate Blocklist | `||measure.office.net^` |
| `mefo1.zdf.de` | 588 | TV 588 | - | `||mefo1.zdf.de^` |
| `a-api.anthropic.com` | 505 | OP-S25 505 | HaGeZi's Ultimate Blocklist | `||a-api.anthropic.com^` |
| `usage-ping.brave.com` | 498 | OP-T490 454, OP-S25 44 | HaGeZi's Ultimate Blocklist | `||usage-ping.brave.com^` |
| `euc-excel-telemetry.officeapps.live.com` | 390 | OP-Work-Laptop 390 | HaGeZi's Ultimate Blocklist | `||euc-excel-telemetry.officeapps.live.com^` |
| `aqm3wd1qlc3dy-ats.iot.us-east-1.amazonaws.com` | 346 | Govee-TV-Light 346 | - | `/.*/$client=192.168.10.0/24` |
| `exo.nel.measure.office.net` | 323 | OP-Work-Laptop 323 | HaGeZi's Ultimate Blocklist | `||measure.office.net^` |
| `spo.nel.measure.office.net` | 296 | OP-Work-Laptop 296 | HaGeZi's Ultimate Blocklist | `||measure.office.net^` |
| `in.appcenter.ms` | 290 | OP-S25 290 | HaGeZi's Windows/Office Tracker Blocklist | `||in.appcenter.ms^` |
| `browser.events.data.microsoft.com` | 281 | OP-Work-Laptop 279, OP-T41S 2 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `enterprise-eudb.activity.windows.com` | 232 | OP-Work-Laptop 232 | HaGeZi's Windows/Office Tracker Blocklist | `||activity.windows.com^` |
| `go-updater.brave.com` | 214 | OP-T490 174, OP-S25 40 | - | `||go-updater.brave.com^$important` |
| `incoming.telemetry.mozilla.org` | 212 | OP-T41S 178, OP-Work-Laptop 34 | AdGuard DNS filter | `||incoming.telemetry.mozilla.org^` |
| `metrics-prod.suno.com` | 193 | OP-S25 193 | HaGeZi's Ultimate Blocklist | `||metrics-prod.suno.com^` |
| `merino.services.mozilla.com` | 151 | OP-T41S 137, OP-Work-Laptop 14 | HaGeZi's Ultimate Blocklist | `||merino.services.mozilla.com^` |
| `o1158394.ingest.us.sentry.io` | 145 | OP-Work-Laptop 142, OP-S25 3 | HaGeZi's Ultimate Blocklist | `||sentry.io^` |
| `10.60.168.192.in-addr.arpa` | 133 | homeassistant 133 | - | `/.*/$client=192.168.60.0/24` |

#### D8 Je Client die meistgeblockten Namen (Top 5)
| Client | Blocks | Namen |
|---|---|---|
| 192.168.70.188 (OP-Work-Laptop) | 33353 | `ipv6.msftconnecttest.com` ×10439<br>`eu-mobile.events.data.microsoft.com` ×6547<br>`self.events.data.microsoft.com` ×4995<br>`eu-teams.events.data.microsoft.com` ×3131<br>`teams.events.data.microsoft.com` ×2350 |
| 192.168.60.245 (homeassistant) | 13000 | `10.60.168.192.in-addr.arpa` ×133<br>`12.60.168.192.in-addr.arpa` ×131<br>`8.60.168.192.in-addr.arpa` ×129<br>`11.60.168.192.in-addr.arpa` ×128<br>`6.60.168.192.in-addr.arpa` ×127 |
| 192.168.50.158 (TV) | 14477 | `on-hweudc-o.api.leiniao.com` ×6853<br>`embeddedassistant.googleapis.com` ×5482<br>`mediaservices.cdn-apple.com` ×1367<br>`mefo1.zdf.de` ×588<br>`firebaseinstallations.googleapis.com` ×62 |
| 192.168.20.111 (OP-T41S) | 4815 | `http-intake.logs.us5.datadoghq.com` ×2327<br>`mobile.events.data.microsoft.com` ×1850<br>`incoming.telemetry.mozilla.org` ×178<br>`nexus-websocket-a.intercom.io` ×156<br>`merino.services.mozilla.com` ×137 |
| 192.168.20.189 (OP-S25) | 4637 | `mobile.pipe.aria.microsoft.com` ×780<br>`teams.events.data.microsoft.com` ×647<br>`eu-mobile.events.data.microsoft.com` ×557<br>`a-api.anthropic.com` ×505<br>`in.appcenter.ms` ×290 |
| 192.168.20.238 (OP-T490) | 1422 | `usage-ping.brave.com` ×454<br>`http-intake.logs.us5.datadoghq.com` ×371<br>`go-updater.brave.com` ×174<br>`mobile.events.data.microsoft.com` ×126<br>`default.exp-tas.com` ×96 |
| 192.168.10.31 (Govee-TV-Light) | 366 | `aqm3wd1qlc3dy-ats.iot.us-east-1.amazonaws.com` ×346<br>`app.govee.com` ×20 |
| 192.168.10.11 (Sonoff-Panel) | 133 | `ntp1.aliyun.com` ×7<br>`time.google.com` ×7<br>`ntp.tencent.com` ×6<br>`time.apple.com` ×6<br>`0.pool.ntp.org` ×6 |
| 192.168.10.189 | 230 | `ntp1.aliyun.com` ×13<br>`time.google.com` ×13<br>`ntp.tencent.com` ×13<br>`time.apple.com` ×13<br>`0.pool.ntp.org` ×13 |
| 192.168.20.1 (Router (private)) | 10 | `us.aws.cdn.hf.co` ×4<br>`hf.co` ×4<br>`cas-bridge.xethub.hf.co` ×2 |

#### D9 Default-Deny-Zonen (`smarthome`, `smarthome_srv`): erlaubte Namen je Gerät (vollständig)
| Gerät | Anfragen | erlaubt | geblockt | erlaubte Namen | erlaubt (Name × Anfragen) | geblockt (Top 8) |
|---|---|---|---|---|---|---|
| 192.168.60.245 (homeassistant) | 19130 | 6130 | 13000 | 32 | `api.tailscale.com` ×4450<br>`checkonline.home-assistant.io` ×870<br>`github.com` ×241<br>`` ×136<br>`aa015h6buqvih86i1.api.met.no` ×121<br>`api.powercalc.nl` ×60<br>`alerts.home-assistant.io` ×43<br>`raw.githubusercontent.com` ×27<br>`data-v2.hacs.xyz` ×22<br>`pipe.deezer.com` ×21<br>`pypi.org` ×20<br>`auth.deezer.com` ×18<br>`openrouter.ai` ×17<br>`www.deezer.com` ×9<br>`cdn-images.dzcdn.net` ×8<br>`api.github.com` ×6<br>`release-assets.githubusercontent.com` ×6<br>`zigbee-ota.sonoff.tech` ×6<br>`brands.home-assistant.io` ×6<br>`ghcr.io` ×6<br>`pkg-containers.githubusercontent.com` ×4<br>`on.dcl.csa-iot.org` ×4<br>`on.test-net.dcl.csa-iot.org` ×4<br>`version.home-assistant.io` ×4<br>`_checkdns.home-assistant.io` ×4<br>`media.deezer.com` ×4<br>`cdnt-stream.dzcdn.net` ×4<br>`controlplane.tailscale.com` ×2<br>`de1.api.radio-browser.info` ×2<br>`wheels.home-assistant.io` ×2<br>`f-cdnt-stream.dzcdn.net` ×2<br>`_api._tcp.radio-browser.info` ×1 | `10.60.168.192.in-addr.arpa` ×133<br>`12.60.168.192.in-addr.arpa` ×131<br>`8.60.168.192.in-addr.arpa` ×129<br>`11.60.168.192.in-addr.arpa` ×128<br>`6.60.168.192.in-addr.arpa` ×127<br>`7.60.168.192.in-addr.arpa` ×126<br>`9.60.168.192.in-addr.arpa` ×126<br>`13.60.168.192.in-addr.arpa` ×126 … |
| 192.168.10.31 (Govee-TV-Light) | 370 | 4 | 366 | 1 | `time.google.com` ×4 | `aqm3wd1qlc3dy-ats.iot.us-east-1.amazonaws.com` ×346<br>`app.govee.com` ×20 |
| 192.168.10.11 (Sonoff-Panel) | 368 | 235 | 133 | 36 | `hub.home.arpa` ×181<br>`f-droid.org` ×6<br>`ntp1.aliyun.com` ×3<br>`suggestqueries.google.com` ×3<br>`mirror.ossplanet.net` ×2<br>`ftp.fau.de` ×2<br>`mirrors.chroot.ro` ×2<br>`fdroid.tetaneutral.net` ×2<br>`mirrors.dotsrc.org` ×2<br>`mirror.init7.net` ×2<br>`mirror.cyberbits.eu` ×2<br>`mirror.level66.services` ×2<br>`mirror.eu.ossplanet.net` ×2<br>`ftp.gwdg.de` ×2<br>`ntp.tencent.com` ×1<br>`eu-apia.coolkit.cc` ×1<br>`mirror.fcix.net` ×1<br>`mirror.level66.network` ×1<br>`mirrors.hostico.ro` ×1<br>`ftp.lug.ro` ×1<br>`mirror.freedif.org` ×1<br>`ftp.agdsn.de` ×1<br>`plug-mirror.rcac.purdue.edu` ×1<br>`opencolo.mm.fcix.net` ×1<br>`my.home-assistant.io` ×1<br>`www.home-assistant.io` ×1<br>`update.googleapis.com` ×1<br>`edgedl.me.gvt1.com` ×1<br>`www.google.com` ×1<br>`twitter.com` ×1<br>`www.facebook.com` ×1<br>`www.yahoo.com` ×1<br>`t1.gstatic.com` ×1<br>`t0.gstatic.com` ×1<br>`raw.githubusercontent.com` ×1<br>`version.pm2.io` ×1 | `ntp1.aliyun.com` ×7<br>`time.google.com` ×7<br>`ntp.tencent.com` ×6<br>`time.apple.com` ×6<br>`0.pool.ntp.org` ×6<br>`time.cloudflare.com` ×6<br>`time.windows.com` ×6<br>`cn.pool.ntp.org` ×6 … |
| 192.168.10.189 | 230 | 0 | 230 | 0 |  | `ntp1.aliyun.com` ×13<br>`time.google.com` ×13<br>`ntp.tencent.com` ×13<br>`time.apple.com` ×13<br>`0.pool.ntp.org` ×13<br>`time.cloudflare.com` ×13<br>`time.windows.com` ×13<br>`cn.pool.ntp.org` ×13 … |
| 192.168.10.10 (Nuki-Bridge) | 12 | 12 | 0 | 5 | `sse7-bridge.nuki.io` ×4<br>`sse3-bridge.nuki.io` ×4<br>`sse9-bridge.nuki.io` ×2<br>`sse8-bridge.nuki.io` ×1<br>`sse4-bridge.nuki.io` ×1 |  |
| 192.168.10.20 (Voice-Assistant-WoZi) | 9 | 9 | 0 | 1 | `firmware.esphome.io` ×9 |  |
| 192.168.10.22 (Voice-Assistant-Kids) | 9 | 9 | 0 | 1 | `firmware.esphome.io` ×9 |  |
| 192.168.10.23 (Voice-Assistant-Kitchen) | 9 | 9 | 0 | 1 | `firmware.esphome.io` ×9 |  |

#### D10 Verschlüsseltes DNS umgehen: Anfragen nach DoH/DoT-Endpunkten und Canaries
| Client | Zone | Name | Ergebnis | Anfragen |
|---|---|---|---|---|
| 192.168.20.189 (OP-S25) | private | `cloudflare-dns.com` | geblockt | 22 |
| 192.168.20.111 (OP-T41S) | private | `cloudflare-dns.com` | geblockt | 14 |
| 192.168.20.189 (OP-S25) | private | `dns.google.com` | geblockt | 8 |
| 192.168.20.189 (OP-S25) | private | `mozilla.cloudflare-dns.com` | geblockt | 8 |
| 192.168.20.189 (OP-S25) | private | `dns.quad9.net` | geblockt | 5 |
| 192.168.20.189 (OP-S25) | private | `dns.google` | geblockt | 3 |
| 192.168.70.188 (OP-Work-Laptop) | work | `cloudflare-dns.com` | geblockt | 1 |
| 192.168.20.189 (OP-S25) | private | `dns11.quad9.net` | geblockt | 1 |
| 192.168.20.189 (OP-S25) | private | `dnsforge.de` | geblockt | 1 |

gesamt 63 Anfragen von 3 Clients; erlaubt: 0

#### D11 Anfragetypen
| Typ | Anfragen | Anteil |
|---|---|---|
| A | 118479 | 72.2 % |
| AAAA | 19660 | 12.0 % |
| PTR | 14062 | 8.6 % |
| HTTPS | 10104 | 6.2 % |
| SRV | 1431 | 0.9 % |
| NS | 139 | 0.1 % |
| SOA | 78 | 0.0 % |
| TXT | 38 | 0.0 % |
| TYPE11 | 3 | 0.0 % |
| CNAME | 3 | 0.0 % |
| HINFO | 3 | 0.0 % |

**Ungewöhnliche Typen je Client** (ANY, AXFR, CNAME, HINFO, IXFR, MX, NS, NULL, SOA, SRV, TXT):

| Client | Typ | Domain | Anfragen |
|---|---|---|---|
| 192.168.70.188 (OP-Work-Laptop) | SRV | `kunde-a.tld` | 976 |
| 192.168.70.188 (OP-Work-Laptop) | SRV | `kunde-b.tld` | 147 |
| 192.168.60.245 (homeassistant) | NS | `` | 136 |
| 192.168.70.188 (OP-Work-Laptop) | SRV | `firma-konzern.tld` | 119 |
| 192.168.70.188 (OP-Work-Laptop) | SOA | `firma-konzern.tld` | 75 |
| 192.168.70.188 (OP-Work-Laptop) | SRV | `firma-intern.tld` | 46 |
| 192.168.70.188 (OP-Work-Laptop) | SRV | `kunde-c.tld` | 43 |
| 192.168.20.238 (OP-T490) | TXT | `cymru.com` | 38 |
| 192.168.20.111 (OP-T41S) | SRV | `ubuntu.com` | 28 |
| 192.168.20.189 (OP-S25) | SRV | `kunde-b.tld` | 15 |
| 192.168.20.111 (OP-T41S) | SRV | `1password.com` | 9 |
| 192.168.20.111 (OP-T41S) | SRV | `docker.com` | 9 |
| 192.168.20.111 (OP-T41S) | SRV | `signal.org` | 8 |
| 192.168.20.238 (OP-T490) | SRV | `ubuntu.com` | 8 |
| 192.168.20.111 (OP-T41S) | SRV | `mozilla.org` | 7 |

#### D12 NXDOMAIN und SERVFAIL
| Client | Name | NXDOMAIN |
|---|---|---|
| 192.168.70.188 (OP-Work-Laptop) | `wpad.firma-intern.tld` | 3893 |
| 192.168.70.188 (OP-Work-Laptop) | `_autodiscover._tcp.kunde-a.tld` | 739 |
| 192.168.70.188 (OP-Work-Laptop) | `ccm1.intern.kunde-b.tld` | 242 |
| 192.168.20.111 (OP-T41S) | `localhost.lan` | 238 |
| 192.168.70.188 (OP-Work-Laptop) | `vedproxypac.firma-konzern.tld` | 139 |
| 192.168.70.188 (OP-Work-Laptop) | `crl.anydesk.com` | 121 |
| 192.168.70.188 (OP-Work-Laptop) | `_8443._https.ccm1.intern.kunde-b.tld` | 90 |
| 192.168.70.188 (OP-Work-Laptop) | `l-378929-1.dom1.firma-konzern.tld` | 31 |
| 192.168.70.188 (OP-Work-Laptop) | `_ldap._tcp.fr002._sites.dc._msdcs.lan.firma-intern.tld` | 24 |
| 192.168.70.188 (OP-Work-Laptop) | `_ldap._tcp.fr002._sites.dc._msdcs.lan.dom1.firma-konzern.tld` | 22 |
| 192.168.70.188 (OP-Work-Laptop) | `_ldap._tcp.fr002._sites.dc._msdcs.lan.firma-konzern.tld` | 22 |
| 192.168.70.188 (OP-Work-Laptop) | `_ldap._tcp.fr002._sites.dc._msdcs.lan.kunde-c.tld` | 22 |
| 192.168.70.188 (OP-Work-Laptop) | `_ldap._tcp.dc._msdcs.lan.firma-intern.tld` | 22 |
| 192.168.70.188 (OP-Work-Laptop) | `_ldap._tcp.dc._msdcs.lan.dom1.firma-konzern.tld` | 22 |
| 192.168.70.188 (OP-Work-Laptop) | `wpad.dom1.firma-konzern.tld` | 21 |

**SERVFAIL / Upstream-Fehler** (0 gesamt):

| Client | Name | Upstream | Anfragen |
|---|---|---|---|

#### D13 Tunnel-Heuristik: viele verschiedene Subdomains je Domain, lange Namen
| Client | Domain | verschiedene Namen | längster Name | Ergebnis |
|---|---|---|---|---|
| 192.168.70.188 (OP-Work-Laptop) | `in-addr.arpa` | 613 | 28 | erlaubt |
| 192.168.60.245 (homeassistant) | `in-addr.arpa` | 254 | 27 | geblockt |
| 192.168.20.189 (OP-S25) | `gvt1.com` | 147 | 27 | erlaubt |
| 192.168.70.188 (OP-Work-Laptop) | `microsoft.com` | 136 | 72 | erlaubt |
| 192.168.20.189 (OP-S25) | `googleapis.com` | 76 | 49 | erlaubt |
| 192.168.70.188 (OP-Work-Laptop) | `office.net` | 50 | 34 | erlaubt |
| 192.168.70.188 (OP-Work-Laptop) | `office.com` | 47 | 54 | erlaubt |
| 192.168.20.189 (OP-S25) | `microsoft.com` | 46 | 52 | erlaubt |
| 192.168.20.238 (OP-T490) | `cymru.com` | 38 | 36 | erlaubt |
| 192.168.20.111 (OP-T41S) | `hcaptcha.com` | 33 | 27 | erlaubt |
| 192.168.70.188 (OP-Work-Laptop) | `cloud.microsoft` | 31 | 60 | erlaubt |
| 192.168.20.189 (OP-S25) | `wbx2.com` | 27 | 40 | erlaubt |
| 192.168.70.188 (OP-Work-Laptop) | `live.com` | 26 | 39 | erlaubt |
| 192.168.70.188 (OP-Work-Laptop) | `webex.com` | 25 | 55 | erlaubt |
| 192.168.20.238 (OP-T490) | `in-addr.arpa` | 25 | 28 | erlaubt |

**Längste Namen:** `<DEVICE-ID>.us-east-1.prod.service.minerva.devices.a2z.com` (110, TV); `_ldap._tcp.<UUID>.domains._msdcs.dom1.firma-konzern.tld` (86, OP-Work-Laptop); `aks-prod-switzerlandnorth.access-point.cloudmessaging.edge.microsoft.com` (72, OP-Work-Laptop); `displaycatalog-caching.bigcatalog-frontdoor-prod.commerce.microsoft.com` (71, OP-Work-Laptop); `www.goooooooooooooooooooooooooooooooooooooooooooooooooooooooooogle.com` (70, OP-S25); `aks-prod-westeurope.access-point.cloudmessaging.edge.microsoft.com` (66, OP-Work-Laptop); `<UUID>.frame.claudeusercontent.com` (64, OP-Work-Laptop); `<UUID>.frame.claudeusercontent.com` (64, OP-Work-Laptop)

#### D14 Clients ohne Reservierung oder außerhalb der Zonen-Netze, Router-eigene Anfragen
| Client | Zone | Anfragen | häufigste Namen |
|---|---|---|---|
| 192.168.10.189 | smarthome | 230 | `ntp1.aliyun.com`, `time.google.com`, `ntp.tencent.com`, `time.apple.com` |
| 127.0.0.1 | unbekannt | 20 | `3.openwrt.pool.ntp.org`, `2.openwrt.pool.ntp.org`, `openwrt.home.arpa`, `example.com` |
| ::1 | unbekannt | 16 | `3.openwrt.pool.ntp.org`, `2.openwrt.pool.ntp.org`, `1.openwrt.pool.ntp.org`, `0.openwrt.pool.ntp.org` |
| 192.168.50.238 | tv | 16 | `boot.net.anydesk.com`, `relay-10cd7580.net.anydesk.com` |
| 192.168.20.1 (Router (private)) | Router (private) | 14 | `us.aws.cdn.hf.co`, `hf.co`, `huggingface.co`, `cdn-lfs.huggingface.co` |

#### D15 Rate-Limit-Sättigung: Sekunden mit ≥ `ratelimit` Anfragen je /24 (Dunkelziffer: verworfene Anfragen stehen nicht im Log)
| /24 | Zone | max Anfragen/s | Sekunden ≥ Limit | schlimmste Sekunde | betroffene Minuten |
|---|---|---|---|---|---|
| 192.168.60.0/24 | smarthome_srv | 21 | 544 | 21.10. 22:03:51 | 124 |
| 192.168.70.0/24 | work | 43 | 88 | 22.10. 10:59:46 | 47 |
| 192.168.20.0/24 | private | 20 | 9 | 21.10. 22:31:16 | 7 |
| 192.168.50.0/24 | tv | 8 | 0 | - | 0 |
| 192.168.10.0/24 | smarthome | 14 | 0 | - | 0 |
| 127.0.0.0/24 | unbekannt | 8 | 0 | - | 0 |
| ::1.0/24 | unbekannt | 8 | 0 | - | 0 |

#### D16 Upstream und Cache
| Größe | Wert |
|---|---|
| Upstream-Antworten (nicht Cache, nicht geblockt) | 58855 |
| Upstreams | tls://<NEXTDNS-ID>.dns.nextdns.io:853 57688, - 1091, tls://9.9.9.9:853 49, tls://149.112.112.112:853 27 |
| Latenz p50 / p90 / p99 (ms) | 47 / 145 / 3048 |
| Antworten > 1 s | 1029 |
| Cache-Trefferquote (nicht geblockt) | 35.7 % |

#### D17 Meistangefragte erlaubte Namen
| Name | Anfragen | Clients |
|---|---|---|
| `outlook.office365.com` | 8984 | OP-Work-Laptop 8406, OP-S25 577, OP-T41S 1 |
| `dns.msftncsi.com` | 6583 | OP-Work-Laptop 6583 |
| `www.msftconnecttest.com` | 6558 | OP-Work-Laptop 6558 |
| `api.tailscale.com` | 4450 | homeassistant 4450 |
| `wpad.firma-intern.tld` | 3948 | OP-Work-Laptop 3948 |
| `www.google.com` | 2556 | OP-S25 1288, TV 684, OP-T490 523 |
| `api.anthropic.com` | 2284 | OP-T41S 1231, OP-T490 959, OP-Work-Laptop 94 |
| `kunde-a.service-now.com` | 2275 | OP-Work-Laptop 2275 |
| `dec-visio.officeapps.live.com` | 2203 | OP-Work-Laptop 2203 |
| `coreservice.heimdalsecurity.com` | 2078 | OP-Work-Laptop 2078 |
| `messagingprodstorage.queue.core.windows.net` | 1970 | OP-Work-Laptop 1970 |
| `autodiscover.kunde-a.tld` | 1344 | OP-Work-Laptop 1344 |
| `login.microsoftonline.com` | 1311 | OP-Work-Laptop 1168, OP-S25 134, OP-T41S 7 |
| `teams.microsoft.com` | 1283 | OP-Work-Laptop 1088, OP-S25 193, OP-T41S 2 |
| `discovery-announce-v6.syncthing.net` | 1274 | OP-T41S 1274 |
| `gateway.zscaler.net` | 1247 | OP-Work-Laptop 1247 |
| `_autodiscover._tcp.kunde-a.tld` | 976 | OP-Work-Laptop 976 |
| `claude.ai` | 937 | OP-Work-Laptop 745, OP-T490 82, OP-T41S 62 |
| `edge.microsoft.com` | 927 | OP-Work-Laptop 894, OP-S25 33 |
| `checkonline.home-assistant.io` | 870 | homeassistant 870 |
| `www.bing.com` | 708 | OP-Work-Laptop 693, OP-S25 15 |
| `config.teams.microsoft.com` | 705 | OP-Work-Laptop 669, OP-S25 33, OP-T41S 3 |
| `outlook.office.com` | 651 | OP-Work-Laptop 560, OP-S25 90, OP-T41S 1 |
| `stun.syncthing.net` | 641 | OP-T41S 641 |
| `ch-veprod.traps.paloaltonetworks.com` | 640 | OP-Work-Laptop 640 |
| `dc-veprod.traps.paloaltonetworks.com` | 631 | OP-Work-Laptop 631 |
| `github.com` | 629 | OP-T41S 319, homeassistant 241, OP-T490 62 |
| `hub.home.arpa` | 617 | OP-S25 396, Sonoff-Panel 181, OP-T490 40 |
| `euc-common.online.office.com` | 601 | OP-Work-Laptop 601 |
| `oauth.officeapps.live.com` | 561 | OP-Work-Laptop 561 |

#### D18 Nur am letzten Tag gesehene Namen (≥ 3 Anfragen, je Client)
| Client | Name | Anfragen | Ergebnis |
|---|---|---|---|

#### D19 AdGuard-Clients (persistent) und ihre Schalter
| Name | IDs | globale Einstellungen | filtering_enabled | ignore_querylog |
|---|---|---|---|---|
| GX-Laptop | 192.168.70.218 | True | False | False |
| Govee-Desk-Lamp | 192.168.10.30 | True | True | False |
| Govee-TV-Light | 192.168.10.31 | True | True | False |
| K1-DROID | 192.168.40.218 | True | False | False |
| Nuki-Bridge | 192.168.10.10 | True | True | False |
| Nuki-Ultra | 192.168.10.40 | True | True | False |
| OP-Work-Laptop | 192.168.70.188 | True | False | False |
| OP-S25 | 192.168.20.189, 192.168.30.189, 192.168.40.189, 192.168.50.189 | True | False | False |
| OP-T41S | 192.168.20.111 | True | False | False |
| OP-T490 | 192.168.10.238, 192.168.20.238, 192.168.30.238, 192.168.40.238, 192.168.50.238 | True | False | False |
| Sonoff-Panel | 192.168.10.11 | True | False | False |
| TV | 192.168.50.158 | True | True | False |
| Voice-Assistant-Bad | 192.168.10.21 | True | True | False |
| Voice-Assistant-Kids | 192.168.10.22 | True | True | False |
| Voice-Assistant-Kitchen | 192.168.10.23 | True | True | False |
| Voice-Assistant-WoZi | 192.168.10.20 | True | True | False |
| ecoflow | 192.168.10.116 | True | False | False |
| homeassistant | 192.168.60.245 | True | True | False |

`filtering_enabled` wirkt nur, wenn `globale Einstellungen` False ist.
