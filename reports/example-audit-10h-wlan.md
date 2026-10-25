# Sicherheitsaudit 2026-10-25 (10 h): Firewall-Log, AdGuard-Query-Log, WLAN-Gesundheit

**Stand:** 2026-10-25, 10:40 Uhr. Kurz-Audit auf Zuruf des Operators, Fenster **25.10. 00:30 – 10:28**
(Routerzeit). Ausgeführt aus der `claude-home`-Session (Coding Agent), rein lesend; keine Änderung am Gerät.
Neu in diesem Lauf: WLAN-Survey mit Client-Gesundheit (passiv, ohne aktiven Nachbar-Scan, Operator-Entscheidung).
Das Fenster überlappt mit dem 6-h-Audit vom 24./25.10. (18:09–00:09, nur Chat) und folgt direkt auf
1.49.2 (`||home.arpa^` NXDOMAIN), 1.50.0 (`Allow-wgvpn-router-ping`) und 1.50.1 (dnsmasq `local`),
ist also zugleich deren Validierung.

> **Zeitumstellung:** Um 03:00 CEST sprang die Uhr auf 02:00 CET. Die Stunde 02 kommt in allen
> Stundenprofilen (T3, D3) **doppelt** vor; das nominelle 10-h-Fenster umfasst real knapp 11 h.

## 1. Rahmen

| Quelle | Fenster | Umfang |
|---|---|---|
| Firewall-Log (`/mnt/nvme/log/system.log`, `scripts/fwlog-audit.py --since '2026-10-25 00:30'`) | 00:30 – 10:28 | **143 Zeilen** (≈ 13/h) |
| AdGuard-Query-Log (`querylog.json`, `scripts/dnslog-audit.py --since '2026-10-25 00:30' --querylog <gzip-Kopie>`) | 00:30 – **09:47** | 5.985 Einträge, 10 Clients, 444 Namen, 31,0 % geblockt |
| WLAN (`iwinfo`, `iw dev … station dump`, `iw dev … survey dump`, hostapd-Zeilen im System-Log; kein `uci show wireless`) | Live 10:33 + Historie 24.10. 00:00 – 25.10. 10:28 | 8 assoziierte Clients (6× 2,4 GHz, 2× 5 GHz) |
| Regelwerk | 1.50.1; `fwview` 75 Regeln, 0 Auffälligkeiten; `agview` 121 aktive Regeln, Doku-Abgleich 121 = 121, 0 Warnungen | Guard `verify`: 47 Regeln mit Set-Referenz rendern korrekt |
| Ergänzend | `nft list chain inet fw4 input_wgvpn`, `wg show`, `conntrack`, `nlbw`, `nslookup`, AdGuard-YAML nur `ratelimit*`/`upstream_dns`/`fallback_dns` | lesend |

**Puffer-Lücke:** AdGuard schreibt das Query-Log erst bei 1.000 gepufferten Einträgen. Letzter Eintrag
09:47:43, die folgenden ~40 Minuten fehlen in Anhang B. Das ist kein Ausfall. `querylog.json.1` fehlt
weiterhin (seit 21.10.). Boot des Routers unverändert 22.10. 17:36 (Uptime 237.446 s um 10:33).

## 2. Ergebnis in Kürze

**Auffällig**

- **F1 Hub → Panel RST-Schübe erneut** (F7 vom 24.10. war „abgeklungen"): 65 Zeilen = 45 % des
  Firewall-Logs, alle `TCP RST` von `homeassistant:8123` an sieben Ephemeralports des `Sonoff-Panel`, in
  drei Schüben (00:30, 01:21, 01:34, je ≈ 1 Minute), dazu 2× `443 → OP-S25` um 01:02. Der Router kennt
  die Verbindungen nicht mehr (kein Conntrack) und weist korrekt ab; 3 Minuten `Block-hubsrv-wan-all` und
  2 Minuten Zonen-Log am Limit. Kein Sicherheitsproblem, aber die Ursache (HA-Neustart? Panel-Websockets
  mit abgelaufenem Conntrack?) bleibt ohne HA-Log unsichtbar (S9 vom 24.10.).
- **F2 WLAN: drei IoT-Geräte fallen wiederholt wegen Inaktivität ab.** `Voice-Assistant-WoZi` war
  00:56 – 09:59 (**9 h**) nicht im WLAN, `Voice-Assistant-Bad` 23:41 – 07:05, `Nuki-Bridge` 00:10 – 07:05.
  Alle drei mit „disassociated due to inactivity", also Gerät sendet nichts mehr, Signal ist mit
  −41…−48 dBm exzellent. `Nuki-Bridge` und `Voice-Assistant-Bad` kamen am 24.10. **und** 25.10. jeweils um
  07:05:07/08 zurück: das sieht nach geschalteter Stromversorgung oder Automation aus, nicht nach Funk.
  `Voice-Assistant-Kids` und `-Kitchen` hängen seit dem Boot ununterbrochen.
- **F3 5-GHz-Clients am Rand:** beide `private`-Clients aktuell bei **−73/−74 dBm, SNR 19** (OP-T41S
  7,9 % Retries, OP-S25 15,8 % Retries, Chain-Ungleichgewicht −83/−74). Durchsatz trägt noch
  (HE-MCS 4–7, 374–609 Mbit erwartet), aber das ist die Grenze, die die Survey vom 13.09. als Boden
  (−70/SNR 22) beschrieben hat. Momentaufnahme, standortabhängig.
- **F4 2,4-GHz-Kanal 1 zu 36 % belegt, fast ausschließlich fremd** (`survey dump` seit Boot: busy 36,0 %,
  davon eigene BSS 0,2 %). Eigene Clients haben trotz starkem Signal 1–13 % Retries. Ein aktiver
  Nachbar-Scan war nicht freigegeben; Kanalwahl bleibt deshalb offen (S2).
- **F5 Proton-Ping-Nachweis (1.50.0) weiter offen:** Zähler der neuen Regel 0, letzte `SRC=10.2.0.1`-Zeile
  bleibt 24.10. 22:36:20. Der Keepalive-Ping ist seit 12 h ausgeblieben, der Tunnel selbst lebt
  (Handshake 10:33). Weder Wirkung noch Fehlen der Regel belegbar.

**Läuft gut** (Abschnitt 4): `||home.arpa^` wirkt (19 Treffer, Reason 11, Upstream leer; Rewrites
unberührt, 177×), **keine einzige `.lan`-Anfrage** mehr, Rate-Limit-Whitelist Hub greift (0 s am Limit in
`smarthome_srv`, max 16/s), Upstream-Latenz deutlich besser als am 22./24.10. (p99 306 ms statt 3 s,
4 statt 1.029 Antworten > 1 s, 0 Quad9-Fallbacks), DoH/DoT-Umgehung 1 Versuch/0 erlaubt, Default-Deny-IoT
exakt auf den Positivlisten, Management nur über den Tunnel (0 Direktversuche), keine fehlgeschlagene
WLAN-Authentifizierung, alle Clients mit MFP außer `Nuki-Bridge` (WPA2-Gerät), 0 SERVFAIL.

**Nachschärfen** (Abschnitt 5): Ursache der IoT-Inaktivitätsabbrüche klären (V1), 5-GHz-Standort/TX-Power
der beiden Laptops/Handy beobachten statt ändern (V2), aktiver 2,4-GHz-Scan zu einem passenden Zeitpunkt
(V3), Zufalls-MAC in `kids` vom 24.10. 12:23 inventarisieren (V4), `a-api.anthropic.com` entscheiden
(V6 vom 22.10., 264× geblockt, 229 davon zwischen 09:00 und 09:47), Hub-Anfragen `api.tailscale.com`
alle 30 s ohne Cache (V5, optional).

**Sichtbarkeit fehlt** (Abschnitt 6): HA-Log (S1), Nachbar-WLANs (S2), TV seit 22.10. 22:03 ohne
Netzkontakt (S3), Query-Log-Puffer (S4), Doppelstunde durch Zeitumstellung in den Profilen (S5).

## 3. Befunde

| Nr. | Befund | Tabellen | Einordnung |
|---|---|---|---|
| F1 | **Hub → Panel RST ohne Conntrack.** 30× `Block-hubsrv-wan-all` + 35× `reject smarthome_srv forward`, alle `SRC=192.168.60.245 SPT=8123 → DST=192.168.10.11 DPT=35626/36056–36062/36258/36264 RST`. Schübe 00:30:28–00:31:32 (25), 01:21:37–01:22:32 (17), 01:34:04–01:35:10 (21); dazwischen 01:02:50 `443 → 192.168.20.189:39520 RST` (2). Das Panel sendet auf alten Verbindungen zur HA-Oberfläche, HA antwortet mit RST, der Router hat keinen Conntrack-Eintrag mehr (aktuell 2 Einträge Panel↔8123). Jeder Schub ≈ 1 Minute, jeweils 1–3 Minuten am Log-Limit (Dunkelziffer). Dasselbe Muster wie F6 (22.10.) und F7 (24.10.) | T1, T5, T6, T9 | Harmlos, Router korrekt. **Ursache offen → V1/S1.** Nebenbefund bleibt: `Block-hubsrv-wan-all` loggt auch LAN-Ziele, Name irreführend (Operator 25.10.: nur Doku) |
| F2 | **IoT-Inaktivitätsabbrüche 2,4 GHz.** `Voice-Assistant-WoZi` (`.10.20`): 24.10. 21:44 ↓, 22:00 ↑, 23:06 ↓, 25.10. 00:45 ↑, 00:50 Re-Auth, **00:56 ↓, 09:59 ↑**. `Voice-Assistant-Bad` (`.10.21`): 24.10. 00:10 ↓, 07:05 ↑, 21:44 ↓, 22:00 ↑, 23:06 ↓, 23:36 ↑, **23:41 ↓, 25.10. 07:05 ↑**. `Nuki-Bridge` (`.10.10`): 24.10. 12:10 ↓, 21:34 ↑, 22:11 Re-Assoc, **25.10. 00:10 ↓, 07:05 ↑**. Alle ↓ = „disassociated due to inactivity (timer DEAUTH/REMOVE)", also kein Frame mehr vom Gerät innerhalb des Inaktivitäts-Timers. Signal live −41/−48/−46 dBm, SNR 45–50. Die beiden anderen Voice-Assistants (`Kids`, `Kitchen`) sind seit dem Boot (22.10. 17:36) ohne Unterbrechung verbunden. DNS: `.10.20` nur 2 Anfragen (00:45, 00:51), `.10.10` 1 (07:05) | W2, W3 | **Nachschärfen (V1).** Verdacht: geschaltete Steckdose/Automation 07:05 bzw. Stromsparen der Geräte, nicht Funk |
| F3 | **5 GHz `private`:** `OP-T41S` −74 dBm (avg −73, Chains −74/−79), SNR 19, TX 720 Mbit HE-MCS 7 NSS 2 80 MHz, 7.987 Retries / 100.752 Pakete (7,9 %), erwartet 609 Mbit, verbunden seit 08:22. `OP-S25` −74 dBm (avg −73, **Chains −83/−74**), SNR 19, TX 432 Mbit HE-MCS 4, 39.372 / 249.815 (15,8 %), erwartet 374 Mbit, seit 09:02. `OP-T490` 06:08 abgemeldet (Standby), nicht zurück. Survey 13.09.: Handy −56, T41S am Arbeitsplatz −70 = „Boden". Heute liegen beide darunter; der Handy-Wert mit Chain-Ungleichgewicht spricht für Abschattung/Lage (Hosentasche, Raumwechsel), nicht für AP-Änderung (TX-Power unverändert 9 dBm, Kanal 149, HE80) | W1 | **Beobachten (V2).** Kein Eingriff aus einer Momentaufnahme |
| F4 | **2,4-GHz-Kanalbelegung:** `survey dump` phy0-ap0 seit Boot: aktiv 237.588 s, busy 85.402 s (**36,0 %**), receive 83.492 s, davon eigene BSS 465 s (0,2 %), eigenes Senden 857 s (0,4 %). Der Kanal ist also zu gut einem Drittel durch fremde Sender belegt. Eigene Clients: Retries 1,3 % (Nuki, WoZi) bis 13,3/13,5 % (`VA-Kids`, `VA-Bad`) trotz −40…−53 dBm. `tx failed` = `tx retries` ist ein Zählerartefakt des mt76-Treibers, nicht echte Verluste. 5 GHz: busy 5,3 % (12.496 s), davon eigen 3,0 % | W1, W4 | **V3:** aktiver Scan (`iwinfo phy0-ap0 scan`) nach Freigabe, dann Kanalentscheidung 1/6/11 |
| F5 | **Proton-Ping (1.50.0):** `input_wgvpn`: `ip saddr 10.2.0.1 … icmp echo-request counter packets 0`. Letzte geloggte Abweisung 24.10. 22:36:20 (SEQ 10). Seit 12 h kein Ping, obwohl der Tunnel arbeitet (Handshake 10:33:29, 15,3 GB rx). Entweder sendet das Gateway den Keepalive nur unter bestimmten Bedingungen (Schübe alle 20–60 min laut 1.50.0, jetzt 12 h Pause) oder die Sitzung hat seit dem Rekey ein anderes Verhalten | T1 (kein Eintrag) | **Offen.** Prüfung wie in 1.50.0 beschrieben, nächstes Audit |
| F6 | **`wgvpn` Rückläufer:** 55× `reject wgvpn in` von 13 externen Adressen an 53 verschiedene hohe TCP-Ports von `10.2.0.2`, 19× `invalid ct state` (`OP-S25 → 82.220.37.2:443` 9, `OP-T41S → 160.79.104.10:443` 4). `82.220.37.2` mit 33 Ports = Antwortseite einer S25-Sitzung (Scan-Tabelle T8 schlägt an, max 2 Ports/10 min = kein Scan). `160.79.104.10` = Anthropic-API. Wie F15 (24.10.), L2 (17.10.) | T4, T7, T8, T10 | Bestätigung, kein Scan |
| F7 | **`adminvpn → smarthome_srv`:** 2× `SRC=192.168.0.3` (Peer `admin-phone` = OP-S25 im Admin-Tunnel) `→ 192.168.60.245 udp/38108`, 09:12:36/42. Port 38108 ist ein hoher UDP-Port des Hubs: Tailscale-Direktpfad-Versuch der Handy-App über den gerade aktiven Admin-Tunnel (Handshake `admin-phone` 10:33:06). Erlaubt ist Admin-Tunnel → Hub nur auf Management-Ports (`wgadm_hub`), der Direktpfad gehört in `private` (`hub_ts_pins`) | T5 | Harmlos, Design hält. Keine Regel nötig: sobald die Handy-App über `private` geht, greift `hub_ts_pins` |
| F8 | **`OP-S25 → Router tcp/80`** je 1 SYN eine Sekunde nach jeder WLAN-Anmeldung (00:33:20, 09:02:34; `Allow-private-router-*` kennt kein HTTP). Android/Samsung Gateway-Probe nach Connect | T4 | Rauschen; optional Mute (nicht empfohlen, 2 Zeilen/Tag) |
| F9 | **MagicDNS-Name mit Suchdomäne:** `OP-S25` fragte 09:02:36 `hub-home-arpa.<REMOVED>.ts.net` einmal am Upstream (NextDNS) und 11× `…ts.net.home.arpa` (lokal NXDOMAIN durch 1.49.2). Direkt nach dem WLAN-Reconnect löst die Handy-App den Tailnet-Namen über das LAN-DNS statt über MagicDNS auf; Android hängt die Suchdomäne an. Der Tailnet-Hostname geht so einmal pro Reconnect an NextDNS | D12, B-Zusatz | Hygiene, gering. Beobachten; keine Regel |
| F10 | **Hub `api.tailscale.com` alle 30 s** (A+AAAA, exakt 120/h, 1.196 im Fenster = 79 % des Hub-DNS, 0 % Cache). Der Tailscale-Add-on-Health-Check oder HA-Integration pollt; AdGuard cached nicht (TTL 0 oder `Cached` nicht gesetzt). Kein Sicherheitsthema, aber 20 % des Gesamt-DNS-Volumens nachts | D4, D9, D17 | Optional **V5** (AdGuard `cache_optimistic`/Min-TTL oder Poll-Intervall im Add-on) |
| F11 | **`a-api.anthropic.com`** 264× geblockt (nur `OP-S25`, HaGeZi Ultimate), 229 davon 09:00–09:47 = aktive Claude-App-Nutzung. `api.anthropic.com` 207× erlaubt (T490, T41S) | D7, D8 | **V6 (22.10.) weiter offen** |
| F12 | **Rate-Limit:** `private` 2 s am Limit (07:20:51, OP-S25 20/s), sonst 0. `smarthome_srv` max 16/s, 0 s am Limit → **V1 vom 24.10. (Whitelist Hub) bestätigt wirksam**; PTR-Sweep nicht mehr im Log (Ignorierliste) | D15 | Erledigt |
| F13 | **Zufalls-MAC in `kids` (außerhalb des Fensters, bisher unberichtet):** `02:59:ab:a7:0a:d1` → `192.168.40.198`, SAE-Anmeldung an `kids` 24.10. 12:23:14, Abmeldung 12:25:21, 1 DNS-Anfrage 12:25:19; nlbwmon führt die MAC mit 1,08 GB Download im Oktober (also mehrfach im Monat). Nicht reserviert, nicht in AdGuard-Clients (`K1-DROID` ist `.40.218`) | nlbw | **V4:** identifizieren (K1-DROID mit Randomisierung? Gastgerät?) |

## 4. Was läuft gut

- **1.49.2 validiert:** 19 Treffer `||home.arpa^$dnsrewrite=NXDOMAIN` (Reason 11, Upstream leer), darunter die
  Operator-Tests `gibtsnicht`/`teams.cloud.microsoft.com.home.arpa` um 00:38; die sieben Rewrites liefern weiter
  (177×: `hub` 150, `openwrt` 12, `adguard` 11, `switch` 4). `nslookup gibtsnicht.home.arpa` → NXDOMAIN, `hub.home.arpa` → `.60.245`.
- **`.lan`-Regel reif zum Entfernen:** 0 `.lan`-Anfragen im Fenster (24.10.: 294 in 61 h). Bedingung aus 1.48.2 erstmals erfüllt; ein weiteres Fenster abwarten.
- **1.50.1 ohne Nebenwirkung:** DHCP vergibt weiter (DHCPACK `homeassistant`, `OP-T41S`, Voice-Assistants im Fenster), Suchdomäne `home.arpa` wird angehängt (F9 zeigt es).
- **Upstream:** NextDNS p50/p90/p99 = 46/83/306 ms, 4 Antworten > 1 s, 0 Fallback auf Quad9, 0 SERVFAIL. Deutlich besser als 22./24.10. (p99 3,0 s). Nachtfenster, geringe Last; Trend im Wochenlauf prüfen.
- **Egress-Policy:** 0 DoH/DoT-Durchbrüche (1 Namensversuch `cloudflare-dns.com`, geblockt), Default-Deny-Zonen exakt auf den Positivlisten (D9: 24 erlaubte Namen Hub, 1 Panel, 1 je Voice-Assistant/Nuki), 12 Blocks beim Hub nur Fonts/Podcast-CDNs.
- **Management:** 0 Direktversuche auf `.30.1`; drei Admin-Peers, zwei mit Handshake im Fenster (`admin-laptop` zuletzt 24.10. 13:45, `admin-phone` 10:33, `OP-T41S` 10:33). C18 (Reboot-Test) damit für Phone und T41S erstmals bestätigt.
- **WLAN-Sicherheit:** alle fünf SSIDs laut `/var/run/hostapd-phy*.conf` wie dokumentiert (`private/kids/tv/work`: SAE, `ieee80211w=2`, `ocv=1`, `sae_pwe=2`; `smarthome`: WPA2-PSK/SHA256, `ieee80211w=1`; überall `ap_isolate=1`, `disassoc_low_ack=1`). Keine fehlgeschlagene Authentifizierung, keine fremde MAC an `private/kids/tv/work` im Fenster. OP-S25 00:33 mit `auth_alg=open` = PMKSA-Caching nach SAE, 09:02 volles SAE.
- **Firewall-Mirror:** `fwview` 75 Regeln, 12 Umleitungen, 0 Auffälligkeiten; `agview` 121 aktive Regeln = 121 dokumentiert, 7 Rewrites = 7, 0 Warnungen, 31 Freigaben ohne Treffer im Fenster (erwartbar, Nacht/Sonntag).

## 5. Vorschläge (nachschärfen)

| Nr. | Thema | Vorschlag | Aufwand |
|---|---|---|---|
| V1 | IoT-Abbrüche (F2) + Hub-RST (F1) | Operator prüft, ob `Voice-Assistant-Bad`, `Voice-Assistant-WoZi`, `Nuki-Bridge` an geschalteten Steckdosen/Automationen hängen (07:05, 22:00). Falls nein: HA-Log der Geräte (unavailable-Zeiten) gegen die hostapd-Zeiten legen. Für F1 HA-Core-Neustarts 00:30/01:21/01:34 prüfen. Voraussetzung S1 (HA-SSH-Key, offen seit 17.10.) | Operator, kein Router-Eingriff |
| V2 | 5 GHz am Rand (F3) | Nichts ändern. Beim nächsten Audit `station dump` erneut; bleibt T41S am Arbeitsplatz ≤ −73/SNR 19 mit > 10 % Retries, TX-Power 5 GHz auf 10–11 dBm testen (Survey 13.09. nannte 9 dBm als Boden mit kleiner Reserve) | 1 UCI-Wert, reversibel |
| V3 | 2,4-GHz-Kanal (F4) | Einmal aktiver Scan `iwinfo phy0-ap0 scan` zu einer Zeit ohne kritische IoT-Aktion (kurze Off-Channel-Pause), Ergebnis in `wifi-survey/`. Danach Kanal 1/6/11 nach geringster Fremdbelegung wählen | 1 Kommando + ggf. 1 UCI-Wert |
| V4 | Zufalls-MAC `kids` (F13) | Gerät identifizieren; falls K1-DROID: Randomisierung für `kids` abschalten oder die MAC reservieren, sonst `kids`-Passwort prüfen | Operator |
| V5 | Hub-DNS (F10) | Optional: AdGuard `cache_optimistic: true` oder `cache_ttl_min: 60`, alternativ Poll-Intervall im Tailscale-Add-on. Spart ≈ 2.900 Upstream-Anfragen/Tag | 1 YAML-Wert |
| V6 | `a-api.anthropic.com` (F11) | Unverändert V6 vom 22.10.: `@@\|\|a-api.anthropic.com^$client=192.168.20.189` oder bewusst gesperrt lassen; in `dns-filtering.md` Teil B einstufen | 1 Regel + Doku |
| V7 | `.lan`-Regel | Nach einem weiteren Fenster ohne `.lan`-Anfragen `\|\|lan^$dnsrewrite=NXDOMAIN;;` entfernen (1.48.2/1.49.2) | 1 Regel + Doku |

## 6. Wo Sichtbarkeit fehlt

| Nr. | Lücke | Folge | Abhilfe |
|---|---|---|---|
| S1 | HA-Ereignisse nicht im Router-Log (S9 vom 24.10.) | F1 und F2 nur zeitlich korrelierbar | HA-SSH-Key → `ha core logs` im Audit |
| S2 | Kein Nachbar-Scan | Fremdbelegung 36 % auf Kanal 1 ohne Verursacher | V3 |
| S3 | **TV ohne Netzkontakt seit 22.10. 22:03** (letzte hostapd-Zeile `02:10:f0:6a:61:e8`, letzte DNS-Anfrage 21:58) | `tv`-Zone seit 2,5 Tagen unbeobachtbar; F10 (24.10.) „konstant 660/h auch nachts" galt bis dahin | Operator: TV stromlos? (Umbau 22.10.) Sonst Verbindung prüfen |
| S4 | Query-Log-Puffer (1.000 Einträge) | DNS-Sicht endet 09:47, Firewall-Sicht 10:28 | bekannt, hinnehmen |
| S5 | Zeitumstellung | Stunde 02 doppelt in T3/D3; Stundenwerte dort nicht mit anderen vergleichbar | Hinweis im Bericht, einmal jährlich |
| S6 | `kids`, `work` ohne Verkehr (Sonntag) | Zonen nicht geprüft | Wochenlauf |

## 7. WLAN-Gesundheit (Momentaufnahme 10:33 + Historie)

### W1 Assoziierte Clients

Schwellen: Signal ≥ −67 dBm gut, −68…−75 ausreichend, < −75 schwach. Retries = `tx retries`/`tx packets` seit
Assoziation. `tx failed` ist beim mt76-Treiber identisch mit `tx retries` und daher nicht aussagekräftig.

| SSID / Band | Gerät | IP | Signal (Chains) | SNR | TX-Rate | RX-Rate | Retries | erwartet | verbunden seit | MFP | Bewertung |
|---|---|---|---|---|---|---|---|---|---|---|---|
| smarthome 2,4 | Voice-Assistant-Kitchen | .10.23 | −40 (−44/−42) | 51 | 65 Mbit MCS 7 | 6 Mbit | 962/17.408 = 5,5 % | 57 Mbit | Boot 22.10. 17:36 | ja | **gut** |
| smarthome 2,4 | Voice-Assistant-WoZi | .10.20 | −41 (−43/−45) | 50 | 65 MCS 7 | 6 | 6/460 = 1,3 % | 57 | 09:59 (34 min) | ja | gut, aber 9 h offline (F2) |
| smarthome 2,4 | Nuki-Bridge | .10.10 | −46 (−55/−47) | 45 | 65 MCS 7 | 72 MCS 7 SGI | 49/3.655 = 1,3 % | 57 | 07:05 (3,5 h) | **nein** (WPA2) | gut, Abbrüche (F2) |
| smarthome 2,4 | Voice-Assistant-Bad | .10.21 | −48 (−55/−49) | 43 | 65 MCS 7 | 6 | 218/1.619 = 13,5 % | 57 | 07:05 (3,5 h) | ja | ausreichend, Abbrüche (F2) |
| smarthome 2,4 | Voice-Assistant-Kids | .10.22 | −49 (−56/−50) | 42 | 65 MCS 7 | 6 | 2.670/20.042 = 13,3 % | 57 | Boot | ja | ausreichend (Retries) |
| smarthome 2,4 | Sonoff-Panel | .10.11 | −52 (−55/−56) | 39 | 65 MCS 7 | 6 | 6.066/196.104 = 3,1 % | 57 | 22.10. 18:47 | ja | **gut** (146 MB TX, stabil) |
| private 5 | OP-T41S | .20.111 | −74 (−75/−79) | 19 | 720 HE-MCS 7 ×2 80 MHz | 432–720 | 7.987/100.752 = 7,9 % | 609 | 08:22 (2,2 h) | ja | ausreichend, am Rand (F3) |
| private 5 | OP-S25 | .20.189 | −74 (**−85**/−74) | 19 | 432 HE-MCS 4 ×2 80 MHz | 6 | 39.372/249.815 = 15,8 % | 374 | 09:02 (1,5 h) | ja | **am Rand** (F3) |
| kids / tv / work 5 | — | — | — | — | — | — | — | — | keine Clients | — | nicht messbar |

Radios: `radio0` 2,4 GHz Kanal 1, HT20, 12 dBm, Noise −92 dBm, `radio1` 5 GHz Kanal 149, HE80 (Center 155), 9 dBm,
Noise −92 dBm, Land DE. Beide Werte unverändert gegenüber Survey 13.09. und F4c der Netzdokumentation.
`RX: 6 Mbit` bei vielen Clients ist die Rate des zuletzt empfangenen (Management-)Frames, kein Datenwert.

### W2 Verbindungsereignisse im Fenster (hostapd)

| Zeit | SSID | Gerät | Ereignis |
|---|---|---|---|
| 00:33:19 | private | OP-S25 | Anmeldung (`auth_alg=open` = PMKSA-Cache nach SAE), 4-Way-HS ok |
| 00:45:56 | smarthome | Voice-Assistant-WoZi | Anmeldung |
| 00:50:52 | smarthome | Voice-Assistant-WoZi | erneute Auth/Assoc (ohne Disconnect dazwischen) |
| 00:56:48 | smarthome | Voice-Assistant-WoZi | **Abbruch: Inaktivität** |
| 01:02:30 | private | OP-T41S | Abmeldung (Client) |
| 06:08:31 | private | OP-T490 | Abmeldung (Client, Standby), kein Reconnect bis 10:28 |
| 07:05:07 | smarthome | Nuki-Bridge | Anmeldung (offline seit 00:10, Inaktivität) |
| 07:05:08 | smarthome | Voice-Assistant-Bad | Anmeldung (offline seit 24.10. 23:41, Inaktivität) |
| 08:22:47 | private | OP-T41S | Anmeldung (`auth_alg=sae`) |
| 08:58:24 | private | OP-S25 | Abmeldung (Client) |
| 09:02:33 | private | OP-S25 | Anmeldung (`auth_alg=sae`) |
| 09:59:43 | smarthome | Voice-Assistant-WoZi | Anmeldung (offline seit 00:56) |

Keine fehlgeschlagene Authentifizierung, kein `deauthenticated` außer durch den Inaktivitäts-Timer, kein
Roaming 2,4 ↔ 5 GHz, keine fremde MAC. `kids`/`tv`/`work`: kein Ereignis seit 24.10. 12:25 (`kids`, F13),
22.10. 22:03 (`tv`, S3) bzw. 23.10. 17:24 (`work`).

### W3 Inaktivitätsabbrüche 24.–25.10. (nur 2,4 GHz, nur drei Geräte)

| Gerät | ↓ Abbrüche (Inaktivität) | ↑ Rückkehr | längste Lücke |
|---|---|---|---|
| Voice-Assistant-Bad | 24.10. 00:10, 21:44, 23:06, 23:41 | 07:05, 22:00, 23:36, **25.10. 07:05** | 7 h 24 min |
| Voice-Assistant-WoZi | 24.10. 21:44, 23:06, 25.10. 00:56 | 22:00, 00:45, **09:59** | 9 h 03 min |
| Nuki-Bridge | 24.10. 12:10, 25.10. 00:10 | 21:34 (+ Re-Assoc 22:11), **07:05** | 9 h 24 min |
| Voice-Assistant-Kids, -Kitchen, Sonoff-Panel | — | — | durchgehend seit 22.10. |

### W4 Kanalbelegung (`iw survey dump`, kumuliert seit Boot, passiv)

| Radio | Kanal | aktiv | busy | davon receive | davon eigene BSS | davon eigenes TX | Fremdanteil |
|---|---|---|---|---|---|---|---|
| radio0 2,4 GHz | 1 (2412 MHz) | 237.588 s | 85.402 s = **36,0 %** | 83.492 s | 465 s | 857 s | ≈ 35 % |
| radio1 5 GHz | 149 (5745 MHz) | 237.417 s | 12.496 s = 5,3 % | 6.345 s | 1.384 s | 5.775 s | ≈ 2 % |

## 8. Methode

`scripts/fwlog-audit.py 1.0.0` (SSH, `cat` des Logs, `uci export`), `scripts/dnslog-audit.py 1.0.0`
(`gzip -c querylog.json` → `--querylog`, da `.1` fehlt). WLAN ausschließlich mit `iwinfo`, `iwinfo … assoclist`,
`iw dev … station dump`, `iw dev … survey dump`, gezielten `uci -q get wireless.radioN.{channel,htmode,txpower,country}`,
`grep` auf `/var/run/hostapd-phy*.conf` (nur Schlüsselverwaltung/MFP/OCV/Isolation) und hostapd-Zeilen des
System-Logs; **kein** `uci show wireless`/`uci export wireless`. Ergänzend `nft list chain inet fw4 input_wgvpn`,
`wg show all latest-handshakes|transfer`, `uci show network | grep wgadm` (Beschreibung, AllowedIPs, öffentliche
Schlüssel), `conntrack -L`, `nlbw -c show -g mac,ip`, `/proc/uptime`, `nslookup` gegen AdGuard, AdGuard-YAML nur
`ratelimit*`, `upstream_dns`, `fallback_dns`. Mirror: `scripts/fwview.py` und `scripts/agview.py --querylog`
nach `docs-internal/` (gitignored). Keine Änderung am Gerät. Firmen-Domäne in Anhang B durch Platzhalter ersetzt.


## Anhang A: Firewall-Log-Tabellen (generiert, Fenster 25.10. 00:30 – 10:28)

<!-- generated by scripts/fwlog-audit.py 1.0.0, source root@192.168.30.1, window 2026-10-25 00:30:00 .. 2026-10-25 10:28:25, 143 firewall lines -->
#### T1 Zeilen je Log-Klasse
| Präfix | Klasse | Zeilen | Anteil | erste | letzte | max/min | Limit/min | Minuten am Limit |
|---|---|---|---|---|---|---|---|---|
| `reject wgvpn in` | zone-in | 55 | 38.5 % | 25.10. 00:50 | 25.10. 10:28 | 4 | 10 | 0 |
| `reject smarthome_srv forward` | zone-fwd | 35 | 24.5 % | 25.10. 00:30 | 25.10. 01:35 | 10 | 10 | 2 |
| `Block-hubsrv-wan-all` | rule | 30 | 21.0 % | 25.10. 00:30 | 25.10. 01:35 | 9 | 6 | 3 |
| `drop wgvpn invalid ct state` | invalid | 19 | 13.3 % | 25.10. 01:18 | 25.10. 09:25 | 3 | - | 0 |
| `reject private in` | zone-in | 2 | 1.4 % | 25.10. 00:33 | 25.10. 09:02 | 1 | 10 | 0 |
| `reject adminvpn forward` | zone-fwd | 2 | 1.4 % | 25.10. 09:12 | 25.10. 09:12 | 2 | 10 | 0 |

`Minuten am Limit`: Minuten, in denen so viele Zeilen wie das Limit erlaubt geschrieben wurden; in diesen Minuten sind weitere Treffer **nicht** im Log (Dunkelziffer).

#### T2 Zeilen je Tag und Klasse
| Tag | zone-in | zone-fwd | collective | rule | invalid | zone-out | other | gesamt |
|---|---|---|---|---|---|---|---|---|
| Sun 25.10. | 57 | 37 | 0 | 30 | 19 | 0 | 0 | 143 |

#### T3 Tagesprofil (Zeilen je Stunde, Summe über die Tage)
| Klasse | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gesamt | 27 | 47 | 16 | 6 | 4 | 4 | 4 | 5 | 18 | 9 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| zone-in | 2 | 6 | 13 | 3 | 4 | 3 | 3 | 5 | 9 | 6 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| rule | 11 | 19 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| zone-fwd | 14 | 21 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| collective | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| invalid | 0 | 1 | 3 | 3 | 0 | 1 | 1 | 0 | 9 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

#### T4 INPUT-Abweisungen je Zone (`reject <zone> in`): Quelle → Router-Adresse, Dienst
| Zone | Quelle | Ziel | Dienst | Zeilen | Anteil in Zone |
|---|---|---|---|---|---|
| private | 192.168.20.189 (OP-S25) | 192.168.20.1 (Router (private)) | tcp/80 (HTTP) | 2 | 100.0 % |
| wgvpn | 160.79.104.10 | 10.2.0.2 (Router (wgvpn)) | tcp/37976 | 3 | 5.5 % |
| wgvpn | 161.69.245.10 | 10.2.0.2 (Router (wgvpn)) | tcp/48822 | 2 | 3.6 % |
| wgvpn | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/34709 | 1 | 1.8 % |
| wgvpn | 147.75.180.17 | 10.2.0.2 (Router (wgvpn)) | tcp/48414 | 1 | 1.8 % |
| wgvpn | 54.76.186.33 | 10.2.0.2 (Router (wgvpn)) | tcp/41940 | 1 | 1.8 % |
| wgvpn | 54.76.186.33 | 10.2.0.2 (Router (wgvpn)) | tcp/41942 | 1 | 1.8 % |
| wgvpn | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/53389 | 1 | 1.8 % |
| wgvpn | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/58821 | 1 | 1.8 % |
| wgvpn | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/48179 | 1 | 1.8 % |
| wgvpn | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/42899 | 1 | 1.8 % |
| wgvpn | 34.247.205.63 | 10.2.0.2 (Router (wgvpn)) | tcp/51420 | 1 | 1.8 % |
| wgvpn | 52.51.224.216 | 10.2.0.2 (Router (wgvpn)) | tcp/36220 | 1 | 1.8 % |

#### T5 Abweisungen zwischen Zonen (FORWARD ohne Regel: Zonen-Log + Sammelzeile)
| von Zone | nach Zone | Quelle | Ziel | Dienst | Präfix | Zeilen |
|---|---|---|---|---|---|---|
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35626 | `reject smarthome_srv forward` | 9 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36264 | `reject smarthome_srv forward` | 7 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36062 | `reject smarthome_srv forward` | 6 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36258 | `reject smarthome_srv forward` | 4 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36056 | `reject smarthome_srv forward` | 3 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36060 | `reject smarthome_srv forward` | 3 |
| smarthome_srv | smarthome | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36058 | `reject smarthome_srv forward` | 2 |
| adminvpn | smarthome_srv | 192.168.0.3 | 192.168.60.245 (homeassistant) | udp/38108 | `reject adminvpn forward` | 2 |
| smarthome_srv | private | 192.168.60.245 (homeassistant) | 192.168.20.189 (OP-S25) | tcp/39520 | `reject smarthome_srv forward` | 1 |

Zonen-Paare gesamt: smarthome_srv→smarthome 34, adminvpn→smarthome_srv 2, smarthome_srv→private 1

#### T6 Egress-Blocks je Regel (`Block-*`): Quelle, Ziel, Dienst
| Regel | Zeilen | Protokolle | Ziel-IPs | Quelle | Ziel | Dienst × Zeilen |
|---|---|---|---|---|---|---|
| `Block-hubsrv-wan-all` | 30 | TCP 30 | 2 |  |  |  |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35626 ×8 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36264 ×6 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36062 ×5 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36258 ×4 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36056 ×3 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36060 ×2 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36058 ×1 |
|  |  |  |  | 192.168.60.245 (homeassistant) | 192.168.20.189 (OP-S25) | tcp/39520 ×1 |

#### T7 Tunnel-Eingang `wgvpn` (INPUT-Abweisungen und `invalid ct state`)
| Präfix | Quelle (extern) | Ziel | Dienst | Zeilen |
|---|---|---|---|---|
| `drop wgvpn invalid ct state` | 192.168.20.189 | 82.220.37.2 | tcp/443 (HTTPS) | 9 |
| `drop wgvpn invalid ct state` | 192.168.20.111 | 160.79.104.10 | tcp/443 (HTTPS) | 4 |
| `reject wgvpn in` | 160.79.104.10 | 10.2.0.2 (Router (wgvpn)) | tcp/37976 | 3 |
| `reject wgvpn in` | 161.69.245.10 | 10.2.0.2 (Router (wgvpn)) | tcp/48822 | 2 |
| `drop wgvpn invalid ct state` | 192.168.20.189 | 74.125.162.228 | tcp/443 (HTTPS) | 2 |
| `reject wgvpn in` | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/34709 | 1 |
| `reject wgvpn in` | 147.75.180.17 | 10.2.0.2 (Router (wgvpn)) | tcp/48414 | 1 |
| `reject wgvpn in` | 54.76.186.33 | 10.2.0.2 (Router (wgvpn)) | tcp/41940 | 1 |
| `reject wgvpn in` | 54.76.186.33 | 10.2.0.2 (Router (wgvpn)) | tcp/41942 | 1 |
| `reject wgvpn in` | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/53389 | 1 |
| `reject wgvpn in` | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/58821 | 1 |
| `reject wgvpn in` | 82.220.37.2 | 10.2.0.2 (Router (wgvpn)) | tcp/48179 | 1 |

verschiedene externe Quellen: 13; Ziel-Ports (udp/tcp) verschieden: 53

#### T8 Scan-Indikatoren: Quellen mit vielen verschiedenen Ziel-Ports oder Ziel-Hosts
| Quelle | Zeilen | Ziel-Ports verschieden | max Ports in 10 min | Ziel-Hosts verschieden | Präfixe |
|---|---|---|---|---|---|
| 82.220.37.2 | 33 | 33 | 2 | 1 | reject wgvpn in |

#### T9 Nur an einem Tag gesehene Quelle→Ziel-Paare (≥ 5 Zeilen)
| Tag | Präfix | Quelle | Ziel | Dienst | Zeilen |
|---|---|---|---|---|---|
| 25.10. | `drop wgvpn invalid ct state` | 192.168.20.189 (OP-S25) | 82.220.37.2 | tcp/443 (HTTPS) | 9 |
| 25.10. | `reject smarthome_srv forward` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35626 | 9 |
| 25.10. | `Block-hubsrv-wan-all` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/35626 | 8 |
| 25.10. | `reject smarthome_srv forward` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36264 | 7 |
| 25.10. | `reject smarthome_srv forward` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36062 | 6 |
| 25.10. | `Block-hubsrv-wan-all` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36264 | 6 |
| 25.10. | `Block-hubsrv-wan-all` | 192.168.60.245 (homeassistant) | 192.168.10.11 (Sonoff-Panel) | tcp/36062 | 5 |

#### T10 Alle Quellen mit Zeilenanzahl (ohne `invalid`)
| Quelle | Zeilen | Anteil | Präfixe |
|---|---|---|---|
| 192.168.60.245 (homeassistant) | 65 | 45.5 % | Block-hubsrv-wan-all, reject smarthome_srv forward |
| 82.220.37.2 | 33 | 23.1 % | reject wgvpn in |
| 160.79.104.10 | 8 | 5.6 % | reject wgvpn in |
| 52.51.224.216 | 3 | 2.1 % | reject wgvpn in |
| 192.168.20.189 (OP-S25) | 2 | 1.4 % | reject private in |
| 147.75.180.17 | 2 | 1.4 % | reject wgvpn in |
| 54.76.186.33 | 2 | 1.4 % | reject wgvpn in |
| 161.69.245.10 | 2 | 1.4 % | reject wgvpn in |
| 192.168.0.3 | 2 | 1.4 % | reject adminvpn forward |
| 34.247.205.63 | 1 | 0.7 % | reject wgvpn in |
| 52.57.152.145 | 1 | 0.7 % | reject wgvpn in |
| 13.226.155.51 | 1 | 0.7 % | reject wgvpn in |
| 143.204.181.46 | 1 | 0.7 % | reject wgvpn in |
| 146.75.121.91 | 1 | 0.7 % | reject wgvpn in |

## Anhang B: AdGuard-Query-Log-Tabellen (generiert, Fenster 25.10. 00:30 – 09:47)

<!-- generated by scripts/dnslog-audit.py 1.0.0, source <scratch>/querylog.json.gz, window 2026-10-25 00:30:00 .. 2026-10-25 09:47:43, 5985 entries, 0 unparsable lines -->
#### D1 Rahmen
| Größe | Wert |
|---|---|
| Einträge | 5985 |
| Zeitraum | 2026-10-25 00:30:00 .. 2026-10-25 09:47:43 (1 Tage) |
| Clients (IPs) | 10 |
| verschiedene Namen | 444 |
| geblockt (`IsFiltered`) | 1857 (31.0 %) |
| aus Cache beantwortet | 682 (11.4 %) |
| Client-Protokoll | plain 5985 |
| AdGuard `ratelimit` | 20/s je /24 |

**Ergebnisklassen (`Result.Reason`):**

| Reason | Bedeutung | Einträge | Anteil |
|---|---|---|---|
| 0 | nicht gefiltert | 2444 | 40.8 % |
| 3 | Blockliste | 1857 | 31.0 % |
| 1 | Allowlist | 1488 | 24.9 % |
| 9 | Rewrite | 177 | 3.0 % |
| 11 | Rewrite (Regel) | 19 | 0.3 % |

#### D2 Anfragen je Tag
| Tag | Anfragen | geblockt | Anteil | Clients | Namen | NXDOMAIN | SERVFAIL/Fehler |
|---|---|---|---|---|---|---|---|
| Sun 25.10. | 5985 | 1857 | 31.0 % | 10 | 444 | 36 | 0 |

#### D3 Tagesprofil (Anfragen je Stunde, Summe über die Tage)
| Zone | 00 | 01 | 02 | 03 | 04 | 05 | 06 | 07 | 08 | 09 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 23 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gesamt | 508 | 643 | 941 | 355 | 398 | 368 | 256 | 777 | 883 | 856 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Router (management) | 12 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| private | 386 | 494 | 638 | 211 | 244 | 220 | 114 | 622 | 723 | 750 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| smarthome | 12 | 6 | 8 | 4 | 6 | 5 | 4 | 5 | 5 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| smarthome_srv | 98 | 143 | 295 | 140 | 148 | 143 | 138 | 150 | 155 | 104 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

#### D4 Je Client: Volumen, Block-Anteil, Breite
| Client | Zone | Anfragen | Anteil | geblockt | Block-Anteil | Namen | NXDOMAIN | max/s | max/min | erste | letzte |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 192.168.20.189 (OP-S25) | private | 3144 | 52.5 % | 1303 | 41.4 % | 359 | 25 | 20 | 86 | 25.10. 00:33 | 25.10. 09:47 |
| 192.168.60.245 (homeassistant) | smarthome_srv | 1514 | 25.3 % | 12 | 0.8 % | 28 | 0 | 16 | 29 | 25.10. 00:30 | 25.10. 09:47 |
| 192.168.20.238 (OP-T490) | private | 731 | 12.2 % | 290 | 39.7 % | 20 | 0 | 8 | 16 | 25.10. 00:31 | 25.10. 06:07 |
| 192.168.20.111 (OP-T41S) | private | 527 | 8.8 % | 248 | 47.1 % | 58 | 7 | 17 | 21 | 25.10. 00:30 | 25.10. 09:47 |
| 192.168.10.11 (Sonoff-Panel) | smarthome | 52 | 0.9 % | 4 | 7.7 % | 3 | 0 | 2 | 4 | 25.10. 00:30 | 25.10. 09:40 |
| 192.168.30.1 (Router (management)) | Router (management) | 12 | 0.2 % | 0 | 0.0 % | 6 | 4 | 12 | 12 | 25.10. 00:38 | 25.10. 00:38 |
| 192.168.10.20 (Voice-Assistant-WoZi) | smarthome | 2 | 0.0 % | 0 | 0.0 % | 1 | 0 | 1 | 1 | 25.10. 00:45 | 25.10. 00:51 |
| 192.168.10.23 (Voice-Assistant-Kitchen) | smarthome | 1 | 0.0 % | 0 | 0.0 % | 1 | 0 | 1 | 1 | 25.10. 04:36 | 25.10. 04:36 |
| 192.168.10.22 (Voice-Assistant-Kids) | smarthome | 1 | 0.0 % | 0 | 0.0 % | 1 | 0 | 1 | 1 | 25.10. 04:36 | 25.10. 04:36 |
| 192.168.10.10 (Nuki-Bridge) | smarthome | 1 | 0.0 % | 0 | 0.0 % | 1 | 0 | 1 | 1 | 25.10. 07:05 | 25.10. 07:05 |

#### D5 Je Zone
| Zone | Clients | Anfragen | Anteil | geblockt | Block-Anteil | Namen |
|---|---|---|---|---|---|---|
| Router (management) | 1 | 12 | 0.2 % | 0 | 0.0 % | 6 |
| private | 3 | 4402 | 73.6 % | 1841 | 41.8 % | 418 |
| smarthome | 5 | 57 | 1.0 % | 4 | 7.0 % | 5 |
| smarthome_srv | 1 | 1514 | 25.3 % | 12 | 0.8 % | 28 |

#### D6 Blocks je Filterliste
| Liste | Blocks | Anteil | Namen | Clients |
|---|---|---|---|---|
| HaGeZi's Ultimate Blocklist | 1071 | 57.7 % | 39 | 3 |
| HaGeZi's Windows/Office Tracker Blocklist | 488 | 26.3 % | 6 | 2 |
| - | 196 | 10.6 % | 11 | 4 |
| AdGuard DNS filter | 101 | 5.4 % | 17 | 3 |
| HaGeZi's Encrypted DNS Bypass | 1 | 0.1 % | 1 | 1 |

#### D7 Meistgeblockte Namen
| Name | Blocks | Clients | Liste | Regel |
|---|---|---|---|---|
| `usage-ping.brave.com` | 342 | OP-S25 182, OP-T490 160 | HaGeZi's Ultimate Blocklist | `||usage-ping.brave.com^` |
| `mobile.pipe.aria.microsoft.com` | 342 | OP-S25 342 | HaGeZi's Windows/Office Tracker Blocklist | `||pipe.aria.microsoft.com^` |
| `a-api.anthropic.com` | 264 | OP-S25 264 | HaGeZi's Ultimate Blocklist | `||a-api.anthropic.com^` |
| `http-intake.logs.us5.datadoghq.com` | 159 | OP-T41S 159 | HaGeZi's Ultimate Blocklist | `||logs.us5.datadoghq.com^` |
| `go-updater.brave.com` | 144 | OP-S25 84, OP-T490 60 | - | `||go-updater.brave.com^$important` |
| `mobile.events.data.microsoft.com` | 68 | OP-T41S 67, OP-S25 1 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `unagi.amazon.de` | 43 | OP-S25 43 | HaGeZi's Ultimate Blocklist | `||unagi.amazon.de^` |
| `eu-mobile.events.data.microsoft.com` | 37 | OP-S25 37 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `zwjvbnvhnzme.heise.de` | 35 | OP-S25 35 | AdGuard DNS filter | `||zwjvbnvhnzme.heise.de^` |
| `star-randsrv.bsg.brave.com` | 34 | OP-T490 34 | HaGeZi's Ultimate Blocklist | `||star-randsrv.bsg.brave.com^` |
| `fls-eu.amazon.de` | 34 | OP-S25 34 | HaGeZi's Ultimate Blocklist | `||fls-eu.amazon.de^` |
| `collector.bsg.brave.com` | 28 | OP-T490 28 | AdGuard DNS filter | `||collector.bsg.brave.com^` |
| `in.appcenter.ms` | 27 | OP-S25 27 | HaGeZi's Windows/Office Tracker Blocklist | `||in.appcenter.ms^` |
| `firebaselogging.googleapis.com` | 23 | OP-S25 23 | - | `||firebaselogging.googleapis.com^` |
| `android-context-data.googleapis.com` | 16 | OP-S25 16 | HaGeZi's Ultimate Blocklist | `||android-context-data.googleapis.com^` |
| `geller-pa.googleapis.com` | 15 | OP-S25 15 | HaGeZi's Ultimate Blocklist | `||geller-pa.googleapis.com^` |
| `crashlyticsreports-pa.googleapis.com` | 14 | OP-S25 14 | HaGeZi's Ultimate Blocklist | `||crashlyticsreports-pa.googleapis.com^` |
| `bf72977jfz.bf.dynatrace.com` | 12 | OP-S25 12 | HaGeZi's Ultimate Blocklist | `||dynatrace.com^` |
| `redirect.prod.experiment.routing.cloudfront.aws.a2z.com` | 12 | OP-S25 12 | HaGeZi's Ultimate Blocklist | `||redirect.prod.experiment.routing.cloudfront.aws.a2z.com^` |
| `sdk.iad-01.braze.com` | 11 | OP-S25 11 | HaGeZi's Ultimate Blocklist | `||braze.com^` |
| `incoming.telemetry.mozilla.org` | 10 | OP-T41S 10 | AdGuard DNS filter | `||incoming.telemetry.mozilla.org^` |
| `merino.services.mozilla.com` | 9 | OP-T41S 9 | HaGeZi's Ultimate Blocklist | `||merino.services.mozilla.com^` |
| `o427061.ingest.sentry.io` | 9 | OP-S25 9 | HaGeZi's Ultimate Blocklist | `||sentry.io^` |
| `api.crashguard.me` | 9 | OP-S25 9 | HaGeZi's Ultimate Blocklist | `||crashguard.me^` |
| `catch6.crashguard.me` | 9 | OP-S25 9 | HaGeZi's Ultimate Blocklist | `||crashguard.me^` |
| `catch.crashguard.me` | 9 | OP-S25 9 | HaGeZi's Ultimate Blocklist | `||crashguard.me^` |
| `firebaselogging-pa.googleapis.com` | 9 | OP-S25 9 | - | `||firebaselogging-pa.googleapis.com^` |
| `eu-teams.events.data.microsoft.com` | 9 | OP-S25 9 | HaGeZi's Windows/Office Tracker Blocklist | `||events.data.microsoft.com^` |
| `sams.spiegel.de` | 8 | OP-S25 8 | HaGeZi's Ultimate Blocklist | `||sams.spiegel.de^` |
| `aax-eu.amazon.de` | 8 | OP-S25 8 | HaGeZi's Ultimate Blocklist | `||aax-eu.amazon.de^` |

#### D8 Je Client die meistgeblockten Namen (Top 5)
| Client | Blocks | Namen |
|---|---|---|
| 192.168.20.189 (OP-S25) | 1303 | `mobile.pipe.aria.microsoft.com` ×342<br>`a-api.anthropic.com` ×264<br>`usage-ping.brave.com` ×182<br>`go-updater.brave.com` ×84<br>`unagi.amazon.de` ×43 |
| 192.168.60.245 (homeassistant) | 12 | `fonts.googleapis.com` ×4<br>`traffic.libsyn.com` ×4<br>`dl.espressif.com` ×2<br>`latenightlinux.com` ×2 |
| 192.168.20.238 (OP-T490) | 290 | `usage-ping.brave.com` ×160<br>`go-updater.brave.com` ×60<br>`star-randsrv.bsg.brave.com` ×34<br>`collector.bsg.brave.com` ×28<br>`ohttp.ads.brave.com` ×6 |
| 192.168.20.111 (OP-T41S) | 248 | `http-intake.logs.us5.datadoghq.com` ×159<br>`mobile.events.data.microsoft.com` ×67<br>`incoming.telemetry.mozilla.org` ×10<br>`merino.services.mozilla.com` ×9<br>`ads.mozilla.org` ×3 |
| 192.168.10.11 (Sonoff-Panel) | 4 | `api.crowdin.com` ×2<br>`distributions.crowdin.net` ×2 |

#### D9 Default-Deny-Zonen (`smarthome`, `smarthome_srv`): erlaubte Namen je Gerät (vollständig)
| Gerät | Anfragen | erlaubt | geblockt | erlaubte Namen | erlaubt (Name × Anfragen) | geblockt (Top 8) |
|---|---|---|---|---|---|---|
| 192.168.60.245 (homeassistant) | 1514 | 1502 | 12 | 24 | `api.tailscale.com` ×1196<br>`checkonline.home-assistant.io` ×144<br>`github.com` ×34<br>`` ×22<br>`aa015h6buqvih86i1.api.met.no` ×20<br>`raw.githubusercontent.com` ×14<br>`api.powercalc.nl` ×10<br>`alerts.home-assistant.io` ×8<br>`cdn-images.dzcdn.net` ×8<br>`pipe.deezer.com` ×7<br>`ghcr.io` ×6<br>`pkg-containers.githubusercontent.com` ×4<br>`pypi.org` ×4<br>`data-v2.hacs.xyz` ×4<br>`auth.deezer.com` ×4<br>`de1.api.radio-browser.info` ×2<br>`wheels.home-assistant.io` ×2<br>`files.pythonhosted.org` ×2<br>`openrouter.ai` ×2<br>`release-assets.githubusercontent.com` ×2<br>`zigbee-ota.sonoff.tech` ×2<br>`identitytoolkit.googleapis.com` ×2<br>`api.ardaudiothek.de` ×2<br>`_api._tcp.radio-browser.info` ×1 | `fonts.googleapis.com` ×4<br>`traffic.libsyn.com` ×4<br>`dl.espressif.com` ×2<br>`latenightlinux.com` ×2 |
| 192.168.10.11 (Sonoff-Panel) | 52 | 48 | 4 | 1 | `hub.home.arpa` ×48 | `api.crowdin.com` ×2<br>`distributions.crowdin.net` ×2 |
| 192.168.10.20 (Voice-Assistant-WoZi) | 2 | 2 | 0 | 1 | `firmware.esphome.io` ×2 |  |
| 192.168.10.23 (Voice-Assistant-Kitchen) | 1 | 1 | 0 | 1 | `firmware.esphome.io` ×1 |  |
| 192.168.10.22 (Voice-Assistant-Kids) | 1 | 1 | 0 | 1 | `firmware.esphome.io` ×1 |  |
| 192.168.10.10 (Nuki-Bridge) | 1 | 1 | 0 | 1 | `sse8-bridge.nuki.io` ×1 |  |

#### D10 Verschlüsseltes DNS umgehen: Anfragen nach DoH/DoT-Endpunkten und Canaries
| Client | Zone | Name | Ergebnis | Anfragen |
|---|---|---|---|---|
| 192.168.20.189 (OP-S25) | private | `cloudflare-dns.com` | geblockt | 1 |

gesamt 1 Anfragen von 1 Clients; erlaubt: 0

#### D11 Anfragetypen
| Typ | Anfragen | Anteil |
|---|---|---|
| A | 4225 | 70.6 % |
| AAAA | 1032 | 17.2 % |
| HTTPS | 680 | 11.4 % |
| NS | 24 | 0.4 % |
| SRV | 12 | 0.2 % |
| PTR | 4 | 0.1 % |
| HINFO | 2 | 0.0 % |
| SOA | 2 | 0.0 % |
| CNAME | 2 | 0.0 % |
| TYPE11 | 2 | 0.0 % |

**Ungewöhnliche Typen je Client** (ANY, AXFR, CNAME, HINFO, IXFR, MX, NS, NULL, SOA, SRV, TXT):

| Client | Typ | Domain | Anfragen |
|---|---|---|---|
| 192.168.60.245 (homeassistant) | NS | `` | 22 |
| 192.168.20.111 (OP-T41S) | SRV | `ubuntu.com` | 3 |
| 192.168.20.189 (OP-S25) | SRV | `firma-intern.tld` | 3 |
| 192.168.20.189 (OP-S25) | NS | `google.com` | 2 |
| 192.168.20.189 (OP-S25) | HINFO | `google.com` | 2 |
| 192.168.20.189 (OP-S25) | SOA | `google.com` | 2 |
| 192.168.20.189 (OP-S25) | CNAME | `google.com` | 2 |
| 192.168.60.245 (homeassistant) | SRV | `radio-browser.info` | 1 |
| 192.168.20.111 (OP-T41S) | SRV | `mozilla.org` | 1 |
| 192.168.20.111 (OP-T41S) | SRV | `signal.org` | 1 |
| 192.168.20.111 (OP-T41S) | SRV | `docker.com` | 1 |
| 192.168.20.111 (OP-T41S) | SRV | `launchpadcontent.net` | 1 |
| 192.168.20.111 (OP-T41S) | SRV | `1password.com` | 1 |

#### D12 NXDOMAIN und SERVFAIL
| Client | Name | NXDOMAIN |
|---|---|---|
| 192.168.20.189 (OP-S25) | `hub-home-arpa.<REMOVED>.ts.net.home.arpa` | 11 |
| 192.168.20.189 (OP-S25) | `216.58.202.4.in-addr.arpa` | 4 |
| 192.168.20.189 (OP-S25) | `*google.com` | 2 |
| 192.168.20.189 (OP-S25) | `google.com.onion` | 2 |
| 192.168.30.1 (Router (management)) | `gibtsnicht.home.arpa` | 2 |
| 192.168.30.1 (Router (management)) | `teams.cloud.microsoft.com.home.arpa` | 2 |
| 192.168.20.189 (OP-S25) | `appassets.androidplatform.net.home.arpa` | 2 |
| 192.168.20.189 (OP-S25) | `cdn-images.dzcdn.net.home.arpa` | 2 |
| 192.168.20.111 (OP-T41S) | `_http._tcp.de.archive.ubuntu.com` | 1 |
| 192.168.20.111 (OP-T41S) | `_http._tcp.security.ubuntu.com` | 1 |
| 192.168.20.111 (OP-T41S) | `_https._tcp.esm.ubuntu.com` | 1 |
| 192.168.20.111 (OP-T41S) | `_https._tcp.packages.mozilla.org` | 1 |
| 192.168.20.111 (OP-T41S) | `_https._tcp.download.docker.com` | 1 |
| 192.168.20.111 (OP-T41S) | `_https._tcp.ppa.launchpadcontent.net` | 1 |
| 192.168.20.111 (OP-T41S) | `_https._tcp.downloads.1password.com` | 1 |

**SERVFAIL / Upstream-Fehler** (0 gesamt):

| Client | Name | Upstream | Anfragen |
|---|---|---|---|

#### D13 Tunnel-Heuristik: viele verschiedene Subdomains je Domain, lange Namen
| Client | Domain | verschiedene Namen | längster Name | Ergebnis |
|---|---|---|---|---|
| 192.168.20.189 (OP-S25) | `googleapis.com` | 46 | 49 | erlaubt |
| 192.168.20.189 (OP-S25) | `gvt1.com` | 29 | 27 | erlaubt |
| 192.168.20.189 (OP-S25) | `microsoft.com` | 22 | 45 | erlaubt |

**Längste Namen:** `www.goooooooooooooooooooooooooooooooooooooooooooooooooooooooooogle.com` (70, OP-S25); `<UUID>.frame.claudeusercontent.com` (64, OP-S25); `aax-events-cell02-cf.eu-central.3px.axp.amazon-adsystem.com` (59, OP-S25); `redirect.prod.experiment.routing.cloudfront.aws.a2z.com` (55, OP-S25); `ohttp-relay-safebrowsing-android.google.fastly-edge.com` (55, OP-S25); `prod-lt-playstoregatewayadapter-pa.googleapis.com` (49, OP-S25); `pub-ent-frce-12-t.trouter.teams.microsoft.com` (45, OP-S25); `locationhistoryplacedetails-pa.googleapis.com` (45, OP-S25)

#### D14 Clients ohne Reservierung oder außerhalb der Zonen-Netze, Router-eigene Anfragen
| Client | Zone | Anfragen | häufigste Namen |
|---|---|---|---|
| 192.168.30.1 (Router (management)) | Router (management) | 12 | `switch.home.arpa`, `adguard.home.arpa`, `hub.home.arpa`, `openwrt.home.arpa` |

#### D15 Rate-Limit-Sättigung: Sekunden mit ≥ `ratelimit` Anfragen je /24 (Dunkelziffer: verworfene Anfragen stehen nicht im Log)
| /24 | Zone | max Anfragen/s | Sekunden ≥ Limit | schlimmste Sekunde | betroffene Minuten |
|---|---|---|---|---|---|
| 192.168.20.0/24 | private | 20 | 2 | 25.10. 07:20:51 | 2 |
| 192.168.10.0/24 | smarthome | 2 | 0 | - | 0 |
| 192.168.60.0/24 | smarthome_srv | 16 | 0 | - | 0 |
| 192.168.30.0/24 | Router (management) | 12 | 0 | - | 0 |

#### D16 Upstream und Cache
| Größe | Wert |
|---|---|
| Upstream-Antworten (nicht Cache, nicht geblockt) | 3446 |
| Upstreams | tls://<NEXTDNS-ID>.dns.nextdns.io:853 3250, - 196 |
| Latenz p50 / p90 / p99 (ms) | 46 / 83 / 306 |
| Antworten > 1 s | 4 |
| Cache-Trefferquote (nicht geblockt) | 16.5 % |

#### D17 Meistangefragte erlaubte Namen
| Name | Anfragen | Clients |
|---|---|---|
| `api.tailscale.com` | 1196 | homeassistant 1196 |
| `www.google.com` | 333 | OP-S25 321, OP-T490 11, OP-T41S 1 |
| `api.anthropic.com` | 207 | OP-T490 160, OP-T41S 47 |
| `hub.home.arpa` | 150 | OP-S25 98, Sonoff-Panel 48, OP-T41S 2 |
| `checkonline.home-assistant.io` | 144 | homeassistant 144 |
| `m.youtube.com` | 142 | OP-S25 142 |
| `github.com` | 70 | homeassistant 34, OP-T490 22, OP-T41S 12 |
| `claude.ai` | 62 | OP-T490 45, OP-S25 16, OP-T41S 1 |
| `m.media-amazon.com` | 60 | OP-S25 60 |
| `www.<REMOVED>.tld` | 55 | OP-S25 55 |
| `vpn-api.proton.me` | 54 | OP-T490 54 |
| `discovery-announce-v6.syncthing.net` | 51 | OP-T41S 51 |
| `play.googleapis.com` | 48 | OP-S25 48 |
| `i.ytimg.com` | 43 | OP-S25 43 |
| `drive-api.proton.me` | 41 | OP-S25 41 |
| `alive.github.com` | 38 | OP-T490 38 |
| `variations.brave.com` | 37 | OP-T490 28, OP-S25 9 |
| `data.amazon.de` | 34 | OP-S25 34 |
| `google.com` | 28 | OP-S25 28 |
| `www.gstatic.com` | 28 | OP-S25 21, OP-T490 7 |
| `stun.syncthing.net` | 26 | OP-T41S 26 |
| `safebrowsing.brave.com` | 26 | OP-T490 26 |
| `images-eu.ssl-images-amazon.com` | 25 | OP-S25 25 |
| `live.github.com` | 23 | OP-T490 23 |
| `` | 22 | homeassistant 22 |
| `aa015h6buqvih86i1.api.met.no` | 20 | homeassistant 20 |
| `outlook.office365.com` | 19 | OP-S25 19 |
| `www.amazon.de` | 19 | OP-S25 19 |
| `calendar-api.proton.me` | 17 | OP-S25 17 |
| `yt3.ggpht.com` | 16 | OP-S25 16 |

#### D18 Nur am letzten Tag gesehene Namen (≥ 3 Anfragen, je Client)
(Fenster umfasst nur einen Tag)

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
