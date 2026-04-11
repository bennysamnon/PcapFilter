# PcapFilter — TODO / Progress Log

## What we built so far

- [x] C# ASP.NET Core web app (dual mode: CLI + web server on port 5000)
- [x] SharpPcap + PacketDotNet for PCAP parsing
- [x] Filter packets by: src/dst IP, src/dst port, protocol (TCP/UDP/ICMP)
- [x] Packet statistics: total/matched packets, bytes, avg/min/max size
- [x] Protocol distribution: TCP, UDP, DNS, HTTP, TLS (port-based + payload detection)
- [x] Top talkers: (src_ip, dst_ip, packet_count, bytes) sorted by volume
- [x] Structured CaptureSummary: total_packets, total_bytes, time_range, top_talkers, protocol_distribution
- [x] Auto-generated human-readable analyst narrative (IR-focused)
- [x] Geolocation via ip-api.com (country, city, ASN, org) — free, no API key
- [x] Leaflet.js network map: markers per public IP, flow lines weighted by traffic volume
- [x] Country flag emojis in map popups, talker table, and IP tables
- [x] 500 MB request body limit
- [x] DNS analysis — domain extraction + Shannon entropy DGA scoring (vowel ratio, digit ratio)
- [x] HTTP visibility — method, host, URI, user-agent extraction + top hosts/UAs table
- [x] Beaconing detection — interval regularity (coefficient of variation < 30%)
- [x] Port scan detection — src IP contacting 15+ unique ports flagged
- [x] Suspicious indicators — large transfers, HTTP POST to external, cleartext HTTP, bad UAs, DGA, beacons, scans
- [x] Network conversations — full 5-tuple (src_ip:port → dst_ip:port + proto) with duration, top 50 by volume
- [x] Event timeline — DNS queries, HTTP requests, sensitive ports, beacons, scans; sorted by time, capped at 300
- [x] 14-section IR dashboard in the web UI

- [x] TLS SNI + version detection — ClientHello parser extracts SNI (extension 0x0000) and TLS version (including 0x002B supported_versions for TLS 1.3); flags SSL 3.0 / TLS 1.0 / TLS 1.1
- [x] Credential leakage detection — HTTP Basic Auth (decoded base64 user:pass), Bearer tokens, HTTP POST with password fields, FTP USER/PASS commands
- [x] App/service detection — DNS domain + SNI + HTTP Host matched against 33 app signatures (Zoom, Teams, Slack, Discord, WhatsApp, Dropbox, OneDrive, Netflix, Spotify, GitHub, AWS, Azure, Tor, Pastebin, …)
- [x] IOC export (JSON + CSV) — external IPs, domains, HTTP URLs, suspicious IPs, suspicious domains; client-side download buttons

## Possible next steps

- [ ] ICMP analysis — type/code breakdown, detect ping sweeps
- [ ] Live capture mode (instead of file upload)
- [ ] Threat intel lookup — check IPs/domains against known blocklists (e.g. AbuseIPDB, VirusTotal)
- [ ] TLS certificate analysis — extract and inspect X.509 cert fields from Server Hello
