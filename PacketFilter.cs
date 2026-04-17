using System.Text;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace PcapFilter;

public static class PacketFilter
{
    private static readonly HashSet<int> HttpPorts      = new() { 80, 8080, 8000, 8888 };
    private static readonly HashSet<int> TlsPorts       = new() { 443, 8443, 465, 993, 995 };
    private static readonly HashSet<int> SensitivePorts = new() { 22, 23, 3389, 445, 135, 139, 5985, 5986 };
    private const int DnsPort = 53;

    // Known malicious / suspicious user-agent substrings
    private static readonly string[] BadUaTokens =
        { "python-requests", "go-http-client", "curl/", "wget/", "powershell", "nmap", "masscan", "zgrab", "sqlmap" };

    // Known app domain signatures  (suffix match)
    private static readonly Dictionary<string, (string name, string category)> AppSignatures =
        new(StringComparer.OrdinalIgnoreCase)
    {
        ["zoom.us"]                = ("Zoom",           "Video Conferencing"),
        ["zoomgov.com"]            = ("Zoom",           "Video Conferencing"),
        ["teams.microsoft.com"]    = ("Teams",          "Video Conferencing"),
        ["slack.com"]              = ("Slack",          "Messaging"),
        ["slack-edge.com"]         = ("Slack",          "Messaging"),
        ["whatsapp.com"]           = ("WhatsApp",       "Messaging"),
        ["whatsapp.net"]           = ("WhatsApp",       "Messaging"),
        ["discord.com"]            = ("Discord",        "Messaging"),
        ["discordapp.com"]         = ("Discord",        "Messaging"),
        ["dropbox.com"]            = ("Dropbox",        "Cloud Storage"),
        ["dropboxapi.com"]         = ("Dropbox",        "Cloud Storage"),
        ["onedrive.live.com"]      = ("OneDrive",       "Cloud Storage"),
        ["sharepoint.com"]         = ("SharePoint",     "Cloud Storage"),
        ["drive.google.com"]       = ("Google Drive",   "Cloud Storage"),
        ["googleapis.com"]         = ("Google",         "Cloud Services"),
        ["youtube.com"]            = ("YouTube",        "Streaming"),
        ["googlevideo.com"]        = ("YouTube",        "Streaming"),
        ["netflix.com"]            = ("Netflix",        "Streaming"),
        ["nflxvideo.net"]          = ("Netflix",        "Streaming"),
        ["spotify.com"]            = ("Spotify",        "Streaming"),
        ["scdn.co"]                = ("Spotify",        "Streaming"),
        ["github.com"]             = ("GitHub",         "Development"),
        ["githubusercontent.com"]  = ("GitHub",         "Development"),
        ["amazonaws.com"]          = ("AWS",            "Cloud Infrastructure"),
        ["azure.com"]              = ("Azure",          "Cloud Infrastructure"),
        ["office.com"]             = ("Office 365",     "Productivity"),
        ["outlook.com"]            = ("Outlook",        "Productivity"),
        ["live.com"]               = ("Microsoft",      "Productivity"),
        ["torproject.org"]         = ("Tor",            "Anonymization"),
        ["tor2web.org"]            = ("Tor",            "Anonymization"),
        ["pastebin.com"]           = ("Pastebin",       "Data Sharing"),
        ["mega.nz"]                = ("Mega",           "Cloud Storage"),
        ["telegram.org"]           = ("Telegram",       "Messaging"),
    };

    // ── Main entry ────────────────────────────────────────────────────────────

    public static AnalysisResult Analyze(string inputPath, FilterOptions options)
    {
        using var reader = new CaptureFileReaderDevice(inputPath);
        reader.Open();

        var stats   = new PacketStats();
        var summary = new CaptureSummary();
        var pd      = summary.ProtocolDistribution;

        // existing accumulators
        var srcIps   = new Dictionary<string, int>();
        var dstIps   = new Dictionary<string, int>();
        var dstPorts = new Dictionary<string, int>();
        var flows    = new Dictionary<(string src, string dst), (int count, long bytes)>();

        // new accumulators
        var dnsQueries     = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var httpEntries    = new List<HttpEntry>();
        var connTimestamps = new Dictionary<(string, string), List<DateTime>>();
        var portMap        = new Dictionary<(string src, string dst), HashSet<int>>();
        var convMap        = new Dictionary<(string src, int sp, string dst, int dp, string proto),
                                           (int pkts, long bytes, DateTime first, DateTime last)>();
        var timelineRaw    = new List<TimelineEvent>();

        // feature accumulators
        var tlsInsightRaw = new List<TlsInsight>();
        var credLeaks     = new List<CredentialLeak>();
        var appHits       = new Dictionary<string, AppDetection>(StringComparer.OrdinalIgnoreCase);
        var seenTlsPairs  = new HashSet<(string src, string dst, string sni)>();

        DateTime? firstTs = null, lastTs = null;

        while (reader.GetNextPacket(out var capture) == GetPacketStatus.PacketRead)
        {
            stats.TotalPackets++;

            var raw    = capture.GetPacket();
            var ts     = raw.Timeval.Date;
            if (firstTs is null || ts < firstTs) firstTs = ts;
            if (lastTs  is null || ts > lastTs)  lastTs  = ts;

            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            if (!Matches(packet, options)) continue;

            // ── matched ───────────────────────────────────────────────────────
            stats.MatchedPackets++;
            summary.TotalPackets++;

            int  size = raw.Data.Length;
            stats.TotalBytes   += size;
            summary.TotalBytes += size;
            if (size < stats.MinPacketSize) stats.MinPacketSize = size;
            if (size > stats.MaxPacketSize) stats.MaxPacketSize = size;

            // extract layers upfront
            var ip   = packet.Extract<IPPacket>();
            var tcp  = packet.Extract<TcpPacket>();
            var udp  = packet.Extract<UdpPacket>();
            var icmp = (Packet?)packet.Extract<IcmpV4Packet>() ?? packet.Extract<IcmpV6Packet>();

            string srcIp = ip?.SourceAddress.ToString()      ?? "";
            string dstIp = ip?.DestinationAddress.ToString() ?? "";
            int    sport = tcp?.SourcePort      ?? udp?.SourcePort      ?? 0;
            int    dport = tcp?.DestinationPort ?? udp?.DestinationPort ?? 0;

            // ── IP-level tracking ─────────────────────────────────────────────
            if (ip is not null)
            {
                srcIps[srcIp] = srcIps.GetValueOrDefault(srcIp) + 1;
                dstIps[dstIp] = dstIps.GetValueOrDefault(dstIp) + 1;

                var flowKey = (srcIp, dstIp);
                var (fc, fb) = flows.GetValueOrDefault(flowKey);
                flows[flowKey] = (fc + 1, fb + size);

                // beaconing timestamps (cap per pair to save memory)
                if (!connTimestamps.TryGetValue(flowKey, out var tsList))
                    connTimestamps[flowKey] = tsList = new List<DateTime>();
                if (tsList.Count < 2000) tsList.Add(ts);
            }

            // ── protocol classification ───────────────────────────────────────
            if (tcp is not null)
            {
                stats.Protocols["TCP"] = stats.Protocols.GetValueOrDefault("TCP") + 1;
                pd.Tcp++;
                dstPorts[dport.ToString()] = dstPorts.GetValueOrDefault(dport.ToString()) + 1;

                if (HttpPorts.Contains(dport) || HttpPorts.Contains(sport) || IsHttpPayload(tcp))
                {
                    pd.Http++;
                    stats.Protocols["HTTP"] = stats.Protocols.GetValueOrDefault("HTTP") + 1;

                    // HTTP header extraction
                    if (httpEntries.Count < 500)
                    {
                        var entry = ParseHttpHeaders(tcp, srcIp, dstIp);
                        if (entry is not null)
                        {
                            httpEntries.Add(entry);
                            if (!string.IsNullOrEmpty(entry.Host))
                                CheckAppSignature(entry.Host, appHits);
                            if (IsSuspiciousUserAgent(entry.UserAgent) && timelineRaw.Count < 2000)
                                timelineRaw.Add(new TimelineEvent
                                {
                                    Timestamp   = ts,
                                    Type        = "SUSPICIOUS_UA",
                                    Severity    = "WARNING",
                                    SourceIp    = srcIp,
                                    DestIp      = dstIp,
                                    Description = $"Suspicious User-Agent: {entry.UserAgent.Truncate(80)} → {entry.Host}{entry.Uri.Truncate(60)}"
                                });
                        }
                    }

                    // HTTP credential detection (cleartext only)
                    if (credLeaks.Count < 200)
                        TryExtractHttpCredentials(tcp, srcIp, dstIp, dport, credLeaks, ts, timelineRaw);
                }
                else if (TlsPorts.Contains(dport) || TlsPorts.Contains(sport) || IsTlsPayload(tcp))
                {
                    pd.Tls++;
                    stats.Protocols["TLS"] = stats.Protocols.GetValueOrDefault("TLS") + 1;

                    // TLS ClientHello parsing (SNI + version)
                    if (tlsInsightRaw.Count < 1000)
                    {
                        var tls = TryParseTlsClientHello(tcp.PayloadData, srcIp, dstIp, dport);
                        if (tls is not null)
                        {
                            var key = (srcIp, dstIp, tls.Sni);
                            if (seenTlsPairs.Add(key))
                            {
                                tlsInsightRaw.Add(tls);
                                if (!string.IsNullOrEmpty(tls.Sni))
                                    CheckAppSignature(tls.Sni, appHits);
                                if (tls.IsOldVersion && timelineRaw.Count < 2000)
                                    timelineRaw.Add(new TimelineEvent
                                    {
                                        Timestamp   = ts,
                                        Type        = "OLD_TLS",
                                        Severity    = "WARNING",
                                        SourceIp    = srcIp,
                                        DestIp      = dstIp,
                                        Description = $"Deprecated {tls.TlsVersion} used" +
                                                      (string.IsNullOrEmpty(tls.Sni) ? "" : $" → {tls.Sni}")
                                    });
                            }
                        }
                    }
                }

                // FTP credential detection
                if ((dport == 21 || sport == 21) && credLeaks.Count < 200)
                    TryExtractFtpCredentials(tcp, srcIp, dstIp, credLeaks, ts, timelineRaw);

                // port map for scan detection
                if (ip is not null)
                {
                    var pKey = (srcIp, dstIp);
                    if (!portMap.TryGetValue(pKey, out var ports))
                        portMap[pKey] = ports = new HashSet<int>();
                    ports.Add(dport);
                }

                // sensitive port: internal → external
                if (ip is not null && SensitivePorts.Contains(dport)
                    && GeoResolver.IsPrivate(srcIp) && !GeoResolver.IsPrivate(dstIp)
                    && timelineRaw.Count < 2000)
                {
                    timelineRaw.Add(new TimelineEvent
                    {
                        Timestamp   = ts,
                        Type        = "SENSITIVE_PORT",
                        Severity    = "WARNING",
                        SourceIp    = srcIp,
                        DestIp      = dstIp,
                        Description = $"Internal host contacting external IP on {PortName(dport)} (port {dport})"
                    });
                }
            }
            else if (udp is not null)
            {
                stats.Protocols["UDP"] = stats.Protocols.GetValueOrDefault("UDP") + 1;
                pd.Udp++;
                dstPorts[dport.ToString()] = dstPorts.GetValueOrDefault(dport.ToString()) + 1;

                if (dport == DnsPort || sport == DnsPort)
                {
                    pd.Dns++;
                    stats.Protocols["DNS"] = stats.Protocols.GetValueOrDefault("DNS") + 1;

                    // DNS domain extraction
                    var domain = ParseDnsQuery(udp.PayloadData);
                    if (domain is not null)
                    {
                        CheckAppSignature(domain, appHits);
                        if (dnsQueries.Add(domain) && timelineRaw.Count < 2000)
                            timelineRaw.Add(new TimelineEvent
                            {
                                Timestamp   = ts,
                                Type        = "DNS",
                                Severity    = "INFO",
                                SourceIp    = srcIp,
                                DestIp      = dstIp,
                                Description = $"DNS query: {domain}"
                            });
                    }
                }
            }
            else if (icmp is not null)
            {
                stats.Protocols["ICMP"] = stats.Protocols.GetValueOrDefault("ICMP") + 1;
                pd.Other++;
            }
            else
            {
                stats.Protocols["Other"] = stats.Protocols.GetValueOrDefault("Other") + 1;
                pd.Other++;
            }

            // ── 5-tuple conversation tracking ─────────────────────────────────
            if (ip is not null)
            {
                string proto = tcp is not null ? "TCP" : udp is not null ? "UDP" : "Other";
                var cKey     = (srcIp, sport, dstIp, dport, proto);
                var (cp, cb, cf, cl) = convMap.GetValueOrDefault(cKey);
                convMap[cKey] = (cp + 1, cb + size, cf == default ? ts : cf, ts);
            }
        }

        // ── post-loop analysis ────────────────────────────────────────────────

        if (stats.MatchedPackets == 0) stats.MinPacketSize = 0;

        stats.TopSourceIps        = Top(srcIps,   10);
        stats.TopDestinationIps   = Top(dstIps,   10);
        stats.TopDestinationPorts = Top(dstPorts, 10);

        summary.TimeRange = new CaptureTimeRange
        {
            StartTime = firstTs,
            EndTime   = lastTs,
            Duration  = (firstTs.HasValue && lastTs.HasValue)
                        ? FormatDuration(lastTs.Value - firstTs.Value) : null
        };

        summary.TopTalkers = flows
            .OrderByDescending(kv => kv.Value.bytes).Take(10)
            .Select(kv => new TalkerEntry
            {
                SourceIp      = kv.Key.src,
                DestinationIp = kv.Key.dst,
                PacketCount   = kv.Value.count,
                Bytes         = kv.Value.bytes
            }).ToList();

        // DNS
        summary.DnsAnalysis = BuildDnsAnalysis(dnsQueries);

        // HTTP
        summary.HttpAnalysis = BuildHttpAnalysis(httpEntries);

        // Beaconing
        summary.BeaconCandidates = DetectBeacons(connTimestamps);

        // Port scans
        summary.PortScans = DetectPortScans(portMap);

        // 5-tuple conversations (top 50 by bytes)
        summary.Conversations = convMap
            .OrderByDescending(kv => kv.Value.bytes).Take(50)
            .Select(kv => new ConversationEntry
            {
                SourceIp        = kv.Key.Item1,
                SourcePort      = kv.Key.Item2,
                DestinationIp   = kv.Key.Item3,
                DestinationPort = kv.Key.Item4,
                Protocol        = kv.Key.Item5,
                PacketCount     = kv.Value.pkts,
                Bytes           = kv.Value.bytes,
                StartTime       = kv.Value.first,
                DurationSeconds = kv.Value.last == kv.Value.first
                                  ? 0 : (kv.Value.last - kv.Value.first).TotalSeconds
            }).ToList();

        // TLS insights
        summary.TlsInsights = tlsInsightRaw.Take(500).ToList();
        summary.TlsVersions = tlsInsightRaw
            .GroupBy(t => t.TlsVersion)
            .ToDictionary(g => g.Key, g => g.Count());

        // Credential leaks (deduplicated)
        summary.CredentialLeaks = credLeaks
            .DistinctBy(c => (c.Type, c.SourceIp, c.DestIp, c.Username))
            .Take(100).ToList();

        // Detected apps
        summary.DetectedApps = appHits.Values
            .OrderByDescending(a => a.HitCount)
            .ToList();

        // Suspicious indicators
        summary.Indicators = BuildIndicators(summary, flows, httpEntries);

        // Add post-loop events to timeline
        foreach (var b in summary.BeaconCandidates)
            timelineRaw.Add(new TimelineEvent
            {
                Timestamp   = firstTs ?? DateTime.UtcNow,
                Type        = "BEACON",
                Severity    = "ALERT",
                SourceIp    = b.SourceIp,
                DestIp      = b.DestinationIp,
                Description = $"{b.Confidence}: {b.ConnectionCount} connections, avg interval {b.AvgIntervalSeconds}s, jitter {b.JitterPct}%"
            });

        foreach (var s in summary.PortScans)
            timelineRaw.Add(new TimelineEvent
            {
                Timestamp   = firstTs ?? DateTime.UtcNow,
                Type        = "PORT_SCAN",
                Severity    = "ALERT",
                SourceIp    = s.SourceIp,
                DestIp      = s.TopTargetIp,
                Description = $"Port scan: {s.UniquePortsContacted} unique ports contacted (sample: {string.Join(", ", s.SampledPorts.Take(5))}…)"
            });

        // Timeline: sort by time, ALERTs first within same second, cap at 300 for UI
        summary.Timeline = timelineRaw
            .OrderBy(e => e.Timestamp)
            .ThenBy(e => e.Severity switch { "ALERT" => 0, "WARNING" => 1, _ => 2 })
            .Take(300)
            .ToList();

        // IOC bundle (after all sections built)
        summary.Iocs = BuildIocBundle(summary, flows);

        summary.HumanReadableSummary = GenerateNarrative(summary, stats);

        return new AnalysisResult { Stats = stats, Summary = summary };
    }

    // ── DNS parsing ───────────────────────────────────────────────────────────

    private static string? ParseDnsQuery(byte[]? payload)
    {
        if (payload is null || payload.Length < 13) return null;

        // QR bit (bit 15 of flags word) = 0 means query, 1 means response
        // We parse both since responses echo the question section
        bool isResponse = (payload[2] & 0x80) != 0;

        // QDCOUNT must be >= 1
        int qdCount = (payload[4] << 8) | payload[5];
        if (qdCount == 0) return null;

        // Question section starts at byte 12
        return ParseDnsName(payload, 12);
    }

    private static string? ParseDnsName(byte[] data, int offset)
    {
        var labels  = new List<string>();
        int pos     = offset;
        int safety  = 0;

        while (pos < data.Length && safety++ < 128)
        {
            byte len = data[pos];
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) break; // compression pointer — stop
            pos++;
            if (pos + len > data.Length) return null;
            labels.Add(Encoding.ASCII.GetString(data, pos, len));
            pos += len;
        }

        if (labels.Count == 0) return null;
        var domain = string.Join(".", labels);
        // Sanity: skip obviously broken names
        return domain.Length > 253 || domain.Contains('\0') ? null : domain;
    }

    // ── DGA detection ─────────────────────────────────────────────────────────

    private static DnsAnalysis BuildDnsAnalysis(HashSet<string> queries)
    {
        var domains    = queries.OrderBy(d => d).ToList();
        var candidates = new List<DgaCandidate>();

        foreach (var domain in domains)
        {
            var parts = domain.Split('.');
            if (parts.Length < 2) continue;
            string sld = parts[^2]; // second-level domain
            if (sld.Length < 6) continue;

            double entropy    = ShannonEntropy(sld);
            double vowelRatio = (double)sld.Count(c => "aeiouAEIOU".Contains(c)) / sld.Length;
            double digitRatio = (double)sld.Count(char.IsDigit) / sld.Length;

            var reasons = new List<string>();
            if (entropy   > 3.5) reasons.Add($"high entropy ({entropy:F1})");
            if (vowelRatio < 0.15) reasons.Add($"low vowel ratio ({vowelRatio:P0})");
            if (digitRatio > 0.35) reasons.Add($"numeric-heavy ({digitRatio:P0} digits)");

            if (reasons.Count > 0)
                candidates.Add(new DgaCandidate
                {
                    Domain       = domain,
                    EntropyScore = Math.Round(entropy, 2),
                    Reason       = string.Join("; ", reasons)
                });
        }

        return new DnsAnalysis
        {
            UniqueCount    = domains.Count,
            QueriedDomains = domains.Take(200).ToList(),
            DgaCandidates  = candidates.OrderByDescending(c => c.EntropyScore).Take(50).ToList()
        };
    }

    private static double ShannonEntropy(string s)
    {
        if (s.Length == 0) return 0;
        return -s.GroupBy(c => c)
                 .Select(g => (double)g.Count() / s.Length)
                 .Sum(p => p * Math.Log2(p));
    }

    // ── HTTP parsing ──────────────────────────────────────────────────────────

    private static HttpEntry? ParseHttpHeaders(TcpPacket tcp, string srcIp, string dstIp)
    {
        var payload = tcp.PayloadData;
        if (payload is null || payload.Length < 10) return null;

        string text = Encoding.Latin1.GetString(payload, 0, Math.Min(4096, payload.Length));
        var lines   = text.Split('\n');
        if (lines.Length == 0) return null;

        var requestLine = lines[0].TrimEnd('\r');
        var parts       = requestLine.Split(' ');
        if (parts.Length < 2) return null;

        string method = parts[0];
        // Only parse requests (not responses)
        if (method is "HTTP/1.0" or "HTTP/1.1" or "HTTP/2") return null;

        string uri = parts.Length > 1 ? parts[1] : "";
        string host = "", userAgent = "";

        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            if (string.IsNullOrEmpty(line)) break;

            if (line.StartsWith("Host:",       StringComparison.OrdinalIgnoreCase))
                host      = line[5..].Trim();
            else if (line.StartsWith("User-Agent:", StringComparison.OrdinalIgnoreCase))
                userAgent = line[11..].Trim();
        }

        return new HttpEntry
        {
            Method    = method,
            Uri       = uri.Truncate(200),
            Host      = host.Truncate(100),
            UserAgent = userAgent.Truncate(200),
            SourceIp  = srcIp,
            DestIp    = dstIp
        };
    }

    private static HttpAnalysis BuildHttpAnalysis(List<HttpEntry> entries)
    {
        var hosts = entries
            .Where(e => !string.IsNullOrEmpty(e.Host))
            .GroupBy(e => e.Host)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .ToDictionary(g => g.Key, g => g.Count());

        var uas = entries
            .Where(e => !string.IsNullOrEmpty(e.UserAgent))
            .GroupBy(e => e.UserAgent)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .ToDictionary(g => g.Key, g => g.Count());

        return new HttpAnalysis
        {
            Requests      = entries.Take(200).ToList(),
            TopHosts      = hosts,
            TopUserAgents = uas
        };
    }

    private static bool IsSuspiciousUserAgent(string ua)
    {
        if (string.IsNullOrWhiteSpace(ua)) return true; // empty UA is suspicious
        var lower = ua.ToLower();
        return BadUaTokens.Any(t => lower.Contains(t));
    }

    // ── Beaconing detection ───────────────────────────────────────────────────

    private static List<BeaconCandidate> DetectBeacons(
        Dictionary<(string src, string dst), List<DateTime>> timestamps)
    {
        var results = new List<BeaconCandidate>();

        foreach (var (pair, times) in timestamps)
        {
            if (times.Count < 5) continue;
            times.Sort();

            var intervals = new List<double>();
            for (int i = 1; i < times.Count; i++)
                intervals.Add((times[i] - times[i - 1]).TotalSeconds);

            double mean = intervals.Average();
            if (mean < 1.0) continue; // sub-second = traffic, not beaconing

            double variance = intervals.Select(x => Math.Pow(x - mean, 2)).Average();
            double stddev   = Math.Sqrt(variance);
            double cv       = mean > 0 ? stddev / mean : 1.0; // coefficient of variation

            if (cv < 0.3) // very regular timing
                results.Add(new BeaconCandidate
                {
                    SourceIp           = pair.src,
                    DestinationIp      = pair.dst,
                    ConnectionCount    = times.Count,
                    AvgIntervalSeconds = Math.Round(mean, 1),
                    JitterPct          = Math.Round(cv * 100, 1),
                    Confidence         = cv < 0.1 ? "HIGH" : "MEDIUM"
                });
        }

        return results.OrderBy(b => b.JitterPct).Take(20).ToList();
    }

    // ── Port scan detection ───────────────────────────────────────────────────

    private static List<PortScanAlert> DetectPortScans(
        Dictionary<(string src, string dst), HashSet<int>> portMap)
    {
        // Group by source IP, sum unique ports across all destinations
        var bySrc = portMap
            .GroupBy(kv => kv.Key.src)
            .Select(g => new
            {
                Src        = g.Key,
                TotalPorts = g.SelectMany(kv => kv.Value).Distinct().Count(),
                TopTarget  = g.OrderByDescending(kv => kv.Value.Count).First()
            })
            .Where(x => x.TotalPorts >= 15)
            .OrderByDescending(x => x.TotalPorts)
            .Take(10);

        return bySrc.Select(x => new PortScanAlert
        {
            SourceIp             = x.Src,
            UniquePortsContacted = x.TotalPorts,
            TopTargetIp          = x.TopTarget.Key.dst,
            SampledPorts         = x.TopTarget.Value.OrderBy(p => p).Take(20).ToList()
        }).ToList();
    }

    // ── Suspicious indicators ─────────────────────────────────────────────────

    private static List<SuspiciousIndicator> BuildIndicators(
        CaptureSummary summary,
        Dictionary<(string src, string dst), (int count, long bytes)> flows,
        List<HttpEntry> httpEntries)
    {
        var list = new List<SuspiciousIndicator>();

        // Large outbound transfers (>5 MB) to external IPs
        foreach (var (pair, (_, bytes)) in flows)
        {
            if (bytes < 5 * 1_048_576) continue;
            if (!GeoResolver.IsPrivate(pair.src) || GeoResolver.IsPrivate(pair.dst)) continue;
            list.Add(new SuspiciousIndicator
            {
                Severity    = "HIGH",
                Type        = "LARGE_TRANSFER",
                SourceIp    = pair.src,
                DestIp      = pair.dst,
                Description = $"Large outbound transfer: {FormatBytes(bytes)} from internal host to external IP"
            });
        }

        // HTTP POST to external (potential exfiltration)
        foreach (var req in httpEntries.Where(r => r.Method == "POST" && !GeoResolver.IsPrivate(r.DestIp)))
            list.Add(new SuspiciousIndicator
            {
                Severity    = "MEDIUM",
                Type        = "HTTP_POST_EXTERNAL",
                SourceIp    = req.SourceIp,
                DestIp      = req.DestIp,
                Description = $"HTTP POST to external host: {req.Host}{req.Uri.Truncate(80)}"
            });

        // Cleartext HTTP
        if (summary.ProtocolDistribution.Http > 0)
            list.Add(new SuspiciousIndicator
            {
                Severity    = "MEDIUM",
                Type        = "CLEARTEXT_HTTP",
                Description = $"Unencrypted HTTP traffic detected ({summary.ProtocolDistribution.Http:N0} packets). Credentials and data exposed in plaintext."
            });

        // Suspicious user agents
        foreach (var req in httpEntries.Where(r => IsSuspiciousUserAgent(r.UserAgent)).DistinctBy(r => r.UserAgent))
            list.Add(new SuspiciousIndicator
            {
                Severity    = "MEDIUM",
                Type        = "SUSPICIOUS_UA",
                SourceIp    = req.SourceIp,
                DestIp      = req.DestIp,
                Description = $"Suspicious or scripted User-Agent: \"{req.UserAgent.Truncate(80)}\""
            });

        // DNS over non-standard port (DNS tunneling hint)
        if (summary.DnsAnalysis.DgaCandidates.Count > 0)
            list.Add(new SuspiciousIndicator
            {
                Severity    = "HIGH",
                Type        = "DGA_DOMAINS",
                Description = $"{summary.DnsAnalysis.DgaCandidates.Count} potential DGA domain(s) detected. May indicate C2 communication or malware activity."
            });

        // Beaconing
        foreach (var b in summary.BeaconCandidates.Where(b => b.Confidence == "HIGH"))
            list.Add(new SuspiciousIndicator
            {
                Severity    = "HIGH",
                Type        = "BEACONING",
                SourceIp    = b.SourceIp,
                DestIp      = b.DestinationIp,
                Description = $"High-confidence beacon: {b.ConnectionCount} connections at ~{b.AvgIntervalSeconds}s intervals (jitter {b.JitterPct}%)"
            });

        // Port scans
        foreach (var scan in summary.PortScans)
            list.Add(new SuspiciousIndicator
            {
                Severity    = "HIGH",
                Type        = "PORT_SCAN",
                SourceIp    = scan.SourceIp,
                DestIp      = scan.TopTargetIp,
                Description = $"Port scan: {scan.UniquePortsContacted} unique destination ports contacted"
            });

        // Credential leaks
        foreach (var leak in summary.CredentialLeaks)
            list.Add(new SuspiciousIndicator
            {
                Severity    = leak.Severity,
                Type        = leak.Type,
                SourceIp    = leak.SourceIp,
                DestIp      = leak.DestIp,
                Description = leak.Detail
            });

        // Old TLS versions
        var oldTls = summary.TlsInsights.Where(t => t.IsOldVersion).ToList();
        if (oldTls.Count > 0)
            list.Add(new SuspiciousIndicator
            {
                Severity    = "MEDIUM",
                Type        = "OLD_TLS_VERSION",
                Description = $"{oldTls.Count} connection(s) using deprecated TLS/SSL versions. Upgrade to TLS 1.2 or 1.3."
            });

        return list
            .OrderBy(i => i.Severity switch { "HIGH" => 0, "MEDIUM" => 1, _ => 2 })
            .ToList();
    }

    // ── Narrative ─────────────────────────────────────────────────────────────

    private static string GenerateNarrative(CaptureSummary s, PacketStats stats)
    {
        var sb    = new StringBuilder();
        var pd    = s.ProtocolDistribution;
        int total = stats.TotalPackets;

        if (s.TimeRange.StartTime.HasValue)
            sb.AppendLine($"Capture spans {s.TimeRange.Duration ?? "unknown duration"}, " +
                          $"from {s.TimeRange.StartTime:yyyy-MM-dd HH:mm:ss} UTC " +
                          $"to {s.TimeRange.EndTime:yyyy-MM-dd HH:mm:ss} UTC.");
        else
            sb.AppendLine("No timing information could be extracted from this capture.");

        sb.AppendLine($"{total:N0} total packets ({FormatBytes(s.TotalBytes)}) recorded; " +
                      $"{s.TotalPackets:N0} matched the applied filter.");

        var dominant = new List<string>();
        if (pd.Tcp > 0) dominant.Add($"TCP ({Pct(pd.Tcp, total)}%)");
        if (pd.Udp > 0) dominant.Add($"UDP ({Pct(pd.Udp, total)}%)");
        if (dominant.Count > 0)
            sb.AppendLine("Traffic is predominantly " + string.Join(" and ", dominant) + ".");

        if (pd.Http > 0)
            sb.AppendLine($"Unencrypted HTTP traffic detected ({pd.Http:N0} packets). " +
                          "Review for credential exposure or plaintext data exfiltration.");
        if (pd.Tls > 0)
            sb.AppendLine($"TLS-encrypted sessions observed ({pd.Tls:N0} packets). " +
                          "Examine certificate CN/SAN fields and SNI for anomalies.");
        if (pd.Dns > 0)
            sb.AppendLine($"DNS activity: {s.DnsAnalysis.UniqueCount} unique domains queried." +
                          (s.DnsAnalysis.DgaCandidates.Count > 0
                            ? $" {s.DnsAnalysis.DgaCandidates.Count} domain(s) flagged as potential DGA — investigate for C2."
                            : " No DGA patterns detected."));

        if (s.BeaconCandidates.Count > 0)
        {
            var top = s.BeaconCandidates[0];
            sb.AppendLine($"ALERT: {s.BeaconCandidates.Count} beaconing pattern(s) detected. " +
                          $"Top candidate: {top.SourceIp} → {top.DestinationIp} " +
                          $"({top.ConnectionCount} connections, ~{top.AvgIntervalSeconds}s interval, {top.Confidence} confidence).");
        }

        if (s.PortScans.Count > 0)
            sb.AppendLine($"ALERT: Port scan activity detected from {s.PortScans.Count} source(s). " +
                          $"Top scanner: {s.PortScans[0].SourceIp} ({s.PortScans[0].UniquePortsContacted} unique ports).");

        if (s.TlsInsights.Count > 0)
        {
            int oldCount = s.TlsInsights.Count(t => t.IsOldVersion);
            sb.AppendLine($"TLS: {s.TlsInsights.Count} unique session(s) observed." +
                          (oldCount > 0 ? $" WARNING: {oldCount} use deprecated protocol versions." : ""));
        }
        if (s.CredentialLeaks.Count > 0)
            sb.AppendLine($"ALERT: {s.CredentialLeaks.Count} credential leak(s) detected in cleartext traffic — immediate review required.");
        if (s.DetectedApps.Count > 0)
            sb.AppendLine($"Applications identified: {string.Join(", ", s.DetectedApps.Take(5).Select(a => a.AppName))}.");

        if (s.TopTalkers.Count > 0)
        {
            var top = s.TopTalkers[0];
            sb.AppendLine($"Highest-volume flow: {top.SourceIp} → {top.DestinationIp} " +
                          $"({top.PacketCount:N0} pkts, {FormatBytes(top.Bytes)}). " +
                          "Investigate if unexpected or disproportionate to baseline.");
        }

        int highCount = s.Indicators.Count(i => i.Severity == "HIGH");
        if (highCount > 0)
            sb.AppendLine($"{highCount} HIGH severity indicator(s) require immediate attention.");

        if (total == 0)
            sb.AppendLine("No packets found. Verify the file is a valid PCAP/PCAPNG.");

        return sb.ToString().Trim();
    }

    // ── Filter matching ───────────────────────────────────────────────────────

    private static bool Matches(Packet packet, FilterOptions options)
    {
        var ip = packet.Extract<IPPacket>();
        if (options.Protocol is not null && ip is null) return false;

        if (ip is not null)
        {
            if (options.SourceIp is not null &&
                !ip.SourceAddress.ToString().Equals(options.SourceIp, StringComparison.OrdinalIgnoreCase))
                return false;
            if (options.DestinationIp is not null &&
                !ip.DestinationAddress.ToString().Equals(options.DestinationIp, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        if (options.Protocol is not null || options.SourcePort is not null || options.DestinationPort is not null)
        {
            var tcp  = packet.Extract<TcpPacket>();
            var udp  = packet.Extract<UdpPacket>();
            var icmp = (Packet?)packet.Extract<IcmpV4Packet>() ?? packet.Extract<IcmpV6Packet>();

            if (options.Protocol is not null)
            {
                bool ok = options.Protocol.ToLower() switch
                {
                    "tcp"  => tcp  is not null,
                    "udp"  => udp  is not null,
                    "icmp" => icmp is not null,
                    _      => true
                };
                if (!ok) return false;
            }

            if (options.SourcePort is not null)
            {
                int src = tcp?.SourcePort ?? udp?.SourcePort ?? -1;
                if (src != options.SourcePort) return false;
            }

            if (options.DestinationPort is not null)
            {
                int dst = tcp?.DestinationPort ?? udp?.DestinationPort ?? -1;
                if (dst != options.DestinationPort) return false;
            }
        }

        return true;
    }

    // ── TLS ClientHello parser ────────────────────────────────────────────────

    private static TlsInsight? TryParseTlsClientHello(byte[]? payload, string srcIp, string dstIp, int dport)
    {
        try
        {
            if (payload is null || payload.Length < 47) return null;
            if (payload[0] != 0x16) return null; // must be Handshake record
            if (payload[5] != 0x01) return null; // must be ClientHello

            int pos = 9; // skip record header (5) + handshake type (1) + 3-byte length (3)

            // client_version (legacy, usually 0x0303 for TLS 1.2+)
            if (pos + 2 > payload.Length) return null;
            ushort clientVersion = (ushort)((payload[pos] << 8) | payload[pos + 1]);
            pos += 2;

            pos += 32; // skip random

            // session_id
            if (pos >= payload.Length) return null;
            pos += 1 + payload[pos];

            // cipher_suites
            if (pos + 2 > payload.Length) return null;
            pos += 2 + ((payload[pos] << 8) | payload[pos + 1]);

            // compression_methods
            if (pos >= payload.Length) return null;
            pos += 1 + payload[pos];

            // extensions
            if (pos + 2 > payload.Length) return null;
            int extEnd = Math.Min(pos + 2 + ((payload[pos] << 8) | payload[pos + 1]), payload.Length);
            pos += 2;

            string sni             = "";
            string negotiatedVer   = ParseTlsVersion(clientVersion);

            while (pos + 4 <= extEnd)
            {
                int extType = (payload[pos] << 8) | payload[pos + 1];
                int extLen  = (payload[pos + 2] << 8) | payload[pos + 3];
                pos += 4;
                if (pos + extLen > extEnd) break;

                if (extType == 0x0000 && extLen >= 5) // SNI
                {
                    int nameLen = (payload[pos + 3] << 8) | payload[pos + 4];
                    if (nameLen > 0 && pos + 5 + nameLen <= extEnd)
                        sni = Encoding.ASCII.GetString(payload, pos + 5, nameLen);
                }
                else if (extType == 0x002B && extLen >= 3) // supported_versions
                {
                    int listLen = payload[pos];
                    ushort maxVer = 0;
                    for (int vi = 0; vi < listLen - 1 && pos + 1 + vi + 1 < payload.Length; vi += 2)
                    {
                        ushort ver = (ushort)((payload[pos + 1 + vi] << 8) | payload[pos + 2 + vi]);
                        if (!IsGreaseValue(ver) && ver > maxVer) maxVer = ver;
                    }
                    if (maxVer > 0) negotiatedVer = ParseTlsVersion(maxVer);
                }

                pos += extLen;
            }

            bool isOld = negotiatedVer is "SSL 3.0" or "TLS 1.0" or "TLS 1.1";
            return new TlsInsight
            {
                SourceIp        = srcIp,
                DestIp          = dstIp,
                DestPort        = dport,
                Sni             = sni,
                TlsVersion      = negotiatedVer,
                IsOldVersion    = isOld,
                IsSuspiciousSni = !string.IsNullOrEmpty(sni) && IsDgaDomain(sni)
            };
        }
        catch { return null; } // malformed packet — skip silently
    }

    // GREASE values (RFC 8701): 0x0A0A, 0x1A1A, 0x2A2A … 0xFAFA — both bytes equal, low nibble = 0xA
    private static bool IsGreaseValue(ushort ver) =>
        (ver & 0x0F) == 0x0A && (ver >> 8) == (ver & 0xFF);

    private static string ParseTlsVersion(ushort ver) => ver switch
    {
        0x0304 => "TLS 1.3",
        0x0303 => "TLS 1.2",
        0x0302 => "TLS 1.1",
        0x0301 => "TLS 1.0",
        0x0300 => "SSL 3.0",
        _      => $"Unknown ({ver:X4})"
    };

    private static bool IsDgaDomain(string domain)
    {
        var parts = domain.Split('.');
        if (parts.Length < 2) return false;
        string sld = parts[^2];
        if (sld.Length < 8) return false;
        return ShannonEntropy(sld) > 3.5;
    }

    // ── Credential detection ──────────────────────────────────────────────────

    private static void TryExtractHttpCredentials(
        TcpPacket tcp, string srcIp, string dstIp, int dport,
        List<CredentialLeak> leaks, DateTime ts, List<TimelineEvent> timeline)
    {
        var payload = tcp.PayloadData;
        if (payload is null || payload.Length < 12) return;

        string text  = Encoding.Latin1.GetString(payload, 0, Math.Min(8192, payload.Length));
        var    lines = text.Split('\n');
        bool   isPost = lines.Length > 0 && lines[0].StartsWith("POST ", StringComparison.OrdinalIgnoreCase);

        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd('\r');

            // Basic Auth
            if (line.StartsWith("Authorization: Basic ", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(line[21..].Trim()));
                    int    colon   = decoded.IndexOf(':');
                    string user    = (colon >= 0 ? decoded[..colon] : decoded).Truncate(80);
                    string pass    = colon >= 0 ? decoded[(colon + 1)..] : "";
                    leaks.Add(new CredentialLeak
                    {
                        Type     = "BASIC_AUTH",
                        Protocol = "HTTP",
                        SourceIp = srcIp,
                        DestIp   = dstIp,
                        Username = user,
                        Secret   = new string('*', Math.Min(pass.Length, 8)),
                        Detail   = $"HTTP Basic Auth for '{user}' sent in cleartext to {dstIp}:{dport}"
                    });
                    if (timeline.Count < 2000)
                        timeline.Add(new TimelineEvent
                        {
                            Timestamp   = ts,
                            Type        = "CREDENTIAL_LEAK",
                            Severity    = "ALERT",
                            SourceIp    = srcIp,
                            DestIp      = dstIp,
                            Description = $"HTTP Basic Auth — user '{user}' credentials exposed in cleartext"
                        });
                }
                catch { /* bad base64 */ }
            }
            // Bearer token (medium severity — may be intentional)
            else if (line.StartsWith("Authorization: Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                string token = line[22..].Trim().Truncate(30);
                leaks.Add(new CredentialLeak
                {
                    Severity = "MEDIUM",
                    Type     = "BEARER_TOKEN",
                    Protocol = "HTTP",
                    SourceIp = srcIp,
                    DestIp   = dstIp,
                    Secret   = token + "…",
                    Detail   = $"Bearer token transmitted over cleartext HTTP to {dstIp}:{dport}"
                });
            }
        }

        // POST body with password fields
        if (isPost)
        {
            int bodyStart = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (bodyStart < 0) bodyStart = text.IndexOf("\n\n", StringComparison.Ordinal);
            if (bodyStart >= 0)
            {
                string body  = text[(bodyStart + 4)..].ToLower();
                bool   hasPw = body.Contains("password=") || body.Contains("passwd=") ||
                               body.Contains("pwd=")      || body.Contains("pass=");
                if (hasPw)
                {
                    string host = lines.Skip(1).Take(20)
                        .FirstOrDefault(l => l.StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
                        ?[5..].Trim() ?? dstIp;
                    leaks.Add(new CredentialLeak
                    {
                        Type     = "FORM_DATA",
                        Protocol = "HTTP",
                        SourceIp = srcIp,
                        DestIp   = dstIp,
                        Detail   = $"HTTP POST with password field to {host} (cleartext)"
                    });
                    if (timeline.Count < 2000)
                        timeline.Add(new TimelineEvent
                        {
                            Timestamp   = ts,
                            Type        = "CREDENTIAL_LEAK",
                            Severity    = "ALERT",
                            SourceIp    = srcIp,
                            DestIp      = dstIp,
                            Description = $"Login form credentials (POST) sent in cleartext to {host}"
                        });
                }
            }
        }
    }

    private static void TryExtractFtpCredentials(
        TcpPacket tcp, string srcIp, string dstIp,
        List<CredentialLeak> leaks, DateTime ts, List<TimelineEvent> timeline)
    {
        var payload = tcp.PayloadData;
        if (payload is null || payload.Length < 6) return;

        string text = Encoding.ASCII.GetString(payload, 0, Math.Min(256, payload.Length));

        if (text.StartsWith("USER ", StringComparison.OrdinalIgnoreCase))
        {
            string user = text[5..].TrimEnd('\r', '\n').Truncate(50);
            leaks.Add(new CredentialLeak
            {
                Type     = "FTP_CREDENTIALS",
                Protocol = "FTP",
                SourceIp = srcIp,
                DestIp   = dstIp,
                Username = user,
                Detail   = $"FTP username '{user}' transmitted in cleartext"
            });
            if (timeline.Count < 2000)
                timeline.Add(new TimelineEvent
                {
                    Timestamp   = ts,
                    Type        = "CREDENTIAL_LEAK",
                    Severity    = "ALERT",
                    SourceIp    = srcIp,
                    DestIp      = dstIp,
                    Description = $"FTP USER command: '{user}' in cleartext"
                });
        }
        else if (text.StartsWith("PASS ", StringComparison.OrdinalIgnoreCase))
        {
            string pass = text[5..].TrimEnd('\r', '\n');
            leaks.Add(new CredentialLeak
            {
                Type     = "FTP_CREDENTIALS",
                Protocol = "FTP",
                SourceIp = srcIp,
                DestIp   = dstIp,
                Secret   = new string('*', Math.Min(pass.Length, 8)),
                Detail   = $"FTP password ({pass.Length} chars) transmitted in cleartext"
            });
        }
    }

    // ── App detection ─────────────────────────────────────────────────────────

    private static void CheckAppSignature(string domain, Dictionary<string, AppDetection> appHits)
    {
        if (string.IsNullOrEmpty(domain)) return;
        var lower = domain.ToLower().TrimEnd('.');
        var parts = lower.Split('.');
        // Try progressively shorter suffix matches
        for (int i = 0; i < parts.Length - 1; i++)
        {
            string candidate = string.Join(".", parts[i..]);
            if (!AppSignatures.TryGetValue(candidate, out var sig)) continue;
            if (!appHits.TryGetValue(sig.name, out var det))
                appHits[sig.name] = det = new AppDetection { AppName = sig.name, Category = sig.category };
            det.HitCount++;
            if (!det.Domains.Contains(domain) && det.Domains.Count < 10)
                det.Domains.Add(domain);
            break;
        }
    }

    // ── IOC bundle ────────────────────────────────────────────────────────────

    private static IocBundle BuildIocBundle(
        CaptureSummary s,
        Dictionary<(string src, string dst), (int count, long bytes)> flows)
    {
        var externalIps = flows.Keys
            .SelectMany(k => new[] { k.src, k.dst })
            .Where(ip => !string.IsNullOrEmpty(ip) && !GeoResolver.IsPrivate(ip))
            .Distinct().OrderBy(ip => ip).Take(200).ToList();

        var urls = s.HttpAnalysis.Requests
            .Where(r => !string.IsNullOrEmpty(r.Host))
            .Select(r => $"http://{r.Host}{r.Uri}")
            .Distinct().Take(100).ToList();

        var suspiciousIps = s.BeaconCandidates
            .SelectMany(b => new[] { b.SourceIp, b.DestinationIp })
            .Concat(s.PortScans.Select(p => p.SourceIp))
            .Concat(s.Indicators.Where(i => i.Severity == "HIGH")
                     .SelectMany(i => new[] { i.SourceIp, i.DestIp }))
            .Where(ip => !string.IsNullOrEmpty(ip) && !GeoResolver.IsPrivate(ip))
            .Distinct().Take(50).ToList();

        var suspiciousDomains = s.DnsAnalysis.DgaCandidates.Select(d => d.Domain)
            .Concat(s.TlsInsights.Where(t => t.IsSuspiciousSni).Select(t => t.Sni))
            .Where(d => !string.IsNullOrEmpty(d))
            .Distinct().Take(50).ToList();

        return new IocBundle
        {
            IpAddresses       = externalIps,
            Domains           = s.DnsAnalysis.QueriedDomains.Take(200).ToList(),
            Urls              = urls,
            SuspiciousIps     = suspiciousIps,
            SuspiciousDomains = suspiciousDomains
        };
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static bool IsHttpPayload(TcpPacket tcp)
    {
        var p = tcp.PayloadData;
        if (p is null || p.Length < 4) return false;
        string head = Encoding.ASCII.GetString(p, 0, Math.Min(8, p.Length));
        return head.StartsWith("GET ")    || head.StartsWith("POST ")   ||
               head.StartsWith("PUT ")    || head.StartsWith("DELETE ") ||
               head.StartsWith("HEAD ")   || head.StartsWith("OPTIONS") ||
               head.StartsWith("HTTP/");
    }

    private static bool IsTlsPayload(TcpPacket tcp)
    {
        var p = tcp.PayloadData;
        return p is { Length: >= 3 } && p[0] == 0x16 && p[1] == 0x03;
    }

    private static string PortName(int port) => port switch
    {
        22   => "SSH",
        23   => "Telnet",
        135  => "RPC",
        139  => "NetBIOS",
        445  => "SMB",
        3389 => "RDP",
        5985 => "WinRM-HTTP",
        5986 => "WinRM-HTTPS",
        _    => port.ToString()
    };

    private static Dictionary<string, int> Top(Dictionary<string, int> src, int n) =>
        src.OrderByDescending(kv => kv.Value).Take(n).ToDictionary(kv => kv.Key, kv => kv.Value);

    private static string FormatDuration(TimeSpan ts)
    {
        if (ts.TotalSeconds < 1)  return $"{ts.TotalMilliseconds:N0} ms";
        if (ts.TotalMinutes < 1)  return $"{ts.TotalSeconds:N1} s";
        if (ts.TotalHours   < 1)  return $"{ts.TotalMinutes:N1} min";
        return $"{ts.TotalHours:N1} h";
    }

    public static string FormatBytes(long b)
    {
        if (b >= 1_073_741_824) return $"{b / 1_073_741_824.0:N2} GB";
        if (b >= 1_048_576)     return $"{b / 1_048_576.0:N2} MB";
        if (b >= 1024)          return $"{b / 1024.0:N1} KB";
        return $"{b} B";
    }

    private static double Pct(int count, int total) =>
        total == 0 ? 0 : Math.Round(count * 100.0 / total, 1);
}

// ── String helper ─────────────────────────────────────────────────────────────

internal static class StringExtensions
{
    public static string Truncate(this string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
