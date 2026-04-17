using PcapFilter;

// ── Web mode (no args) ────────────────────────────────────────────────────────
if (args.Length == 0)
{
    var builder = WebApplication.CreateBuilder(args);
    builder.WebHost.UseUrls("http://localhost:5000");
    builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = 500 * 1024 * 1024); // 500 MB

    var app = builder.Build();

    app.UseDefaultFiles();
    var mimeTypes = new Microsoft.AspNetCore.StaticFiles.FileExtensionContentTypeProvider();
    mimeTypes.Mappings[".geojson"] = "application/geo+json";
    app.UseStaticFiles(new Microsoft.AspNetCore.Builder.StaticFileOptions { ContentTypeProvider = mimeTypes });

    // POST /filter  — upload pcap + options, returns JSON statistics
    app.MapPost("/filter", [Microsoft.AspNetCore.Mvc.RequestSizeLimit(500 * 1024 * 1024)] async (HttpRequest request) =>
    {
        if (!request.HasFormContentType)
            return Results.BadRequest("Expected multipart/form-data.");

        var form = await request.ReadFormAsync();
        var file = form.Files["file"];

        if (file is null || file.Length == 0)
            return Results.BadRequest("No PCAP file provided.");

        var inputPath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.pcap");

        try
        {
            await using (var fs = File.Create(inputPath))
                await file.CopyToAsync(fs);

            var options = new FilterOptions
            {
                SourceIp        = NullIfEmpty(form["srcIp"]),
                DestinationIp   = NullIfEmpty(form["dstIp"]),
                SourcePort      = int.TryParse(form["srcPort"],  out int sp) ? sp : null,
                DestinationPort = int.TryParse(form["dstPort"],  out int dp) ? dp : null,
                Protocol        = NullIfEmpty(form["protocol"]),
            };

            bool useLocalDb = form["geoLocalDb"] != "false";

            var result = PacketFilter.Analyze(inputPath, options);

            // Geo-resolve all unique IPs seen in flows and top-IP tables
            var allIps = result.Summary.TopTalkers
                .SelectMany(t => new[] { t.SourceIp, t.DestinationIp })
                .Concat(result.Stats.TopSourceIps.Keys)
                .Concat(result.Stats.TopDestinationIps.Keys)
                .Distinct();

            result.GeoMap = await GeoResolver.ResolveAsync(allIps, useLocalDb);

            return Results.Json(result);
        }
        finally
        {
            if (File.Exists(inputPath)) File.Delete(inputPath);
        }
    });

    Console.WriteLine("PcapFilter web UI running at http://localhost:5000");
    app.Run();
    return 0;
}

// ── CLI mode ──────────────────────────────────────────────────────────────────
if (args.Length < 2)
{
    PrintUsage();
    return 1;
}

string input  = args[0];
string output = args[1];

if (!File.Exists(input))
{
    Console.Error.WriteLine($"Error: file not found: {input}");
    return 1;
}

var cliOptions = ParseOptions(args[2..]);

if (cliOptions is null)
{
    PrintUsage();
    return 1;
}

if (cliOptions.IsEmpty)
    Console.WriteLine("Warning: no filters specified — all packets will be copied.");

try
{
    var result = PacketFilter.Analyze(input, cliOptions);
    var s = result.Summary;
    Console.WriteLine($"Total packets : {result.Stats.TotalPackets:N0}");
    Console.WriteLine($"Matched       : {result.Stats.MatchedPackets:N0}");
    Console.WriteLine($"Total bytes   : {PacketFilter.FormatBytes(s.TotalBytes)}");
    if (s.TimeRange.StartTime.HasValue)
        Console.WriteLine($"Time range    : {s.TimeRange.StartTime:s} → {s.TimeRange.EndTime:s} ({s.TimeRange.Duration})");
    Console.WriteLine();
    Console.WriteLine("── Protocol Distribution ──");
    Console.WriteLine($"  TCP   {s.ProtocolDistribution.Tcp,6:N0}    HTTP  {s.ProtocolDistribution.Http,6:N0}");
    Console.WriteLine($"  UDP   {s.ProtocolDistribution.Udp,6:N0}    TLS   {s.ProtocolDistribution.Tls,6:N0}");
    Console.WriteLine($"  DNS   {s.ProtocolDistribution.Dns,6:N0}    Other {s.ProtocolDistribution.Other,6:N0}");
    Console.WriteLine();
    Console.WriteLine("── Top Talkers ──");
    foreach (var t in s.TopTalkers)
        Console.WriteLine($"  {t.SourceIp,-15} → {t.DestinationIp,-15}  {t.PacketCount,6} pkts  {PacketFilter.FormatBytes(t.Bytes)}");
    Console.WriteLine();
    Console.WriteLine("── Summary ──");
    Console.WriteLine(s.HumanReadableSummary);
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 1;
}

// ── helpers ───────────────────────────────────────────────────────────────────

static string? NullIfEmpty(Microsoft.Extensions.Primitives.StringValues v)
{
    var s = v.FirstOrDefault();
    return string.IsNullOrWhiteSpace(s) ? null : s;
}

static FilterOptions? ParseOptions(string[] args)
{
    var opts = new FilterOptions();

    for (int i = 0; i < args.Length - 1; i += 2)
    {
        string flag  = args[i].ToLower();
        string value = args[i + 1];

        switch (flag)
        {
            case "--src-ip":   opts.SourceIp        = value; break;
            case "--dst-ip":   opts.DestinationIp   = value; break;
            case "--src-port":
                if (!int.TryParse(value, out int sp)) { Console.Error.WriteLine("Invalid src-port"); return null; }
                opts.SourcePort = sp;
                break;
            case "--dst-port":
                if (!int.TryParse(value, out int dp)) { Console.Error.WriteLine("Invalid dst-port"); return null; }
                opts.DestinationPort = dp;
                break;
            case "--protocol": opts.Protocol = value; break;
            default:
                Console.Error.WriteLine($"Unknown flag: {flag}");
                return null;
        }
    }

    return opts;
}

static void PrintUsage()
{
    Console.WriteLine("""
        PcapFilter — filter packets from a .pcap file

        Usage (CLI):
          PcapFilter <input.pcap> <output.pcap> [options]

        Usage (Web UI):
          PcapFilter                  (starts web server on http://localhost:5000)

        Options:
          --src-ip    <ip>        Filter by source IP address
          --dst-ip    <ip>        Filter by destination IP address
          --src-port  <port>      Filter by source port (TCP/UDP)
          --dst-port  <port>      Filter by destination port (TCP/UDP)
          --protocol  <proto>     Filter by protocol: tcp | udp | icmp

        Examples:
          PcapFilter capture.pcap out.pcap --protocol tcp --dst-port 443
          PcapFilter capture.pcap out.pcap --src-ip 192.168.1.1
        """);
}
