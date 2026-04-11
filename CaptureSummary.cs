namespace PcapFilter;

public class AnalysisResult
{
    public PacketStats                 Stats   { get; set; } = new();
    public CaptureSummary              Summary { get; set; } = new();
    public Dictionary<string, GeoInfo> GeoMap  { get; set; } = new();
}

public class CaptureSummary
{
    public int               TotalPackets         { get; set; }
    public long              TotalBytes           { get; set; }
    public CaptureTimeRange  TimeRange            { get; set; } = new();
    public List<TalkerEntry> TopTalkers           { get; set; } = new();
    public ProtoDistribution ProtocolDistribution { get; set; } = new();
    public string            HumanReadableSummary { get; set; } = "";

    // ── new IR sections ───────────────────────────────────────────────────────
    public DnsAnalysis               DnsAnalysis      { get; set; } = new();
    public HttpAnalysis              HttpAnalysis     { get; set; } = new();
    public List<BeaconCandidate>     BeaconCandidates { get; set; } = new();
    public List<PortScanAlert>       PortScans        { get; set; } = new();
    public List<SuspiciousIndicator> Indicators       { get; set; } = new();
    public List<ConversationEntry>   Conversations    { get; set; } = new();
    public List<TimelineEvent>       Timeline         { get; set; } = new();

    // ── new: TLS / credentials / app detection / IOC ──────────────────────────
    public List<TlsInsight>          TlsInsights      { get; set; } = new();
    public Dictionary<string, int>   TlsVersions      { get; set; } = new();
    public List<CredentialLeak>      CredentialLeaks  { get; set; } = new();
    public List<AppDetection>        DetectedApps     { get; set; } = new();
    public IocBundle                 Iocs             { get; set; } = new();
}

// ── existing types ────────────────────────────────────────────────────────────

public class CaptureTimeRange
{
    public DateTime? StartTime { get; set; }
    public DateTime? EndTime   { get; set; }
    public string?   Duration  { get; set; }
}

public class TalkerEntry
{
    public string SourceIp      { get; set; } = "";
    public string DestinationIp { get; set; } = "";
    public int    PacketCount   { get; set; }
    public long   Bytes         { get; set; }
}

public class ProtoDistribution
{
    public int Tcp   { get; set; }
    public int Udp   { get; set; }
    public int Dns   { get; set; }
    public int Http  { get; set; }
    public int Tls   { get; set; }
    public int Other { get; set; }
}

// ── DNS ───────────────────────────────────────────────────────────────────────

public class DnsAnalysis
{
    public int               UniqueCount    { get; set; }
    public List<string>      QueriedDomains { get; set; } = new();
    public List<DgaCandidate> DgaCandidates { get; set; } = new();
}

public class DgaCandidate
{
    public string Domain       { get; set; } = "";
    public double EntropyScore { get; set; }
    public string Reason       { get; set; } = "";
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

public class HttpAnalysis
{
    public List<HttpEntry>         Requests      { get; set; } = new();
    public Dictionary<string, int> TopHosts      { get; set; } = new();
    public Dictionary<string, int> TopUserAgents { get; set; } = new();
}

public class HttpEntry
{
    public string Method    { get; set; } = "";
    public string Host      { get; set; } = "";
    public string Uri       { get; set; } = "";
    public string UserAgent { get; set; } = "";
    public string SourceIp  { get; set; } = "";
    public string DestIp    { get; set; } = "";
}

// ── Beaconing ─────────────────────────────────────────────────────────────────

public class BeaconCandidate
{
    public string SourceIp           { get; set; } = "";
    public string DestinationIp      { get; set; } = "";
    public int    ConnectionCount    { get; set; }
    public double AvgIntervalSeconds { get; set; }
    public double JitterPct          { get; set; } // coefficient of variation %
    public string Confidence         { get; set; } = "";
}

// ── Port scan ─────────────────────────────────────────────────────────────────

public class PortScanAlert
{
    public string    SourceIp             { get; set; } = "";
    public string    TopTargetIp          { get; set; } = "";
    public int       UniquePortsContacted { get; set; }
    public List<int> SampledPorts         { get; set; } = new();
}

// ── Suspicious indicators ─────────────────────────────────────────────────────

public class SuspiciousIndicator
{
    public string Severity    { get; set; } = ""; // HIGH | MEDIUM | LOW
    public string Type        { get; set; } = "";
    public string Description { get; set; } = "";
    public string SourceIp    { get; set; } = "";
    public string DestIp      { get; set; } = "";
}

// ── Network conversations ─────────────────────────────────────────────────────

public class ConversationEntry
{
    public string   SourceIp        { get; set; } = "";
    public int      SourcePort      { get; set; }
    public string   DestinationIp   { get; set; } = "";
    public int      DestinationPort { get; set; }
    public string   Protocol        { get; set; } = "";
    public int      PacketCount     { get; set; }
    public long     Bytes           { get; set; }
    public double   DurationSeconds { get; set; }
    public DateTime StartTime       { get; set; }
}

// ── TLS ───────────────────────────────────────────────────────────────────────

public class TlsInsight
{
    public string SourceIp        { get; set; } = "";
    public string DestIp          { get; set; } = "";
    public int    DestPort        { get; set; }
    public string Sni             { get; set; } = "";
    public string TlsVersion      { get; set; } = "";
    public bool   IsOldVersion    { get; set; }
    public bool   IsSuspiciousSni { get; set; }
}

// ── Credentials ───────────────────────────────────────────────────────────────

public class CredentialLeak
{
    public string Severity { get; set; } = "HIGH";
    public string Type     { get; set; } = ""; // BASIC_AUTH | BEARER_TOKEN | FTP_CREDENTIALS | FORM_DATA
    public string Protocol { get; set; } = "";
    public string SourceIp { get; set; } = "";
    public string DestIp   { get; set; } = "";
    public string Username { get; set; } = "";
    public string Secret   { get; set; } = "";
    public string Detail   { get; set; } = "";
}

// ── App detection ─────────────────────────────────────────────────────────────

public class AppDetection
{
    public string       AppName  { get; set; } = "";
    public string       Category { get; set; } = "";
    public int          HitCount { get; set; }
    public List<string> Domains  { get; set; } = new();
}

// ── IOC bundle ────────────────────────────────────────────────────────────────

public class IocBundle
{
    public List<string> IpAddresses       { get; set; } = new();
    public List<string> Domains           { get; set; } = new();
    public List<string> Urls              { get; set; } = new();
    public List<string> SuspiciousIps     { get; set; } = new();
    public List<string> SuspiciousDomains { get; set; } = new();
}

// ── Timeline ──────────────────────────────────────────────────────────────────

public class TimelineEvent
{
    public DateTime Timestamp   { get; set; }
    public string   Type        { get; set; } = "";
    public string   Severity    { get; set; } = "INFO"; // INFO | WARNING | ALERT
    public string   SourceIp    { get; set; } = "";
    public string   DestIp      { get; set; } = "";
    public string   Description { get; set; } = "";
}
