namespace PcapFilter;

public class FilterOptions
{
    public string? SourceIp { get; set; }
    public string? DestinationIp { get; set; }
    public int? SourcePort { get; set; }
    public int? DestinationPort { get; set; }

    // "tcp", "udp", "icmp" — null means any
    public string? Protocol { get; set; }

    public bool IsEmpty =>
        SourceIp is null &&
        DestinationIp is null &&
        SourcePort is null &&
        DestinationPort is null &&
        Protocol is null;
}
