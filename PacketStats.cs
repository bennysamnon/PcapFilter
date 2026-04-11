namespace PcapFilter;

public class PacketStats
{
    public int TotalPackets  { get; set; }
    public int MatchedPackets { get; set; }
    public long TotalBytes   { get; set; }
    public int MinPacketSize { get; set; } = int.MaxValue;
    public int MaxPacketSize { get; set; }

    public double AveragePacketSize =>
        MatchedPackets == 0 ? 0 : Math.Round((double)TotalBytes / MatchedPackets, 1);

    // protocol → count
    public Dictionary<string, int> Protocols { get; set; } = new();

    // ip → count  (top 10 shown in UI)
    public Dictionary<string, int> TopSourceIps      { get; set; } = new();
    public Dictionary<string, int> TopDestinationIps { get; set; } = new();

    // port → count  (top 10)
    public Dictionary<string, int> TopDestinationPorts { get; set; } = new();
}
