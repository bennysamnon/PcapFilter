using System.Net.Http.Json;
using System.Text.Json.Serialization;
using MaxMind.GeoIP2;
using MaxMind.GeoIP2.Exceptions;

namespace PcapFilter;

public class GeoInfo
{
    public string Ip          { get; set; } = "";
    public double Lat         { get; set; }
    public double Lon         { get; set; }
    public string Country     { get; set; } = "";
    public string CountryCode { get; set; } = "";
    public string City        { get; set; } = "";
    public string Asn         { get; set; } = "";
    public string Org         { get; set; } = "";
    public bool   IsPrivate   { get; set; }
}

public static class GeoResolver
{
    private static readonly HttpClient Http = new() { Timeout = TimeSpan.FromSeconds(10) };

    // Look for .mmdb files next to the executable or in a GeoIP/ subdirectory
    private static readonly string? CityDbPath = FindDb("GeoLite2-City.mmdb");
    private static readonly string? AsnDbPath  = FindDb("GeoLite2-ASN.mmdb");

    public static bool HasLocalDb => CityDbPath is not null;

    private static string? FindDb(string filename)
    {
        var bases = new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() };
        var candidates = bases.SelectMany(b => new[]
        {
            Path.Combine(b, filename),
            Path.Combine(b, "GeoIP", filename),
        });
        return candidates.FirstOrDefault(File.Exists);
    }

    public static async Task<Dictionary<string, GeoInfo>> ResolveAsync(IEnumerable<string> ips, bool useLocalDb = true)
    {
        var result    = new Dictionary<string, GeoInfo>();
        var all       = ips.Distinct().ToList();
        var publicIps = all.Where(ip => !IsPrivate(ip)).ToList();

        // Private IPs — no geo lookup needed
        foreach (var ip in all.Where(IsPrivate))
            result[ip] = new GeoInfo { Ip = ip, IsPrivate = true, Country = "Private Network" };

        if (publicIps.Count == 0) return result;

        if (useLocalDb && CityDbPath is not null)
            ResolveOffline(publicIps, result);
        else
            await ResolveOnlineAsync(publicIps, result);

        return result;
    }

    private static void ResolveOffline(List<string> publicIps, Dictionary<string, GeoInfo> result)
    {
        using var cityReader = new DatabaseReader(CityDbPath!);
        using var asnReader  = AsnDbPath is not null ? new DatabaseReader(AsnDbPath) : null;

        foreach (var ip in publicIps)
        {
            try
            {
                var city = cityReader.City(ip);
                var geo  = new GeoInfo
                {
                    Ip          = ip,
                    Country     = city.Country.Name     ?? "",
                    CountryCode = city.Country.IsoCode  ?? "",
                    City        = city.City.Name        ?? "",
                    Lat         = city.Location.Latitude  ?? 0,
                    Lon         = city.Location.Longitude ?? 0,
                };

                if (asnReader is not null)
                {
                    try
                    {
                        var asn = asnReader.Asn(ip);
                        geo.Asn = $"AS{asn.AutonomousSystemNumber}";
                        geo.Org = asn.AutonomousSystemOrganization ?? "";
                    }
                    catch (AddressNotFoundException) { }
                }

                result[ip] = geo;
            }
            catch (AddressNotFoundException) { }
            catch { }
        }
    }

    // ip-api.com batch endpoint: free, no key, up to 100 IPs per request
    private static async Task ResolveOnlineAsync(List<string> publicIps, Dictionary<string, GeoInfo> result)
    {
        foreach (var batch in publicIps.Chunk(100))
        {
            try
            {
                var payload  = batch.Select(ip => new { query = ip }).ToArray();
                var response = await Http.PostAsJsonAsync(
                    "http://ip-api.com/batch?fields=status,country,countryCode,city,lat,lon,asn,org,query",
                    payload);

                if (!response.IsSuccessStatusCode) continue;

                var items = await response.Content.ReadFromJsonAsync<List<IpApiResult>>();
                if (items is null) continue;

                foreach (var item in items.Where(i => i.Status == "success"))
                    result[item.Query] = new GeoInfo
                    {
                        Ip          = item.Query,
                        Lat         = item.Lat,
                        Lon         = item.Lon,
                        Country     = item.Country,
                        CountryCode = item.CountryCode,
                        City        = item.City,
                        Asn         = item.Asn,
                        Org         = item.Org,
                    };
            }
            catch
            {
                // geo lookup is best-effort — skip silently if unreachable
            }
        }
    }

    public static bool IsPrivate(string ipStr)
    {
        if (!System.Net.IPAddress.TryParse(ipStr, out var addr)) return true;
        var b = addr.GetAddressBytes();
        if (b.Length != 4) return false; // IPv6 treated as public
        return b[0] == 10
            || b[0] == 127
            || (b[0] == 172 && b[1] is >= 16 and <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254);
    }

    private sealed class IpApiResult
    {
        [JsonPropertyName("status")]      public string Status      { get; set; } = "";
        [JsonPropertyName("query")]       public string Query       { get; set; } = "";
        [JsonPropertyName("country")]     public string Country     { get; set; } = "";
        [JsonPropertyName("countryCode")] public string CountryCode { get; set; } = "";
        [JsonPropertyName("city")]        public string City        { get; set; } = "";
        [JsonPropertyName("lat")]         public double Lat         { get; set; }
        [JsonPropertyName("lon")]         public double Lon         { get; set; }
        [JsonPropertyName("asn")]         public string Asn         { get; set; } = "";
        [JsonPropertyName("org")]         public string Org         { get; set; } = "";
    }
}
