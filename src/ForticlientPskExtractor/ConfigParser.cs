using System.Xml.Linq;

namespace ForticlientPskExtractor;

/// <summary>
/// Parses a FortiClient configuration XML (a <c>.conf</c> produced by FortiClient
/// or by <c>FCConfig.exe ... -o export</c>) into a list of tunnels.
/// </summary>
public static class ConfigParser
{
    public static List<Tunnel> Parse(string xmlPath)
    {
        var doc = XDocument.Load(xmlPath);
        var tunnels = new List<Tunnel>();

        var vpn = doc.Root?.Element("vpn");
        if (vpn is null)
            return tunnels;

        // IPsec tunnels: name, server, xauth username, preshared key.
        foreach (var c in vpn.Element("ipsecvpn")?.Element("connections")?.Elements("connection")
                          ?? Enumerable.Empty<XElement>())
        {
            var ike = c.Element("ike_settings");
            tunnels.Add(new Tunnel
            {
                Name = (string?)c.Element("name") ?? "(unnamed)",
                Type = "IPsec",
                Server = (string?)ike?.Element("server"),
                UsernameEnc = Clean((string?)ike?.Element("xauth")?.Element("username")),
                PresharedKeyEnc = Clean((string?)ike?.Element("auth_data")?.Element("preshared_key")),
            });
        }

        // SSL-VPN tunnels: name, server, username (no preshared key).
        foreach (var c in vpn.Element("sslvpn")?.Element("connections")?.Elements("connection")
                          ?? Enumerable.Empty<XElement>())
        {
            tunnels.Add(new Tunnel
            {
                Name = (string?)c.Element("name") ?? "(unnamed)",
                Type = "SSL",
                Server = (string?)c.Element("server"),
                UsernameEnc = Clean((string?)c.Element("username")),
                PresharedKeyEnc = null,
            });
        }

        return tunnels;
    }

    private static string? Clean(string? v)
    {
        v = v?.Trim();
        return string.IsNullOrEmpty(v) ? null : v;
    }
}
