using System.Text;

namespace ForticlientPskExtractor;

/// <summary>Renders the decrypted tunnel list as an aligned console table.</summary>
public static class Report
{
    public static void Print(IReadOnlyList<Tunnel> tunnels, bool showHex)
    {
        string Psk(Tunnel t) =>
            t.PresharedKey ?? (t.Type == "SSL" ? "-" : "(not recovered)");
        string User(Tunnel t) => t.Username ?? "-";

        var rows = tunnels.Select(t => new[]
        {
            t.Name,
            t.Type,
            t.Server ?? "-",
            User(t),
            Psk(t),
        }).ToList();

        string[] headers = { "TUNNEL", "TYPE", "SERVER", "USERNAME", "PRESHARED KEY" };
        var widths = new int[headers.Length];
        for (int i = 0; i < headers.Length; i++)
            widths[i] = Math.Max(headers[i].Length, rows.Count == 0 ? 0 : rows.Max(r => r[i].Length));

        Console.WriteLine();
        WriteRow(headers, widths);
        Console.WriteLine(string.Join("-+-", widths.Select(w => new string('-', w))));
        foreach (var r in rows)
            WriteRow(r, widths);
        Console.WriteLine();

        int ok = tunnels.Count(t => t.PresharedKey is not null);
        int ipsec = tunnels.Count(t => t.Type == "IPsec");
        Console.WriteLine($"{tunnels.Count} tunnel(s): {ipsec} IPsec, {tunnels.Count - ipsec} SSL. " +
                          $"Preshared keys recovered: {ok}/{ipsec}.");

        var notes = tunnels.Where(t => t.Note is not null).ToList();
        if (notes.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("Notes:");
            foreach (var t in notes)
                Console.WriteLine($"  {t.Name}: {t.Note}");
        }

        if (showHex)
        {
            Console.WriteLine();
            Console.WriteLine("Hex (plaintext bytes):");
            foreach (var t in tunnels)
            {
                if (t.PresharedKey is not null)
                    Console.WriteLine($"  {t.Name} psk  = {ToHex(t.PresharedKey)}");
                if (t.Username is not null)
                    Console.WriteLine($"  {t.Name} user = {ToHex(t.Username)}");
            }
        }
    }

    private static void WriteRow(string[] cells, int[] widths)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < cells.Length; i++)
        {
            if (i > 0) sb.Append(" | ");
            sb.Append(cells[i].PadRight(widths[i]));
        }
        Console.WriteLine(sb.ToString().TrimEnd());
    }

    private static string ToHex(string s) =>
        Convert.ToHexString(Encoding.UTF8.GetBytes(s));
}
