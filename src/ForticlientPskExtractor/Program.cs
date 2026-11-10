using ForticlientPskExtractor;

// ---------------------------------------------------------------------------
// fcpsk - FortiClient VPN preshared-key / username extractor
//
// Lists VPN tunnels from a FortiClient configuration and decrypts their
// EncX-protected preshared keys and usernames by calling FortiClient's own
// utilsdll.dll. See README.md for the full workflow.
// ---------------------------------------------------------------------------

var opts = CliOptions.Parse(args);
if (opts is null) { CliOptions.PrintUsage(); return 2; }
if (opts.ShowHelp) { CliOptions.PrintUsage(); return 0; }

if (!File.Exists(opts.ConfigPath))
{
    Console.Error.WriteLine($"Config file not found: {opts.ConfigPath}");
    return 2;
}

// The context/password is required to decrypt. Prompt if not supplied.
var password = opts.Password;
if (string.IsNullOrEmpty(password))
    password = Prompt("Export password (context): ");
if (string.IsNullOrEmpty(password))
{
    Console.Error.WriteLine("No password/context provided; cannot decrypt.");
    return 2;
}

List<Tunnel> tunnels;
try
{
    tunnels = ConfigParser.Parse(opts.ConfigPath);
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Failed to parse config: {ex.Message}");
    return 1;
}

if (tunnels.Count == 0)
{
    Console.WriteLine("No VPN tunnels found in the configuration.");
    return 0;
}

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine(
        "Decryption requires Windows x64: this tool loads FortiClient's native DLLs.");
    return 1;
}

NativeDecryptor decryptor;
try
{
    decryptor = NativeDecryptor.Create(opts.FcDir, password);
}
catch (Exception ex)
{
    Console.Error.WriteLine("Cannot initialise decryptor:");
    Console.Error.WriteLine("  " + ex.Message);
    return 1;
}

foreach (var t in tunnels)
{
    if (t.UsernameEnc is not null)
    {
        t.Username = decryptor.Decrypt(t.UsernameEnc, out var uerr);
        if (t.Username is null && uerr is not null) t.Note = $"username: {uerr}";
    }
    if (t.PresharedKeyEnc is not null)
    {
        t.PresharedKey = decryptor.Decrypt(t.PresharedKeyEnc, out var perr);
        if (t.PresharedKey is null && perr is not null)
            t.Note = t.Note is null ? $"psk: {perr}" : $"{t.Note}; psk: {perr}";
    }
}

Report.Print(tunnels, opts.ShowHex);
return 0;

// --- local helper -----------------------------------------------------------
static string Prompt(string label)
{
    Console.Write(label);
    return Console.ReadLine()?.Trim() ?? string.Empty;
}
